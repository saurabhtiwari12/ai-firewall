"""
Threat Feed Manager – IP reputation scoring from multiple threat intelligence sources.

Sources supported:
  * AbuseIPDB  – confidence-of-abuse score (API key optional; falls back to mock)
  * Spamhaus   – DNS-based block-list look-up (ZEN composite list)
  * Emerging Threats – plain-text IP block list (downloaded by updater)
  * Local cache  – persisted JSON file updated by :mod:`updater`

The final ``get_reputation_score`` value is a float in ``[0, 1]`` where
``1.0`` means *definitely malicious*.  Individual source scores are blended
using configurable weights.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import socket
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
import os

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CACHE_DIR = Path(__file__).parent / "cache"
_CACHE_FILE = _CACHE_DIR / "ip_reputation.json"
_ET_BLOCK_FILE = _CACHE_DIR / "emerging_threats.txt"
_SPAMHAUS_ZONE = "zen.spamhaus.org"

# Weight given to each source when blending scores (must sum to 1.0).
_SOURCE_WEIGHTS: dict[str, float] = {
    "abuseipdb": 0.45,
    "spamhaus": 0.30,
    "emerging_threats": 0.25,
}

# How many seconds a cached score remains fresh.
_CACHE_TTL_SECONDS: int = int(os.getenv("THREAT_CACHE_TTL", "3600"))

# AbuseIPDB REST endpoint.
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_cache() -> dict[str, Any]:
    """Return the on-disk cache as a dict, or an empty dict on any error."""
    try:
        if _CACHE_FILE.exists():
            with _CACHE_FILE.open("r") as fh:
                return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read reputation cache: %s", exc)
    return {}


def _save_cache(cache: dict[str, Any]) -> None:
    """Persist *cache* to disk, silently ignoring I/O errors."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with _CACHE_FILE.open("w") as fh:
            json.dump(cache, fh, indent=2)
    except OSError as exc:
        logger.warning("Could not write reputation cache: %s", exc)


def _load_et_blocklist() -> set[str]:
    """Load Emerging Threats IP block list from the local cache file."""
    ips: set[str] = set()
    if not _ET_BLOCK_FILE.exists():
        logger.debug("Emerging Threats block file not found; skipping")
        return ips
    try:
        with _ET_BLOCK_FILE.open("r") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Accept plain IPs and CIDR notation
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    ips.add(str(net))
                except ValueError:
                    pass
    except OSError as exc:
        logger.warning("Could not read Emerging Threats file: %s", exc)
    return ips


def _normalise_ip(ip: str) -> str:
    """Raise ``ValueError`` for invalid IPs; return the canonical form."""
    return str(ipaddress.ip_address(ip))


# ---------------------------------------------------------------------------
# ThreatFeedManager
# ---------------------------------------------------------------------------

class ThreatFeedManager:
    """
    Unified threat-intelligence manager.

    Parameters
    ----------
    abuseipdb_key:
        API key for AbuseIPDB.  If *None* the value of the environment
        variable ``ABUSEIPDB_API_KEY`` is used.  When no key is available
        the AbuseIPDB source is mocked with a deterministic heuristic.
    cache_ttl:
        Seconds before a cached reputation entry expires.
    request_timeout:
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        abuseipdb_key: str | None = None,
        cache_ttl: int = _CACHE_TTL_SECONDS,
        request_timeout: int = 5,
    ) -> None:
        self._api_key: str = abuseipdb_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self._cache_ttl = cache_ttl
        self._timeout = request_timeout
        self._cache: dict[str, Any] = _load_cache()
        self._et_blocklist: set[str] = _load_et_blocklist()
        logger.info(
            "ThreatFeedManager initialised (AbuseIPDB key=%s, ET entries=%d)",
            "present" if self._api_key else "absent/mock",
            len(self._et_blocklist),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_ip(self, ip: str) -> dict[str, Any]:
        """
        Return a detailed threat profile for *ip*.

        Returns
        -------
        dict with keys:
          ``ip``, ``score`` (0-1), ``is_malicious`` (bool),
          ``sources`` (per-source scores), ``cached`` (bool).
        """
        try:
            ip = _normalise_ip(ip)
        except ValueError:
            logger.error("Invalid IP address: %s", ip)
            return {"ip": ip, "score": 0.0, "is_malicious": False, "sources": {}, "cached": False, "error": "invalid_ip"}

        cached_result = self._get_from_cache(ip)
        if cached_result is not None:
            cached_result["cached"] = True
            return cached_result

        sources: dict[str, float] = {
            "abuseipdb": self._score_abuseipdb(ip),
            "spamhaus": self._score_spamhaus(ip),
            "emerging_threats": self._score_emerging_threats(ip),
        }

        score = sum(sources[src] * _SOURCE_WEIGHTS[src] for src in sources)
        score = min(max(score, 0.0), 1.0)
        is_malicious = score >= 0.5

        result: dict[str, Any] = {
            "ip": ip,
            "score": round(score, 4),
            "is_malicious": is_malicious,
            "sources": {k: round(v, 4) for k, v in sources.items()},
            "cached": False,
            "timestamp": time.time(),
        }

        self._store_in_cache(ip, result)
        logger.debug("check_ip %s → score=%.4f malicious=%s", ip, score, is_malicious)
        return result

    def get_reputation_score(self, ip: str) -> float:
        """
        Return a blended reputation score in ``[0, 1]`` for *ip*.

        ``1.0`` → definitely malicious.  ``0.0`` → clean.
        """
        return self.check_ip(ip)["score"]

    def check_bulk(self, ips: list[str]) -> list[dict[str, Any]]:
        """Check a list of IPs, returning one result dict per IP."""
        results: list[dict[str, Any]] = []
        for ip in ips:
            results.append(self.check_ip(ip))
        return results

    def is_known_malicious(self, ip: str) -> bool:
        """Return ``True`` if *ip* should be immediately blocked."""
        return self.get_reputation_score(ip) >= 0.8

    def reload_et_blocklist(self) -> None:
        """Re-read the Emerging Threats file from disk (useful after updates)."""
        self._et_blocklist = _load_et_blocklist()
        logger.info("ET blocklist reloaded (%d entries)", len(self._et_blocklist))

    def invalidate_cache(self, ip: str | None = None) -> None:
        """Remove *ip* from the cache (or clear the entire cache if *ip* is ``None``)."""
        if ip is None:
            self._cache.clear()
            logger.info("Reputation cache cleared")
        else:
            self._cache.pop(ip, None)
        _save_cache(self._cache)

    # ------------------------------------------------------------------
    # Per-source scoring
    # ------------------------------------------------------------------

    def _score_abuseipdb(self, ip: str) -> float:
        """Return normalised AbuseIPDB confidence score in ``[0, 1]``."""
        if not self._api_key:
            return self._mock_abuseipdb_score(ip)

        try:
            resp = requests.get(
                _ABUSEIPDB_URL,
                headers={"Accept": "application/json", "Key": self._api_key},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return data.get("abuseConfidenceScore", 0) / 100.0
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB request failed for %s: %s", ip, exc)
            return 0.0

    def _mock_abuseipdb_score(self, ip: str) -> float:
        """Deterministic mock score derived from the IP's hash (dev/CI only)."""
        digest = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
        # Reserve a handful of well-known "bad" IPs for testing.
        _KNOWN_BAD = {"192.0.2.1", "198.51.100.1", "203.0.113.1"}
        if ip in _KNOWN_BAD:
            return 0.9
        # Otherwise produce a stable float in [0, 0.4] so most IPs look clean.
        return (digest % 40) / 100.0

    def _score_spamhaus(self, ip: str) -> float:
        """
        Query the Spamhaus ZEN DNS block list.

        Performs a reverse-DNS lookup against ``zen.spamhaus.org``.
        Returns ``1.0`` if listed, ``0.0`` otherwise.
        """
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version != 4:
                # ZEN is IPv4-only; skip for IPv6.
                return 0.0
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.{_SPAMHAUS_ZONE}"
            socket.getaddrinfo(query, None)
            logger.debug("Spamhaus listed: %s", ip)
            return 1.0
        except socket.gaierror:
            # NXDOMAIN – IP is *not* listed.
            return 0.0
        except Exception as exc:
            logger.warning("Spamhaus lookup error for %s: %s", ip, exc)
            return 0.0

    def _score_emerging_threats(self, ip: str) -> float:
        """Return ``1.0`` if *ip* appears in the Emerging Threats block list."""
        try:
            addr = ipaddress.ip_address(ip)
            for entry in self._et_blocklist:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    if addr in net:
                        return 1.0
                except ValueError:
                    continue
        except ValueError:
            pass
        return 0.0

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _get_from_cache(self, ip: str) -> dict[str, Any] | None:
        entry = self._cache.get(ip)
        if entry is None:
            return None
        age = time.time() - entry.get("timestamp", 0.0)
        if age > self._cache_ttl:
            del self._cache[ip]
            return None
        return entry

    def _store_in_cache(self, ip: str, result: dict[str, Any]) -> None:
        self._cache[ip] = result
        _save_cache(self._cache)
