"""
Firewall enforcement module.

Translates ``PolicyDecision`` objects into OS-level firewall rules.

Platform support
----------------
  Linux   – iptables (default) or nftables
  Windows – netsh advfirewall

A *dry-run* mode (enabled by default in non-production) logs the commands
that *would* be executed without running them.  Enable live enforcement only
on systems with appropriate privileges.

All rules are tracked in an internal registry so they can be cleaned up when
they expire or are superseded.
"""

from __future__ import annotations

import logging
import platform
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from zero_trust_policy import PolicyAction, PolicyDecision

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Backend enum
# ---------------------------------------------------------------------------

class EnforcementBackend(str, Enum):
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    NETSH = "netsh"
    MOCK = "mock"  # no-op for testing


# ---------------------------------------------------------------------------
# Tracked rule entry
# ---------------------------------------------------------------------------

@dataclass
class EnforcedRule:
    """Record of a firewall rule installed by this engine."""

    rule_id: str
    ip: str
    action: PolicyAction
    backend: EnforcementBackend
    installed_at: float = field(default_factory=time.time)
    ttl_sec: int = 3600  # seconds until auto-cleanup
    undo_command: Optional[list[str]] = None  # command to remove the rule

    @property
    def expired(self) -> bool:
        return time.time() > self.installed_at + self.ttl_sec


# ---------------------------------------------------------------------------
# FirewallEnforcer
# ---------------------------------------------------------------------------

class FirewallEnforcer:
    """
    Applies policy decisions as OS-level firewall rules.

    Parameters
    ----------
    dry_run:
        When ``True``, commands are logged but not executed.
    backend:
        ``"auto"`` detects the platform; otherwise specify explicitly.
    sinkhole_ip:
        IP address to which quarantined traffic is redirected.
    rule_cleanup_interval_sec:
        How often the background cleaner runs to remove expired rules.
    """

    def __init__(
        self,
        dry_run: bool = True,
        backend: str = "auto",
        sinkhole_ip: str = "100.64.0.1",
        rule_cleanup_interval_sec: int = 300,
    ) -> None:
        self.dry_run = dry_run
        self.sinkhole_ip = sinkhole_ip
        self._backend = self._resolve_backend(backend)

        self._rules: dict[str, EnforcedRule] = {}
        self._rules_lock = threading.Lock()

        self._cleanup_stop = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_interval = rule_cleanup_interval_sec

        self._stats = {"applied": 0, "removed": 0, "errors": 0}
        self._stats_lock = threading.Lock()

        mode_tag = "DRY-RUN" if dry_run else "LIVE"
        logger.info(
            "FirewallEnforcer initialised [backend=%s mode=%s sinkhole=%s]",
            self._backend.value,
            mode_tag,
            sinkhole_ip,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start background rule-cleanup thread."""
        self._cleanup_stop.clear()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, name="fw-cleanup", daemon=True
        )
        self._cleanup_thread.start()

    def stop(self) -> None:
        """Stop cleanup thread and remove all tracked rules."""
        self._cleanup_stop.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5.0)
        self._remove_all_rules()
        logger.info("FirewallEnforcer stopped. Stats: %s", self._stats)

    # ------------------------------------------------------------------
    # Public enforcement API
    # ------------------------------------------------------------------

    def enforce(self, decision: PolicyDecision) -> bool:
        """
        Apply a policy decision.

        Returns ``True`` if an enforcement action was taken.
        """
        action = decision.action
        ip = decision.src_ip

        if action == PolicyAction.ALLOW or action == PolicyAction.MONITOR:
            return False

        if action == PolicyAction.BLOCK:
            return self.block_ip(ip, reason=decision.reason)

        if action == PolicyAction.RATE_LIMIT:
            return self.rate_limit_ip(ip)

        if action == PolicyAction.QUARANTINE:
            return self.quarantine_ip(ip)

        logger.debug("No enforcement action for policy=%s", action)
        return False

    def block_ip(self, ip: str, ttl_sec: int = 3600, reason: str = "") -> bool:
        """Install a DROP rule for *ip*."""
        rule_id = f"block-{ip}"
        if self._rule_exists(rule_id):
            logger.debug("Block rule already installed for %s", ip)
            return True

        cmds = self._build_block_cmds(ip)
        undo = self._build_unblock_cmds(ip)
        return self._apply_rule(rule_id, ip, PolicyAction.BLOCK, cmds, undo, ttl_sec,
                                f"Blocking {ip} – {reason}")

    def rate_limit_ip(self, ip: str, pps: int = 10, burst: int = 20,
                      ttl_sec: int = 300) -> bool:
        """Install a rate-limiting rule for *ip*."""
        rule_id = f"ratelimit-{ip}"
        if self._rule_exists(rule_id):
            return True
        cmds = self._build_ratelimit_cmds(ip, pps, burst)
        undo = self._build_unratelimit_cmds(ip)
        return self._apply_rule(rule_id, ip, PolicyAction.RATE_LIMIT, cmds, undo, ttl_sec,
                                f"Rate-limiting {ip}")

    def quarantine_ip(self, ip: str, ttl_sec: int = 1800) -> bool:
        """Redirect all traffic from *ip* to the sinkhole."""
        rule_id = f"quarantine-{ip}"
        if self._rule_exists(rule_id):
            return True
        cmds = self._build_quarantine_cmds(ip)
        undo = self._build_unquarantine_cmds(ip)
        return self._apply_rule(rule_id, ip, PolicyAction.QUARANTINE, cmds, undo, ttl_sec,
                                f"Quarantining {ip} → {self.sinkhole_ip}")

    def unblock_ip(self, ip: str) -> bool:
        """Remove a block rule for *ip* immediately."""
        return self._remove_rule(f"block-{ip}")

    def cleanup_expired_rules(self) -> int:
        """Remove all expired rules; return count removed."""
        with self._rules_lock:
            expired = [rid for rid, rule in self._rules.items() if rule.expired]
        removed = 0
        for rid in expired:
            if self._remove_rule(rid):
                removed += 1
        return removed

    def get_active_rules(self) -> list[EnforcedRule]:
        with self._rules_lock:
            return [r for r in self._rules.values() if not r.expired]

    # ------------------------------------------------------------------
    # Platform-specific command builders
    # ------------------------------------------------------------------

    def _build_block_cmds(self, ip: str) -> list[list[str]]:
        if self._backend == EnforcementBackend.IPTABLES:
            return [["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                    ["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"]]
        if self._backend == EnforcementBackend.NFTABLES:
            return [["nft", "add", "rule", "ip", "filter", "input",
                     f"ip saddr {ip}", "drop"]]
        if self._backend == EnforcementBackend.NETSH:
            return [["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name=FW_BLOCK_{ip}", "dir=in", "action=block",
                     f"remoteip={ip}"]]
        return []  # mock

    def _build_unblock_cmds(self, ip: str) -> list[list[str]]:
        if self._backend == EnforcementBackend.IPTABLES:
            return [["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"]]
        if self._backend == EnforcementBackend.NFTABLES:
            return []  # nftables rules require handle IDs for deletion
        if self._backend == EnforcementBackend.NETSH:
            return [["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name=FW_BLOCK_{ip}"]]
        return []

    def _build_ratelimit_cmds(self, ip: str, pps: int, burst: int) -> list[list[str]]:
        if self._backend == EnforcementBackend.IPTABLES:
            return [
                ["iptables", "-I", "INPUT", "-s", ip, "-m", "limit",
                 "--limit", f"{pps}/sec", "--limit-burst", str(burst),
                 "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            ]
        return []

    def _build_unratelimit_cmds(self, ip: str) -> list[list[str]]:
        if self._backend == EnforcementBackend.IPTABLES:
            return [["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]]
        return []

    def _build_quarantine_cmds(self, ip: str) -> list[list[str]]:
        if self._backend == EnforcementBackend.IPTABLES:
            return [
                ["iptables", "-t", "nat", "-I", "PREROUTING", "-s", ip,
                 "-j", "DNAT", "--to-destination", self.sinkhole_ip],
            ]
        if self._backend == EnforcementBackend.NETSH:
            return [["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name=FW_QUARANTINE_{ip}", "dir=in", "action=block",
                     f"remoteip={ip}"]]
        return []

    def _build_unquarantine_cmds(self, ip: str) -> list[list[str]]:
        if self._backend == EnforcementBackend.IPTABLES:
            return [
                ["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip,
                 "-j", "DNAT", "--to-destination", self.sinkhole_ip],
            ]
        return []

    # ------------------------------------------------------------------
    # Rule execution helpers
    # ------------------------------------------------------------------

    def _apply_rule(
        self,
        rule_id: str,
        ip: str,
        action: PolicyAction,
        cmds: list[list[str]],
        undo: list[list[str]],
        ttl_sec: int,
        log_message: str,
    ) -> bool:
        success = True
        for cmd in cmds:
            if not self._exec(cmd):
                success = False
                break

        if success or self.dry_run:
            record = EnforcedRule(
                rule_id=rule_id,
                ip=ip,
                action=action,
                backend=self._backend,
                ttl_sec=ttl_sec,
                undo_command=undo[0] if undo else None,
            )
            with self._rules_lock:
                self._rules[rule_id] = record
            with self._stats_lock:
                self._stats["applied"] += 1
            logger.info("%s %s", "[DRY-RUN]" if self.dry_run else "[ENFORCED]", log_message)

        return success

    def _remove_rule(self, rule_id: str) -> bool:
        with self._rules_lock:
            rule = self._rules.get(rule_id)
        if not rule:
            return False

        if rule.undo_command:
            self._exec(rule.undo_command)

        with self._rules_lock:
            self._rules.pop(rule_id, None)
        with self._stats_lock:
            self._stats["removed"] += 1
        return True

    def _remove_all_rules(self) -> None:
        with self._rules_lock:
            rule_ids = list(self._rules.keys())
        for rid in rule_ids:
            self._remove_rule(rid)

    def _rule_exists(self, rule_id: str) -> bool:
        with self._rules_lock:
            rule = self._rules.get(rule_id)
        return rule is not None and not rule.expired

    def _exec(self, cmd: list[str]) -> bool:
        """Execute a shell command, honouring dry_run mode."""
        cmd_str = shlex.join(cmd)
        if self.dry_run or self._backend == EnforcementBackend.MOCK:
            logger.debug("[DRY-RUN] %s", cmd_str)
            return True
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error(
                    "Command failed (rc=%d): %s\n%s",
                    result.returncode,
                    cmd_str,
                    result.stderr.strip(),
                )
                with self._stats_lock:
                    self._stats["errors"] += 1
                return False
            return True
        except FileNotFoundError:
            logger.error("Command not found: %s", cmd[0])
            with self._stats_lock:
                self._stats["errors"] += 1
            return False
        except subprocess.TimeoutExpired:
            logger.error("Command timed out: %s", cmd_str)
            with self._stats_lock:
                self._stats["errors"] += 1
            return False
        except Exception as exc:
            logger.exception("Unexpected error running %s: %s", cmd_str, exc)
            with self._stats_lock:
                self._stats["errors"] += 1
            return False

    # ------------------------------------------------------------------
    # Background cleanup
    # ------------------------------------------------------------------

    def _cleanup_loop(self) -> None:
        while not self._cleanup_stop.wait(timeout=self._cleanup_interval):
            removed = self.cleanup_expired_rules()
            if removed:
                logger.info("Cleaned up %d expired firewall rules", removed)

    # ------------------------------------------------------------------
    # Platform detection
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_backend(backend: str) -> EnforcementBackend:
        if backend == "mock":
            return EnforcementBackend.MOCK

        if backend != "auto":
            try:
                return EnforcementBackend(backend)
            except ValueError:
                logger.warning("Unknown backend '%s'; falling back to auto", backend)

        system = platform.system().lower()
        if system == "windows":
            return EnforcementBackend.NETSH
        if system == "linux":
            # Prefer nftables if available
            if _command_exists("nft"):
                return EnforcementBackend.NFTABLES
            if _command_exists("iptables"):
                return EnforcementBackend.IPTABLES
        logger.warning(
            "No supported firewall backend found on platform '%s'; using MOCK", system
        )
        return EnforcementBackend.MOCK


def _command_exists(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None
