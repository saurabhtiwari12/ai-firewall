"""
Zero-trust policy engine for the AI Firewall.

Implements continuous verification of every flow against a layered ruleset:

  1. **Whitelist** – permanently allow trusted IPs/CIDRs (highest precedence)
  2. **Blacklist** – block known-bad IPs with optional TTL
  3. **Policy rules** – JSON-configured rules that match on various flow fields
  4. **Rate limiting** – per-IP token-bucket limiter
  5. **Threat-score-based** – escalating actions based on risk level

Policy decisions (in order of precedence)
-----------------------------------------
  allow      – pass traffic without logging
  monitor    – pass and record telemetry
  rate_limit – throttle the source IP
  block      – drop and log
  quarantine – redirect to sinkhole for deep inspection

All decisions are written to a rotating audit log.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Union

from threat_scoring import ThreatScore, RiskLevel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Policy actions
# ---------------------------------------------------------------------------

class PolicyAction(str, Enum):
    ALLOW = "allow"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    BLOCK = "block"
    QUARANTINE = "quarantine"


# ---------------------------------------------------------------------------
# Policy decision
# ---------------------------------------------------------------------------

@dataclass
class PolicyDecision:
    """Result of evaluating a flow against the zero-trust policy engine."""

    action: PolicyAction
    reason: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    threat_score: Optional[float] = None
    risk_level: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    rule_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "threat_score": self.threat_score,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp,
            "rule_name": self.rule_name,
        }


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

@dataclass
class _TokenBucket:
    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(default_factory=time.monotonic, init=False)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)

    def consume(self, amount: int = 1) -> bool:
        """Return True if *amount* tokens are available and consume them."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


# ---------------------------------------------------------------------------
# Policy rule
# ---------------------------------------------------------------------------

@dataclass
class PolicyRule:
    """A single named policy rule loaded from configuration."""

    name: str
    action: PolicyAction
    priority: int = 100  # lower = higher precedence

    # Match conditions – None means "match anything"
    src_ip_cidr: Optional[str] = None
    dst_ip_cidr: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    min_threat_score: Optional[float] = None
    max_threat_score: Optional[float] = None
    risk_levels: Optional[list[str]] = None  # e.g. ["high_risk", "critical"]

    def matches(self, ts: ThreatScore) -> bool:
        """Test whether this rule matches *ts*."""
        if self.src_ip_cidr and not _ip_in_cidr(ts.src_ip, self.src_ip_cidr):
            return False
        if self.dst_ip_cidr and not _ip_in_cidr(ts.dst_ip, self.dst_ip_cidr):
            return False
        if self.src_port is not None and ts.src_port != self.src_port:
            return False
        if self.dst_port is not None and ts.dst_port != self.dst_port:
            return False
        if self.protocol is not None and ts.protocol != self.protocol:
            return False
        if self.min_threat_score is not None and ts.composite < self.min_threat_score:
            return False
        if self.max_threat_score is not None and ts.composite > self.max_threat_score:
            return False
        if self.risk_levels is not None and ts.risk_level.value not in self.risk_levels:
            return False
        return True

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyRule":
        action = PolicyAction(data["action"])
        return cls(
            name=data["name"],
            action=action,
            priority=data.get("priority", 100),
            src_ip_cidr=data.get("src_ip_cidr"),
            dst_ip_cidr=data.get("dst_ip_cidr"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol"),
            min_threat_score=data.get("min_threat_score"),
            max_threat_score=data.get("max_threat_score"),
            risk_levels=data.get("risk_levels"),
        )


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# ZeroTrustPolicyEngine
# ---------------------------------------------------------------------------

class ZeroTrustPolicyEngine:
    """
    Evaluates network flows against a zero-trust policy.

    Parameters
    ----------
    default_action:
        Fall-through action when no rule matches.
    blacklist_ttl_sec:
        How long (seconds) a dynamically added blacklist entry persists.
    rate_limit_rps:
        Requests-per-second token-bucket capacity per IP.
    rate_limit_window_sec:
        Token refill window (essentially 1/refill_rate).
    audit_log_path:
        Path for the JSON-lines audit log file.
    policy_file:
        Path to a JSON file containing ``PolicyRule`` definitions.
    """

    def __init__(
        self,
        default_action: str = "monitor",
        blacklist_ttl_sec: int = 3600,
        rate_limit_rps: int = 100,
        rate_limit_window_sec: int = 1,
        audit_log_path: str = "logs/audit.log",
        policy_file: Optional[str] = None,
    ) -> None:
        self.default_action = PolicyAction(default_action)
        self.blacklist_ttl = blacklist_ttl_sec
        self.rate_limit_rps = rate_limit_rps
        self.rate_limit_window = rate_limit_window_sec

        # IP sets
        self._whitelist: set[str] = set()
        self._whitelist_cidrs: list[str] = []
        self._blacklist: dict[str, float] = {}  # ip -> expiry timestamp
        self._lock = threading.RLock()

        # Rate limiters per IP
        self._rate_limiters: dict[str, _TokenBucket] = {}

        # Policy rules (sorted by priority)
        self._rules: list[PolicyRule] = []

        # Audit logger
        self._audit_logger = self._setup_audit_logger(audit_log_path)

        # Load optional policy file
        if policy_file:
            self.load_policy_file(policy_file)

        # Default hardcoded rules
        self._install_default_rules()

    # ------------------------------------------------------------------
    # Whitelist / Blacklist management
    # ------------------------------------------------------------------

    def add_whitelist(self, ip_or_cidr: str) -> None:
        """Add an IP or CIDR to the permanent whitelist."""
        with self._lock:
            if "/" in ip_or_cidr:
                self._whitelist_cidrs.append(ip_or_cidr)
            else:
                self._whitelist.add(ip_or_cidr)
        logger.info("Whitelisted: %s", ip_or_cidr)

    def remove_whitelist(self, ip_or_cidr: str) -> None:
        with self._lock:
            self._whitelist.discard(ip_or_cidr)
            if ip_or_cidr in self._whitelist_cidrs:
                self._whitelist_cidrs.remove(ip_or_cidr)

    def add_blacklist(self, ip: str, ttl: Optional[int] = None) -> None:
        """Blacklist *ip* for *ttl* seconds (default: configured TTL)."""
        expiry = time.time() + (ttl if ttl is not None else self.blacklist_ttl)
        with self._lock:
            self._blacklist[ip] = expiry
        logger.info("Blacklisted: %s (expires in %ds)", ip, ttl or self.blacklist_ttl)

    def remove_blacklist(self, ip: str) -> None:
        with self._lock:
            self._blacklist.pop(ip, None)

    def is_blacklisted(self, ip: str) -> bool:
        with self._lock:
            expiry = self._blacklist.get(ip)
            if expiry is None:
                return False
            if time.time() > expiry:
                del self._blacklist[ip]
                return False
            return True

    def purge_expired_blacklist(self) -> int:
        """Remove expired blacklist entries; return count removed."""
        now = time.time()
        with self._lock:
            expired = [ip for ip, exp in self._blacklist.items() if now > exp]
            for ip in expired:
                del self._blacklist[ip]
        if expired:
            logger.debug("Purged %d expired blacklist entries", len(expired))
        return len(expired)

    # ------------------------------------------------------------------
    # Policy rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: PolicyRule) -> None:
        with self._lock:
            self._rules.append(rule)
            self._rules.sort(key=lambda r: r.priority)

    def load_policy_file(self, path: Union[str, Path]) -> int:
        """Load rules from a JSON file.  Returns the number of rules loaded."""
        p = Path(path)
        if not p.exists():
            logger.warning("Policy file not found: %s", p)
            return 0
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            rules = [PolicyRule.from_dict(r) for r in data.get("rules", [])]
            with self._lock:
                for rule in rules:
                    self._rules.append(rule)
                self._rules.sort(key=lambda r: r.priority)
            logger.info("Loaded %d policy rules from %s", len(rules), p)
            return len(rules)
        except Exception as exc:
            logger.error("Failed to load policy file %s: %s", p, exc)
            return 0

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate(self, threat_score: ThreatScore) -> PolicyDecision:
        """
        Evaluate a threat score and return a policy decision.

        Precedence:
          1. Whitelist → allow
          2. Blacklist → block
          3. Rate limiter → rate_limit
          4. Policy rules (by priority)
          5. Default action
        """
        src = threat_score.src_ip

        # 1. Whitelist
        if self._is_whitelisted(src):
            decision = self._decide(
                PolicyAction.ALLOW, "whitelist", threat_score, rule_name="whitelist"
            )
            self._audit(decision)
            return decision

        # 2. Blacklist
        if self.is_blacklisted(src):
            decision = self._decide(
                PolicyAction.BLOCK, "blacklist", threat_score, rule_name="blacklist"
            )
            self._audit(decision)
            return decision

        # 3. Rate limiter
        if not self._check_rate_limit(src):
            decision = self._decide(
                PolicyAction.RATE_LIMIT, "rate_limit_exceeded", threat_score,
                rule_name="rate_limiter",
            )
            self._audit(decision)
            return decision

        # 4. Policy rules
        with self._lock:
            rules_snapshot = list(self._rules)

        for rule in rules_snapshot:
            if rule.matches(threat_score):
                decision = self._decide(rule.action, f"rule:{rule.name}", threat_score, rule.name)
                # Auto-blacklist on block/quarantine decisions
                if rule.action in (PolicyAction.BLOCK, PolicyAction.QUARANTINE):
                    self.add_blacklist(src)
                self._audit(decision)
                return decision

        # 5. Default
        decision = self._decide(self.default_action, "default", threat_score)
        self._audit(decision)
        return decision

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_whitelisted(self, ip: str) -> bool:
        with self._lock:
            if ip in self._whitelist:
                return True
            return any(_ip_in_cidr(ip, cidr) for cidr in self._whitelist_cidrs)

    def _check_rate_limit(self, ip: str) -> bool:
        """Return True if the IP is within its rate limit."""
        with self._lock:
            if ip not in self._rate_limiters:
                self._rate_limiters[ip] = _TokenBucket(
                    capacity=self.rate_limit_rps,
                    refill_rate=self.rate_limit_rps / max(1, self.rate_limit_window),
                )
            bucket = self._rate_limiters[ip]
        return bucket.consume()

    @staticmethod
    def _decide(
        action: PolicyAction,
        reason: str,
        ts: ThreatScore,
        rule_name: Optional[str] = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            action=action,
            reason=reason,
            src_ip=ts.src_ip,
            dst_ip=ts.dst_ip,
            src_port=ts.src_port,
            dst_port=ts.dst_port,
            protocol=ts.protocol,
            threat_score=ts.composite,
            risk_level=ts.risk_level.value,
            rule_name=rule_name,
        )

    def _audit(self, decision: PolicyDecision) -> None:
        try:
            import json as _json
            self._audit_logger.info(_json.dumps(decision.to_dict()))
        except Exception as exc:
            logger.debug("Audit log write failed: %s", exc)

    @staticmethod
    def _setup_audit_logger(path: str) -> logging.Logger:
        audit = logging.getLogger("firewall.audit")
        audit.setLevel(logging.INFO)
        audit.propagate = False
        if audit.handlers:
            return audit
        try:
            log_path = Path(path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                log_path, maxBytes=50 * 1024 * 1024, backupCount=10, encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            audit.addHandler(handler)
        except OSError as exc:
            logger.warning("Cannot open audit log %s: %s", path, exc)
        return audit

    def _install_default_rules(self) -> None:
        """Install built-in catch-all rules for critical threat levels."""
        self.add_rule(
            PolicyRule(
                name="auto-block-critical",
                action=PolicyAction.BLOCK,
                priority=10,
                risk_levels=["critical"],
            )
        )
        self.add_rule(
            PolicyRule(
                name="auto-quarantine-high-risk",
                action=PolicyAction.QUARANTINE,
                priority=20,
                risk_levels=["high_risk"],
                min_threat_score=0.70,
            )
        )
        self.add_rule(
            PolicyRule(
                name="rate-limit-suspicious",
                action=PolicyAction.RATE_LIMIT,
                priority=30,
                risk_levels=["suspicious"],
            )
        )
