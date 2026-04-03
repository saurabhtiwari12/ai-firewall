"""
Behavioral analysis engine for the AI Firewall.

Tracks per-IP connection history and detects:
  * **Port scanning** – one source probing many ports in a short window
  * **Rate anomalies** – connection or packet burst beyond threshold
  * **Data exfiltration** – abnormally large outbound byte transfers
  * **Botnet beaconing** – periodic, low-variance connections to the same dst
  * **DDoS** – many sources flooding the same destination IP

Each analyser returns a score in [0.0, 1.0] where 1.0 is maximum suspicion.
The aggregate ``BehavioralScore`` combines sub-scores with equal weights.

Thread safety: ``BehavioralAnalyzer`` uses a single internal lock and is safe
to call from multiple threads.
"""

from __future__ import annotations

import collections
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from flow_aggregation import FlowRecord

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sub-score results
# ---------------------------------------------------------------------------

@dataclass
class BehavioralScore:
    """Composite behavioral threat score for a single flow."""

    port_scan_score: float = 0.0
    rate_anomaly_score: float = 0.0
    exfiltration_score: float = 0.0
    beaconing_score: float = 0.0
    ddos_score: float = 0.0

    # Detected pattern descriptions
    indicators: list[str] = field(default_factory=list)

    @property
    def overall(self) -> float:
        """Unweighted mean of all sub-scores, clipped to [0, 1]."""
        scores = [
            self.port_scan_score,
            self.rate_anomaly_score,
            self.exfiltration_score,
            self.beaconing_score,
            self.ddos_score,
        ]
        return float(min(1.0, sum(scores) / len(scores)))


# ---------------------------------------------------------------------------
# Internal per-IP state objects
# ---------------------------------------------------------------------------

@dataclass
class _IPState:
    """Sliding-window state tracked per source IP."""

    # Ring-buffer of (timestamp, dst_port) for port-scan detection
    port_history: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=2000)
    )
    # Ring-buffer of connection timestamps for rate detection
    conn_timestamps: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=5000)
    )
    # Total outbound bytes tracked
    outbound_bytes: int = 0
    # Timestamps of connections to each dst_ip for beaconing
    beacon_history: dict[str, collections.deque] = field(
        default_factory=lambda: collections.defaultdict(
            lambda: collections.deque(maxlen=100)
        )
    )
    # Last reset timestamp (for periodic cleanup)
    created_at: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# Analyzers
# ---------------------------------------------------------------------------

class BehavioralAnalyzer:
    """
    Stateful per-IP behavioral analysis.

    Parameters
    ----------
    port_scan_threshold:
        Number of unique ports to distinct destinations in *port_scan_window_sec*
        that triggers a port-scan alert.
    port_scan_window_sec:
        Sliding window for port-scan detection.
    conn_rate_threshold:
        Max new connections within *conn_rate_window_sec* before flagging.
    conn_rate_window_sec:
        Rate-check window in seconds.
    exfil_bytes_threshold:
        Cumulative outbound bytes per IP that triggers exfiltration concern.
    beacon_interval_sec:
        Expected beaconing interval (seconds) for C&C detection.
    beacon_jitter_tolerance:
        Fractional tolerance; 0.1 = ±10 % jitter.
    ddos_src_threshold:
        Unique source IPs to the same destination within *ddos_window_sec*.
    ddos_window_sec:
        DDoS detection window.
    history_window_sec:
        Maximum age of tracking data to retain (for memory management).
    """

    def __init__(
        self,
        port_scan_threshold: int = 20,
        port_scan_window_sec: int = 60,
        conn_rate_threshold: int = 100,
        conn_rate_window_sec: int = 10,
        exfil_bytes_threshold: int = 10_000_000,
        beacon_interval_sec: float = 60.0,
        beacon_jitter_tolerance: float = 0.1,
        ddos_src_threshold: int = 50,
        ddos_window_sec: int = 10,
        history_window_sec: int = 300,
    ) -> None:
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window_sec
        self.conn_rate_threshold = conn_rate_threshold
        self.conn_rate_window = conn_rate_window_sec
        self.exfil_bytes_threshold = exfil_bytes_threshold
        self.beacon_interval = beacon_interval_sec
        self.beacon_jitter = beacon_jitter_tolerance
        self.ddos_src_threshold = ddos_src_threshold
        self.ddos_window = ddos_window_sec
        self.history_window = history_window_sec

        self._ip_state: dict[str, _IPState] = {}
        # dst_ip → deque of (timestamp, src_ip) for DDoS tracking
        self._dst_srcs: dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=10_000)
        )
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, flow: FlowRecord) -> BehavioralScore:
        """
        Analyze a completed flow and return a ``BehavioralScore``.

        This method is thread-safe.
        """
        with self._lock:
            self._maybe_cleanup()
            src = flow.src_ip
            state = self._get_or_create(src)

            now = flow.last_seen
            self._record_connection(state, flow, now)

            score = BehavioralScore()
            score.port_scan_score = self._check_port_scan(state, now)
            score.rate_anomaly_score = self._check_rate_anomaly(state, now)
            score.exfiltration_score = self._check_exfiltration(state, flow)
            score.beaconing_score = self._check_beaconing(state, flow, now)
            score.ddos_score = self._check_ddos(flow, now)

            if score.port_scan_score > 0.5:
                score.indicators.append("port_scan")
            if score.rate_anomaly_score > 0.5:
                score.indicators.append("rate_anomaly")
            if score.exfiltration_score > 0.5:
                score.indicators.append("data_exfiltration")
            if score.beaconing_score > 0.5:
                score.indicators.append("beaconing")
            if score.ddos_score > 0.5:
                score.indicators.append("ddos")

            return score

    def reset_ip(self, ip: str) -> None:
        """Clear all tracking state for *ip*."""
        with self._lock:
            self._ip_state.pop(ip, None)

    # ------------------------------------------------------------------
    # Internal helpers – state management
    # ------------------------------------------------------------------

    def _get_or_create(self, ip: str) -> _IPState:
        if ip not in self._ip_state:
            self._ip_state[ip] = _IPState()
        return self._ip_state[ip]

    def _record_connection(self, state: _IPState, flow: FlowRecord, now: float) -> None:
        state.conn_timestamps.append(now)
        state.port_history.append((now, flow.dst_ip, flow.dst_port))
        state.outbound_bytes += flow.fwd_bytes
        state.beacon_history[flow.dst_ip].append(now)

        self._dst_srcs[flow.dst_ip].append((now, flow.src_ip))

    # ------------------------------------------------------------------
    # Internal helpers – detection logic
    # ------------------------------------------------------------------

    def _check_port_scan(self, state: _IPState, now: float) -> float:
        """Return a score proportional to distinct ports contacted in the window."""
        cutoff = now - self.port_scan_window
        recent_ports: set[tuple[str, int]] = set()
        for ts, dst_ip, dst_port in state.port_history:
            if ts >= cutoff:
                recent_ports.add((dst_ip, dst_port))

        count = len(recent_ports)
        if count < self.port_scan_threshold:
            return 0.0
        # Sigmoid-like score: reaches ~0.9 at 3× threshold
        ratio = count / self.port_scan_threshold
        return float(min(1.0, 1.0 - 1.0 / (1.0 + (ratio - 1.0) ** 2)))

    def _check_rate_anomaly(self, state: _IPState, now: float) -> float:
        """Score based on new connections per second."""
        cutoff = now - self.conn_rate_window
        recent = sum(1 for t in state.conn_timestamps if t >= cutoff)
        if recent < self.conn_rate_threshold:
            return 0.0
        ratio = recent / self.conn_rate_threshold
        return float(min(1.0, math.log(ratio) / math.log(10)))

    def _check_exfiltration(self, state: _IPState, flow: FlowRecord) -> float:
        """Score based on cumulative outbound bytes."""
        if state.outbound_bytes < self.exfil_bytes_threshold:
            return 0.0
        ratio = state.outbound_bytes / self.exfil_bytes_threshold
        return float(min(1.0, math.log(ratio + 1) / math.log(11)))

    def _check_beaconing(self, state: _IPState, flow: FlowRecord, now: float) -> float:
        """
        Detect periodic beaconing to a single destination.

        Requires at least 5 samples; calculates coefficient of variation of
        inter-arrival times.  Low variance near the expected interval → high score.
        """
        timestamps = list(state.beacon_history[flow.dst_ip])
        if len(timestamps) < 5:
            return 0.0

        # Compute inter-arrival times
        iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        n = len(iats)
        mean_iat = sum(iats) / n
        if mean_iat <= 0:
            return 0.0

        variance = sum((x - mean_iat) ** 2 for x in iats) / n
        cv = math.sqrt(variance) / mean_iat  # coefficient of variation

        # Is the period close to the expected beacon interval?
        period_match = abs(mean_iat - self.beacon_interval) / self.beacon_interval
        if period_match > 1.0:
            return 0.0  # interval is way off

        # Low CV (regular) + close period = strong beaconing signal
        regularity_score = max(0.0, 1.0 - cv / self.beacon_jitter)
        period_score = max(0.0, 1.0 - period_match)
        return float(min(1.0, regularity_score * period_score))

    def _check_ddos(self, flow: FlowRecord, now: float) -> float:
        """Count unique source IPs to the destination in the DDoS window."""
        cutoff = now - self.ddos_window
        recent_srcs: set[str] = set()
        for ts, src_ip in self._dst_srcs[flow.dst_ip]:
            if ts >= cutoff:
                recent_srcs.add(src_ip)

        count = len(recent_srcs)
        if count < self.ddos_src_threshold:
            return 0.0
        ratio = count / self.ddos_src_threshold
        return float(min(1.0, 1.0 - 1.0 / ratio))

    # ------------------------------------------------------------------
    # Periodic cleanup
    # ------------------------------------------------------------------

    def _maybe_cleanup(self) -> None:
        """Evict IP state entries older than the history window."""
        now = time.monotonic()
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        cutoff = now - self.history_window
        stale = [ip for ip, s in self._ip_state.items() if s.created_at < cutoff]
        for ip in stale:
            del self._ip_state[ip]
        if stale:
            logger.debug("Evicted %d stale IP state entries", len(stale))
