"""
Network flow aggregation from raw packets.

A *flow* is identified by its 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
Packets belonging to the same flow are grouped and statistics are accumulated
until the flow expires by idle or active timeout, at which point it is
exported to the ``export_queue`` for downstream processing.

Thread Safety
-------------
FlowAggregator is designed to be called from a single consumer thread
(``add_packet``).  A separate reaper thread handles periodic expiry and export.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from packet_capture import PacketInfo, Protocol

logger = logging.getLogger(__name__)

# 5-tuple type alias
FiveTuple = tuple[str, str, int, int, int]


# ---------------------------------------------------------------------------
# Flow data model
# ---------------------------------------------------------------------------

@dataclass
class FlowRecord:
    """Accumulated statistics for a single network flow."""

    # Identity
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    # Timing
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Counters
    packet_count: int = 0
    byte_count: int = 0

    # Forward / backward (relative to first packet direction)
    fwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_packets: int = 0
    bwd_bytes: int = 0

    # TCP flags union (OR of all flags seen)
    flags_union: int = 0
    # Per-flag packet counts
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0

    # Inter-arrival times (seconds) — kept as a list for stddev calculation
    inter_arrival_times: list[float] = field(default_factory=list, repr=False)
    _last_pkt_time: float = field(default=0.0, init=False, repr=False)

    # Packet sizes
    packet_sizes: list[int] = field(default_factory=list, repr=False)

    # TTL samples
    ttl_min: int = 255
    ttl_max: int = 0

    # Export state
    exported: bool = False

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.start_time)

    @property
    def five_tuple(self) -> FiveTuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    @property
    def reverse_tuple(self) -> FiveTuple:
        return (self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)

    def avg_packet_size(self) -> float:
        return self.byte_count / self.packet_count if self.packet_count else 0.0

    def pkt_rate(self) -> float:
        dur = self.duration
        return self.packet_count / dur if dur > 0 else float(self.packet_count)

    def byte_rate(self) -> float:
        dur = self.duration
        return self.byte_count / dur if dur > 0 else float(self.byte_count)

    def fwd_bwd_ratio(self) -> float:
        if self.bwd_packets == 0:
            return float(self.fwd_packets)
        return self.fwd_packets / self.bwd_packets

    def inter_arrival_mean(self) -> float:
        if not self.inter_arrival_times:
            return 0.0
        return sum(self.inter_arrival_times) / len(self.inter_arrival_times)

    def inter_arrival_std(self) -> float:
        iats = self.inter_arrival_times
        n = len(iats)
        if n < 2:
            return 0.0
        mean = sum(iats) / n
        variance = sum((x - mean) ** 2 for x in iats) / (n - 1)
        return variance ** 0.5

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "fwd_packets": self.fwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_packets": self.bwd_packets,
            "bwd_bytes": self.bwd_bytes,
            "flags_union": self.flags_union,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "avg_packet_size": self.avg_packet_size(),
            "pkt_rate": self.pkt_rate(),
            "byte_rate": self.byte_rate(),
            "fwd_bwd_ratio": self.fwd_bwd_ratio(),
            "inter_arrival_mean": self.inter_arrival_mean(),
            "inter_arrival_std": self.inter_arrival_std(),
            "ttl_min": self.ttl_min,
            "ttl_max": self.ttl_max,
        }


# ---------------------------------------------------------------------------
# Aggregation statistics
# ---------------------------------------------------------------------------

@dataclass
class AggregationStats:
    """Metrics for the flow aggregator."""

    active_flows: int = 0
    total_flows_created: int = 0
    total_flows_exported: int = 0
    packets_processed: int = 0
    bytes_processed: int = 0


# ---------------------------------------------------------------------------
# FlowAggregator
# ---------------------------------------------------------------------------

class FlowAggregator:
    """
    Aggregates PacketInfo objects into FlowRecord sessions.

    Parameters
    ----------
    idle_timeout_sec:
        A flow is expired if no packets arrive within this window.
    active_timeout_sec:
        A flow is forcibly expired after this total duration regardless of activity.
    max_flows:
        Upper bound on simultaneous tracked flows.  Oldest flows are evicted when
        the limit is reached to prevent unbounded memory growth.
    export_queue_maxsize:
        Capacity of the internal export queue.
    """

    # TCP flag bit masks (avoid importing TCPFlags to keep the module reusable)
    _FLAG_SYN = 0x02
    _FLAG_ACK = 0x10
    _FLAG_FIN = 0x01
    _FLAG_RST = 0x04
    _FLAG_PSH = 0x08

    def __init__(
        self,
        idle_timeout_sec: int = 30,
        active_timeout_sec: int = 300,
        max_flows: int = 100_000,
        export_queue_maxsize: int = 5_000,
    ) -> None:
        self.idle_timeout = idle_timeout_sec
        self.active_timeout = active_timeout_sec
        self.max_flows = max_flows

        self._flows: dict[FiveTuple, FlowRecord] = {}
        self._flows_lock = threading.Lock()

        self.export_queue: queue.Queue[FlowRecord] = queue.Queue(maxsize=export_queue_maxsize)
        self._stats = AggregationStats()
        self._stats_lock = threading.Lock()

        self._reaper_stop = threading.Event()
        self._reaper_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background flow-reaper thread."""
        self._reaper_stop.clear()
        self._reaper_thread = threading.Thread(
            target=self._reaper_loop,
            name="flow-reaper",
            daemon=True,
        )
        self._reaper_thread.start()
        logger.info(
            "FlowAggregator started (idle=%ds active=%ds max_flows=%d)",
            self.idle_timeout,
            self.active_timeout,
            self.max_flows,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the reaper to stop; export all remaining flows."""
        self._reaper_stop.set()
        if self._reaper_thread:
            self._reaper_thread.join(timeout=timeout)
        self._expire_all()
        logger.info("FlowAggregator stopped. %s", self.get_stats())

    def add_packet(self, pkt: PacketInfo) -> None:
        """
        Ingest a packet into the flow table.

        This method is *not* thread-safe by design – call it from one thread.
        """
        key = pkt.five_tuple
        rev_key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)

        with self._flows_lock:
            flow = self._flows.get(key) or self._flows.get(rev_key)
            is_forward = flow is None or key in self._flows

            if flow is None:
                self._maybe_evict()
                flow = FlowRecord(
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    start_time=pkt.timestamp,
                    last_seen=pkt.timestamp,
                )
                flow._last_pkt_time = pkt.timestamp
                self._flows[key] = flow
                with self._stats_lock:
                    self._stats.total_flows_created += 1

            self._update_flow(flow, pkt, is_forward)

            # Active timeout: export mid-flight if flow is too old
            if pkt.timestamp - flow.start_time >= self.active_timeout:
                self._export_flow(flow, key if key in self._flows else rev_key)

        with self._stats_lock:
            self._stats.packets_processed += 1
            self._stats.bytes_processed += pkt.size

    def get_stats(self) -> AggregationStats:
        with self._stats_lock:
            with self._flows_lock:
                active = len(self._flows)
            return AggregationStats(
                active_flows=active,
                total_flows_created=self._stats.total_flows_created,
                total_flows_exported=self._stats.total_flows_exported,
                packets_processed=self._stats.packets_processed,
                bytes_processed=self._stats.bytes_processed,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_flow(self, flow: FlowRecord, pkt: PacketInfo, is_forward: bool) -> None:
        flow.packet_count += 1
        flow.byte_count += pkt.size
        flow.flags_union |= pkt.flags
        flow.ttl_min = min(flow.ttl_min, pkt.ttl)
        flow.ttl_max = max(flow.ttl_max, pkt.ttl)
        flow.packet_sizes.append(pkt.size)

        if is_forward:
            flow.fwd_packets += 1
            flow.fwd_bytes += pkt.size
        else:
            flow.bwd_packets += 1
            flow.bwd_bytes += pkt.size

        # Per-flag accounting
        if pkt.flags & self._FLAG_SYN:
            flow.syn_count += 1
        if pkt.flags & self._FLAG_ACK:
            flow.ack_count += 1
        if pkt.flags & self._FLAG_FIN:
            flow.fin_count += 1
        if pkt.flags & self._FLAG_RST:
            flow.rst_count += 1
        if pkt.flags & self._FLAG_PSH:
            flow.psh_count += 1

        # Inter-arrival time
        if flow._last_pkt_time > 0 and pkt.timestamp > flow._last_pkt_time:
            flow.inter_arrival_times.append(pkt.timestamp - flow._last_pkt_time)
        flow._last_pkt_time = pkt.timestamp
        flow.last_seen = pkt.timestamp

    def _export_flow(self, flow: FlowRecord, key: FiveTuple) -> None:
        """Mark the flow as exported, remove from table, and enqueue for processing."""
        if flow.exported:
            return
        flow.exported = True
        self._flows.pop(key, None)

        try:
            self.export_queue.put_nowait(flow)
        except queue.Full:
            logger.warning(
                "Export queue full – discarding flow %s -> %s",
                flow.src_ip,
                flow.dst_ip,
            )

        with self._stats_lock:
            self._stats.total_flows_exported += 1

    def _maybe_evict(self) -> None:
        """If at capacity, evict the 10 least-recently-seen flows (under lock)."""
        if len(self._flows) < self.max_flows:
            return
        evict_count = max(1, self.max_flows // 100)
        sorted_keys = sorted(
            self._flows.keys(), key=lambda k: self._flows[k].last_seen
        )
        for key in sorted_keys[:evict_count]:
            flow = self._flows.get(key)
            if flow:
                self._export_flow(flow, key)

    def _reaper_loop(self) -> None:
        """Periodically expire idle and over-active flows."""
        check_interval = max(1, min(self.idle_timeout // 2, 10))
        while not self._reaper_stop.wait(timeout=check_interval):
            self._expire_timed_out()

    def _expire_timed_out(self) -> None:
        now = time.time()
        expired_keys: list[FiveTuple] = []

        with self._flows_lock:
            for key, flow in list(self._flows.items()):
                idle = now - flow.last_seen >= self.idle_timeout
                active_too_long = now - flow.start_time >= self.active_timeout
                if idle or active_too_long:
                    expired_keys.append(key)

            for key in expired_keys:
                flow = self._flows.get(key)
                if flow:
                    self._export_flow(flow, key)

        if expired_keys:
            logger.debug("Reaped %d expired flows", len(expired_keys))

    def _expire_all(self) -> None:
        """Export all remaining flows (called on shutdown)."""
        with self._flows_lock:
            for key, flow in list(self._flows.items()):
                self._export_flow(flow, key)
        logger.debug("Exported all remaining flows on shutdown")
