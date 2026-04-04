"""
Real-time packet capture module for the AI Firewall Engine.

Uses Scapy when available; falls back to a realistic mock generator for
environments without raw-socket privileges or Scapy installed.

Architecture
------------
PacketCapture runs a background thread that feeds parsed PacketInfo objects
into a bounded queue.  Consumers (e.g. FlowAggregator) pull from that queue
asynchronously, decoupling capture from analysis latency.
"""

from __future__ import annotations

import ipaddress
import logging
import queue
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

class Protocol(IntEnum):
    ICMP = 1
    TCP = 6
    UDP = 17
    ICMPv6 = 58
    OTHER = 255


# TCP flag bit masks (RFC 793 + ECN)
class TCPFlags(IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class PacketInfo:
    """Parsed representation of a single network packet."""

    timestamp: float          # UNIX epoch with sub-second precision
    src_ip: str
    dst_ip: str
    src_port: int             # 0 for ICMP
    dst_port: int             # 0 for ICMP
    protocol: int             # IP protocol number
    flags: int                # TCP flags bitmask; 0 for non-TCP
    size: int                 # total IP payload bytes
    ip_version: int           # 4 or 6
    ttl: int                  # IP TTL / hop limit
    raw: bytes = field(default=b"", repr=False)

    # Convenience helpers ------------------------------------------------

    def has_flag(self, flag: TCPFlags) -> bool:
        return bool(self.flags & flag)

    @property
    def five_tuple(self) -> tuple[str, str, int, int, int]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    def flag_str(self) -> str:
        names = []
        for f in TCPFlags:
            if self.flags & f:
                names.append(f.name)
        return "|".join(names) if names else "NONE"


# ---------------------------------------------------------------------------
# Capture statistics
# ---------------------------------------------------------------------------

@dataclass
class CaptureStats:
    """Thread-safe snapshot of capture metrics."""

    packets_captured: int = 0
    packets_dropped: int = 0
    bytes_captured: int = 0
    start_time: float = field(default_factory=time.monotonic)

    def pps(self) -> float:
        elapsed = time.monotonic() - self.start_time
        return self.packets_captured / elapsed if elapsed > 0 else 0.0

    def mbps(self) -> float:
        elapsed = time.monotonic() - self.start_time
        return (self.bytes_captured * 8 / 1_000_000) / elapsed if elapsed > 0 else 0.0


# ---------------------------------------------------------------------------
# PacketCapture
# ---------------------------------------------------------------------------

class PacketCapture:
    """
    Captures network packets and exposes them via a thread-safe queue.

    Parameters
    ----------
    interface:
        Network interface name (e.g. ``eth0``, ``en0``).  Ignored in mock mode.
    bpf_filter:
        Optional BPF filter string passed to Scapy (e.g. ``"tcp port 80"``).
    queue_maxsize:
        Maximum packets buffered in the internal queue.  Overflow drops are
        counted in ``stats.packets_dropped``.
    mock_mode:
        When ``True`` (or Scapy is unavailable) a built-in traffic generator
        produces realistic synthetic packets at *mock_pps* packets per second.
    mock_pps:
        Synthetic packet rate used in mock mode.
    on_packet:
        Optional callback invoked synchronously for every captured packet
        (in addition to the queue).  Keep it fast – it runs in the capture thread.
    """

    def __init__(
        self,
        interface: str = "eth0",
        bpf_filter: str = "",
        queue_maxsize: int = 10_000,
        mock_mode: bool = False,
        mock_pps: int = 50,
        on_packet: Optional[Callable[[PacketInfo], None]] = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.mock_mode = mock_mode
        self.mock_pps = max(1, mock_pps)
        self.on_packet = on_packet

        self._queue: queue.Queue[PacketInfo] = queue.Queue(maxsize=queue_maxsize)
        self._stats = CaptureStats()
        self._stats_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scapy_available = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background capture thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("Capture already running; ignoring start()")
            return

        self._stop_event.clear()
        self._stats = CaptureStats()

        if not self.mock_mode:
            self._scapy_available = self._check_scapy()

        if self.mock_mode or not self._scapy_available:
            logger.info("PacketCapture starting in MOCK mode (pps=%d)", self.mock_pps)
            target = self._mock_capture_loop
        else:
            logger.info(
                "PacketCapture starting on interface '%s' (filter='%s')",
                self.interface,
                self.bpf_filter or "<none>",
            )
            target = self._scapy_capture_loop

        self._thread = threading.Thread(target=target, name="packet-capture", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the capture thread to stop and wait for it to join."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("Capture thread did not stop within %.1fs", timeout)
            self._thread = None
        logger.info("PacketCapture stopped. Stats: %s", self.get_stats())

    def get_packet(self, block: bool = True, timeout: Optional[float] = 1.0) -> Optional[PacketInfo]:
        """Retrieve the next packet from the queue (blocking by default)."""
        try:
            return self._queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

    def get_stats(self) -> CaptureStats:
        with self._stats_lock:
            return CaptureStats(
                packets_captured=self._stats.packets_captured,
                packets_dropped=self._stats.packets_dropped,
                bytes_captured=self._stats.bytes_captured,
                start_time=self._stats.start_time,
            )

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Internal: Scapy live capture
    # ------------------------------------------------------------------

    @staticmethod
    def _check_scapy() -> bool:
        try:
            import scapy.all  # noqa: F401
            return True
        except Exception:
            logger.warning("Scapy not available; falling back to mock mode")
            return False

    def _scapy_capture_loop(self) -> None:
        """Run Scapy sniff in a loop, respecting the stop event."""
        try:
            from scapy.all import sniff  # type: ignore[import-untyped]
        except Exception as exc:
            logger.error("Failed to import Scapy in capture thread: %s", exc)
            return

        def _scapy_handler(pkt: object) -> None:
            info = self._parse_scapy_packet(pkt)
            if info:
                self._enqueue(info)

        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter or None,
                    prn=_scapy_handler,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                    timeout=2,
                )
            except PermissionError:
                logger.error(
                    "Insufficient privileges for raw-socket capture on '%s'. "
                    "Run as root or switch to mock mode.",
                    self.interface,
                )
                break
            except Exception as exc:
                logger.exception("Unexpected error in Scapy capture loop: %s", exc)
                time.sleep(1)

    def _parse_scapy_packet(self, pkt: object) -> Optional[PacketInfo]:
        """Convert a Scapy packet object to PacketInfo."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore[import-untyped]
            from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]

            ts = float(pkt.time)  # type: ignore[attr-defined]
            size = len(pkt)  # type: ignore[arg-type]
            ip_version = 4
            src_ip = dst_ip = "0.0.0.0"
            proto = Protocol.OTHER
            ttl = 64
            src_port = dst_port = 0
            flags = 0

            if pkt.haslayer(IP):  # type: ignore[attr-defined]
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto = ip_layer.proto
                ttl = ip_layer.ttl
                ip_version = 4
            elif pkt.haslayer(IPv6):  # type: ignore[attr-defined]
                ip6 = pkt[IPv6]
                src_ip = ip6.src
                dst_ip = ip6.dst
                proto = ip6.nh
                ttl = ip6.hlim
                ip_version = 6

            if pkt.haslayer(TCP):  # type: ignore[attr-defined]
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                flags = int(tcp.flags)
            elif pkt.haslayer(UDP):  # type: ignore[attr-defined]
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport

            return PacketInfo(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=int(proto),
                flags=flags,
                size=size,
                ip_version=ip_version,
                ttl=ttl,
            )
        except Exception as exc:
            logger.debug("Failed to parse Scapy packet: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Internal: Mock capture
    # ------------------------------------------------------------------

    # Common ports to simulate realistic traffic
    _COMMON_PORTS = [80, 443, 22, 53, 8080, 8443, 3306, 5432, 6379, 27017]
    _EPHEMERAL_LOW, _EPHEMERAL_HIGH = 32768, 60999

    # Subnet pools for synthetic traffic
    _INTERNAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    _EXTERNAL_NETS = ["1.0.0.0/8", "8.8.8.0/24", "52.0.0.0/8", "104.0.0.0/8"]

    def _random_ip_in(self, cidr: str) -> str:
        net = ipaddress.ip_network(cidr, strict=False)
        host_count = int(net.num_addresses) - 2
        if host_count <= 0:
            return str(net.network_address)
        offset = random.randint(1, max(1, host_count))
        return str(net.network_address + offset)

    def _make_mock_packet(self) -> PacketInfo:
        """Generate a single realistic synthetic packet."""
        ts = time.time()
        proto = random.choices(
            [Protocol.TCP, Protocol.UDP, Protocol.ICMP],
            weights=[65, 25, 10],
        )[0]

        internal_net = random.choice(self._INTERNAL_NETS)
        external_net = random.choice(self._EXTERNAL_NETS)

        # Outbound or inbound traffic
        if random.random() < 0.6:
            src_ip = self._random_ip_in(internal_net)
            dst_ip = self._random_ip_in(external_net)
        else:
            src_ip = self._random_ip_in(external_net)
            dst_ip = self._random_ip_in(internal_net)

        dst_port = random.choice(self._COMMON_PORTS)
        src_port = random.randint(self._EPHEMERAL_LOW, self._EPHEMERAL_HIGH)
        flags = 0
        size = random.randint(40, 1500)
        ttl = random.choice([64, 128, 255])

        if proto == Protocol.TCP:
            # Simulate SYN / established / data packets
            flag_choice = random.choices(
                [TCPFlags.SYN, TCPFlags.ACK, TCPFlags.SYN | TCPFlags.ACK, TCPFlags.PSH | TCPFlags.ACK, TCPFlags.FIN | TCPFlags.ACK],
                weights=[15, 40, 10, 30, 5],
            )[0]
            flags = int(flag_choice)
        elif proto == Protocol.ICMP:
            src_port = dst_port = 0

        return PacketInfo(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=int(proto),
            flags=flags,
            size=size,
            ip_version=4,
            ttl=ttl,
        )

    def _mock_capture_loop(self) -> None:
        """Emit synthetic packets at the configured rate until stopped."""
        interval = 1.0 / self.mock_pps
        while not self._stop_event.is_set():
            start = time.monotonic()
            pkt = self._make_mock_packet()
            self._enqueue(pkt)
            elapsed = time.monotonic() - start
            sleep_for = max(0.0, interval - elapsed)
            if sleep_for > 0:
                time.sleep(sleep_for)

    # ------------------------------------------------------------------
    # Internal: queue helper
    # ------------------------------------------------------------------

    def _enqueue(self, pkt: PacketInfo) -> None:
        """Push packet to queue; update statistics; invoke optional callback."""
        with self._stats_lock:
            self._stats.packets_captured += 1
            self._stats.bytes_captured += pkt.size

        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            with self._stats_lock:
                self._stats.packets_dropped += 1
            logger.debug("Packet queue full – dropping packet from %s", pkt.src_ip)
            return

        if self.on_packet:
            try:
                self.on_packet(pkt)
            except Exception as exc:
                logger.debug("on_packet callback raised: %s", exc)
