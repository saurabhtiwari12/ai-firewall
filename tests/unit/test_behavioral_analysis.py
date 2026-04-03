"""Unit tests for the behavioral_analysis module."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../firewall-engine'))

import time
import pytest
from behavioral_analysis import BehavioralAnalyzer, BehavioralScore
from flow_aggregation import FlowRecord


def _make_flow(src_ip="1.2.3.4", dst_port=80, packets=10, bytes_=1000, protocol="TCP") -> FlowRecord:
    return FlowRecord(
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=dst_port,
        protocol=protocol,
        start_time=time.time(),
        end_time=time.time() + 1.0,
        packet_count=packets,
        byte_count=bytes_,
        fwd_packets=packets // 2,
        bwd_packets=packets // 2,
        fwd_bytes=bytes_ // 2,
        bwd_bytes=bytes_ // 2,
        syn_count=1,
        ack_count=packets - 1,
        fin_count=1,
        rst_count=0,
        psh_count=2,
        inter_arrival_times=[0.1] * max(1, packets - 1),
    )


def test_port_scan_detection():
    analyzer = BehavioralAnalyzer()
    # Simulate scanning many ports from one source
    for port in range(1, 60):
        flow = _make_flow(src_ip="192.168.1.100", dst_port=port, packets=1, bytes_=64)
        score = analyzer.analyze(flow)
    assert score.port_scan_score > 0.0


def test_rate_anomaly_detection():
    analyzer = BehavioralAnalyzer()
    # Flood with high packet/byte count
    for _ in range(20):
        flow = _make_flow(src_ip="10.1.1.1", packets=10000, bytes_=5000000)
        score = analyzer.analyze(flow)
    assert score.rate_anomaly_score >= 0.0


def test_behavioral_score_range():
    analyzer = BehavioralAnalyzer()
    for port in range(1, 30):
        flow = _make_flow(dst_port=port)
        score = analyzer.analyze(flow)
    assert 0.0 <= score.overall <= 1.0


def test_ip_tracking():
    analyzer = BehavioralAnalyzer()
    ip = "172.16.0.55"
    for i in range(5):
        flow = _make_flow(src_ip=ip, dst_port=i + 100)
        analyzer.analyze(flow)
    # Verify the IP is tracked internally
    assert analyzer._get_ip_state(ip) is not None
