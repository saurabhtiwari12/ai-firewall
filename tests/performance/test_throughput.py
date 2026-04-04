"""Performance test: feature_engineering throughput >= 1000 flows/second."""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../firewall-engine'))

import pytest
from feature_engineering import FeatureExtractor, FEATURE_DIM
from flow_aggregation import FlowRecord


def _make_flow(i: int) -> FlowRecord:
    return FlowRecord(
        src_ip=f"10.0.{i % 256}.{i % 100}",
        dst_ip="10.0.0.1",
        src_port=10000 + (i % 50000),
        dst_port=443,
        protocol="TCP",
        start_time=time.time(),
        end_time=time.time() + 1.0,
        packet_count=20,
        byte_count=4000,
        fwd_packets=10,
        bwd_packets=10,
        fwd_bytes=2000,
        bwd_bytes=2000,
        syn_count=1,
        ack_count=18,
        fin_count=1,
        rst_count=0,
        psh_count=3,
        inter_arrival_times=[0.05] * 19,
    )


def test_throughput_1000_flows_per_second():
    """FeatureExtractor must process at least 1000 flows/second."""
    extractor = FeatureExtractor()
    n_flows = 5000
    flows = [_make_flow(i) for i in range(n_flows)]

    start = time.perf_counter()
    for flow in flows:
        extractor.extract(flow)
    elapsed = time.perf_counter() - start

    throughput = n_flows / elapsed
    print(f"\nThroughput: {throughput:.0f} flows/second")
    assert throughput >= 1000, f"Throughput {throughput:.0f} flows/s is below 1000 flows/s requirement"
