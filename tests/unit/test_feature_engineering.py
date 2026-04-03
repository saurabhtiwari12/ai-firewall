"""Unit tests for the feature_engineering module."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../firewall-engine'))

import time
import pytest
import numpy as np
from feature_engineering import FeatureExtractor, FEATURE_DIM
from flow_aggregation import FlowRecord


def _make_flow(**kwargs) -> FlowRecord:
    defaults = dict(
        src_ip="1.2.3.4",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=443,
        protocol="TCP",
        start_time=time.time(),
        end_time=time.time() + 2.0,
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
        inter_arrival_times=[0.1] * 19,
    )
    defaults.update(kwargs)
    return FlowRecord(**defaults)


def test_feature_extraction():
    extractor = FeatureExtractor()
    flow = _make_flow()
    vec = extractor.extract(flow)
    assert vec is not None
    assert isinstance(vec, np.ndarray)


def test_normalization_range():
    extractor = FeatureExtractor()
    flow = _make_flow()
    vec = extractor.extract(flow)
    # All normalized features should be finite
    assert np.all(np.isfinite(vec))


def test_missing_value_handling():
    extractor = FeatureExtractor()
    # Flow with minimal data
    flow = _make_flow(packet_count=0, byte_count=0, inter_arrival_times=[])
    vec = extractor.extract(flow)
    assert vec is not None
    assert not np.any(np.isnan(vec))


def test_feature_vector_dimensions():
    extractor = FeatureExtractor()
    flow = _make_flow()
    vec = extractor.extract(flow)
    assert vec.shape == (FEATURE_DIM,)
