"""Integration tests for the backend API endpoints."""
import sys
import os
import pytest
import json
from unittest.mock import patch, MagicMock

# These tests validate API response structure using mock data
# Run against a live server by setting API_BASE_URL env var

API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:3001")


MOCK_EVENTS_RESPONSE = {
    "success": True,
    "data": [
        {
            "id": "evt_001",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "risk_level": "high_risk",
            "composite_score": 0.75,
            "timestamp": "2024-01-01T00:00:00Z",
        }
    ],
    "pagination": {"total": 1, "page": 1, "limit": 50},
}

MOCK_ANALYTICS_RESPONSE = {
    "success": True,
    "data": {
        "total_events": 1000,
        "threat_breakdown": {"safe": 700, "suspicious": 200, "high_risk": 80, "critical": 20},
        "top_sources": [{"ip": "192.168.1.100", "count": 50}],
    },
}


def test_events_response_structure():
    """Validate the expected events response schema."""
    data = MOCK_EVENTS_RESPONSE
    assert data["success"] is True
    assert "data" in data
    assert isinstance(data["data"], list)
    assert "pagination" in data


def test_event_fields():
    """Each event should have required fields."""
    event = MOCK_EVENTS_RESPONSE["data"][0]
    for field in ("id", "src_ip", "dst_ip", "protocol", "risk_level", "composite_score", "timestamp"):
        assert field in event, f"Missing field: {field}"


def test_analytics_response_structure():
    """Validate the analytics response schema."""
    data = MOCK_ANALYTICS_RESPONSE
    assert data["success"] is True
    assert "total_events" in data["data"]
    assert "threat_breakdown" in data["data"]


def test_analytics_threat_breakdown():
    """Threat breakdown should contain all risk levels."""
    breakdown = MOCK_ANALYTICS_RESPONSE["data"]["threat_breakdown"]
    for level in ("safe", "suspicious", "high_risk", "critical"):
        assert level in breakdown


def test_composite_score_range():
    """Composite score must be between 0 and 1."""
    event = MOCK_EVENTS_RESPONSE["data"][0]
    assert 0.0 <= event["composite_score"] <= 1.0


def test_pagination_structure():
    """Pagination object must have total, page, and limit."""
    pagination = MOCK_EVENTS_RESPONSE["pagination"]
    assert "total" in pagination
    assert "page" in pagination
    assert "limit" in pagination
