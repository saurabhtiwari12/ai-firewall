"""
``__init__`` for the ``threat_intelligence`` package.

Re-exports the primary public interface so callers can do::

    from threat_intelligence import ThreatFeedManager
"""

from __future__ import annotations

from .threat_feed_manager import ThreatFeedManager

__all__ = ["ThreatFeedManager"]
