'use strict';

const express = require('express');
const mongoose = require('mongoose');
const { authenticate } = require('../middleware/auth');
const SecurityEvent = require('../models/Event');
const Alert = require('../models/Alert');
const logger = require('../utils/logger');

const router = express.Router();

router.use(authenticate);

// GET /api/dashboard/summary
router.get('/summary', async (req, res) => {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const since1h  = new Date(Date.now() -      60 * 60 * 1000);

    const [
      totalEvents,
      criticalLastHour,
      riskBreakdown,
      actionBreakdown,
      activeAlerts,
      recentEvents,
    ] = await Promise.all([
      SecurityEvent.countDocuments({ timestamp: { $gte: since24h } }),
      SecurityEvent.countDocuments({ timestamp: { $gte: since1h }, risk_level: 'critical' }),
      SecurityEvent.aggregate([
        { $match: { timestamp: { $gte: since24h } } },
        { $group: { _id: '$risk_level', count: { $sum: 1 } } },
      ]),
      SecurityEvent.aggregate([
        { $match: { timestamp: { $gte: since24h } } },
        { $group: { _id: '$action_taken', count: { $sum: 1 } } },
      ]),
      Alert.countDocuments({ status: 'open' }),
      SecurityEvent.find({ timestamp: { $gte: since24h } })
        .sort({ timestamp: -1 })
        .limit(5)
        .lean(),
    ]);

    // Flatten aggregation arrays into plain objects
    const byRiskLevel = {};
    for (const { _id, count } of riskBreakdown) {
      if (_id) byRiskLevel[_id] = count;
    }

    const byAction = {};
    for (const { _id, count } of actionBreakdown) {
      if (_id) byAction[_id] = count;
    }

    const blockedCount = byAction.block || 0;
    const blockRate = totalEvents > 0
      ? Math.round((blockedCount / totalEvents) * 100)
      : 0;

    return res.json({
      success: true,
      data: {
        total_events_24h: totalEvents,
        critical_last_hour: criticalLastHour,
        active_alerts: activeAlerts,
        block_rate_percent: blockRate,
        by_risk_level: byRiskLevel,
        by_action: byAction,
        recent_events: recentEvents,
        generated_at: new Date().toISOString(),
      },
    });
  } catch (err) {
    logger.error(`getDashboardSummary: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve dashboard summary' });
  }
});

module.exports = router;
