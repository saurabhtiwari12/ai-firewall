'use strict';

const SecurityEvent = require('../models/Event');
const logger = require('../utils/logger');

// ── Helper: build a time-range filter ────────────────────────────────────────
function timeFilter(req) {
  const hours = Math.min(168, Math.max(1, parseInt(req.query.hours, 10) || 24));
  return { timestamp: { $gte: new Date(Date.now() - hours * 60 * 60 * 1000) } };
}

// ── Time-series traffic data ──────────────────────────────────────────────────
async function getTrafficTimeSeries(req, res) {
  try {
    const hours = Math.min(168, Math.max(1, parseInt(req.query.hours, 10) || 24));
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);

    const data = await SecurityEvent.aggregate([
      { $match: { timestamp: { $gte: since } } },
      {
        $group: {
          _id: {
            $dateToString: {
              format: hours <= 24 ? '%Y-%m-%dT%H:00' : '%Y-%m-%d',
              date: '$timestamp',
            },
          },
          total: { $sum: 1 },
          blocked: { $sum: { $cond: [{ $eq: ['$action_taken', 'block'] }, 1, 0] } },
          allowed: { $sum: { $cond: [{ $eq: ['$action_taken', 'allow'] }, 1, 0] } },
          critical: { $sum: { $cond: [{ $eq: ['$risk_level', 'critical'] }, 1, 0] } },
          avg_threat_score: { $avg: '$threat_score' },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    return res.json({ success: true, data });
  } catch (err) {
    logger.error(`getTrafficTimeSeries: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve traffic data' });
  }
}

// ── Threat distribution ───────────────────────────────────────────────────────
async function getThreatDistribution(req, res) {
  try {
    const filter = timeFilter(req);
    const data = await SecurityEvent.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$risk_level',
          count: { $sum: 1 },
          avg_score: { $avg: '$threat_score' },
        },
      },
      { $sort: { count: -1 } },
    ]);
    return res.json({ success: true, data });
  } catch (err) {
    logger.error(`getThreatDistribution: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve threat data' });
  }
}

// ── Top attacking source IPs ──────────────────────────────────────────────────
async function getTopAttackers(req, res) {
  try {
    const filter = {
      ...timeFilter(req),
      risk_level: { $in: ['suspicious', 'high', 'critical'] },
    };
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));

    const data = await SecurityEvent.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$src_ip',
          event_count: { $sum: 1 },
          max_threat_score: { $max: '$threat_score' },
          avg_threat_score: { $avg: '$threat_score' },
          attack_types: { $addToSet: '$attack_type' },
          last_seen: { $max: '$timestamp' },
        },
      },
      { $sort: { event_count: -1 } },
      { $limit: limit },
      { $project: { ip: '$_id', _id: 0, event_count: 1, max_threat_score: 1, avg_threat_score: 1, attack_types: 1, last_seen: 1 } },
    ]);

    return res.json({ success: true, data });
  } catch (err) {
    logger.error(`getTopAttackers: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve top attackers' });
  }
}

// ── Attack type breakdown ─────────────────────────────────────────────────────
async function getAttackTypes(req, res) {
  try {
    const filter = timeFilter(req);
    const data = await SecurityEvent.aggregate([
      { $match: filter },
      {
        $group: {
          _id: '$attack_type',
          count: { $sum: 1 },
          avg_score: { $avg: '$threat_score' },
          blocked: { $sum: { $cond: [{ $eq: ['$action_taken', 'block'] }, 1, 0] } },
        },
      },
      { $sort: { count: -1 } },
    ]);
    return res.json({ success: true, data });
  } catch (err) {
    logger.error(`getAttackTypes: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve attack type data' });
  }
}

// ── Events per hour (last 24 h) ───────────────────────────────────────────────
async function getHourlyBreakdown(req, res) {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const data = await SecurityEvent.aggregate([
      { $match: { timestamp: { $gte: since } } },
      {
        $group: {
          _id: { $hour: '$timestamp' },
          total: { $sum: 1 },
          threats: {
            $sum: {
              $cond: [{ $in: ['$risk_level', ['high', 'critical']] }, 1, 0],
            },
          },
        },
      },
      { $sort: { _id: 1 } },
      { $project: { hour: '$_id', _id: 0, total: 1, threats: 1 } },
    ]);
    return res.json({ success: true, data });
  } catch (err) {
    logger.error(`getHourlyBreakdown: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve hourly data' });
  }
}

module.exports = {
  getTrafficTimeSeries,
  getThreatDistribution,
  getTopAttackers,
  getAttackTypes,
  getHourlyBreakdown,
};
