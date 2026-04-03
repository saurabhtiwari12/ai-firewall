'use strict';

const SecurityEvent = require('../models/Event');
const alertService = require('../services/alertService');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');

// ── Ingest new security event ─────────────────────────────────────────────────
async function createEvent(req, res) {
  try {
    const event = await SecurityEvent.create(req.body);

    // Fire-and-forget: alert evaluation + real-time push
    const io = req.app.get('io');
    setImmediate(async () => {
      await alertService.evaluateEvent(event.toObject(), io);
      if (io) io.emit('new_event', event.toObject());
    });

    await auditService.logAction({
      ...auditService.fromRequest(req),
      action: 'create_event',
      resource: 'SecurityEvent',
      resourceId: String(event._id),
    });

    return res.status(201).json({ success: true, data: event });
  } catch (err) {
    logger.error(`createEvent: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to create event' });
  }
}

// ── List events with pagination + filters ─────────────────────────────────────
async function getEvents(req, res) {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 25));
    const skip = (page - 1) * limit;

    const filter = {};
    if (req.query.risk_level) filter.risk_level = req.query.risk_level;
    if (req.query.attack_type) filter.attack_type = req.query.attack_type;
    if (req.query.src_ip) filter.src_ip = req.query.src_ip;
    if (req.query.resolved !== undefined) filter.resolved = req.query.resolved === 'true';

    // Date range
    if (req.query.from || req.query.to) {
      filter.timestamp = {};
      if (req.query.from) filter.timestamp.$gte = new Date(req.query.from);
      if (req.query.to) filter.timestamp.$lte = new Date(req.query.to);
    }

    const [events, total] = await Promise.all([
      SecurityEvent.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).lean(),
      SecurityEvent.countDocuments(filter),
    ]);

    return res.json({
      success: true,
      data: events,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    logger.error(`getEvents: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve events' });
  }
}

// ── Get single event ──────────────────────────────────────────────────────────
async function getEventById(req, res) {
  try {
    const event = await SecurityEvent.findById(req.params.id).lean();
    if (!event) {
      return res.status(404).json({ success: false, message: 'Event not found' });
    }
    return res.json({ success: true, data: event });
  } catch (err) {
    logger.error(`getEventById: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve event' });
  }
}

// ── Resolve event ─────────────────────────────────────────────────────────────
async function resolveEvent(req, res) {
  try {
    const event = await SecurityEvent.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ success: false, message: 'Event not found' });
    }

    event.resolved = true;
    event.resolved_at = new Date();
    event.resolved_by = req.user._id;
    if (req.body.notes) event.notes = req.body.notes;
    await event.save();

    await auditService.logAction({
      ...auditService.fromRequest(req),
      action: 'resolve_event',
      resource: 'SecurityEvent',
      resourceId: String(event._id),
    });

    const io = req.app.get('io');
    if (io) io.emit('event_resolved', { id: event._id });

    return res.json({ success: true, data: event });
  } catch (err) {
    logger.error(`resolveEvent: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to resolve event' });
  }
}

// ── Summary stats ─────────────────────────────────────────────────────────────
async function getEventStats(req, res) {
  try {
    const [totals, byRisk, byAction, recentCritical] = await Promise.all([
      SecurityEvent.countDocuments(),
      SecurityEvent.aggregate([
        { $group: { _id: '$risk_level', count: { $sum: 1 } } },
      ]),
      SecurityEvent.aggregate([
        { $group: { _id: '$action_taken', count: { $sum: 1 } } },
      ]),
      SecurityEvent.countDocuments({
        risk_level: 'critical',
        timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) },
      }),
    ]);

    const riskMap = Object.fromEntries(byRisk.map((r) => [r._id, r.count]));
    const actionMap = Object.fromEntries(byAction.map((a) => [a._id, a.count]));

    return res.json({
      success: true,
      data: {
        total: totals,
        by_risk_level: riskMap,
        by_action: actionMap,
        critical_last_hour: recentCritical,
      },
    });
  } catch (err) {
    logger.error(`getEventStats: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve stats' });
  }
}

// ── Delete event (admin only) ─────────────────────────────────────────────────
async function deleteEvent(req, res) {
  try {
    const event = await SecurityEvent.findByIdAndDelete(req.params.id);
    if (!event) {
      return res.status(404).json({ success: false, message: 'Event not found' });
    }

    await auditService.logAction({
      ...auditService.fromRequest(req),
      action: 'delete_event',
      resource: 'SecurityEvent',
      resourceId: String(req.params.id),
    });

    return res.json({ success: true, message: 'Event deleted' });
  } catch (err) {
    logger.error(`deleteEvent: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to delete event' });
  }
}

module.exports = { createEvent, getEvents, getEventById, resolveEvent, getEventStats, deleteEvent };
