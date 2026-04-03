'use strict';

const express = require('express');
const Alert = require('../models/Alert');
const { authenticate } = require('../middleware/auth');
const { requireMinRole, requireRole } = require('../middleware/rbac');
const { validateObjectId } = require('../middleware/validation');
const auditService = require('../services/auditService');
const { body } = require('express-validator');
const { handleValidationErrors } = require('../middleware/validation');
const logger = require('../utils/logger');

const ALLOWED_ALERT_STATUSES = new Set(['open', 'acknowledged', 'resolved', 'false_positive']);
const ALLOWED_ALERT_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);

/** Return the value only if it is a plain string; otherwise null. */
function safeString(val) {
  return typeof val === 'string' ? val : null;
}

const router = express.Router();

router.use(authenticate);

// GET /api/alerts
router.get('/', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const filter = {};
    const status = safeString(req.query.status);
    if (status && ALLOWED_ALERT_STATUSES.has(status)) filter.status = status;
    const severity = safeString(req.query.severity);
    if (severity && ALLOWED_ALERT_SEVERITIES.has(severity)) filter.severity = severity;

    const [alerts, total] = await Promise.all([
      Alert.find(filter).sort({ created_at: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Alert.countDocuments(filter),
    ]);

    return res.json({
      success: true,
      data: alerts,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    logger.error(`GET /alerts: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve alerts' });
  }
});

// POST /api/alerts
router.post(
  '/',
  requireMinRole('analyst'),
  [
    body('title').trim().notEmpty().withMessage('title is required').isLength({ max: 256 }),
    body('severity').isIn(['low', 'medium', 'high', 'critical']).withMessage('Invalid severity'),
    body('message').trim().notEmpty().withMessage('message is required').isLength({ max: 2000 }),
    body('source_ip').optional().isIP().withMessage('source_ip must be a valid IP'),
    handleValidationErrors,
  ],
  async (req, res) => {
    try {
      const alert = await Alert.create(req.body);
      const io = req.app.get('io');
      if (io) io.emit('new_alert', alert.toObject());

      await auditService.logAction({
        ...auditService.fromRequest(req),
        action: 'create_alert',
        resource: 'Alert',
        resourceId: String(alert._id),
      });

      return res.status(201).json({ success: true, data: alert });
    } catch (err) {
      logger.error(`POST /alerts: ${err.message}`);
      return res.status(500).json({ success: false, message: 'Failed to create alert' });
    }
  }
);

// PUT /api/alerts/:id
router.put(
  '/:id',
  requireMinRole('analyst'),
  validateObjectId('id'),
  [
    body('status').optional().isIn(['open', 'acknowledged', 'resolved', 'false_positive']),
    body('notes').optional().isLength({ max: 2000 }),
    handleValidationErrors,
  ],
  async (req, res) => {
    try {
      const update = {};
      const newStatus = safeString(req.body.status);
      if (newStatus && ALLOWED_ALERT_STATUSES.has(newStatus)) {
        update.status = newStatus;
        if (newStatus === 'acknowledged') {
          update.acknowledged_by = req.user._id;
          update.acknowledged_at = new Date();
        } else if (newStatus === 'resolved') {
          update.resolved_by = req.user._id;
          update.resolved_at = new Date();
        }
      }
      if (typeof req.body.notes === 'string') update.notes = req.body.notes;

      const alert = await Alert.findByIdAndUpdate(req.params.id, update, {
        new: true,
        runValidators: true,
      });
      if (!alert) {
        return res.status(404).json({ success: false, message: 'Alert not found' });
      }

      await auditService.logAction({
        ...auditService.fromRequest(req),
        action: 'update_alert',
        resource: 'Alert',
        resourceId: String(alert._id),
      });

      return res.json({ success: true, data: alert });
    } catch (err) {
      logger.error(`PUT /alerts/:id: ${err.message}`);
      return res.status(500).json({ success: false, message: 'Failed to update alert' });
    }
  }
);

// DELETE /api/alerts/:id
router.delete('/:id', requireRole('admin'), validateObjectId('id'), async (req, res) => {
  try {
    const alert = await Alert.findByIdAndDelete(req.params.id);
    if (!alert) {
      return res.status(404).json({ success: false, message: 'Alert not found' });
    }

    await auditService.logAction({
      ...auditService.fromRequest(req),
      action: 'delete_alert',
      resource: 'Alert',
      resourceId: String(req.params.id),
    });

    return res.json({ success: true, message: 'Alert deleted' });
  } catch (err) {
    logger.error(`DELETE /alerts/:id: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to delete alert' });
  }
});

module.exports = router;
