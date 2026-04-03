'use strict';

const Alert = require('../models/Alert');
const logger = require('../utils/logger');

/** Thresholds that trigger automatic alert creation */
const THRESHOLDS = {
  critical: { threat_score: 0.9, label: 'critical' },
  high: { threat_score: 0.7, label: 'high' },
  suspicious: { threat_score: 0.5, label: 'medium' },
};

/**
 * Evaluate a newly ingested SecurityEvent and auto-create an Alert if warranted.
 * @param {object} event  - Plain SecurityEvent document
 * @param {object} io     - Socket.io server instance (may be null)
 */
async function evaluateEvent(event, io = null) {
  try {
    let severity = null;
    if (event.threat_score >= THRESHOLDS.critical.threat_score) {
      severity = THRESHOLDS.critical.label;
    } else if (event.threat_score >= THRESHOLDS.high.threat_score) {
      severity = THRESHOLDS.high.label;
    } else if (event.threat_score >= THRESHOLDS.suspicious.threat_score) {
      severity = THRESHOLDS.suspicious.label;
    }

    if (!severity) return;

    const alert = await Alert.create({
      title: `${severity.toUpperCase()} threat detected from ${event.src_ip}`,
      severity,
      message: `Attack type: ${event.attack_type}. Threat score: ${event.threat_score.toFixed(2)}. Action: ${event.action_taken}.`,
      source_ip: event.src_ip,
      event_count: 1,
      status: 'open',
      related_events: [event._id],
    });

    logger.info(`Alert created: ${alert._id} (${severity}) for event ${event._id}`);

    if (io) {
      io.emit('new_alert', alert.toObject());
    }

    await sendWebhook(alert);
  } catch (err) {
    logger.error(`AlertService.evaluateEvent failed: ${err.message}`);
  }
}

/**
 * Send alert payload to a configured webhook URL, if set.
 * @param {object} alert
 */
async function sendWebhook(alert) {
  const url = process.env.ALERT_WEBHOOK_URL;
  if (!url) return;

  try {
    // Use native fetch (Node 18+); fall back gracefully if unavailable
    const fetchFn = globalThis.fetch;
    if (!fetchFn) {
      logger.warn('AlertService: fetch not available, skipping webhook');
      return;
    }

    const res = await fetchFn(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event: 'alert', data: alert }),
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      logger.warn(`AlertService: webhook responded with ${res.status}`);
    }
  } catch (err) {
    logger.error(`AlertService: webhook delivery failed – ${err.message}`);
  }
}

/**
 * Retrieve open alerts, optionally filtered by severity.
 * @param {{ severity?: string, status?: string, limit?: number }} opts
 */
async function getAlerts({ severity, status = 'open', limit = 50 } = {}) {
  const filter = { status };
  if (severity) filter.severity = severity;
  return Alert.find(filter).sort({ created_at: -1 }).limit(limit).lean();
}

module.exports = { evaluateEvent, getAlerts, sendWebhook };
