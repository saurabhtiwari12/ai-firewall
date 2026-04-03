'use strict';

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

/**
 * Record a user action to the audit log.
 * Failures are caught and logged but do NOT propagate – never let audit
 * logging break a request.
 *
 * @param {object} opts
 * @param {object|null} opts.user      - req.user (may be null for failed auth)
 * @param {string}      opts.action    - AuditLog action enum value
 * @param {string}     [opts.resource] - Resource type (e.g. 'SecurityEvent')
 * @param {string}     [opts.resourceId]
 * @param {string}     [opts.ip]       - Requester IP
 * @param {string}     [opts.userAgent]
 * @param {'success'|'failure'} [opts.status]
 * @param {*}          [opts.details]  - Any additional context
 */
async function logAction({
  user = null,
  action,
  resource = '',
  resourceId = '',
  ip = '',
  userAgent = '',
  status = 'success',
  details = null,
} = {}) {
  try {
    await AuditLog.create({
      user: user?._id ?? null,
      username: user?.username ?? 'anonymous',
      action,
      resource,
      resource_id: resourceId,
      ip,
      user_agent: userAgent,
      status,
      details,
    });
  } catch (err) {
    logger.error(`AuditService: failed to write audit log – ${err.message}`);
  }
}

/**
 * Convenience: build common fields from an Express request object.
 * @param {import('express').Request} req
 * @returns {{ user, ip, userAgent }}
 */
function fromRequest(req) {
  return {
    user: req.user ?? null,
    ip: req.ip || req.headers['x-forwarded-for'] || '',
    userAgent: req.headers['user-agent'] || '',
  };
}

module.exports = { logAction, fromRequest };
