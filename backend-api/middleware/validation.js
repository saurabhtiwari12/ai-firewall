'use strict';

const { body, param, query, validationResult } = require('express-validator');

/** Reusable helper: sends 422 if any validation error exists. */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }
  return next();
}

// ── Event ingestion ───────────────────────────────────────────────────────────
const validateEvent = [
  body('src_ip')
    .trim()
    .notEmpty().withMessage('src_ip is required')
    .isIP().withMessage('src_ip must be a valid IP address'),
  body('dst_ip')
    .trim()
    .notEmpty().withMessage('dst_ip is required')
    .isIP().withMessage('dst_ip must be a valid IP address'),
  body('src_port')
    .optional()
    .isInt({ min: 0, max: 65535 }).withMessage('src_port must be 0-65535'),
  body('dst_port')
    .optional()
    .isInt({ min: 0, max: 65535 }).withMessage('dst_port must be 0-65535'),
  body('protocol')
    .optional()
    .isIn(['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH', 'OTHER'])
    .withMessage('Invalid protocol'),
  body('threat_score')
    .notEmpty().withMessage('threat_score is required')
    .isFloat({ min: 0, max: 1 }).withMessage('threat_score must be between 0 and 1'),
  body('risk_level')
    .notEmpty().withMessage('risk_level is required')
    .isIn(['safe', 'suspicious', 'high', 'critical']).withMessage('Invalid risk_level'),
  body('attack_type')
    .optional()
    .isIn([
      'port_scan', 'brute_force', 'sql_injection', 'xss', 'ddos',
      'malware', 'ransomware', 'data_exfiltration', 'man_in_the_middle',
      'zero_day', 'normal', 'unknown',
    ]).withMessage('Invalid attack_type'),
  body('action_taken')
    .optional()
    .isIn(['allow', 'block', 'monitor', 'quarantine']).withMessage('Invalid action_taken'),
  body('ai_score')
    .optional()
    .isFloat({ min: 0, max: 1 }).withMessage('ai_score must be between 0 and 1'),
  body('anomaly_score')
    .optional()
    .isFloat({ min: 0, max: 1 }).withMessage('anomaly_score must be between 0 and 1'),
  body('behavioral_score')
    .optional()
    .isFloat({ min: 0, max: 1 }).withMessage('behavioral_score must be between 0 and 1'),
  handleValidationErrors,
];

// ── User creation / registration ──────────────────────────────────────────────
const validateUserCreation = [
  body('username')
    .trim()
    .notEmpty().withMessage('username is required')
    .isLength({ min: 3, max: 64 }).withMessage('username must be 3-64 characters')
    .matches(/^[a-zA-Z0-9_.-]+$/).withMessage('username may only contain letters, digits, _, -, .'),
  body('email')
    .trim()
    .notEmpty().withMessage('email is required')
    .isEmail().withMessage('email must be valid')
    .normalizeEmail(),
  body('password')
    .notEmpty().withMessage('password is required')
    .isLength({ min: 8 }).withMessage('password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('password must contain an uppercase letter')
    .matches(/[0-9]/).withMessage('password must contain a number'),
  body('role')
    .optional()
    .isIn(['admin', 'analyst', 'viewer']).withMessage('Invalid role'),
  handleValidationErrors,
];

// ── Login ──────────────────────────────────────────────────────────────────────
const validateLogin = [
  body('email')
    .trim()
    .notEmpty().withMessage('email is required')
    .isEmail().withMessage('email must be valid')
    .normalizeEmail(),
  body('password')
    .notEmpty().withMessage('password is required'),
  handleValidationErrors,
];

// ── Mongo ObjectId param ──────────────────────────────────────────────────────
const validateObjectId = (paramName = 'id') => [
  param(paramName)
    .isMongoId().withMessage(`${paramName} must be a valid MongoDB ObjectId`),
  handleValidationErrors,
];

// ── Pagination query ──────────────────────────────────────────────────────────
const validatePagination = [
  query('page').optional().isInt({ min: 1 }).withMessage('page must be >= 1'),
  query('limit').optional().isInt({ min: 1, max: 200 }).withMessage('limit must be 1-200'),
  handleValidationErrors,
];

module.exports = {
  validateEvent,
  validateUserCreation,
  validateLogin,
  validateObjectId,
  validatePagination,
  handleValidationErrors,
};
