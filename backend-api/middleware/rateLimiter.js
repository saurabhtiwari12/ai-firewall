'use strict';

const rateLimit = require('express-rate-limit');

const WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000;
const API_MAX = parseInt(process.env.RATE_LIMIT_MAX, 10) || 100;
const AUTH_MAX = parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 10;

function buildLimiter(max, message) {
  return rateLimit({
    windowMs: WINDOW_MS,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json({
        success: false,
        message,
        retryAfter: Math.ceil(WINDOW_MS / 1000),
      });
    },
  });
}

/** General API rate limiter – 100 req / 15 min */
const apiLimiter = buildLimiter(
  API_MAX,
  'Too many requests. Please slow down.'
);

/** Stricter limiter for authentication endpoints – 10 req / 15 min */
const authLimiter = buildLimiter(
  AUTH_MAX,
  'Too many authentication attempts. Please try again later.'
);

module.exports = { apiLimiter, authLimiter };
