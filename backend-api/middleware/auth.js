'use strict';

const { verifyAccessToken } = require('../config/jwt');
const User = require('../models/User');
const logger = require('../utils/logger');

/**
 * Middleware: verify Bearer token and attach decoded user to req.user.
 * Fetches a lean user record so downstream handlers can check role, active, etc.
 */
async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    const token = authHeader.slice(7);
    const decoded = verifyAccessToken(token);

    const user = await User.findById(decoded.id).lean();
    if (!user || !user.active) {
      return res.status(401).json({ success: false, message: 'User not found or inactive' });
    }

    req.user = user;
    return next();
  } catch (err) {
    logger.warn(`Auth failed: ${err.message}`);
    const message =
      err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
    return res.status(401).json({ success: false, message });
  }
}

module.exports = { authenticate };
