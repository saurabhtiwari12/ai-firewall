'use strict';

const User = require('../models/User');
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require('../config/jwt');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const bcrypt = require('bcryptjs');

// ── Register ──────────────────────────────────────────────────────────────────
async function register(req, res) {
  try {
    const { username, email, password, role } = req.body;

    const exists = await User.findOne({ $or: [{ email }, { username }] }).lean();
    if (exists) {
      return res.status(409).json({
        success: false,
        message: 'A user with that email or username already exists',
      });
    }

    // Only admins may create accounts with elevated roles
    const assignedRole =
      req.user?.role === 'admin' && role ? role : 'viewer';

    const user = await User.create({ username, email, password, role: assignedRole });

    await auditService.logAction({
      ...auditService.fromRequest(req),
      action: 'register',
      resource: 'User',
      resourceId: String(user._id),
    });

    return res.status(201).json({ success: true, data: user.toSafeObject() });
  } catch (err) {
    logger.error(`register: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Registration failed' });
  }
}

// ── Login ─────────────────────────────────────────────────────────────────────
async function login(req, res) {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');
    if (!user || !user.active) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const valid = await user.comparePassword(password);
    if (!valid) {
      await auditService.logAction({
        ...auditService.fromRequest(req),
        action: 'login',
        resource: 'User',
        resourceId: String(user._id),
        status: 'failure',
      });
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.last_login = new Date();
    const refreshToken = generateRefreshToken({ id: user._id, role: user.role });
    user.refresh_token_hash = await bcrypt.hash(refreshToken, 10);
    await user.save();

    const accessToken = generateAccessToken({ id: user._id, role: user.role });

    await auditService.logAction({
      ...auditService.fromRequest(req),
      action: 'login',
      resource: 'User',
      resourceId: String(user._id),
    });

    return res.json({
      success: true,
      data: {
        access_token: accessToken,
        refresh_token: refreshToken,
        user: user.toSafeObject(),
      },
    });
  } catch (err) {
    logger.error(`login: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Login failed' });
  }
}

// ── Refresh access token ──────────────────────────────────────────────────────
async function refresh(req, res) {
  try {
    const { refresh_token } = req.body;
    if (!refresh_token) {
      return res.status(400).json({ success: false, message: 'refresh_token is required' });
    }

    let decoded;
    try {
      decoded = verifyRefreshToken(refresh_token);
    } catch {
      return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
    }

    const user = await User.findById(decoded.id).select('+refresh_token_hash');
    if (!user || !user.active || !user.refresh_token_hash) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }

    const valid = await bcrypt.compare(refresh_token, user.refresh_token_hash);
    if (!valid) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }

    const newAccessToken = generateAccessToken({ id: user._id, role: user.role });
    return res.json({ success: true, data: { access_token: newAccessToken } });
  } catch (err) {
    logger.error(`refresh: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Token refresh failed' });
  }
}

// ── Get current user ──────────────────────────────────────────────────────────
async function getMe(req, res) {
  try {
    const user = await User.findById(req.user._id).lean();
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const { _id, username, email, role, active, last_login, createdAt } = user;
    return res.json({ success: true, data: { id: _id, username, email, role, active, last_login, createdAt } });
  } catch (err) {
    logger.error(`getMe: ${err.message}`);
    return res.status(500).json({ success: false, message: 'Failed to retrieve user' });
  }
}

module.exports = { register, login, refresh, getMe };
