'use strict';

const express = require('express');
const os = require('os');
const mongoose = require('mongoose');
const client = require('prom-client');
const { authenticate } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');

const router = express.Router();

// ── GET /api/system/health  (public) ─────────────────────────────────────────
router.get('/health', (req, res) => {
  const dbState = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  const healthy = mongoose.connection.readyState === 1;
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    database: dbState[mongoose.connection.readyState] ?? 'unknown',
    uptime_s: Math.floor(process.uptime()),
  });
});

// ── GET /api/system/status  (authenticated) ───────────────────────────────────
router.get('/status', authenticate, (req, res) => {
  res.json({
    success: true,
    data: {
      node_version: process.version,
      platform: process.platform,
      memory: process.memoryUsage(),
      cpu_count: os.cpus().length,
      load_avg: os.loadavg(),
      uptime_s: Math.floor(process.uptime()),
      env: process.env.NODE_ENV || 'development',
    },
  });
});

// ── GET /api/system/metrics  (admin – Prometheus text format) ─────────────────
router.get('/metrics', authenticate, requireRole('admin'), async (req, res) => {
  if (process.env.METRICS_ENABLED !== 'true') {
    return res.status(404).json({ success: false, message: 'Metrics not enabled' });
  }
  try {
    res.set('Content-Type', client.register.contentType);
    const metrics = await client.register.metrics();
    return res.end(metrics);
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to collect metrics' });
  }
});

module.exports = router;
