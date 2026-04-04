'use strict';

const express = require('express');
const { authenticate } = require('../middleware/auth');
const { requireMinRole } = require('../middleware/rbac');
const {
  getTrafficTimeSeries,
  getThreatDistribution,
  getTopAttackers,
  getAttackTypes,
  getHourlyBreakdown,
} = require('../controllers/analyticsController');

const router = express.Router();

router.use(authenticate);

// GET /api/analytics/traffic?hours=24
router.get('/traffic', getTrafficTimeSeries);

// GET /api/analytics/threats?hours=24
router.get('/threats', getThreatDistribution);

// GET /api/analytics/top-attackers?hours=24&limit=10
router.get('/top-attackers', requireMinRole('analyst'), getTopAttackers);

// GET /api/analytics/attack-types?hours=24
router.get('/attack-types', getAttackTypes);

// GET /api/analytics/hourly
router.get('/hourly', getHourlyBreakdown);

module.exports = router;
