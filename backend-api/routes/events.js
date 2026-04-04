'use strict';

const express = require('express');
const { authenticate } = require('../middleware/auth');
const { requireRole, requireMinRole } = require('../middleware/rbac');
const { validateEvent, validateObjectId, validatePagination } = require('../middleware/validation');
const {
  createEvent,
  getEvents,
  getEventById,
  resolveEvent,
  getEventStats,
  deleteEvent,
} = require('../controllers/eventController');

const router = express.Router();

// All event routes require authentication
router.use(authenticate);

// GET /api/events/stats/summary  – must be before /:id to avoid param capture
router.get('/stats/summary', getEventStats);

// POST /api/events
router.post('/', requireMinRole('analyst'), validateEvent, createEvent);

// GET /api/events
router.get('/', validatePagination, getEvents);

// GET /api/events/:id
router.get('/:id', validateObjectId('id'), getEventById);

// PUT /api/events/:id/resolve
router.put('/:id/resolve', requireMinRole('analyst'), validateObjectId('id'), resolveEvent);

// DELETE /api/events/:id  (admin only)
router.delete('/:id', requireRole('admin'), validateObjectId('id'), deleteEvent);

module.exports = router;
