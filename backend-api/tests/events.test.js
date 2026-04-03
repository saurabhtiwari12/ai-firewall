'use strict';

/**
 * Tests for /api/events
 *
 * Uses Jest mocks for Mongoose models so no real database is required.
 * Tests the full HTTP layer: routing, auth middleware, RBAC, validation,
 * and controller logic.
 */

// ── Environment must be set before any app module is required ─────────────────
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_12345';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_12345';
process.env.JWT_EXPIRES_IN = '15m';
process.env.METRICS_ENABLED = 'false';

const mongoose = require('mongoose');
const request = require('supertest');

// ── Mock Mongoose models before app is required ───────────────────────────────
jest.mock('../models/User');
jest.mock('../models/Event');
jest.mock('../models/Alert');
jest.mock('../models/AuditLog');
jest.mock('../services/alertService', () => ({ evaluateEvent: jest.fn() }));
jest.mock('../services/auditService', () => ({
  logAction: jest.fn(),
  fromRequest: jest.fn(() => ({ user: null, ip: '127.0.0.1', userAgent: 'jest' })),
}));

const User = require('../models/User');
const SecurityEvent = require('../models/Event');
const AuditLog = require('../models/AuditLog');

// ── Token helpers (real JWT, no DB) ──────────────────────────────────────────
const { generateAccessToken } = require('../config/jwt');

const makeToken = (role) =>
  generateAccessToken({ id: new mongoose.Types.ObjectId().toString(), role });

const FAKE_ID = new mongoose.Types.ObjectId();

// ── Shared user stubs ────────────────────────────────────────────────────────
const adminUser  = { _id: FAKE_ID, username: 'admin',   role: 'admin',   active: true };
const analystUser = { _id: FAKE_ID, username: 'analyst', role: 'analyst', active: true };
const viewerUser  = { _id: FAKE_ID, username: 'viewer',  role: 'viewer',  active: true };

let adminToken;
let analystToken;
let viewerToken;

// ── App (required after mocks are in place) ───────────────────────────────────
const { app } = require('../server');

// ── Valid event fixture ────────────────────────────────────────────────────────
const validEventPayload = () => ({
  src_ip: '192.168.1.100',
  dst_ip: '10.0.0.1',
  src_port: 54321,
  dst_port: 80,
  protocol: 'TCP',
  threat_score: 0.85,
  risk_level: 'high',
  attack_type: 'port_scan',
  action_taken: 'block',
  ai_score: 0.88,
  anomaly_score: 0.72,
  behavioral_score: 0.80,
});

const fakeEvent = () => ({
  _id: FAKE_ID,
  ...validEventPayload(),
  resolved: false,
  timestamp: new Date(),
  toObject: function () { return { ...this }; },
  save: jest.fn().mockResolvedValue(this),
});

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeAll(() => {
  adminToken   = makeToken('admin');
  analystToken = makeToken('analyst');
  viewerToken  = makeToken('viewer');

  // AuditLog.create is fire-and-forget; silence it
  AuditLog.create = jest.fn().mockResolvedValue({});
});

beforeEach(() => {
  // Default: User.findById returns a lean user based on the role encoded in the token.
  // We patch per-describe where needed.
  User.findById = jest.fn().mockImplementation((id) => ({
    lean: () => Promise.resolve(analystUser),
    select: () => ({ lean: () => Promise.resolve(analystUser) }),
  }));
});

afterEach(() => {
  jest.clearAllMocks();
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/events
// ─────────────────────────────────────────────────────────────────────────────
describe('POST /api/events', () => {
  beforeEach(() => {
    const saved = fakeEvent();
    SecurityEvent.create = jest.fn().mockResolvedValue(saved);
  });

  test('analyst can ingest a valid security event → 201', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(analystUser) });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${analystToken}`)
      .send(validEventPayload());

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toMatchObject({ src_ip: '192.168.1.100', risk_level: 'high' });
    expect(SecurityEvent.create).toHaveBeenCalledTimes(1);
  });

  test('returns 422 when required fields are missing', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(analystUser) });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ src_ip: '1.2.3.4' }); // missing dst_ip, threat_score, risk_level

    expect(res.status).toBe(422);
    expect(res.body.success).toBe(false);
    expect(res.body.errors).toBeInstanceOf(Array);
    expect(res.body.errors.length).toBeGreaterThan(0);
  });

  test('returns 422 for an invalid src_ip', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(analystUser) });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ ...validEventPayload(), src_ip: 'not-an-ip' });

    expect(res.status).toBe(422);
    expect(res.body.errors.some((e) => e.field === 'src_ip')).toBe(true);
  });

  test('returns 403 when viewer tries to ingest event', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(viewerUser) });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${viewerToken}`)
      .send(validEventPayload());

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  test('returns 401 without auth token', async () => {
    const res = await request(app)
      .post('/api/events')
      .send(validEventPayload());

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('returns 422 when threat_score is out of range', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(analystUser) });

    const res = await request(app)
      .post('/api/events')
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ ...validEventPayload(), threat_score: 1.5 });

    expect(res.status).toBe(422);
    expect(res.body.errors.some((e) => e.field === 'threat_score')).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/events
// ─────────────────────────────────────────────────────────────────────────────
describe('GET /api/events', () => {
  const events = [
    { _id: new mongoose.Types.ObjectId(), ...validEventPayload(), src_ip: '1.1.1.1', risk_level: 'critical' },
    { _id: new mongoose.Types.ObjectId(), ...validEventPayload(), src_ip: '2.2.2.2', risk_level: 'high' },
    { _id: new mongoose.Types.ObjectId(), ...validEventPayload(), src_ip: '3.3.3.3', risk_level: 'safe' },
  ];

  beforeEach(() => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(viewerUser) });

    const chain = { sort: jest.fn(), skip: jest.fn(), limit: jest.fn(), lean: jest.fn() };
    chain.sort.mockReturnValue(chain);
    chain.skip.mockReturnValue(chain);
    chain.limit.mockReturnValue(chain);
    chain.lean.mockResolvedValue(events.slice(0, 2));

    SecurityEvent.find = jest.fn().mockReturnValue(chain);
    SecurityEvent.countDocuments = jest.fn().mockResolvedValue(3);
  });

  test('viewer can list events with pagination metadata', async () => {
    const res = await request(app)
      .get('/api/events?page=1&limit=2')
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toHaveLength(2);
    expect(res.body.pagination).toMatchObject({ page: 1, limit: 2, total: 3 });
  });

  test('returns 401 without token', async () => {
    const res = await request(app).get('/api/events');
    expect(res.status).toBe(401);
  });

  test('returns 422 for invalid pagination params', async () => {
    const res = await request(app)
      .get('/api/events?page=-1')
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(res.status).toBe(422);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/events/:id
// ─────────────────────────────────────────────────────────────────────────────
describe('GET /api/events/:id', () => {
  beforeEach(() => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(viewerUser) });
  });

  test('returns event for a valid id', async () => {
    const ev = fakeEvent();
    SecurityEvent.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(ev) });

    const res = await request(app)
      .get(`/api/events/${FAKE_ID}`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data._id).toBe(String(FAKE_ID));
  });

  test('returns 404 when event does not exist', async () => {
    SecurityEvent.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(null) });

    const res = await request(app)
      .get(`/api/events/${FAKE_ID}`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);
  });

  test('returns 422 for malformed ObjectId', async () => {
    const res = await request(app)
      .get('/api/events/not-a-valid-id')
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(422);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PUT /api/events/:id/resolve
// ─────────────────────────────────────────────────────────────────────────────
describe('PUT /api/events/:id/resolve', () => {
  test('analyst can resolve an event', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(analystUser) });

    const ev = fakeEvent();
    ev.save = jest.fn().mockResolvedValue(ev);
    SecurityEvent.findById = jest.fn().mockResolvedValue(ev);

    const res = await request(app)
      .put(`/api/events/${FAKE_ID}/resolve`)
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ notes: 'Confirmed false positive' });

    expect(res.status).toBe(200);
    expect(ev.resolved).toBe(true);
    expect(ev.notes).toBe('Confirmed false positive');
    expect(ev.save).toHaveBeenCalled();
  });

  test('viewer cannot resolve an event → 403', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(viewerUser) });

    const res = await request(app)
      .put(`/api/events/${FAKE_ID}/resolve`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({});

    expect(res.status).toBe(403);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/events/stats/summary
// ─────────────────────────────────────────────────────────────────────────────
describe('GET /api/events/stats/summary', () => {
  beforeEach(() => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(viewerUser) });
    SecurityEvent.countDocuments = jest.fn().mockResolvedValue(10);
    SecurityEvent.aggregate = jest
      .fn()
      .mockResolvedValueOnce([
        { _id: 'critical', count: 3 },
        { _id: 'high', count: 4 },
      ])
      .mockResolvedValueOnce([
        { _id: 'block', count: 5 },
        { _id: 'allow', count: 5 },
      ])
      .mockResolvedValueOnce(2); // recentCritical via countDocuments below
    // The third call in getEventStats is countDocuments (not aggregate), reset:
    SecurityEvent.countDocuments = jest.fn()
      .mockResolvedValueOnce(10)    // total
      .mockResolvedValueOnce(2);   // critical_last_hour
  });

  test('returns summary stats object', async () => {
    const res = await request(app)
      .get('/api/events/stats/summary')
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toHaveProperty('total');
    expect(res.body.data).toHaveProperty('by_risk_level');
    expect(res.body.data).toHaveProperty('by_action');
    expect(res.body.data).toHaveProperty('critical_last_hour');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /api/events/:id
// ─────────────────────────────────────────────────────────────────────────────
describe('DELETE /api/events/:id', () => {
  test('admin can delete an event → 200', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(adminUser) });
    SecurityEvent.findByIdAndDelete = jest.fn().mockResolvedValue(fakeEvent());

    const res = await request(app)
      .delete(`/api/events/${FAKE_ID}`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(SecurityEvent.findByIdAndDelete).toHaveBeenCalledWith(String(FAKE_ID));
  });

  test('analyst cannot delete an event → 403', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(analystUser) });

    const res = await request(app)
      .delete(`/api/events/${FAKE_ID}`)
      .set('Authorization', `Bearer ${analystToken}`);

    expect(res.status).toBe(403);
  });

  test('returns 404 when event not found', async () => {
    User.findById = jest.fn().mockReturnValue({ lean: () => Promise.resolve(adminUser) });
    SecurityEvent.findByIdAndDelete = jest.fn().mockResolvedValue(null);

    const res = await request(app)
      .delete(`/api/events/${FAKE_ID}`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Health check (no auth)
// ─────────────────────────────────────────────────────────────────────────────
describe('GET /health', () => {
  test('returns ok without authentication', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.timestamp).toBeDefined();
  });
});
