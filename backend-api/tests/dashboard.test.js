'use strict';

/**
 * Tests for GET /api/dashboard/summary
 *
 * Uses Jest mocks for Mongoose models so no real database is required.
 */

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test_secret_12345';
process.env.JWT_REFRESH_SECRET = 'test_refresh_secret_12345';
process.env.JWT_EXPIRES_IN = '15m';
process.env.METRICS_ENABLED = 'false';

const mongoose = require('mongoose');
const request = require('supertest');

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
const Alert = require('../models/Alert');

const { generateAccessToken } = require('../config/jwt');

const makeToken = (role) =>
  generateAccessToken({ id: new mongoose.Types.ObjectId().toString(), role });

const viewerUser  = { _id: new mongoose.Types.ObjectId(), username: 'viewer',  role: 'viewer',  active: true };
const analystUser = { _id: new mongoose.Types.ObjectId(), username: 'analyst', role: 'analyst', active: true };

let viewerToken;
let analystToken;

const { app } = require('../server');

beforeAll(() => {
  viewerToken  = makeToken('viewer');
  analystToken = makeToken('analyst');
});

beforeEach(() => {
  User.findById = jest.fn().mockReturnValue({
    lean: () => Promise.resolve(viewerUser),
    select: () => ({ lean: () => Promise.resolve(viewerUser) }),
  });

  SecurityEvent.countDocuments = jest.fn()
    .mockResolvedValueOnce(42)   // total events in 24h
    .mockResolvedValueOnce(3);   // critical in last hour

  SecurityEvent.aggregate = jest.fn()
    .mockResolvedValueOnce([
      { _id: 'critical', count: 5 },
      { _id: 'high',     count: 10 },
      { _id: 'safe',     count: 27 },
    ])
    .mockResolvedValueOnce([
      { _id: 'block',   count: 20 },
      { _id: 'allow',   count: 22 },
    ]);

  SecurityEvent.find = jest.fn().mockReturnValue({
    sort:  jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    lean:  jest.fn().mockResolvedValue([]),
  });

  Alert.countDocuments = jest.fn().mockResolvedValue(7);
});

afterEach(() => {
  jest.clearAllMocks();
});

describe('GET /api/dashboard/summary', () => {
  test('authenticated viewer receives summary data → 200', async () => {
    const res = await request(app)
      .get('/api/dashboard/summary')
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    const { data } = res.body;
    expect(data).toHaveProperty('total_events_24h', 42);
    expect(data).toHaveProperty('critical_last_hour', 3);
    expect(data).toHaveProperty('active_alerts', 7);
    expect(data).toHaveProperty('block_rate_percent');
    expect(data).toHaveProperty('by_risk_level');
    expect(data).toHaveProperty('by_action');
    expect(data).toHaveProperty('recent_events');
    expect(data).toHaveProperty('generated_at');

    expect(data.by_risk_level.critical).toBe(5);
    expect(data.by_risk_level.high).toBe(10);
    expect(data.by_action.block).toBe(20);
    // block_rate = round(20 / 42 * 100) = 48
    expect(data.block_rate_percent).toBe(48);
  });

  test('returns 401 when no auth token provided', async () => {
    const res = await request(app).get('/api/dashboard/summary');
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('analyst also receives summary data → 200', async () => {
    User.findById = jest.fn().mockReturnValue({
      lean: () => Promise.resolve(analystUser),
    });

    const res = await request(app)
      .get('/api/dashboard/summary')
      .set('Authorization', `Bearer ${analystToken}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('returns 500 when database throws', async () => {
    SecurityEvent.countDocuments = jest.fn().mockRejectedValue(new Error('DB error'));

    const res = await request(app)
      .get('/api/dashboard/summary')
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
  });

  test('block_rate_percent is 0 when there are no events', async () => {
    SecurityEvent.countDocuments = jest.fn()
      .mockResolvedValueOnce(0)   // total_events_24h
      .mockResolvedValueOnce(0);  // critical_last_hour

    SecurityEvent.aggregate = jest.fn()
      .mockResolvedValueOnce([])   // risk breakdown
      .mockResolvedValueOnce([]);  // action breakdown

    const res = await request(app)
      .get('/api/dashboard/summary')
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.block_rate_percent).toBe(0);
  });
});
