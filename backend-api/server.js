'use strict';

require('dotenv').config();

const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const { Server: SocketIOServer } = require('socket.io');
const client = require('prom-client');

const { connectWithRetry } = require('./config/database');
const logger = require('./utils/logger');
const { apiLimiter } = require('./middleware/rateLimiter');

// ── Route modules ─────────────────────────────────────────────────────────────
const authRoutes = require('./routes/auth');
const eventRoutes = require('./routes/events');
const analyticsRoutes = require('./routes/analytics');
const alertRoutes = require('./routes/alerts');
const systemRoutes = require('./routes/system');

// ── Prometheus: collect default metrics ──────────────────────────────────────
if (process.env.METRICS_ENABLED === 'true') {
  client.collectDefaultMetrics({ prefix: 'aifirewall_' });
}

// ── App + HTTP server ─────────────────────────────────────────────────────────
const app = express();
const httpServer = http.createServer(app);

// ── Socket.io ─────────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map((o) => o.trim());

const io = new SocketIOServer(httpServer, {
  cors: { origin: allowedOrigins, methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
});

io.on('connection', (socket) => {
  logger.info(`Socket connected: ${socket.id}`);
  socket.on('disconnect', () => logger.info(`Socket disconnected: ${socket.id}`));
});

// Expose io to controllers via app
app.set('io', io);

// ── Security / transport middleware ───────────────────────────────────────────
app.use(helmet());
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      cb(new Error(`CORS: origin ${origin} not allowed`));
    },
    credentials: true,
  })
);
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ── Logging ───────────────────────────────────────────────────────────────────
app.use(
  morgan('combined', {
    stream: { write: (msg) => logger.http(msg.trimEnd()) },
    skip: (req) => req.url === '/health',
  })
);

// ── General rate limiter ──────────────────────────────────────────────────────
app.use('/api/', apiLimiter);

// ── Public health check ───────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Prometheus metrics (top-level, admin-only guard is inside route) ──────────
app.get('/metrics', async (req, res) => {
  if (process.env.METRICS_ENABLED !== 'true') {
    return res.status(404).end();
  }
  try {
    res.set('Content-Type', client.register.contentType);
    return res.end(await client.register.metrics());
  } catch {
    return res.status(500).end();
  }
});

// ── API routes ────────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/events', eventRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/system', systemRoutes);

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: `Route ${req.method} ${req.url} not found` });
});

// ── Global error handler ──────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  logger.error(`Unhandled error: ${err.message}`, { stack: err.stack });

  if (err.message && err.message.startsWith('CORS')) {
    return res.status(403).json({ success: false, message: err.message });
  }

  const status = err.status || err.statusCode || 500;
  const message =
    process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message;

  return res.status(status).json({ success: false, message });
});

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function start() {
  if (process.env.NODE_ENV !== 'test') {
    await connectWithRetry();
  }

  const PORT = parseInt(process.env.PORT, 10) || 5000;
  httpServer.listen(PORT, () => {
    logger.info(`AI Firewall API listening on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
  });
}

// ── Graceful shutdown ─────────────────────────────────────────────────────────
function shutdown(signal) {
  logger.info(`${signal} received – shutting down gracefully`);
  httpServer.close(async () => {
    try {
      const mongoose = require('mongoose');
      await mongoose.connection.close();
      logger.info('MongoDB connection closed');
    } catch { /* ignore */ }
    process.exit(0);
  });

  // Force-exit after 10 s if still open
  setTimeout(() => {
    logger.error('Forcing exit after timeout');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

if (require.main === module) {
  start();
}

module.exports = { app, httpServer };
