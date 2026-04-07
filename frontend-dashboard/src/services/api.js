import axios from 'axios';

const BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT token to every request
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Handle auth errors globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('auth_token');
      // Optionally redirect to login
    }
    return Promise.reject(error);
  }
);

// ─── Security Events ──────────────────────────────────────────────────────────

export const getEvents = (params = {}) =>
  api.get('/api/events', { params }).then((r) => r.data);

export const getEventById = (id) =>
  api.get(`/api/events/${id}`).then((r) => r.data);

export const exportEvents = (params = {}) =>
  api.get('/api/events/export', { params, responseType: 'blob' }).then((r) => r.data);

// ─── Analytics ───────────────────────────────────────────────────────────────

export const getAnalytics = (params = {}) =>
  api.get('/api/analytics', { params }).then((r) => r.data);

export const getTrafficTimeSeries = (params = {}) =>
  api.get('/api/analytics/traffic', { params }).then((r) => r.data);

export const getAttackTypeDistribution = (params = {}) =>
  api.get('/api/analytics/attack-types', { params }).then((r) => r.data);

export const getTopSourceIPs = (params = {}) =>
  api.get('/api/analytics/top-ips', { params }).then((r) => r.data);

export const getThreatScoreDistribution = (params = {}) =>
  api.get('/api/analytics/threat-scores', { params }).then((r) => r.data);

export const getHourlyHeatmap = (params = {}) =>
  api.get('/api/analytics/heatmap', { params }).then((r) => r.data);

// ─── Alerts ───────────────────────────────────────────────────────────────────

export const getAlerts = (params = {}) =>
  api.get('/api/alerts', { params }).then((r) => r.data);

export const acknowledgeAlert = (id) =>
  api.patch(`/api/alerts/${id}/acknowledge`).then((r) => r.data);

export const resolveAlert = (id) =>
  api.patch(`/api/alerts/${id}/resolve`).then((r) => r.data);

export const dismissAlert = (id) =>
  api.patch(`/api/alerts/${id}/dismiss`).then((r) => r.data);

// ─── System Status ────────────────────────────────────────────────────────────

export const getSystemStatus = () =>
  api.get('/api/system/status').then((r) => r.data);

export const getDashboardSummary = () =>
  api.get('/api/dashboard/summary').then((r) => r.data);

// ─── Geo / Map ────────────────────────────────────────────────────────────────

export const getAttackGeoData = (params = {}) =>
  api.get('/api/geo/attacks', { params }).then((r) => r.data);

// ─── Blocked IPs ──────────────────────────────────────────────────────────────

export const getBlockedIPs = (params = {}) =>
  api.get('/api/blocked-ips', { params }).then((r) => r.data);

export const unblockIP = (ip) =>
  api.delete(`/api/blocked-ips/${ip}`).then((r) => r.data);

export default api;
