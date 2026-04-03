import { io } from 'socket.io-client';

const WS_URL = process.env.REACT_APP_WS_URL || 'http://localhost:3001';

let socket = null;

export const getSocket = () => {
  if (!socket) {
    socket = io(WS_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 10000,
      randomizationFactor: 0.5,
      timeout: 20000,
      auth: () => {
        const token = localStorage.getItem('auth_token');
        return token ? { token } : {};
      },
    });

    socket.on('connect', () => {
      console.info('[Socket] Connected:', socket.id);
    });

    socket.on('disconnect', (reason) => {
      console.warn('[Socket] Disconnected:', reason);
    });

    socket.on('connect_error', (err) => {
      console.error('[Socket] Connection error:', err.message);
    });

    socket.on('reconnect', (attempt) => {
      console.info('[Socket] Reconnected after', attempt, 'attempts');
    });

    socket.on('reconnect_attempt', (attempt) => {
      console.info('[Socket] Reconnection attempt', attempt);
    });
  }

  return socket;
};

export const disconnectSocket = () => {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
};

// ─── Typed subscription helpers ──────────────────────────────────────────────

export const onNewEvent = (callback) => {
  const s = getSocket();
  s.on('new_event', callback);
  return () => s.off('new_event', callback);
};

export const onNewAlert = (callback) => {
  const s = getSocket();
  s.on('new_alert', callback);
  return () => s.off('new_alert', callback);
};

export const onMetricsUpdate = (callback) => {
  const s = getSocket();
  s.on('metrics_update', callback);
  return () => s.off('metrics_update', callback);
};

export const onSystemStatus = (callback) => {
  const s = getSocket();
  s.on('system_status', callback);
  return () => s.off('system_status', callback);
};

export const onTrafficData = (callback) => {
  const s = getSocket();
  s.on('traffic_data', callback);
  return () => s.off('traffic_data', callback);
};

export const getConnectionStatus = () => {
  if (!socket) return 'disconnected';
  if (socket.connected) return 'connected';
  return 'connecting';
};

export default { getSocket, disconnectSocket, onNewEvent, onNewAlert, onMetricsUpdate, onSystemStatus, onTrafficData, getConnectionStatus };
