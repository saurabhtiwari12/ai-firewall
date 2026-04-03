import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Activity,
  ShieldAlert,
  Ban,
  Server,
  RefreshCw,
  Clock,
} from 'lucide-react';
import MetricCard from '../components/MetricCard';
import ThreatTable from '../components/ThreatTable';
import AlertBanner from '../components/AlertBanner';
import TrafficChart from '../charts/TrafficChart';
import { getDashboardSummary, getEvents, getAlerts, getTrafficTimeSeries } from '../services/api';
import { formatDateRelative, formatNumber } from '../utils/helpers';
import { onNewEvent, onNewAlert, onMetricsUpdate } from '../services/socket';
import { format, subMinutes } from 'date-fns';

// ─── Mock data generators (used when API is unavailable) ──────────────────────

const ATTACK_TYPES = ['SQL Injection', 'XSS', 'DDoS', 'Port Scan', 'Brute Force', 'CSRF', 'Path Traversal', 'RCE'];
const RISK_LEVELS = ['critical', 'high', 'medium', 'low'];
const ACTIONS = ['block', 'allow', 'monitor', 'alert'];
const IPS = ['192.168.1.45', '10.0.0.23', '172.16.0.100', '203.0.113.5', '198.51.100.8', '45.33.32.156', '104.21.14.2', '185.220.101.47'];

function mockEvent(i) {
  const now = new Date();
  return {
    id: `evt-${Date.now()}-${i}`,
    timestamp: new Date(now - Math.random() * 3600000).toISOString(),
    src_ip: IPS[Math.floor(Math.random() * IPS.length)],
    dst_ip: `10.10.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}`,
    attack_type: ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)],
    threat_score: parseFloat((Math.random()).toFixed(3)),
    risk_level: RISK_LEVELS[Math.floor(Math.random() * RISK_LEVELS.length)],
    action: ACTIONS[Math.floor(Math.random() * ACTIONS.length)],
    protocol: ['TCP', 'UDP', 'HTTP', 'HTTPS'][Math.floor(Math.random() * 4)],
    dst_port: [80, 443, 22, 3306, 5432, 8080][Math.floor(Math.random() * 6)],
    country: ['CN', 'RU', 'US', 'DE', 'BR', 'IN'][Math.floor(Math.random() * 6)],
    confidence: parseFloat((0.7 + Math.random() * 0.3).toFixed(3)),
  };
}

function mockTrafficData(points = 30) {
  const now = new Date();
  const labels = [];
  const traffic = [];
  const blocked = [];
  for (let i = points - 1; i >= 0; i--) {
    labels.push(format(subMinutes(now, i * 2), 'HH:mm'));
    const base = 200 + Math.random() * 400;
    traffic.push(Math.round(base));
    blocked.push(Math.round(base * 0.15 + Math.random() * 50));
  }
  return {
    labels,
    datasets: [
      { label: 'Total Traffic', data: traffic, color: '#00d4ff' },
      { label: 'Blocked', data: blocked, color: '#ff4444' },
    ],
  };
}

function mockAlerts() {
  return [
    {
      id: 'a1',
      severity: 'critical',
      title: 'DDoS Attack Detected',
      message: 'High-volume traffic spike from 203.0.113.0/24. Over 50,000 req/s in last 5 minutes.',
      timestamp: new Date().toISOString(),
    },
    {
      id: 'a2',
      severity: 'warning',
      title: 'Brute Force Attempt',
      message: 'Multiple failed SSH logins from 45.33.32.156 — 342 attempts in 10 minutes.',
      timestamp: new Date(Date.now() - 300000).toISOString(),
    },
    {
      id: 'a3',
      severity: 'info',
      title: 'Threat Intelligence Updated',
      message: 'Loaded 2,841 new IOCs from threat feed.',
      timestamp: new Date(Date.now() - 600000).toISOString(),
    },
  ];
}

const s = {
  page: {
    padding: '28px',
    maxWidth: '1600px',
  },
  pageHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '24px',
  },
  pageTitle: {
    fontSize: '20px',
    fontWeight: '700',
    color: '#e6edf3',
    letterSpacing: '-0.3px',
  },
  pageSubtitle: {
    fontSize: '12px',
    color: '#8b949e',
    marginTop: '2px',
  },
  headerRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  refreshInfo: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    fontSize: '11px',
    color: '#484f58',
  },
  refreshBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    background: '#161b22',
    border: '1px solid #21262d',
    borderRadius: '6px',
    color: '#8b949e',
    padding: '6px 12px',
    fontSize: '12px',
    cursor: 'pointer',
    transition: 'all 0.15s ease',
  },
  metricsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '16px',
    marginBottom: '24px',
  },
  mainGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 360px',
    gap: '20px',
    marginBottom: '24px',
  },
  card: {
    background: '#161b22',
    border: '1px solid #21262d',
    borderRadius: '10px',
    padding: '20px',
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '16px',
  },
  cardTitle: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#e6edf3',
  },
  cardBadge: {
    fontSize: '10px',
    color: '#00d4ff',
    background: '#00d4ff15',
    padding: '2px 8px',
    borderRadius: '4px',
    letterSpacing: '0.5px',
    textTransform: 'uppercase',
    fontWeight: '500',
  },
  liveIndicator: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    fontSize: '11px',
    color: '#00cc66',
  },
  liveDot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    background: '#00cc66',
    boxShadow: '0 0 6px #00cc66',
    animation: 'pulse 2s infinite',
  },
  alertFeed: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    maxHeight: '300px',
    overflowY: 'auto',
  },
  alertItem: (sev) => {
    const colors = { critical: '#ff4444', high: '#ff6b35', warning: '#ffaa00', medium: '#ffaa00', info: '#4488ff', low: '#00cc66' };
    const c = colors[sev] || '#8b949e';
    return {
      background: `${c}10`,
      border: `1px solid ${c}30`,
      borderLeft: `3px solid ${c}`,
      borderRadius: '6px',
      padding: '10px 12px',
    };
  },
  alertItemTitle: {
    fontSize: '12px',
    fontWeight: '600',
    color: '#e6edf3',
    marginBottom: '2px',
  },
  alertItemMsg: {
    fontSize: '11px',
    color: '#8b949e',
    lineHeight: 1.4,
  },
  alertItemTime: {
    fontSize: '10px',
    color: '#484f58',
    marginTop: '4px',
  },
  sectionHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '16px',
  },
};

const REFRESH_INTERVAL = 30000;

export default function Dashboard() {
  const [metrics, setMetrics] = useState(null);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [trafficData, setTrafficData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [refreshing, setRefreshing] = useState(false);
  const timerRef = useRef(null);

  const loadData = useCallback(async () => {
    setRefreshing(true);
    try {
      const [summaryRes, eventsRes, alertsRes, trafficRes] = await Promise.allSettled([
        getDashboardSummary(),
        getEvents({ limit: 10, sort: 'timestamp', order: 'desc' }),
        getAlerts({ status: 'active', limit: 5 }),
        getTrafficTimeSeries({ range: '1h', interval: '2m' }),
      ]);

      if (summaryRes.status === 'fulfilled') setMetrics(summaryRes.value);
      if (eventsRes.status === 'fulfilled') setEvents(eventsRes.value?.data || eventsRes.value || []);
      if (alertsRes.status === 'fulfilled') setAlerts(alertsRes.value?.data || alertsRes.value || []);
      if (trafficRes.status === 'fulfilled') setTrafficData(trafficRes.value);
    } catch (err) {
      console.error('Dashboard load error:', err);
    } finally {
      // Fall back to mock data if APIs unavailable
      setMetrics((m) => m || {
        total_events: 48291,
        active_threats: 23,
        blocked_ips: 1847,
        system_status: 'operational',
        events_trend: 12,
        threats_trend: -8,
        blocked_trend: 5,
      });
      setEvents((e) => e.length ? e : Array.from({ length: 10 }, (_, i) => mockEvent(i)));
      setAlerts((a) => a.length ? a : mockAlerts());
      setTrafficData((t) => t || mockTrafficData());
      setLoading(false);
      setRefreshing(false);
      setLastRefresh(new Date());
    }
  }, []);

  useEffect(() => {
    loadData();
    timerRef.current = setInterval(loadData, REFRESH_INTERVAL);

    const unsubEvent = onNewEvent((evt) => {
      setEvents((prev) => [evt, ...prev.slice(0, 9)]);
      setMetrics((m) => m ? { ...m, total_events: (m.total_events || 0) + 1 } : m);
    });
    const unsubAlert = onNewAlert((alert) => {
      setAlerts((prev) => [alert, ...prev.slice(0, 4)]);
    });
    const unsubMetrics = onMetricsUpdate((data) => {
      setMetrics((m) => ({ ...m, ...data }));
    });

    return () => {
      clearInterval(timerRef.current);
      unsubEvent();
      unsubAlert();
      unsubMetrics();
    };
  }, [loadData]);

  const systemColor =
    metrics?.system_status === 'operational' ? '#00cc66'
    : metrics?.system_status === 'degraded'  ? '#ffaa00'
    : '#ff4444';

  return (
    <div style={s.page}>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }`}</style>

      <div style={s.pageHeader}>
        <div>
          <div style={s.pageTitle}>Security Overview</div>
          <div style={s.pageSubtitle}>Real-time SOC monitoring dashboard</div>
        </div>
        <div style={s.headerRight}>
          <div style={s.refreshInfo}>
            <Clock size={12} />
            Last updated {formatDateRelative(lastRefresh)}
          </div>
          <button
            style={s.refreshBtn}
            onClick={loadData}
            disabled={refreshing}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#00d4ff44'; e.currentTarget.style.color = '#00d4ff'; }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = '#21262d'; e.currentTarget.style.color = '#8b949e'; }}
          >
            <RefreshCw size={13} style={{ animation: refreshing ? 'spin 0.8s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>
      </div>

      <AlertBanner alerts={alerts.filter((a) => a.severity === 'critical')} />

      {/* Metric Cards */}
      <div style={s.metricsGrid}>
        <MetricCard
          title="Total Events"
          value={formatNumber(metrics?.total_events)}
          icon={Activity}
          color="#00d4ff"
          trend={metrics?.events_trend}
          loading={loading}
        />
        <MetricCard
          title="Active Threats"
          value={metrics?.active_threats ?? '—'}
          icon={ShieldAlert}
          color="#ff4444"
          trend={metrics?.threats_trend}
          loading={loading}
        />
        <MetricCard
          title="Blocked IPs"
          value={formatNumber(metrics?.blocked_ips)}
          icon={Ban}
          color="#ffaa00"
          trend={metrics?.blocked_trend}
          loading={loading}
        />
        <MetricCard
          title="System Status"
          value={metrics?.system_status ? metrics.system_status.charAt(0).toUpperCase() + metrics.system_status.slice(1) : '—'}
          icon={Server}
          color={systemColor}
          subtitle={metrics?.system_status === 'operational' ? 'All systems nominal' : 'Degraded performance'}
          loading={loading}
        />
      </div>

      {/* Charts + Alert Feed */}
      <div style={s.mainGrid}>
        <div style={s.card}>
          <div style={s.cardHeader}>
            <span style={s.cardTitle}>Network Traffic (Last 60 min)</span>
            <div style={s.liveIndicator}>
              <div style={s.liveDot} />
              Live
            </div>
          </div>
          {trafficData ? (
            <TrafficChart data={trafficData} height={240} />
          ) : (
            <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#484f58' }}>
              Loading chart…
            </div>
          )}
        </div>

        <div style={s.card}>
          <div style={s.cardHeader}>
            <span style={s.cardTitle}>Alert Feed</span>
            <span style={s.cardBadge}>{alerts.length} Active</span>
          </div>
          <div style={s.alertFeed}>
            {alerts.length === 0 ? (
              <div style={{ color: '#484f58', fontSize: '13px', textAlign: 'center', padding: '24px 0' }}>
                No active alerts
              </div>
            ) : (
              alerts.map((alert) => (
                <div key={alert.id} style={s.alertItem(alert.severity)}>
                  <div style={s.alertItemTitle}>{alert.title || alert.message}</div>
                  {alert.title && alert.message && (
                    <div style={s.alertItemMsg}>{alert.message}</div>
                  )}
                  <div style={s.alertItemTime}>{formatDateRelative(alert.timestamp)}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Recent Events */}
      <div>
        <div style={s.sectionHeader}>
          <span style={{ fontSize: '15px', fontWeight: '600', color: '#e6edf3' }}>
            Recent Security Events
          </span>
          <span style={{ fontSize: '11px', color: '#8b949e' }}>Last 10 events</span>
        </div>
        <ThreatTable events={events} loading={loading} compact />
      </div>

      <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
    </div>
  );
}
