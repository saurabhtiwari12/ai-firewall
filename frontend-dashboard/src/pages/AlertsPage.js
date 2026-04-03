import React, { useState, useEffect, useCallback } from 'react';
import { Bell, CheckCircle, XCircle, AlertTriangle, Info, AlertCircle, RefreshCw, Filter } from 'lucide-react';
import { getAlerts, acknowledgeAlert, resolveAlert, dismissAlert } from '../services/api';
import { formatDateRelative, getSeverityColor } from '../utils/helpers';

// ─── Mock data ────────────────────────────────────────────────────────────────
const MOCK_ALERTS = [
  { id: 'a1', severity: 'critical', title: 'DDoS Attack Detected', message: 'High-volume SYN flood from 203.0.113.0/24. Over 50K req/s in last 5 minutes. Mitigation rules applied.', status: 'active', timestamp: new Date(Date.now() - 120000).toISOString(), src_ip: '203.0.113.5', category: 'DDoS' },
  { id: 'a2', severity: 'critical', title: 'Ransomware C2 Communication', message: 'Internal host 10.0.0.45 communicating with known ransomware C2 server. Immediate isolation recommended.', status: 'active', timestamp: new Date(Date.now() - 300000).toISOString(), src_ip: '10.0.0.45', category: 'Malware' },
  { id: 'a3', severity: 'high', title: 'SQL Injection Campaign', message: 'Automated SQL injection probe detected from 185.220.101.47 targeting /api/users endpoint — 1,200 requests.', status: 'active', timestamp: new Date(Date.now() - 600000).toISOString(), src_ip: '185.220.101.47', category: 'Injection' },
  { id: 'a4', severity: 'high', title: 'Brute Force Attack', message: 'SSH brute force from 45.33.32.156 — 342 failed attempts targeting admin accounts.', status: 'acknowledged', timestamp: new Date(Date.now() - 900000).toISOString(), src_ip: '45.33.32.156', category: 'Auth' },
  { id: 'a5', severity: 'warning', title: 'Unusual Port Scanning', message: 'Broad TCP port scan detected. Source 91.108.4.0 probing ports 1–65535 on 10.0.0.0/24.', status: 'acknowledged', timestamp: new Date(Date.now() - 1800000).toISOString(), src_ip: '91.108.4.0', category: 'Recon' },
  { id: 'a6', severity: 'warning', title: 'Expired SSL Certificate', message: 'SSL certificate for api.internal.company.com expired 2 days ago. Connections may be insecure.', status: 'active', timestamp: new Date(Date.now() - 3600000).toISOString(), src_ip: null, category: 'Config' },
  { id: 'a7', severity: 'info', title: 'Threat Intelligence Updated', message: 'Loaded 2,841 new IOCs from external threat feed. 12 active blocklist entries updated.', status: 'resolved', timestamp: new Date(Date.now() - 7200000).toISOString(), src_ip: null, category: 'System' },
  { id: 'a8', severity: 'info', title: 'Firewall Rule Update', message: 'GeoIP blocking rules updated. CN and RU traffic now rate-limited to 100 req/min per IP.', status: 'resolved', timestamp: new Date(Date.now() - 10800000).toISOString(), src_ip: null, category: 'Policy' },
];

const SEV_CONFIG = {
  critical: { icon: AlertCircle, color: '#ff4444', bg: '#ff444415', border: '#ff444440' },
  high:     { icon: AlertTriangle, color: '#ff6b35', bg: '#ff6b3515', border: '#ff6b3540' },
  warning:  { icon: AlertTriangle, color: '#ffaa00', bg: '#ffaa0015', border: '#ffaa0040' },
  info:     { icon: Info, color: '#4488ff', bg: '#4488ff15', border: '#4488ff40' },
};

const STATUS_CONFIG = {
  active:       { label: 'Active',       color: '#ff4444', bg: '#ff444420' },
  acknowledged: { label: 'Acknowledged', color: '#ffaa00', bg: '#ffaa0020' },
  resolved:     { label: 'Resolved',     color: '#00cc66', bg: '#00cc6620' },
};

const s = {
  page: { padding: '28px', maxWidth: '1400px' },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' },
  title: { fontSize: '20px', fontWeight: '700', color: '#e6edf3' },
  subtitle: { fontSize: '12px', color: '#8b949e', marginTop: '2px' },
  controls: { display: 'flex', alignItems: 'center', gap: '10px' },
  filterBar: {
    display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap',
    background: '#161b22', border: '1px solid #21262d', borderRadius: '10px',
    padding: '12px 16px', marginBottom: '20px',
  },
  select: {
    background: '#0d1117', border: '1px solid #21262d', borderRadius: '6px',
    color: '#e6edf3', fontSize: '13px', padding: '7px 10px', outline: 'none', cursor: 'pointer',
  },
  statsRow: { display: 'flex', gap: '12px', marginBottom: '20px', flexWrap: 'wrap' },
  statCard: (color) => ({
    background: '#161b22', border: `1px solid ${color}30`,
    borderRadius: '8px', padding: '14px 20px', display: 'flex',
    alignItems: 'center', gap: '12px', flex: '1 1 140px',
  }),
  statNum: (color) => ({ fontSize: '24px', fontWeight: '700', color }),
  statLabel: { fontSize: '11px', color: '#8b949e' },
  alertList: { display: 'flex', flexDirection: 'column', gap: '10px' },
  alertCard: (cfg, status) => ({
    background: status === 'resolved' ? '#0d1117' : cfg.bg,
    border: `1px solid ${status === 'resolved' ? '#21262d' : cfg.border}`,
    borderLeft: `3px solid ${status === 'resolved' ? '#30363d' : cfg.color}`,
    borderRadius: '8px', padding: '16px',
    opacity: status === 'resolved' ? 0.6 : 1,
    transition: 'all 0.2s ease',
  }),
  alertHeader: { display: 'flex', alignItems: 'flex-start', gap: '12px' },
  alertBody: { flex: 1 },
  alertTitleRow: { display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px', flexWrap: 'wrap' },
  alertTitle: { fontSize: '14px', fontWeight: '600', color: '#e6edf3' },
  alertMsg: { fontSize: '12px', color: '#8b949e', lineHeight: 1.5, marginTop: '4px' },
  alertMeta: { display: 'flex', gap: '16px', marginTop: '10px', flexWrap: 'wrap', alignItems: 'center' },
  metaItem: { fontSize: '11px', color: '#484f58', display: 'flex', alignItems: 'center', gap: '4px' },
  badge: (color, bg) => ({
    fontSize: '10px', fontWeight: '600', color, background: bg,
    padding: '2px 8px', borderRadius: '4px', textTransform: 'uppercase', letterSpacing: '0.5px',
    whiteSpace: 'nowrap',
  }),
  actions: { display: 'flex', gap: '6px', flexShrink: 0 },
  actionBtn: (color) => ({
    display: 'flex', alignItems: 'center', gap: '5px',
    background: `${color}15`, border: `1px solid ${color}40`,
    borderRadius: '6px', color, padding: '6px 12px',
    fontSize: '11px', fontWeight: '500', cursor: 'pointer',
    transition: 'all 0.15s ease', whiteSpace: 'nowrap',
  }),
  emptyState: {
    textAlign: 'center', padding: '60px 0', color: '#484f58',
  },
  refreshBtn: {
    display: 'flex', alignItems: 'center', gap: '6px',
    background: '#161b22', border: '1px solid #21262d', borderRadius: '6px',
    color: '#8b949e', padding: '7px 14px', fontSize: '12px', cursor: 'pointer',
  },
};

export default function AlertsPage() {
  const [alerts, setAlerts] = useState(MOCK_ALERTS);
  const [loading, setLoading] = useState(false);
  const [sevFilter, setSevFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('active');
  const [updating, setUpdating] = useState(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAlerts();
      setAlerts(res?.data || res || MOCK_ALERTS);
    } catch {
      setAlerts(MOCK_ALERTS);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const updateAlert = async (id, action) => {
    setUpdating((s) => new Set([...s, id]));
    try {
      const fn = action === 'acknowledge' ? acknowledgeAlert
               : action === 'resolve'     ? resolveAlert
               : dismissAlert;
      await fn(id);
    } catch {}
    const nextStatus = action === 'acknowledge' ? 'acknowledged' : action === 'resolve' ? 'resolved' : 'dismissed';
    setAlerts((prev) => prev.map((a) => a.id === id ? { ...a, status: nextStatus } : a));
    setUpdating((s) => { const n = new Set(s); n.delete(id); return n; });
  };

  const filtered = alerts.filter((a) => {
    if (sevFilter && a.severity !== sevFilter) return false;
    if (statusFilter && a.status !== statusFilter) return false;
    return true;
  });

  const counts = {
    active: alerts.filter((a) => a.status === 'active').length,
    acknowledged: alerts.filter((a) => a.status === 'acknowledged').length,
    resolved: alerts.filter((a) => a.status === 'resolved').length,
    critical: alerts.filter((a) => a.severity === 'critical' && a.status === 'active').length,
  };

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <div style={s.title}>Alerts Management</div>
          <div style={s.subtitle}>Monitor, acknowledge and resolve security alerts</div>
        </div>
        <button style={s.refreshBtn} onClick={load}>
          <RefreshCw size={13} style={{ animation: loading ? 'spin 0.8s linear infinite' : 'none' }} />
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div style={s.statsRow}>
        {[
          { label: 'Active', count: counts.active, color: '#ff4444' },
          { label: 'Critical Active', count: counts.critical, color: '#ff6b35' },
          { label: 'Acknowledged', count: counts.acknowledged, color: '#ffaa00' },
          { label: 'Resolved', count: counts.resolved, color: '#00cc66' },
        ].map(({ label, count, color }) => (
          <div key={label} style={s.statCard(color)}>
            <Bell size={18} color={color} />
            <div>
              <div style={s.statNum(color)}>{count}</div>
              <div style={s.statLabel}>{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={s.filterBar}>
        <Filter size={13} color="#484f58" />
        <select style={s.select} value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </select>
        <select style={s.select} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">All Statuses</option>
          <option value="active">Active</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
        <span style={{ fontSize: '12px', color: '#484f58', marginLeft: 'auto' }}>
          {filtered.length} alert{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Alert List */}
      <div style={s.alertList}>
        {filtered.length === 0 ? (
          <div style={s.emptyState}>
            <CheckCircle size={40} style={{ opacity: 0.3, marginBottom: '12px' }} />
            <div style={{ fontSize: '14px' }}>No alerts match your filters</div>
          </div>
        ) : (
          filtered.map((alert) => {
            const cfg = SEV_CONFIG[alert.severity] || SEV_CONFIG.info;
            const statusCfg = STATUS_CONFIG[alert.status] || STATUS_CONFIG.active;
            const Icon = cfg.icon;
            const isUpdating = updating.has(alert.id);
            return (
              <div key={alert.id} style={s.alertCard(cfg, alert.status)}>
                <div style={s.alertHeader}>
                  <Icon size={18} color={cfg.color} style={{ marginTop: '2px', flexShrink: 0 }} />
                  <div style={s.alertBody}>
                    <div style={s.alertTitleRow}>
                      <span style={s.alertTitle}>{alert.title}</span>
                      <span style={s.badge(cfg.color, cfg.bg)}>{alert.severity}</span>
                      <span style={s.badge(statusCfg.color, statusCfg.bg)}>{statusCfg.label}</span>
                      {alert.category && (
                        <span style={s.badge('#8b949e', '#8b949e15')}>{alert.category}</span>
                      )}
                    </div>
                    <div style={s.alertMsg}>{alert.message}</div>
                    <div style={s.alertMeta}>
                      <span style={s.metaItem}>{formatDateRelative(alert.timestamp)}</span>
                      {alert.src_ip && (
                        <span style={{ ...s.metaItem, fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: '#8b949e' }}>
                          {alert.src_ip}
                        </span>
                      )}
                    </div>
                  </div>
                  {/* Actions */}
                  {alert.status !== 'resolved' && (
                    <div style={s.actions}>
                      {alert.status === 'active' && (
                        <button
                          style={s.actionBtn('#ffaa00')}
                          onClick={() => updateAlert(alert.id, 'acknowledge')}
                          disabled={isUpdating}
                        >
                          <CheckCircle size={12} />
                          Ack
                        </button>
                      )}
                      <button
                        style={s.actionBtn('#00cc66')}
                        onClick={() => updateAlert(alert.id, 'resolve')}
                        disabled={isUpdating}
                      >
                        <CheckCircle size={12} />
                        Resolve
                      </button>
                      <button
                        style={s.actionBtn('#ff4444')}
                        onClick={() => updateAlert(alert.id, 'dismiss')}
                        disabled={isUpdating}
                      >
                        <XCircle size={12} />
                        Dismiss
                      </button>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
      <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
    </div>
  );
}
