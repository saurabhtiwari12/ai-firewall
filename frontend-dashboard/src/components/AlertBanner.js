import React, { useState } from 'react';
import { X, AlertTriangle, Info, AlertCircle, CheckCircle } from 'lucide-react';

const SEVERITY_CONFIG = {
  info: {
    icon: Info,
    color: '#4488ff',
    bg: '#4488ff15',
    border: '#4488ff40',
    label: 'INFO',
  },
  warning: {
    icon: AlertTriangle,
    color: '#ffaa00',
    bg: '#ffaa0015',
    border: '#ffaa0040',
    label: 'WARNING',
  },
  critical: {
    icon: AlertCircle,
    color: '#ff4444',
    bg: '#ff444415',
    border: '#ff444440',
    label: 'CRITICAL',
  },
  success: {
    icon: CheckCircle,
    color: '#00cc66',
    bg: '#00cc6615',
    border: '#00cc6640',
    label: 'SUCCESS',
  },
};

const s = {
  banner: (cfg, visible) => ({
    display: visible ? 'flex' : 'none',
    alignItems: 'flex-start',
    gap: '12px',
    padding: '12px 16px',
    background: cfg.bg,
    border: `1px solid ${cfg.border}`,
    borderLeft: `3px solid ${cfg.color}`,
    borderRadius: '8px',
    marginBottom: '16px',
    animation: 'slideIn 0.2s ease',
  }),
  iconWrap: (cfg) => ({
    color: cfg.color,
    flexShrink: 0,
    marginTop: '1px',
  }),
  body: {
    flex: 1,
    minWidth: 0,
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '2px',
  },
  severityLabel: (cfg) => ({
    fontSize: '10px',
    fontWeight: '700',
    color: cfg.color,
    letterSpacing: '1px',
    textTransform: 'uppercase',
  }),
  title: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#e6edf3',
  },
  message: {
    fontSize: '12px',
    color: '#8b949e',
    lineHeight: 1.5,
    marginTop: '2px',
    wordBreak: 'break-word',
  },
  closeBtn: (cfg) => ({
    background: 'none',
    border: 'none',
    color: cfg.color,
    cursor: 'pointer',
    padding: '2px',
    borderRadius: '4px',
    display: 'flex',
    alignItems: 'center',
    opacity: 0.7,
    transition: 'opacity 0.15s ease',
    flexShrink: 0,
  }),
  timestamp: {
    fontSize: '10px',
    color: '#484f58',
    marginTop: '4px',
  },
};

export default function AlertBanner({ alerts = [], onDismiss }) {
  const [dismissed, setDismissed] = useState(new Set());

  const handleDismiss = (id) => {
    setDismissed((prev) => new Set([...prev, id]));
    if (onDismiss) onDismiss(id);
  };

  const visible = alerts.filter((a) => !dismissed.has(a.id));
  if (!visible.length) return null;

  return (
    <div>
      <style>{`@keyframes slideIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }`}</style>
      {visible.map((alert) => {
        const sev = alert.severity || 'info';
        const cfg = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.info;
        const Icon = cfg.icon;
        return (
          <div key={alert.id} style={s.banner(cfg, true)}>
            <div style={s.iconWrap(cfg)}>
              <Icon size={16} />
            </div>
            <div style={s.body}>
              <div style={s.header}>
                <span style={s.severityLabel(cfg)}>{cfg.label}</span>
                {alert.title && <span style={s.title}>{alert.title}</span>}
              </div>
              {alert.message && (
                <div style={s.message}>{alert.message}</div>
              )}
              {alert.timestamp && (
                <div style={s.timestamp}>
                  {new Date(alert.timestamp).toLocaleString()}
                </div>
              )}
            </div>
            <button
              style={s.closeBtn(cfg)}
              onClick={() => handleDismiss(alert.id)}
              aria-label="Dismiss alert"
              onMouseEnter={(e) => (e.currentTarget.style.opacity = '1')}
              onMouseLeave={(e) => (e.currentTarget.style.opacity = '0.7')}
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
