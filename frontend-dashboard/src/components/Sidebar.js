import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  AlertTriangle,
  BarChart3,
  Bell,
  Map,
  ChevronLeft,
  ChevronRight,
  Activity,
  Zap,
} from 'lucide-react';

const NAV_ITEMS = [
  { to: '/',          label: 'Dashboard',       icon: LayoutDashboard },
  { to: '/events',    label: 'Security Events', icon: Activity },
  { to: '/analytics', label: 'Analytics',       icon: BarChart3 },
  { to: '/alerts',    label: 'Alerts',          icon: Bell },
  { to: '/map',       label: 'Attack Map',      icon: Map },
];

const styles = {
  sidebar: (collapsed) => ({
    width: collapsed ? '60px' : '220px',
    minHeight: '100vh',
    background: '#0d1117',
    borderRight: '1px solid #21262d',
    display: 'flex',
    flexDirection: 'column',
    transition: 'width 0.25s ease',
    overflow: 'hidden',
    flexShrink: 0,
    position: 'relative',
    zIndex: 100,
  }),
  logo: (collapsed) => ({
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: collapsed ? '18px 14px' : '18px 20px',
    borderBottom: '1px solid #21262d',
    minHeight: '60px',
    overflow: 'hidden',
  }),
  logoIcon: {
    color: '#00d4ff',
    flexShrink: 0,
  },
  logoText: {
    display: 'flex',
    flexDirection: 'column',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
  },
  logoTitle: {
    fontSize: '14px',
    fontWeight: '700',
    color: '#e6edf3',
    letterSpacing: '0.5px',
  },
  logoSub: {
    fontSize: '10px',
    color: '#00d4ff',
    letterSpacing: '1.5px',
    textTransform: 'uppercase',
    fontWeight: '500',
  },
  nav: {
    flex: 1,
    padding: '12px 0',
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  navItem: (collapsed) => ({
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: collapsed ? '10px 18px' : '10px 20px',
    margin: '0 8px',
    borderRadius: '8px',
    color: '#8b949e',
    fontWeight: '500',
    fontSize: '13px',
    textDecoration: 'none',
    transition: 'all 0.15s ease',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    position: 'relative',
  }),
  footer: (collapsed) => ({
    padding: collapsed ? '12px 10px' : '12px 16px',
    borderTop: '1px solid #21262d',
    display: 'flex',
    alignItems: 'center',
    justifyContent: collapsed ? 'center' : 'space-between',
    gap: '8px',
  }),
  statusDot: (online) => ({
    width: '7px',
    height: '7px',
    borderRadius: '50%',
    background: online ? '#00cc66' : '#ff4444',
    boxShadow: online ? '0 0 6px #00cc66' : '0 0 6px #ff4444',
    flexShrink: 0,
  }),
  statusText: {
    fontSize: '11px',
    color: '#8b949e',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
  },
  collapseBtn: {
    background: 'none',
    border: '1px solid #21262d',
    borderRadius: '6px',
    color: '#8b949e',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '4px',
    transition: 'all 0.15s ease',
    flexShrink: 0,
  },
};

export default function Sidebar({ wsStatus }) {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  const isOnline = wsStatus === 'connected';

  return (
    <nav style={styles.sidebar(collapsed)} aria-label="Main navigation">
      <div style={styles.logo(collapsed)}>
        <Shield size={22} style={styles.logoIcon} />
        {!collapsed && (
          <div style={styles.logoText}>
            <span style={styles.logoTitle}>AI Firewall</span>
            <span style={styles.logoSub}>SOC Platform</span>
          </div>
        )}
      </div>

      <div style={styles.nav}>
        {NAV_ITEMS.map(({ to, label, icon: Icon }) => {
          const active =
            to === '/'
              ? location.pathname === '/'
              : location.pathname.startsWith(to);
          return (
            <NavLink
              key={to}
              to={to}
              style={{
                ...styles.navItem(collapsed),
                ...(active
                  ? {
                      background: '#00d4ff15',
                      color: '#00d4ff',
                      borderLeft: '2px solid #00d4ff',
                      paddingLeft: collapsed ? '16px' : '18px',
                    }
                  : {}),
              }}
              title={collapsed ? label : undefined}
            >
              <Icon size={17} style={{ flexShrink: 0 }} />
              {!collapsed && <span>{label}</span>}
              {active && !collapsed && (
                <Zap
                  size={10}
                  style={{ marginLeft: 'auto', color: '#00d4ff', opacity: 0.7 }}
                />
              )}
            </NavLink>
          );
        })}
      </div>

      <div style={styles.footer(collapsed)}>
        {!collapsed && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' }}>
            <div style={styles.statusDot(isOnline)} />
            <span style={styles.statusText}>
              {isOnline ? 'Live' : 'Offline'}
            </span>
          </div>
        )}
        <button
          style={styles.collapseBtn}
          onClick={() => setCollapsed((c) => !c)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>
      </div>
    </nav>
  );
}
