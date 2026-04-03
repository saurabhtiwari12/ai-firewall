import React from 'react';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

const styles = {
  card: (color) => ({
    background: '#161b22',
    border: `1px solid #21262d`,
    borderTop: `2px solid ${color}`,
    borderRadius: '10px',
    padding: '20px',
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
    transition: 'all 0.2s ease',
    cursor: 'default',
    position: 'relative',
    overflow: 'hidden',
  }),
  glowBg: (color) => ({
    position: 'absolute',
    top: 0,
    right: 0,
    width: '80px',
    height: '80px',
    borderRadius: '50%',
    background: `${color}10`,
    filter: 'blur(20px)',
    pointerEvents: 'none',
  }),
  header: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
  },
  title: {
    fontSize: '12px',
    fontWeight: '500',
    color: '#8b949e',
    textTransform: 'uppercase',
    letterSpacing: '0.8px',
  },
  iconWrap: (color) => ({
    width: '36px',
    height: '36px',
    borderRadius: '8px',
    background: `${color}18`,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: color,
    flexShrink: 0,
  }),
  value: {
    fontSize: '32px',
    fontWeight: '700',
    color: '#e6edf3',
    letterSpacing: '-0.5px',
    lineHeight: 1,
    fontVariantNumeric: 'tabular-nums',
  },
  footer: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  },
  trendBadge: (positive) => ({
    display: 'flex',
    alignItems: 'center',
    gap: '3px',
    fontSize: '11px',
    fontWeight: '600',
    color: positive ? '#00cc66' : '#ff4444',
    background: positive ? '#00cc6615' : '#ff444415',
    padding: '2px 6px',
    borderRadius: '4px',
  }),
  trendLabel: {
    fontSize: '11px',
    color: '#8b949e',
  },
  subtitle: {
    fontSize: '11px',
    color: '#8b949e',
  },
  loadingPulse: {
    height: '32px',
    width: '80px',
    background: 'linear-gradient(90deg, #21262d 25%, #2d333b 50%, #21262d 75%)',
    backgroundSize: '200% 100%',
    animation: 'shimmer 1.5s infinite',
    borderRadius: '4px',
  },
};

export default function MetricCard({
  title,
  value,
  icon: Icon,
  color = '#00d4ff',
  trend,
  trendLabel = 'vs last hour',
  subtitle,
  loading = false,
}) {
  const trendPositive = trend > 0;
  const trendNeutral = trend === 0 || trend == null;

  return (
    <div
      style={styles.card(color)}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = '#1c2230';
        e.currentTarget.style.boxShadow = `0 0 20px ${color}18`;
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = '#161b22';
        e.currentTarget.style.boxShadow = 'none';
      }}
    >
      <div style={styles.glowBg(color)} />

      <div style={styles.header}>
        <span style={styles.title}>{title}</span>
        {Icon && (
          <div style={styles.iconWrap(color)}>
            <Icon size={16} />
          </div>
        )}
      </div>

      {loading ? (
        <div style={styles.loadingPulse} />
      ) : (
        <div style={styles.value}>{value ?? '—'}</div>
      )}

      <div style={styles.footer}>
        {!trendNeutral && (
          <span style={styles.trendBadge(trendPositive)}>
            {trendPositive ? (
              <TrendingUp size={11} />
            ) : (
              <TrendingDown size={11} />
            )}
            {Math.abs(trend)}%
          </span>
        )}
        {trendNeutral && trend === 0 && (
          <span
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '3px',
              fontSize: '11px',
              fontWeight: '600',
              color: '#8b949e',
              background: '#8b949e15',
              padding: '2px 6px',
              borderRadius: '4px',
            }}
          >
            <Minus size={11} />
            0%
          </span>
        )}
        {trend != null && (
          <span style={styles.trendLabel}>{trendLabel}</span>
        )}
        {subtitle && !trend && (
          <span style={styles.subtitle}>{subtitle}</span>
        )}
      </div>

      <style>{`@keyframes shimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }`}</style>
    </div>
  );
}
