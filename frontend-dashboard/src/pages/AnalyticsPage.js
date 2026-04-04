import React, { useState, useEffect, useCallback } from 'react';
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, BarElement,
  PointElement, LineElement, ArcElement,
  Title, Tooltip, Legend, Filler,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';
import { RefreshCw } from 'lucide-react';
import TrafficChart from '../charts/TrafficChart';
import ThreatDistributionChart from '../charts/ThreatDistributionChart';
import {
  getTrafficTimeSeries, getAttackTypeDistribution,
  getTopSourceIPs, getThreatScoreDistribution, getHourlyHeatmap,
} from '../services/api';
import { format, subHours, subDays } from 'date-fns';

ChartJS.register(
  CategoryScale, LinearScale, BarElement,
  PointElement, LineElement, ArcElement,
  Title, Tooltip, Legend, Filler
);

// ─── Mock generators ──────────────────────────────────────────────────────────
function mockTraffic(range) {
  const points = range === '24h' ? 24 : range === '7d' ? 84 : 30;
  const labels = [];
  const traffic = [];
  const blocked = [];
  const now = new Date();
  for (let i = points - 1; i >= 0; i--) {
    const d = range === '24h' ? subHours(now, i) : subHours(now, i * 2);
    labels.push(format(d, range === '24h' ? 'HH:00' : 'MM/dd HH:mm'));
    const base = 500 + Math.sin(i / 5) * 200 + Math.random() * 300;
    traffic.push(Math.round(base));
    blocked.push(Math.round(base * 0.1 + Math.random() * 80));
  }
  return {
    labels,
    datasets: [
      { label: 'Total Traffic', data: traffic, color: '#00d4ff' },
      { label: 'Blocked', data: blocked, color: '#ff4444' },
    ],
  };
}

function mockAttackDist() {
  return {
    labels: ['SQL Injection', 'XSS', 'DDoS', 'Port Scan', 'Brute Force', 'CSRF', 'Path Traversal', 'RCE'],
    values: [342, 278, 195, 432, 167, 89, 54, 38],
  };
}

function mockTopIPs() {
  return {
    labels: ['45.33.32.156', '185.220.101.47', '203.0.113.5', '91.108.4.0', '141.101.64.0', '198.51.100.8', '104.21.14.2', '172.16.0.100'],
    values: [1243, 987, 756, 643, 521, 412, 334, 289],
  };
}

function mockScoreDist() {
  return {
    labels: ['0–0.2', '0.2–0.4', '0.4–0.6', '0.6–0.8', '0.8–1.0'],
    values: [1820, 3450, 4120, 2890, 1340],
  };
}

function mockHeatmap() {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const hours = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`);
  return { days, hours, data: days.map(() => hours.map(() => Math.floor(Math.random() * 300))) };
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function BarChartCard({ title, data, color = '#00d4ff', height = 220 }) {
  if (!data) return null;
  const chartData = {
    labels: data.labels,
    datasets: [{
      label: title,
      data: data.values,
      backgroundColor: `${color}55`,
      borderColor: color,
      borderWidth: 1,
      borderRadius: 4,
      hoverBackgroundColor: `${color}99`,
    }],
  };
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#161b22',
        titleColor: '#e6edf3',
        bodyColor: '#8b949e',
        borderColor: '#30363d',
        borderWidth: 1,
        padding: 10,
      },
    },
    scales: {
      x: {
        grid: { color: '#21262d' },
        ticks: {
          color: '#484f58',
          font: { size: 10, family: 'Inter, sans-serif' },
          maxRotation: 30,
        },
      },
      y: {
        grid: { color: '#21262d' },
        ticks: {
          color: '#484f58',
          font: { size: 10 },
          callback: (v) => v >= 1000 ? `${(v / 1000).toFixed(0)}K` : v,
        },
        beginAtZero: true,
      },
    },
  };
  return (
    <div style={{ height, width: '100%' }}>
      <Bar data={chartData} options={options} />
    </div>
  );
}

function HeatmapChart({ data }) {
  if (!data) return null;
  const { days, hours, data: cells } = data;
  const maxVal = Math.max(...cells.flat());

  return (
    <div style={{ overflowX: 'auto' }}>
      <div style={{ display: 'flex', gap: '4px', minWidth: '600px' }}>
        {/* Y-axis labels */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', paddingTop: '20px' }}>
          {days.map((d) => (
            <div key={d} style={{ height: '22px', fontSize: '10px', color: '#484f58', width: '28px', display: 'flex', alignItems: 'center' }}>
              {d}
            </div>
          ))}
        </div>
        {/* Cells + X-axis */}
        <div style={{ flex: 1 }}>
          {/* X-axis hours */}
          <div style={{ display: 'flex', gap: '4px', marginBottom: '4px' }}>
            {hours.filter((_, i) => i % 3 === 0).map((h) => (
              <div key={h} style={{ flex: 1, fontSize: '9px', color: '#484f58', textAlign: 'center' }}>{h}</div>
            ))}
          </div>
          {/* Rows */}
          {days.map((day, di) => (
            <div key={day} style={{ display: 'flex', gap: '4px', marginBottom: '4px' }}>
              {hours.map((hour, hi) => {
                const val = cells[di]?.[hi] ?? 0;
                const intensity = maxVal > 0 ? val / maxVal : 0;
                const bg = intensity > 0.8 ? '#ff4444'
                  : intensity > 0.6 ? '#ff6b35'
                  : intensity > 0.4 ? '#ffaa00'
                  : intensity > 0.2 ? '#00d4ff'
                  : intensity > 0   ? '#00d4ff44'
                  : '#21262d';
                return (
                  <div
                    key={hour}
                    title={`${day} ${hour}: ${val} events`}
                    style={{
                      flex: 1, height: '22px', borderRadius: '3px',
                      background: bg, opacity: 0.8 + intensity * 0.2,
                      cursor: 'default', transition: 'opacity 0.1s',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.opacity = '1')}
                    onMouseLeave={(e) => (e.currentTarget.style.opacity = String(0.8 + intensity * 0.2))}
                  />
                );
              })}
            </div>
          ))}
        </div>
      </div>
      {/* Legend */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '12px', fontSize: '10px', color: '#484f58' }}>
        <span>Low</span>
        {['#00d4ff44', '#00d4ff', '#ffaa00', '#ff6b35', '#ff4444'].map((c) => (
          <div key={c} style={{ width: '20px', height: '10px', background: c, borderRadius: '2px' }} />
        ))}
        <span>High</span>
      </div>
    </div>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const s = {
  page: { padding: '28px', maxWidth: '1600px' },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' },
  title: { fontSize: '20px', fontWeight: '700', color: '#e6edf3' },
  subtitle: { fontSize: '12px', color: '#8b949e', marginTop: '2px' },
  controls: { display: 'flex', alignItems: 'center', gap: '10px' },
  rangeBtn: (active) => ({
    background: active ? '#00d4ff20' : '#161b22',
    border: `1px solid ${active ? '#00d4ff60' : '#21262d'}`,
    borderRadius: '6px', color: active ? '#00d4ff' : '#8b949e',
    padding: '6px 14px', fontSize: '12px', cursor: 'pointer',
    transition: 'all 0.15s ease', fontWeight: active ? '600' : '400',
  }),
  grid2: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' },
  card: {
    background: '#161b22', border: '1px solid #21262d', borderRadius: '10px', padding: '20px',
  },
  cardHeader: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' },
  cardTitle: { fontSize: '13px', fontWeight: '600', color: '#e6edf3' },
  cardSub: { fontSize: '11px', color: '#484f58' },
};

const RANGES = [
  { label: '1H',  value: '1h' },
  { label: '24H', value: '24h' },
  { label: '7D',  value: '7d' },
];

export default function AnalyticsPage() {
  const [range, setRange] = useState('24h');
  const [traffic, setTraffic] = useState(null);
  const [attackDist, setAttackDist] = useState(null);
  const [topIPs, setTopIPs] = useState(null);
  const [scoreDist, setScoreDist] = useState(null);
  const [heatmap, setHeatmap] = useState(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [t, a, ip, s, h] = await Promise.allSettled([
        getTrafficTimeSeries({ range }),
        getAttackTypeDistribution({ range }),
        getTopSourceIPs({ range, limit: 10 }),
        getThreatScoreDistribution({ range }),
        getHourlyHeatmap({ range }),
      ]);
      if (t.status === 'fulfilled') setTraffic(t.value);
      if (a.status === 'fulfilled') setAttackDist(a.value);
      if (ip.status === 'fulfilled') setTopIPs(ip.value);
      if (s.status === 'fulfilled') setScoreDist(s.value);
      if (h.status === 'fulfilled') setHeatmap(h.value);
    } catch {}
    // Mock fallback
    setTraffic((v) => v || mockTraffic(range));
    setAttackDist((v) => v || mockAttackDist());
    setTopIPs((v) => v || mockTopIPs());
    setScoreDist((v) => v || mockScoreDist());
    setHeatmap((v) => v || mockHeatmap());
    setLoading(false);
  }, [range]);

  useEffect(() => { load(); }, [load]);

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <div style={s.title}>Analytics</div>
          <div style={s.subtitle}>Traffic analysis and threat intelligence metrics</div>
        </div>
        <div style={s.controls}>
          {RANGES.map(({ label, value }) => (
            <button key={value} style={s.rangeBtn(range === value)} onClick={() => setRange(value)}>
              {label}
            </button>
          ))}
          <button
            onClick={load}
            style={{ ...s.rangeBtn(false), display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={12} style={{ animation: loading ? 'spin 0.8s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>
      </div>

      {/* Traffic Chart */}
      <div style={{ ...s.card, marginBottom: '20px' }}>
        <div style={s.cardHeader}>
          <span style={s.cardTitle}>Network Traffic Volume</span>
          <span style={s.cardSub}>Packets/connections over time</span>
        </div>
        <TrafficChart data={traffic} height={260} />
      </div>

      {/* Row 2 */}
      <div style={s.grid2}>
        <div style={s.card}>
          <div style={s.cardHeader}>
            <span style={s.cardTitle}>Attack Type Distribution</span>
            <span style={s.cardSub}>{attackDist?.values?.reduce((a, b) => a + b, 0)?.toLocaleString() || '—'} total</span>
          </div>
          <ThreatDistributionChart data={attackDist} height={260} />
        </div>

        <div style={s.card}>
          <div style={s.cardHeader}>
            <span style={s.cardTitle}>Top Source IPs</span>
            <span style={s.cardSub}>By event count</span>
          </div>
          <BarChartCard title="Events" data={topIPs} color="#a855f7" height={220} />
        </div>
      </div>

      {/* Row 3 */}
      <div style={s.grid2}>
        <div style={s.card}>
          <div style={s.cardHeader}>
            <span style={s.cardTitle}>Threat Score Distribution</span>
            <span style={s.cardSub}>Histogram of AI confidence scores</span>
          </div>
          <BarChartCard title="Events" data={scoreDist} color="#ffaa00" height={220} />
        </div>

        <div style={s.card}>
          <div style={s.cardHeader}>
            <span style={s.cardTitle}>Hourly Event Heatmap</span>
            <span style={s.cardSub}>Day × Hour activity pattern</span>
          </div>
          <HeatmapChart data={heatmap} />
        </div>
      </div>
      <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
    </div>
  );
}
