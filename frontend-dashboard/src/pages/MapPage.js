import React, { useState, useEffect, useCallback, useRef } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { Shield, RefreshCw, Activity } from 'lucide-react';
import { getAttackGeoData } from '../services/api';
import { formatDateRelative, getRiskColor } from '../utils/helpers';

// ─── Mock geo attack data ─────────────────────────────────────────────────────
const MOCK_ATTACKS = [
  { id: 1,  lat: 39.9,  lng: 116.4, ip: '101.4.55.32',     country: 'China',         attack_type: 'DDoS',          risk_level: 'critical', threat_score: 0.95, timestamp: new Date(Date.now() - 60000).toISOString() },
  { id: 2,  lat: 55.75, lng: 37.62, ip: '185.220.101.47',  country: 'Russia',        attack_type: 'Brute Force',   risk_level: 'high',     threat_score: 0.82, timestamp: new Date(Date.now() - 120000).toISOString() },
  { id: 3,  lat: 37.77, lng: -122.4,ip: '104.21.14.2',     country: 'United States', attack_type: 'Port Scan',     risk_level: 'medium',   threat_score: 0.45, timestamp: new Date(Date.now() - 180000).toISOString() },
  { id: 4,  lat: 51.5,  lng: -0.12, ip: '91.108.4.15',     country: 'UK',            attack_type: 'SQL Injection', risk_level: 'high',     threat_score: 0.78, timestamp: new Date(Date.now() - 240000).toISOString() },
  { id: 5,  lat: -23.5, lng: -46.6, ip: '177.75.50.100',   country: 'Brazil',        attack_type: 'XSS',           risk_level: 'medium',   threat_score: 0.55, timestamp: new Date(Date.now() - 300000).toISOString() },
  { id: 6,  lat: 48.86, lng: 2.35,  ip: '212.47.246.40',   country: 'France',        attack_type: 'CSRF',          risk_level: 'low',      threat_score: 0.28, timestamp: new Date(Date.now() - 360000).toISOString() },
  { id: 7,  lat: 28.7,  lng: 77.1,  ip: '49.248.32.5',     country: 'India',         attack_type: 'Malware',       risk_level: 'critical', threat_score: 0.91, timestamp: new Date(Date.now() - 420000).toISOString() },
  { id: 8,  lat: 35.7,  lng: 139.7, ip: '210.160.105.200', country: 'Japan',         attack_type: 'Path Traversal',risk_level: 'high',     threat_score: 0.72, timestamp: new Date(Date.now() - 480000).toISOString() },
  { id: 9,  lat: 52.5,  lng: 13.4,  ip: '85.214.118.160',  country: 'Germany',       attack_type: 'Recon',         risk_level: 'low',      threat_score: 0.22, timestamp: new Date(Date.now() - 540000).toISOString() },
  { id: 10, lat: -33.9, lng: 151.2, ip: '203.2.218.55',    country: 'Australia',     attack_type: 'RCE',           risk_level: 'critical', threat_score: 0.97, timestamp: new Date(Date.now() - 600000).toISOString() },
  { id: 11, lat: 19.4,  lng: -99.1, ip: '189.146.100.5',   country: 'Mexico',        attack_type: 'DDoS',          risk_level: 'high',     threat_score: 0.76, timestamp: new Date(Date.now() - 660000).toISOString() },
  { id: 12, lat: 41.0,  lng: 28.9,  ip: '78.188.180.80',   country: 'Turkey',        attack_type: 'Brute Force',   risk_level: 'medium',   threat_score: 0.58, timestamp: new Date(Date.now() - 720000).toISOString() },
  { id: 13, lat: 6.36,  lng: 2.42,  ip: '41.138.0.80',     country: 'Nigeria',       attack_type: 'Phishing',      risk_level: 'high',     threat_score: 0.84, timestamp: new Date(Date.now() - 780000).toISOString() },
  { id: 14, lat: 1.35,  lng: 103.82,ip: '182.19.0.1',      country: 'Singapore',     attack_type: 'MITM',          risk_level: 'critical', threat_score: 0.93, timestamp: new Date(Date.now() - 840000).toISOString() },
  { id: 15, lat: 37.57, lng: 126.98,ip: '220.75.212.30',   country: 'South Korea',   attack_type: 'Cryptojacking', risk_level: 'medium',   threat_score: 0.62, timestamp: new Date(Date.now() - 900000).toISOString() },
];

function getMarkerConfig(riskLevel) {
  switch (riskLevel?.toLowerCase()) {
    case 'critical': return { color: '#ff4444', radius: 12, weight: 2, fillOpacity: 0.7 };
    case 'high':     return { color: '#ff6b35', radius: 9,  weight: 2, fillOpacity: 0.65 };
    case 'medium':   return { color: '#ffaa00', radius: 7,  weight: 1, fillOpacity: 0.6 };
    default:         return { color: '#00d4ff', radius: 5,  weight: 1, fillOpacity: 0.5 };
  }
}

function PulsingMarker({ attack }) {
  const cfg = getMarkerConfig(attack.risk_level);
  return (
    <CircleMarker
      center={[attack.lat, attack.lng]}
      radius={cfg.radius}
      pathOptions={{
        color: cfg.color,
        fillColor: cfg.color,
        fillOpacity: cfg.fillOpacity,
        weight: cfg.weight,
      }}
    >
      <Popup>
        <div style={{
          background: '#161b22', color: '#e6edf3', borderRadius: '8px',
          padding: '14px', minWidth: '200px', fontFamily: 'Inter, sans-serif',
          border: '1px solid #30363d',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <Shield size={14} color={cfg.color} />
            <strong style={{ fontSize: '13px' }}>{attack.attack_type}</strong>
            <span style={{
              fontSize: '10px', fontWeight: '700', padding: '1px 6px', borderRadius: '3px',
              background: `${cfg.color}22`, color: cfg.color, textTransform: 'uppercase',
            }}>
              {attack.risk_level}
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px' }}>
            <div><span style={{ color: '#484f58' }}>IP: </span><span style={{ fontFamily: "'JetBrains Mono', monospace" }}>{attack.ip}</span></div>
            <div><span style={{ color: '#484f58' }}>Country: </span>{attack.country}</div>
            <div><span style={{ color: '#484f58' }}>Threat Score: </span>
              <span style={{ color: cfg.color, fontWeight: '600' }}>{(attack.threat_score * 100).toFixed(0)}%</span>
            </div>
            <div style={{ color: '#484f58', fontSize: '11px', marginTop: '4px' }}>
              {formatDateRelative(attack.timestamp)}
            </div>
          </div>
        </div>
      </Popup>
    </CircleMarker>
  );
}

const s = {
  page: { padding: '28px', maxWidth: '1600px' },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' },
  title: { fontSize: '20px', fontWeight: '700', color: '#e6edf3' },
  subtitle: { fontSize: '12px', color: '#8b949e', marginTop: '2px' },
  controls: { display: 'flex', alignItems: 'center', gap: '10px' },
  refreshBtn: {
    display: 'flex', alignItems: 'center', gap: '6px',
    background: '#161b22', border: '1px solid #21262d', borderRadius: '6px',
    color: '#8b949e', padding: '7px 14px', fontSize: '12px', cursor: 'pointer',
  },
  mapContainer: {
    height: 'calc(100vh - 220px)', minHeight: '500px',
    background: '#0d1117', border: '1px solid #21262d',
    borderRadius: '10px', overflow: 'hidden', position: 'relative',
  },
  legend: {
    position: 'absolute', bottom: '30px', left: '16px', zIndex: 1000,
    background: '#161b22ee', border: '1px solid #21262d',
    borderRadius: '8px', padding: '12px 14px',
  },
  legendTitle: { fontSize: '11px', fontWeight: '600', color: '#8b949e', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.7px' },
  legendItem: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '5px', fontSize: '12px', color: '#e6edf3' },
  legendDot: (color, size) => ({
    width: size, height: size, borderRadius: '50%',
    background: color, flexShrink: 0, boxShadow: `0 0 6px ${color}`,
  }),
  statsBar: {
    display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap',
  },
  statCard: (color) => ({
    display: 'flex', alignItems: 'center', gap: '8px',
    background: `${color}15`, border: `1px solid ${color}30`,
    borderRadius: '8px', padding: '8px 14px',
    fontSize: '12px', color: '#e6edf3',
  }),
  statNum: (color) => ({ fontSize: '16px', fontWeight: '700', color }),
};

export default function MapPage() {
  const [attacks, setAttacks] = useState(MOCK_ATTACKS);
  const [loading, setLoading] = useState(false);
  const [riskFilter, setRiskFilter] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAttackGeoData();
      if (res?.length) setAttacks(res);
    } catch {
      setAttacks(MOCK_ATTACKS);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = riskFilter ? attacks.filter((a) => a.risk_level === riskFilter) : attacks;

  const counts = {
    critical: attacks.filter((a) => a.risk_level === 'critical').length,
    high: attacks.filter((a) => a.risk_level === 'high').length,
    medium: attacks.filter((a) => a.risk_level === 'medium').length,
    low: attacks.filter((a) => a.risk_level === 'low').length,
  };

  return (
    <div style={s.page}>
      <style>{`
        .leaflet-container { background: #0a0e1a !important; }
        .leaflet-tile { filter: invert(1) hue-rotate(180deg) brightness(0.7) saturate(0.8); }
        .leaflet-control-attribution { background: #0d1117 !important; color: #484f58 !important; font-size: 9px !important; }
        .leaflet-popup-content-wrapper { background: transparent !important; border: none !important; box-shadow: none !important; padding: 0 !important; }
        .leaflet-popup-content { margin: 0 !important; }
        .leaflet-popup-tip { background: #161b22 !important; }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
      `}</style>

      <div style={s.header}>
        <div>
          <div style={s.title}>Global Attack Map</div>
          <div style={s.subtitle}>Real-time geographic distribution of detected threats</div>
        </div>
        <div style={s.controls}>
          <select
            style={{ background: '#161b22', border: '1px solid #21262d', borderRadius: '6px', color: '#e6edf3', fontSize: '13px', padding: '7px 10px', outline: 'none' }}
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
          >
            <option value="">All Risk Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button style={s.refreshBtn} onClick={load}>
            <RefreshCw size={13} style={{ animation: loading ? 'spin 0.8s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div style={s.statsBar}>
        {[
          { label: 'Critical', count: counts.critical, color: '#ff4444' },
          { label: 'High',     count: counts.high,     color: '#ff6b35' },
          { label: 'Medium',   count: counts.medium,   color: '#ffaa00' },
          { label: 'Low',      count: counts.low,      color: '#00d4ff' },
        ].map(({ label, count, color }) => (
          <div key={label} style={s.statCard(color)}>
            <Activity size={14} color={color} />
            <span style={s.statNum(color)}>{count}</span>
            <span>{label}</span>
          </div>
        ))}
        <div style={{ ...s.statCard('#8b949e'), marginLeft: 'auto' }}>
          <Shield size={14} color="#8b949e" />
          <span style={{ fontSize: '14px', fontWeight: '700', color: '#e6edf3' }}>{filtered.length}</span>
          <span>Total Shown</span>
        </div>
      </div>

      {/* Map */}
      <div style={s.mapContainer}>
        <MapContainer
          center={[20, 0]}
          zoom={2}
          style={{ height: '100%', width: '100%' }}
          zoomControl={true}
          attributionControl={true}
        >
          <TileLayer
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            attribution='© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          />
          {filtered.map((attack) => (
            <PulsingMarker key={attack.id} attack={attack} />
          ))}
        </MapContainer>

        {/* Legend */}
        <div style={s.legend}>
          <div style={s.legendTitle}>Risk Level</div>
          {[
            { label: 'Critical', color: '#ff4444', size: '14px' },
            { label: 'High',     color: '#ff6b35', size: '11px' },
            { label: 'Medium',   color: '#ffaa00', size: '9px' },
            { label: 'Low',      color: '#00d4ff', size: '7px' },
          ].map(({ label, color, size }) => (
            <div key={label} style={s.legendItem}>
              <div style={s.legendDot(color, size)} />
              <span>{label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
