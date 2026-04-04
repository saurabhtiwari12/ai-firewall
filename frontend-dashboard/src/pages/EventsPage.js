import React, { useState, useEffect, useCallback } from 'react';
import { Search, Filter, Download, X, ChevronLeft, ChevronRight, ExternalLink } from 'lucide-react';
import ThreatTable from '../components/ThreatTable';
import { getEvents } from '../services/api';
import { formatDate, getRiskColor, getRiskBgColor, getActionColor, downloadCSV } from '../utils/helpers';
import { format, subDays } from 'date-fns';

// ─── Mock data ────────────────────────────────────────────────────────────────
const ATTACK_TYPES = ['SQL Injection', 'XSS', 'DDoS', 'Port Scan', 'Brute Force', 'CSRF', 'Path Traversal', 'RCE', 'MITM', 'Ransomware'];
const RISK_LEVELS = ['critical', 'high', 'medium', 'low'];
const ACTIONS = ['block', 'allow', 'monitor', 'alert'];
const IPS = ['192.168.1.45','10.0.0.23','172.16.0.100','203.0.113.5','198.51.100.8','45.33.32.156','104.21.14.2','185.220.101.47','91.108.4.0','141.101.64.0'];

function generateMockEvents(count = 200) {
  return Array.from({ length: count }, (_, i) => ({
    id: `evt-${1000 + i}`,
    timestamp: new Date(Date.now() - Math.random() * 86400000 * 7).toISOString(),
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
  }));
}

const ALL_EVENTS = generateMockEvents(200);

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];

const s = {
  page: { padding: '28px', maxWidth: '1600px' },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' },
  title: { fontSize: '20px', fontWeight: '700', color: '#e6edf3' },
  subtitle: { fontSize: '12px', color: '#8b949e', marginTop: '2px' },
  filtersBar: {
    display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center',
    background: '#161b22', border: '1px solid #21262d', borderRadius: '10px',
    padding: '14px 16px', marginBottom: '20px',
  },
  searchWrap: {
    display: 'flex', alignItems: 'center', gap: '8px',
    background: '#0d1117', border: '1px solid #21262d', borderRadius: '6px',
    padding: '7px 12px', flex: '1 1 200px', minWidth: '180px',
  },
  searchInput: {
    background: 'none', border: 'none', outline: 'none',
    color: '#e6edf3', fontSize: '13px', width: '100%',
  },
  select: {
    background: '#0d1117', border: '1px solid #21262d', borderRadius: '6px',
    color: '#e6edf3', fontSize: '13px', padding: '7px 10px', outline: 'none',
    cursor: 'pointer', minWidth: '130px',
  },
  dateInput: {
    background: '#0d1117', border: '1px solid #21262d', borderRadius: '6px',
    color: '#e6edf3', fontSize: '12px', padding: '7px 10px', outline: 'none',
    colorScheme: 'dark',
  },
  exportBtn: {
    display: 'flex', alignItems: 'center', gap: '6px',
    background: '#161b22', border: '1px solid #21262d', borderRadius: '6px',
    color: '#8b949e', padding: '7px 14px', fontSize: '12px', cursor: 'pointer',
    transition: 'all 0.15s ease', whiteSpace: 'nowrap',
  },
  clearBtn: {
    display: 'flex', alignItems: 'center', gap: '4px',
    background: 'none', border: 'none', color: '#8b949e',
    fontSize: '12px', cursor: 'pointer', padding: '4px 8px', borderRadius: '4px',
  },
  results: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    marginBottom: '12px', fontSize: '12px', color: '#8b949e',
  },
  pagination: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    marginTop: '16px', padding: '12px 0',
  },
  pageInfo: { fontSize: '12px', color: '#8b949e' },
  pageControls: { display: 'flex', alignItems: 'center', gap: '4px' },
  pageBtn: (active, disabled) => ({
    background: active ? '#00d4ff20' : 'none',
    border: `1px solid ${active ? '#00d4ff60' : '#21262d'}`,
    borderRadius: '6px', color: active ? '#00d4ff' : disabled ? '#484f58' : '#8b949e',
    padding: '5px 10px', fontSize: '12px', cursor: disabled ? 'not-allowed' : 'pointer',
    minWidth: '32px', textAlign: 'center',
  }),
  modal: {
    position: 'fixed', inset: 0, background: '#00000088', zIndex: 1000,
    display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px',
  },
  modalInner: {
    background: '#161b22', border: '1px solid #30363d', borderRadius: '12px',
    maxWidth: '720px', width: '100%', maxHeight: '80vh', overflow: 'auto',
    boxShadow: '0 24px 80px rgba(0,0,0,0.6)',
  },
  modalHeader: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '20px 24px', borderBottom: '1px solid #21262d', position: 'sticky', top: 0,
    background: '#161b22', zIndex: 1,
  },
  modalTitle: { fontSize: '15px', fontWeight: '600', color: '#e6edf3' },
  modalClose: {
    background: 'none', border: 'none', color: '#8b949e', cursor: 'pointer', padding: '4px',
  },
  modalBody: { padding: '24px' },
  detailGrid: {
    display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '20px',
  },
  detailField: { display: 'flex', flexDirection: 'column', gap: '4px' },
  detailLabel: {
    fontSize: '10px', color: '#8b949e', textTransform: 'uppercase',
    letterSpacing: '0.7px', fontWeight: '500',
  },
  detailValue: {
    fontSize: '13px', color: '#e6edf3', fontFamily: "'JetBrains Mono', monospace",
    wordBreak: 'break-all',
  },
};

export default function EventsPage() {
  const [allEvents, setAllEvents] = useState(ALL_EVENTS);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [selectedEvent, setSelectedEvent] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const params = {};
      if (riskFilter) params.risk_level = riskFilter;
      if (typeFilter) params.attack_type = typeFilter;
      if (dateFrom) params.from = dateFrom;
      if (dateTo) params.to = dateTo;
      const res = await getEvents(params);
      setAllEvents(res?.data || res || []);
    } catch {
      // Keep mock data
    } finally {
      setLoading(false);
    }
  }, [riskFilter, typeFilter, dateFrom, dateTo]);

  useEffect(() => { loadData(); }, [loadData]);

  const filtered = allEvents.filter((e) => {
    const q = search.toLowerCase();
    if (q && ![e.src_ip, e.dst_ip, e.attack_type, e.risk_level, e.action].some((v) => String(v || '').toLowerCase().includes(q))) return false;
    if (riskFilter && e.risk_level !== riskFilter) return false;
    if (typeFilter && e.attack_type !== typeFilter) return false;
    if (actionFilter && e.action !== actionFilter) return false;
    if (dateFrom && new Date(e.timestamp) < new Date(dateFrom)) return false;
    if (dateTo && new Date(e.timestamp) > new Date(dateTo + 'T23:59:59')) return false;
    return true;
  });

  const totalPages = Math.ceil(filtered.length / pageSize);
  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);

  const attackTypes = [...new Set(allEvents.map((e) => e.attack_type).filter(Boolean))].sort();

  const clearFilters = () => {
    setSearch(''); setRiskFilter(''); setTypeFilter(''); setActionFilter(''); setDateFrom(''); setDateTo('');
    setPage(1);
  };

  const hasFilters = search || riskFilter || typeFilter || actionFilter || dateFrom || dateTo;

  const handleExport = () => {
    downloadCSV(filtered, `security-events-${format(new Date(), 'yyyy-MM-dd')}.csv`);
  };

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <div style={s.title}>Security Events</div>
          <div style={s.subtitle}>Complete audit log of all detected threats and traffic events</div>
        </div>
        <button
          style={s.exportBtn}
          onClick={handleExport}
          onMouseEnter={(e) => { e.currentTarget.style.color = '#00cc66'; e.currentTarget.style.borderColor = '#00cc6640'; }}
          onMouseLeave={(e) => { e.currentTarget.style.color = '#8b949e'; e.currentTarget.style.borderColor = '#21262d'; }}
        >
          <Download size={13} />
          Export CSV
        </button>
      </div>

      {/* Filters */}
      <div style={s.filtersBar}>
        <div style={s.searchWrap}>
          <Search size={14} color="#484f58" />
          <input
            style={s.searchInput}
            placeholder="Search by IP, attack type, action…"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          />
          {search && (
            <button style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#484f58', display: 'flex' }} onClick={() => setSearch('')}>
              <X size={12} />
            </button>
          )}
        </div>

        <select style={s.select} value={riskFilter} onChange={(e) => { setRiskFilter(e.target.value); setPage(1); }}>
          <option value="">All Risk Levels</option>
          {RISK_LEVELS.map((r) => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
        </select>

        <select style={s.select} value={typeFilter} onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}>
          <option value="">All Attack Types</option>
          {attackTypes.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>

        <select style={s.select} value={actionFilter} onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}>
          <option value="">All Actions</option>
          {ACTIONS.map((a) => <option key={a} value={a}>{a.charAt(0).toUpperCase() + a.slice(1)}</option>)}
        </select>

        <input type="date" style={s.dateInput} value={dateFrom} onChange={(e) => { setDateFrom(e.target.value); setPage(1); }} title="From date" />
        <input type="date" style={s.dateInput} value={dateTo} onChange={(e) => { setDateTo(e.target.value); setPage(1); }} title="To date" />

        {hasFilters && (
          <button style={s.clearBtn} onClick={clearFilters}>
            <X size={12} /> Clear
          </button>
        )}
      </div>

      {/* Results count + page size */}
      <div style={s.results}>
        <span>
          Showing <strong style={{ color: '#e6edf3' }}>{filtered.length.toLocaleString()}</strong> events
          {hasFilters && ' (filtered)'}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>Rows per page:</span>
          <select
            style={{ ...s.select, minWidth: '70px' }}
            value={pageSize}
            onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}
          >
            {PAGE_SIZE_OPTIONS.map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </div>
      </div>

      <ThreatTable events={paginated} loading={loading} />

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={s.pagination}>
          <span style={s.pageInfo}>
            Page {page} of {totalPages}
          </span>
          <div style={s.pageControls}>
            <button
              style={s.pageBtn(false, page === 1)}
              onClick={() => setPage(1)}
              disabled={page === 1}
            >«</button>
            <button
              style={s.pageBtn(false, page === 1)}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              <ChevronLeft size={14} />
            </button>
            {Array.from({ length: Math.min(7, totalPages) }, (_, i) => {
              let p;
              if (totalPages <= 7) p = i + 1;
              else if (page <= 4) p = i + 1;
              else if (page >= totalPages - 3) p = totalPages - 6 + i;
              else p = page - 3 + i;
              return (
                <button
                  key={p}
                  style={s.pageBtn(page === p, false)}
                  onClick={() => setPage(p)}
                >
                  {p}
                </button>
              );
            })}
            <button
              style={s.pageBtn(false, page === totalPages)}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
            >
              <ChevronRight size={14} />
            </button>
            <button
              style={s.pageBtn(false, page === totalPages)}
              onClick={() => setPage(totalPages)}
              disabled={page === totalPages}
            >»</button>
          </div>
        </div>
      )}
    </div>
  );
}
