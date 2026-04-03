import React, { useState } from 'react';
import { ChevronUp, ChevronDown, ChevronRight, Shield, ExternalLink } from 'lucide-react';
import { formatDate, getRiskColor, getRiskBgColor, getActionColor, getThreatScoreColor } from '../utils/helpers';

const COLUMNS = [
  { key: 'timestamp',    label: 'Timestamp',     sortable: true,  width: '160px' },
  { key: 'src_ip',       label: 'Source IP',     sortable: true,  width: '130px' },
  { key: 'dst_ip',       label: 'Destination',   sortable: true,  width: '130px' },
  { key: 'attack_type',  label: 'Attack Type',   sortable: true,  width: '150px' },
  { key: 'threat_score', label: 'Threat Score',  sortable: true,  width: '110px' },
  { key: 'risk_level',   label: 'Risk',          sortable: true,  width: '90px'  },
  { key: 'action',       label: 'Action',        sortable: true,  width: '90px'  },
  { key: '_expand',      label: '',              sortable: false, width: '40px'  },
];

const s = {
  wrapper: {
    background: '#161b22',
    border: '1px solid #21262d',
    borderRadius: '10px',
    overflow: 'hidden',
  },
  tableWrap: {
    overflowX: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: '13px',
  },
  thead: {
    background: '#0d1117',
    position: 'sticky',
    top: 0,
    zIndex: 1,
  },
  th: (sortable) => ({
    padding: '12px 14px',
    textAlign: 'left',
    fontSize: '11px',
    fontWeight: '600',
    color: '#8b949e',
    textTransform: 'uppercase',
    letterSpacing: '0.7px',
    borderBottom: '1px solid #21262d',
    whiteSpace: 'nowrap',
    cursor: sortable ? 'pointer' : 'default',
    userSelect: 'none',
  }),
  thInner: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  },
  tr: (expanded) => ({
    borderBottom: '1px solid #21262d',
    cursor: 'pointer',
    background: expanded ? '#0d1117' : 'transparent',
    transition: 'background 0.1s ease',
  }),
  td: {
    padding: '11px 14px',
    color: '#e6edf3',
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '12px',
    whiteSpace: 'nowrap',
  },
  riskBadge: (level) => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: '600',
    fontFamily: 'Inter, sans-serif',
    color: getRiskColor(level),
    background: getRiskBgColor(level),
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  }),
  actionBadge: (action) => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: '600',
    fontFamily: 'Inter, sans-serif',
    color: getActionColor(action),
    background: `${getActionColor(action)}22`,
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  }),
  scoreBar: (score) => ({
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  }),
  scoreBarTrack: {
    flex: 1,
    height: '4px',
    background: '#21262d',
    borderRadius: '2px',
    overflow: 'hidden',
    minWidth: '40px',
  },
  scoreBarFill: (score) => ({
    height: '100%',
    width: `${(score * 100).toFixed(0)}%`,
    background: getThreatScoreColor(score),
    borderRadius: '2px',
    transition: 'width 0.3s ease',
  }),
  expandRow: {
    background: '#0d1117',
    borderBottom: '1px solid #21262d',
  },
  expandContent: {
    padding: '16px 20px',
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
    gap: '16px',
  },
  expandField: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
  },
  expandLabel: {
    fontSize: '10px',
    color: '#8b949e',
    textTransform: 'uppercase',
    letterSpacing: '0.7px',
    fontWeight: '500',
  },
  expandValue: {
    fontSize: '13px',
    color: '#e6edf3',
    fontFamily: "'JetBrains Mono', monospace",
    wordBreak: 'break-all',
  },
  emptyRow: {
    textAlign: 'center',
    padding: '48px 0',
    color: '#484f58',
  },
  emptyIcon: {
    marginBottom: '12px',
    opacity: 0.4,
  },
};

function ThreatScore({ score }) {
  const pct = ((score || 0) * 100).toFixed(0);
  return (
    <div style={s.scoreBar()}>
      <span style={{ color: getThreatScoreColor(score), minWidth: '34px' }}>{pct}%</span>
      <div style={s.scoreBarTrack}>
        <div style={s.scoreBarFill(score || 0)} />
      </div>
    </div>
  );
}

function ExpandedRow({ event }) {
  const fields = [
    { label: 'Event ID',       value: event.id || event._id },
    { label: 'Protocol',       value: event.protocol },
    { label: 'Port',           value: event.dst_port || event.port },
    { label: 'Country',        value: event.country || event.src_country },
    { label: 'ASN',            value: event.asn },
    { label: 'User Agent',     value: event.user_agent },
    { label: 'Payload Size',   value: event.payload_size ? `${event.payload_size} bytes` : null },
    { label: 'Duration (ms)',  value: event.duration_ms },
    { label: 'ML Model',       value: event.ml_model },
    { label: 'Confidence',     value: event.confidence ? `${(event.confidence * 100).toFixed(1)}%` : null },
    { label: 'Rule ID',        value: event.rule_id },
    { label: 'Notes',          value: event.notes },
  ].filter((f) => f.value != null);

  return (
    <div style={s.expandContent}>
      {fields.map((f) => (
        <div key={f.label} style={s.expandField}>
          <span style={s.expandLabel}>{f.label}</span>
          <span style={s.expandValue}>{String(f.value)}</span>
        </div>
      ))}
    </div>
  );
}

export default function ThreatTable({ events = [], loading = false, compact = false }) {
  const [sortKey, setSortKey] = useState('timestamp');
  const [sortDir, setSortDir] = useState('desc');
  const [expandedId, setExpandedId] = useState(null);

  const handleSort = (key) => {
    if (!key) return;
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  };

  const sorted = [...events].sort((a, b) => {
    let av = a[sortKey];
    let bv = b[sortKey];
    if (av == null) return 1;
    if (bv == null) return -1;
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    if (av < bv) return sortDir === 'asc' ? -1 : 1;
    if (av > bv) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  const visibleColumns = compact
    ? COLUMNS.filter((c) => ['timestamp', 'src_ip', 'attack_type', 'risk_level', 'action', '_expand'].includes(c.key))
    : COLUMNS;

  return (
    <div style={s.wrapper}>
      <div style={s.tableWrap}>
        <table style={s.table}>
          <thead style={s.thead}>
            <tr>
              {visibleColumns.map((col) => (
                <th
                  key={col.key}
                  style={{ ...s.th(col.sortable), width: col.width }}
                  onClick={() => col.sortable && handleSort(col.key)}
                >
                  <div style={s.thInner}>
                    {col.label}
                    {col.sortable && sortKey === col.key && (
                      sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #21262d' }}>
                  {visibleColumns.map((col) => (
                    <td key={col.key} style={s.td}>
                      <div
                        style={{
                          height: '14px',
                          width: '80%',
                          background: 'linear-gradient(90deg, #21262d 25%, #2d333b 50%, #21262d 75%)',
                          backgroundSize: '200% 100%',
                          animation: 'shimmer 1.5s infinite',
                          borderRadius: '3px',
                        }}
                      />
                    </td>
                  ))}
                </tr>
              ))
            ) : sorted.length === 0 ? (
              <tr>
                <td colSpan={visibleColumns.length} style={s.td}>
                  <div style={s.emptyRow}>
                    <div style={s.emptyIcon}><Shield size={40} /></div>
                    <div style={{ fontFamily: 'Inter, sans-serif', fontSize: '14px' }}>No security events found</div>
                  </div>
                </td>
              </tr>
            ) : (
              sorted.map((event) => {
                const id = event.id || event._id || event.timestamp;
                const isExpanded = expandedId === id;
                return (
                  <React.Fragment key={id}>
                    <tr
                      style={s.tr(isExpanded)}
                      onClick={() => setExpandedId(isExpanded ? null : id)}
                      onMouseEnter={(e) => { if (!isExpanded) e.currentTarget.style.background = '#1c2230'; }}
                      onMouseLeave={(e) => { if (!isExpanded) e.currentTarget.style.background = 'transparent'; }}
                    >
                      {(!compact || visibleColumns.find(c => c.key === 'timestamp')) && (
                        <td style={{ ...s.td, color: '#8b949e', fontSize: '11px' }}>
                          {formatDate(event.timestamp, 'MM/dd HH:mm:ss')}
                        </td>
                      )}
                      <td style={s.td}>{event.src_ip || '—'}</td>
                      {!compact && <td style={{ ...s.td, color: '#8b949e' }}>{event.dst_ip || '—'}</td>}
                      <td style={{ ...s.td, color: '#e6edf3', fontFamily: 'Inter, sans-serif' }}>
                        {event.attack_type || '—'}
                      </td>
                      {!compact && (
                        <td style={s.td}>
                          <ThreatScore score={event.threat_score} />
                        </td>
                      )}
                      <td style={s.td}>
                        <span style={s.riskBadge(event.risk_level)}>
                          {event.risk_level || '—'}
                        </span>
                      </td>
                      <td style={s.td}>
                        <span style={s.actionBadge(event.action)}>
                          {event.action || '—'}
                        </span>
                      </td>
                      <td style={{ ...s.td, color: '#484f58' }}>
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr style={s.expandRow}>
                        <td colSpan={visibleColumns.length} style={{ padding: 0 }}>
                          <ExpandedRow event={event} />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      <style>{`@keyframes shimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }`}</style>
    </div>
  );
}
