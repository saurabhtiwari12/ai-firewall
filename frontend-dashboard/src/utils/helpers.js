import { format, formatDistanceToNow, parseISO } from 'date-fns';

export const formatDate = (dateStr, fmt = 'MMM dd, yyyy HH:mm:ss') => {
  if (!dateStr) return '—';
  try {
    const d = typeof dateStr === 'string' ? parseISO(dateStr) : new Date(dateStr);
    return format(d, fmt);
  } catch {
    return String(dateStr);
  }
};

export const formatDateRelative = (dateStr) => {
  if (!dateStr) return '—';
  try {
    const d = typeof dateStr === 'string' ? parseISO(dateStr) : new Date(dateStr);
    return formatDistanceToNow(d, { addSuffix: true });
  } catch {
    return String(dateStr);
  }
};

export const formatBytes = (bytes, decimals = 2) => {
  if (bytes == null || isNaN(bytes)) return '—';
  if (bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
};

export const formatNumber = (n) => {
  if (n == null || isNaN(n)) return '—';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
};

export const capitalize = (str) => {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
};

export const getRiskColor = (riskLevel) => {
  switch (String(riskLevel).toLowerCase()) {
    case 'critical': return '#ff4444';
    case 'high':     return '#ff6b35';
    case 'medium':   return '#ffaa00';
    case 'low':      return '#00cc66';
    case 'info':     return '#4488ff';
    default:         return '#8b949e';
  }
};

export const getRiskBgColor = (riskLevel) => {
  switch (String(riskLevel).toLowerCase()) {
    case 'critical': return '#ff444422';
    case 'high':     return '#ff6b3522';
    case 'medium':   return '#ffaa0022';
    case 'low':      return '#00cc6622';
    case 'info':     return '#4488ff22';
    default:         return '#8b949e22';
  }
};

export const getSeverityColor = (severity) => {
  switch (String(severity).toLowerCase()) {
    case 'critical': return '#ff4444';
    case 'high':     return '#ff6b35';
    case 'warning':
    case 'medium':   return '#ffaa00';
    case 'info':
    case 'low':      return '#4488ff';
    default:         return '#8b949e';
  }
};

export const getThreatScoreColor = (score) => {
  if (score >= 0.8) return '#ff4444';
  if (score >= 0.6) return '#ff6b35';
  if (score >= 0.4) return '#ffaa00';
  if (score >= 0.2) return '#4488ff';
  return '#00cc66';
};

export const downloadCSV = (data, filename = 'export.csv') => {
  if (!data || !data.length) return;
  const headers = Object.keys(data[0]);
  const rows = data.map((row) =>
    headers.map((h) => {
      const val = row[h] == null ? '' : String(row[h]);
      return val.includes(',') || val.includes('"') ? `"${val.replace(/"/g, '""')}"` : val;
    }).join(',')
  );
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

export const truncateIP = (ip) => ip || '—';

export const getActionColor = (action) => {
  switch (String(action).toLowerCase()) {
    case 'block':   return '#ff4444';
    case 'allow':   return '#00cc66';
    case 'monitor': return '#ffaa00';
    case 'alert':   return '#4488ff';
    default:        return '#8b949e';
  }
};
