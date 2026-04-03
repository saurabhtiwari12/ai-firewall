import React, { useEffect, useRef } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line } from 'react-chartjs-2';
import { formatDate } from '../utils/helpers';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 400 },
  interaction: {
    mode: 'index',
    intersect: false,
  },
  plugins: {
    legend: {
      display: true,
      position: 'top',
      align: 'end',
      labels: {
        color: '#8b949e',
        boxWidth: 12,
        boxHeight: 2,
        font: { size: 11, family: 'Inter, sans-serif' },
        padding: 16,
        usePointStyle: true,
        pointStyle: 'line',
      },
    },
    tooltip: {
      backgroundColor: '#161b22',
      titleColor: '#e6edf3',
      bodyColor: '#8b949e',
      borderColor: '#30363d',
      borderWidth: 1,
      padding: 12,
      titleFont: { size: 12, family: 'Inter, sans-serif', weight: '600' },
      bodyFont: { size: 11, family: 'JetBrains Mono, monospace' },
      callbacks: {
        label: (ctx) => ` ${ctx.dataset.label}: ${ctx.parsed.y.toLocaleString()}`,
      },
    },
  },
  scales: {
    x: {
      grid: { color: '#21262d', drawBorder: false },
      ticks: {
        color: '#484f58',
        font: { size: 10, family: 'Inter, sans-serif' },
        maxTicksLimit: 12,
        maxRotation: 0,
      },
    },
    y: {
      grid: { color: '#21262d', drawBorder: false },
      ticks: {
        color: '#484f58',
        font: { size: 10, family: 'Inter, sans-serif' },
        callback: (v) => (v >= 1000 ? `${(v / 1000).toFixed(0)}K` : v),
      },
      beginAtZero: true,
    },
  },
};

export default function TrafficChart({ data, height = 260, title }) {
  const labels = data?.labels || [];
  const datasets = data?.datasets || [];

  const chartData = {
    labels,
    datasets: datasets.map((ds, i) => ({
      label: ds.label || `Series ${i + 1}`,
      data: ds.data || [],
      borderColor: ds.color || '#00d4ff',
      backgroundColor: ds.fill !== false
        ? `${ds.color || '#00d4ff'}18`
        : 'transparent',
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 4,
      pointHoverBackgroundColor: ds.color || '#00d4ff',
      tension: 0.4,
      fill: ds.fill !== false,
    })),
  };

  const options = {
    ...CHART_DEFAULTS,
    plugins: {
      ...CHART_DEFAULTS.plugins,
      title: title
        ? {
            display: true,
            text: title,
            color: '#8b949e',
            font: { size: 12, family: 'Inter, sans-serif', weight: '500' },
            padding: { bottom: 16 },
          }
        : { display: false },
    },
  };

  return (
    <div style={{ height, width: '100%', position: 'relative' }}>
      <Line data={chartData} options={options} />
    </div>
  );
}
