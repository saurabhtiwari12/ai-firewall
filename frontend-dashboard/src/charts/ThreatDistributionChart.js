import React from 'react';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

const PALETTE = [
  '#ff4444',
  '#ffaa00',
  '#00d4ff',
  '#a855f7',
  '#00cc66',
  '#ff6b35',
  '#4488ff',
  '#f472b6',
  '#34d399',
  '#fbbf24',
];

export default function ThreatDistributionChart({ data, height = 260 }) {
  const labels = data?.labels || [];
  const values = data?.values || [];

  const chartData = {
    labels,
    datasets: [
      {
        data: values,
        backgroundColor: PALETTE.slice(0, labels.length).map((c) => `${c}cc`),
        borderColor: PALETTE.slice(0, labels.length),
        borderWidth: 2,
        hoverOffset: 6,
        hoverBorderWidth: 3,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 500 },
    cutout: '62%',
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#8b949e',
          boxWidth: 12,
          boxHeight: 12,
          font: { size: 11, family: 'Inter, sans-serif' },
          padding: 12,
          usePointStyle: true,
          pointStyle: 'rectRounded',
        },
      },
      tooltip: {
        backgroundColor: '#161b22',
        titleColor: '#e6edf3',
        bodyColor: '#8b949e',
        borderColor: '#30363d',
        borderWidth: 1,
        padding: 12,
        callbacks: {
          label: (ctx) => {
            const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
            const pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
            return ` ${ctx.label}: ${ctx.parsed.toLocaleString()} (${pct}%)`;
          },
        },
      },
    },
  };

  const total = values.reduce((a, b) => a + b, 0);

  return (
    <div style={{ height, width: '100%', position: 'relative' }}>
      {total === 0 ? (
        <div
          style={{
            height: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#484f58',
            fontSize: '13px',
          }}
        >
          No data available
        </div>
      ) : (
        <Doughnut data={chartData} options={options} />
      )}
    </div>
  );
}
