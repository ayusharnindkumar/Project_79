/**
 * charts.js — Chart.js Visualization Manager
 * ==========================================
 * Manages all Chart.js v4 charts in the dashboard:
 *   1. trafficChart  — live packet rate line chart with attack annotations
 *   2. modelChart    — grouped bar chart comparing 3 edge models
 *   3. featureChart  — radar chart of top-8 feature importances
 *   4. donutChart    — traffic composition doughnut
 */

'use strict';

const Charts = (() => {

  // ── Shared theme ──────────────────────────────────────────────────────────
  const THEME = {
    bg:        '#060d1a',
    panel:     '#0d1628',
    cyan:      '#00d4ff',
    green:     '#00ff88',
    red:       '#ff3d3d',
    orange:    '#ff6b35',
    gold:      '#ffd700',
    purple:    '#bf5fff',
    text:      '#8aa0c0',
    textLight: '#ccd6f6',
    grid:      'rgba(30, 48, 80, 0.7)',
  };

  const ATTACK_COLORS = [THEME.green, THEME.red, THEME.orange, THEME.gold, THEME.purple];

  Chart.defaults.color             = THEME.text;
  Chart.defaults.font.family       = "'JetBrains Mono', monospace";
  Chart.defaults.font.size         = 11;
  Chart.defaults.borderColor       = THEME.grid;
  Chart.defaults.plugins.legend.labels.boxWidth = 12;

  // ── Traffic Line Chart ────────────────────────────────────────────────────
  const MAX_TRAFFIC_POINTS = 60;
  let trafficChart = null;
  let trafficLabels = [];
  let normalData   = [];
  let attackData   = [];

  function initTrafficChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');

    // Pre-fill with zeros
    for (let i = MAX_TRAFFIC_POINTS; i > 0; i--) {
      trafficLabels.push('');
      normalData.push(null);
      attackData.push(null);
    }

    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
    gradient.addColorStop(0,   'rgba(0, 212, 255, 0.3)');
    gradient.addColorStop(1,   'rgba(0, 212, 255, 0.0)');

    const attackGrad = ctx.createLinearGradient(0, 0, 0, 300);
    attackGrad.addColorStop(0, 'rgba(255, 61, 61, 0.4)');
    attackGrad.addColorStop(1, 'rgba(255, 61, 61, 0.0)');

    trafficChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: trafficLabels,
        datasets: [
          {
            label: 'Normal Traffic',
            data: normalData,
            borderColor:     THEME.cyan,
            backgroundColor: gradient,
            borderWidth: 2,
            pointRadius: 0,
            fill: true,
            tension: 0.4,
          },
          {
            label: 'Attack Traffic',
            data: attackData,
            borderColor:     THEME.red,
            backgroundColor: attackGrad,
            borderWidth: 2.5,
            pointRadius: 0,
            fill: true,
            tension: 0.4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 0 },
        interaction: { intersect: false, mode: 'index' },
        plugins: {
          legend: {
            position: 'top',
            align: 'end',
            labels: { color: THEME.textLight, padding: 16 },
          },
          tooltip: {
            backgroundColor: 'rgba(13, 22, 40, 0.95)',
            borderColor:      THEME.cyan,
            borderWidth: 1,
            callbacks: {
              label: (ctx) => ` ${ctx.dataset.label}: ${ctx.parsed.y?.toLocaleString() ?? 0} pkt/s`,
            },
          },
        },
        scales: {
          x: {
            display: false,
            grid: { display: false },
          },
          y: {
            beginAtZero: true,
            grid: { color: THEME.grid },
            ticks: {
              color: THEME.text,
              callback: (v) => v >= 1000 ? `${(v/1000).toFixed(1)}K` : v,
            },
            title: { display: true, text: 'Packets / sec', color: THEME.text },
          },
        },
      },
    });
  }

  function updateTrafficChart(normalPkts, attackPkts) {
    const now = new Date().toLocaleTimeString('en-US', { hour12: false });
    trafficLabels.push(now);
    normalData.push(normalPkts);
    attackData.push(attackPkts);

    if (trafficLabels.length > MAX_TRAFFIC_POINTS) {
      trafficLabels.shift();
      normalData.shift();
      attackData.shift();
    }
    trafficChart.update('none');
  }

  // ── Model Comparison Bar Chart ────────────────────────────────────────────
  let modelChart = null;

  const MODEL_METRICS = {
    'Random Forest': { accuracy: 98.7, f1: 97.3, latency: 1.2, size: 842 },
    'Decision Tree': { accuracy: 94.2, f1: 93.1, latency: 0.3, size: 2.1 },
    'Iso. Forest':   { accuracy: 88.5, f1: 87.2, latency: 0.8, size: 214 },
  };

  function initModelChart() {
    const ctx = document.getElementById('modelChart').getContext('2d');
    const labels = Object.keys(MODEL_METRICS);

    modelChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Accuracy (%)',
            data: labels.map(m => MODEL_METRICS[m].accuracy),
            backgroundColor: 'rgba(0, 212, 255, 0.75)',
            borderColor:     THEME.cyan,
            borderWidth: 1,
            borderRadius: 4,
          },
          {
            label: 'F1 Score (%)',
            data: labels.map(m => MODEL_METRICS[m].f1),
            backgroundColor: 'rgba(0, 255, 136, 0.75)',
            borderColor:     THEME.green,
            borderWidth: 1,
            borderRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: { color: THEME.textLight, padding: 12 },
          },
          tooltip: {
            backgroundColor: 'rgba(13, 22, 40, 0.95)',
            borderColor: THEME.cyan,
            borderWidth: 1,
          },
        },
        scales: {
          y: {
            min: 80,
            max: 100,
            grid: { color: THEME.grid },
            ticks: { color: THEME.text, callback: v => `${v}%` },
          },
          x: {
            grid: { display: false },
            ticks: { color: THEME.textLight },
          },
        },
      },
    });
  }

  // ── Feature Importance Radar ──────────────────────────────────────────────
  let featureChart = null;

  // From Random Forest training — top 8 features by importance
  const FEATURE_IMPORTANCE = {
    'packet_rate':    0.28,
    'syn_ratio':      0.22,
    'byte_rate':      0.16,
    'is_icmp':        0.10,
    'avg_pkt_size':   0.08,
    'entropy':        0.07,
    'inter_arrival':  0.05,
    'dst_port_div':   0.04,
  };

  function initFeatureChart() {
    const ctx = document.getElementById('featureChart').getContext('2d');
    const labels = Object.keys(FEATURE_IMPORTANCE);
    const values = Object.values(FEATURE_IMPORTANCE).map(v => +(v * 100).toFixed(1));

    featureChart = new Chart(ctx, {
      type: 'radar',
      data: {
        labels,
        datasets: [{
          label: 'RF Feature Importance',
          data: values,
          borderColor:       THEME.cyan,
          backgroundColor:   'rgba(0, 212, 255, 0.12)',
          pointBackgroundColor: THEME.cyan,
          pointBorderColor:  '#fff',
          pointRadius: 4,
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(13, 22, 40, 0.95)',
            borderColor: THEME.cyan,
            borderWidth: 1,
            callbacks: { label: ctx => ` ${ctx.parsed.r.toFixed(1)}% importance` },
          },
        },
        scales: {
          r: {
            beginAtZero: true,
            max: 30,
            grid:      { color: 'rgba(30, 48, 80, 0.8)' },
            angleLines: { color: 'rgba(30, 48, 80, 0.8)' },
            pointLabels: { color: THEME.textLight, font: { size: 10 } },
            ticks: { display: false },
          },
        },
      },
    });
  }

  // ── Traffic Composition Doughnut ─────────────────────────────────────────
  let donutChart = null;

  function initDonutChart() {
    const ctx = document.getElementById('trafficDonut').getContext('2d');
    donutChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Normal', 'SYN Flood', 'UDP Flood', 'HTTP Flood', 'Smurf'],
        datasets: [{
          data: [100, 0, 0, 0, 0],
          backgroundColor: ATTACK_COLORS.map(c => c + 'cc'),
          borderColor:     ATTACK_COLORS,
          borderWidth: 1.5,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color:    THEME.textLight,
              padding:  8,
              boxWidth: 10,
              font: { size: 10 },
            },
          },
          tooltip: {
            backgroundColor: 'rgba(13, 22, 40, 0.95)',
            borderColor: THEME.cyan,
            borderWidth: 1,
            callbacks: {
              label: ctx => ` ${ctx.label}: ${ctx.parsed.toFixed(1)}%`,
            },
          },
        },
      },
    });
  }

  function updateDonutChart(counts) {
    const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
    const data = [
      (counts.normal / total) * 100,
      (counts.syn    / total) * 100,
      (counts.udp    / total) * 100,
      (counts.http   / total) * 100,
      (counts.smurf  / total) * 100,
    ];
    donutChart.data.datasets[0].data = data;
    donutChart.update('none');
  }

  // ── Init all ──────────────────────────────────────────────────────────────
  function initAll() {
    initTrafficChart();
    initModelChart();
    initFeatureChart();
    initDonutChart();
  }

  return {
    initAll,
    updateTrafficChart,
    updateDonutChart,
  };

})();

window.Charts = Charts;
