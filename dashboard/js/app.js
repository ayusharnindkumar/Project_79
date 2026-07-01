/**
 * app.js — EdgeGuard AI Dashboard Orchestrator
 * =============================================
 * Initializes all subsystems, handles UI events, and wires together
 * the traffic simulator → edge ML inference → chart/DOM updates pipeline.
 */

'use strict';

const App = (() => {

  // ── State ──────────────────────────────────────────────────────────────────
  let alertCount    = 0;
  let attacksBlocked = 0;
  let currentMode   = 'normal';
  let threatLevel   = 0;   // 0-100
  let animFrameId   = null;
  let totalPkts     = 0;
  let uptimeSeconds = 0;
  let uptimeInterval = null;

  // Smoothed metrics (exponential moving average)
  let smoothedNormal = 0;
  let smoothedAttack = 0;
  const EMA_ALPHA    = 0.3;

  // ── DOM refs ───────────────────────────────────────────────────────────────
  const $  = id => document.getElementById(id);
  const $$ = sel => document.querySelectorAll(sel);

  const dom = {
    systemStatus:   'systemStatus',
    uptimeDisplay:  'uptimeDisplay',
    totalPackets:   'totalPackets',
    attacksBlocked: 'attacksBlocked',
    gaugeArc:       'gaugeArc',
    gaugeNeedle:    'gaugeNeedle',
    gaugeValue:     'gaugeValue',
    gaugeLabel:     'gaugeLabel',
    gaugePanel:     'gaugePanel',
    trafficRate:    'trafficRate',
    alertFeed:      'alertFeed',
    alertCount:     'alertCount',
    detectorPanel:  'detectorPanel',
    detectedType:   'detectedType',
    confidenceFill: 'confidenceFill',
    confidenceValue:'confidenceValue',
    detectorFeatures: 'detectorFeatures',
    cpuBar: 'cpuBar', cpuValue: 'cpuValue',
    memBar: 'memBar', memValue: 'memValue',
    netBar: 'netBar', netValue: 'netValue',
    infBar: 'infBar', infValue: 'infValue',
    countSyn:  'countSyn',  progressSyn:  'progressSyn',
    countUdp:  'countUdp',  progressUdp:  'progressUdp',
    countHttp: 'countHttp', progressHttp: 'progressHttp',
    countSmurf:'countSmurf',progressSmurf:'progressSmurf',
  };

  // ── Gauge helpers ──────────────────────────────────────────────────────────
  const GAUGE_ARC_LEN = 251.3; // π × r × (180°/360° for semicircle) ≈ π×80≈251

  function setGauge(level) {
    // level: 0-100
    const filled = (level / 100) * GAUGE_ARC_LEN;
    const empty  = GAUGE_ARC_LEN - filled;
    $(dom.gaugeArc).setAttribute('stroke-dasharray', `${filled} ${empty}`);

    // Needle: -90° (far left) to +90° (far right), mapped from 0-100
    const angle = -90 + (level / 100) * 180;
    $(dom.gaugeNeedle).setAttribute('transform', `rotate(${angle}, 100, 100)`);

    $(dom.gaugeValue).textContent = `${Math.round(level)}%`;

    let label, cls;
    if (level < 30) {
      label = 'SAFE';    cls = 'safe';
    } else if (level < 65) {
      label = 'WARNING'; cls = 'warning';
    } else {
      label = 'CRITICAL'; cls = 'critical';
    }
    $(dom.gaugeLabel).textContent = label;
    $(dom.gaugeLabel).className   = `gauge-label ${cls}`;

    // Panel glow
    const panel = $(dom.gaugePanel);
    panel.classList.toggle('attack-glow',   level >= 65);
    panel.classList.toggle('warning-glow',  level >= 30 && level < 65);
    panel.classList.remove('safe-glow');
    if (level < 30) panel.classList.add('safe-glow');
  }

  // ── System status ─────────────────────────────────────────────────────────
  function setSystemStatus(mode) {
    const el = $(dom.systemStatus);
    const map = {
      normal: { text: '● SYSTEM NOMINAL',  cls: 'status-ok'       },
      syn:    { text: '⚡ SYN FLOOD DETECTED',  cls: 'status-attack'  },
      udp:    { text: '📡 UDP FLOOD DETECTED',  cls: 'status-attack'  },
      http:   { text: '🌐 HTTP FLOOD DETECTED', cls: 'status-warning' },
      smurf:  { text: '💀 SMURF ATTACK DETECTED', cls: 'status-attack' },
    };
    const s = map[mode] || map.normal;
    el.textContent  = s.text;
    el.className    = `system-status ${s.cls}`;
  }

  // ── Alert feed ────────────────────────────────────────────────────────────
  function addAlert(result, srcIP) {
    if (!result.isAttack) return;

    alertCount++;
    attacksBlocked++;
    $(dom.alertCount).textContent   = alertCount;
    $(dom.attacksBlocked).textContent = attacksBlocked.toLocaleString();

    const feed = $(dom.alertFeed);

    // Remove empty state
    const empty = feed.querySelector('.alert-empty');
    if (empty) empty.remove();

    const severity = result.severity;
    const severityClass = severity >= 3 ? 'alert-critical' : 'alert-warning';
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });

    const item = document.createElement('div');
    item.className = `alert-item ${severityClass} alert-enter`;
    item.innerHTML = `
      <div class="alert-header">
        <span class="alert-icon">${result.icon}</span>
        <span class="alert-type">${result.type}</span>
        <span class="alert-time">${time}</span>
      </div>
      <div class="alert-detail">
        <span class="alert-src">SRC: ${srcIP}</span>
        <span class="alert-conf">${(result.confidence * 100).toFixed(1)}% confidence</span>
      </div>`;

    feed.prepend(item);

    // Trigger CSS enter animation
    requestAnimationFrame(() => item.classList.remove('alert-enter'));

    // Keep max 30 alerts
    const items = feed.querySelectorAll('.alert-item');
    if (items.length > 30) items[items.length - 1].remove();
  }

  // ── Attack detector panel ─────────────────────────────────────────────────
  function updateDetector(latestResult, counts) {
    const panel = $(dom.detectorPanel);
    const typeEl = $(dom.detectedType);
    const fillEl = $(dom.confidenceFill);
    const confEl = $(dom.confidenceValue);

    typeEl.textContent = latestResult.type.toUpperCase();
    typeEl.style.color = latestResult.color;

    const conf = latestResult.confidence * 100;
    fillEl.style.width       = `${conf}%`;
    fillEl.style.background  = latestResult.color;
    confEl.textContent       = `${conf.toFixed(1)}%`;

    panel.classList.toggle('panel-attack', latestResult.isAttack);

    // Feature bar visualization (top 5 features)
    const topFeatures = [
      { name: 'Packet Rate',   value: Math.min(1, latestResult.probabilities[latestResult.label] * 1.1) },
      { name: 'SYN Ratio',     value: latestResult.label === 1 ? 0.92 : 0.12 },
      { name: 'Entropy',       value: latestResult.label === 2 ? 0.95 : 0.45 },
      { name: 'Avg Pkt Size',  value: latestResult.label === 4 ? 0.88 : 0.35 },
      { name: 'Flow Duration', value: latestResult.label === 3 ? 0.75 : 0.50 },
    ];

    const featEl = $(dom.detectorFeatures);
    featEl.innerHTML = topFeatures.map(f => `
      <div class="feat-row">
        <span class="feat-name">${f.name}</span>
        <div class="feat-bar-wrap">
          <div class="feat-bar" style="width:${(f.value*100).toFixed(0)}%;background:${latestResult.color}44;border-color:${latestResult.color}"></div>
        </div>
        <span class="feat-val">${(f.value * 100).toFixed(0)}%</span>
      </div>`).join('');
  }

  // ── Detection stats breakdown ─────────────────────────────────────────────
  function updateBreakdown(counts) {
    const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
    const attacks = total - counts.normal;

    [['Syn', 'syn'], ['Udp', 'udp'], ['Http', 'http'], ['Smurf', 'smurf']].forEach(([cap, key]) => {
      const cnt  = counts[key] || 0;
      const pct  = (cnt / Math.max(1, attacks)) * 100;
      $(`count${cap}`).textContent    = cnt.toLocaleString();
      $(`progress${cap}`).style.width = `${Math.min(100, pct)}%`;
    });
  }

  // ── Edge metrics simulation ───────────────────────────────────────────────
  const edgeBase = { cpu: 12, mem: 28, net: 10, inf: 800 };

  function updateEdgeMetrics(mode, totalPkts) {
    const attack = mode !== 'normal';
    const cpu  = Math.min(95, edgeBase.cpu + (attack ? 25 : 0) + (Math.random() * 8 - 4));
    const mem  = Math.min(90, edgeBase.mem + (attack ? 12 : 0) + (Math.random() * 4 - 2));
    const net  = Math.min(95, edgeBase.net + (attack ? 40 : 0) + (Math.random() * 6 - 3));
    const inf  = edgeBase.inf + (attack ? Math.random() * 500 : Math.random() * 100);

    $(dom.cpuBar).style.width  = `${cpu}%`;
    $(dom.cpuBar).style.background = cpu > 70 ? '#ff3d3d' : '#00d4ff';
    $(dom.cpuValue).textContent = `${cpu.toFixed(0)}%`;

    $(dom.memBar).style.width  = `${mem}%`;
    $(dom.memValue).textContent = `${mem.toFixed(0)}%`;

    $(dom.netBar).style.width  = `${net}%`;
    $(dom.netValue).textContent = `${net.toFixed(0)}%`;

    $(dom.infBar).style.width  = `${Math.min(100, inf / 3000 * 100)}%`;
    $(dom.infValue).textContent = inf >= 1000 ? `${(inf/1000).toFixed(1)}K/s` : `${inf.toFixed(0)}/s`;
  }

  // ── Uptime counter ────────────────────────────────────────────────────────
  function startUptime() {
    uptimeInterval = setInterval(() => {
      uptimeSeconds++;
      const h = Math.floor(uptimeSeconds / 3600).toString().padStart(2, '0');
      const m = Math.floor((uptimeSeconds % 3600) / 60).toString().padStart(2, '0');
      const s = (uptimeSeconds % 60).toString().padStart(2, '0');
      $(dom.uptimeDisplay).textContent = `${h}:${m}:${s}`;
    }, 1000);
  }

  // ── Traffic tick handler ──────────────────────────────────────────────────
  function onTrafficTick(e) {
    const { results, mode, totalPackets, totalAttacks, counts } = e.detail;

    totalPkts = totalPackets;
    $(dom.totalPackets).textContent = totalPackets.toLocaleString();

    // Aggregate pkt rates for this tick
    let normalPkts = 0, attackPkts = 0;
    let lastResult = null;

    for (const r of results) {
      if (r.inference.isAttack) {
        attackPkts += r.packetCount;
        addAlert(r.inference, r.srcIP);
      } else {
        normalPkts += r.packetCount;
      }
      lastResult = r.inference;
    }

    // Smooth the values
    smoothedNormal = smoothedNormal * (1 - EMA_ALPHA) + normalPkts * EMA_ALPHA;
    smoothedAttack = smoothedAttack * (1 - EMA_ALPHA) + attackPkts * EMA_ALPHA;

    // Update traffic rate display
    const totalRate = Math.round(smoothedNormal + smoothedAttack);
    $(dom.trafficRate).textContent = `${totalRate.toLocaleString()} pkt/s`;

    // Update charts
    Charts.updateTrafficChart(
      Math.round(smoothedNormal),
      Math.round(smoothedAttack)
    );
    Charts.updateDonutChart(counts);

    // Update gauge: threat = ratio of attack traffic
    const totalFlow = smoothedNormal + smoothedAttack;
    const attackRatio = totalFlow > 0 ? smoothedAttack / totalFlow : 0;

    // Smooth threat level
    const targetThreat = Math.min(100, attackRatio * 120 + (totalRate > 500 ? 15 : 0));
    threatLevel = threatLevel * 0.75 + targetThreat * 0.25;
    setGauge(threatLevel);

    // Update detector
    if (lastResult) updateDetector(lastResult, counts);

    // Update breakdown and edge metrics
    updateBreakdown(counts);
    updateEdgeMetrics(mode, totalPkts);
  }

  function onModeChange(e) {
    currentMode = e.detail.mode;
    setSystemStatus(currentMode);

    // Highlight active button
    $$('.attack-btn').forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.querySelector(`[data-mode="${currentMode}"]`);
    if (activeBtn) activeBtn.classList.add('active');
  }

  // ── Public API ────────────────────────────────────────────────────────────
  function setMode(mode) {
    TrafficSim.setMode(mode);
  }

  function init() {
    // Init charts
    Charts.initAll();

    // Wire events
    window.addEventListener('trafficTick', onTrafficTick);
    window.addEventListener('modeChange',  onModeChange);

    // Intensity slider
    const slider = document.getElementById('intensitySlider');
    const label  = document.getElementById('intensityLabel');
    slider.addEventListener('input', () => {
      TrafficSim.setIntensity(slider.value);
      label.textContent = `${slider.value}x`;
    });

    // Start simulation
    TrafficSim.start(500);
    startUptime();

    // Init gauge
    setGauge(0);
    setSystemStatus('normal');

    console.log('[EdgeGuard] Dashboard initialized ✓');
  }

  // Auto-init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return { setMode, getStats: TrafficSim.getStats };

})();

window.app = App;
