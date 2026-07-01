/**
 * traffic-sim.js — Real-Time Network Traffic Simulator
 * =====================================================
 * Generates realistic synthetic network traffic for each DoS attack mode,
 * runs edge ML inference on every flow, and dispatches events to the dashboard.
 *
 * Attack modes: 'normal' | 'syn' | 'udp' | 'http' | 'smurf'
 * Tick rate   : every 500ms
 */

'use strict';

const TrafficSim = (() => {

  // ── State ──────────────────────────────────────────────────────────────────
  let mode          = 'normal';
  let intensity     = 5;          // 1-10 slider
  let tickInterval  = null;
  let tickCount     = 0;
  let startTime     = Date.now();

  // Counters
  const counts = { normal: 0, syn: 0, udp: 0, http: 0, smurf: 0 };
  let totalPackets  = 0;
  let totalAttacks  = 0;

  // ── Random helpers ─────────────────────────────────────────────────────────
  const rand = (min, max) => Math.random() * (max - min) + min;
  const randInt = (min, max) => Math.floor(rand(min, max));
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  const jitter = (v, pct = 0.15) => v * (1 + rand(-pct, pct));

  // Random IP for alert display
  const randIP = () =>
    `${randInt(1, 254)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;

  // ── Feature generators per mode ────────────────────────────────────────────

  function genNormal() {
    const isTCP = Math.random() < 0.65;
    const isUDP = !isTCP && Math.random() < 0.72;
    const isICMP = !isTCP && !isUDP ? 1 : 0;
    return {
      packet_rate:    jitter(rand(30, 200)),
      byte_rate:      jitter(rand(5_000, 50_000)),
      flow_duration:  rand(50, 3_000),
      avg_packet_size: jitter(rand(400, 1_200)),
      syn_ratio:      rand(0.03, 0.18),
      ack_ratio:      rand(0.45, 0.85),
      fin_ratio:      rand(0.05, 0.25),
      rst_ratio:      rand(0.01, 0.08),
      src_port_div:   rand(0.6, 0.95),
      dst_port_div:   rand(0.5, 0.9),
      inter_arrival:  rand(5, 100),
      payload_entropy: rand(3.5, 7.0),
      is_tcp:  isTCP ? 1 : 0,
      is_udp:  isUDP ? 1 : 0,
      is_icmp: isICMP,
    };
  }

  function genSYNFlood() {
    const mult = intensity * 0.8;
    return {
      packet_rate:    jitter(rand(1_500, 3_000) * mult),
      byte_rate:      jitter(rand(80_000, 250_000) * mult),
      flow_duration:  rand(10, 150),
      avg_packet_size: jitter(rand(40, 80)),     // tiny SYN packets
      syn_ratio:      rand(0.88, 0.98),           // overwhelming SYN
      ack_ratio:      rand(0.01, 0.06),
      fin_ratio:      rand(0.005, 0.02),
      rst_ratio:      rand(0.01, 0.08),
      src_port_div:   rand(0.85, 0.99),           // spoofed src ports
      dst_port_div:   rand(0.01, 0.08),           // single target port
      inter_arrival:  rand(0.05, 2),
      payload_entropy: rand(0.5, 2.5),
      is_tcp: 1, is_udp: 0, is_icmp: 0,
    };
  }

  function genUDPFlood() {
    const mult = intensity * 0.9;
    return {
      packet_rate:    jitter(rand(1_000, 4_000) * mult),
      byte_rate:      jitter(rand(200_000, 800_000) * mult),
      flow_duration:  rand(5, 300),
      avg_packet_size: jitter(rand(1_100, 1_480)),  // max-size UDP
      syn_ratio:      rand(0, 0.01),
      ack_ratio:      rand(0, 0.01),
      fin_ratio:      0,
      rst_ratio:      0,
      src_port_div:   rand(0.7, 0.95),
      dst_port_div:   rand(0.6, 0.9),
      inter_arrival:  rand(0.05, 3),
      payload_entropy: rand(7.0, 7.95),   // random payload → high entropy
      is_tcp: 0, is_udp: 1, is_icmp: 0,
    };
  }

  function genHTTPFlood() {
    const mult = intensity * 0.6;
    return {
      packet_rate:    jitter(rand(300, 900) * mult),
      byte_rate:      jitter(rand(30_000, 150_000) * mult),
      flow_duration:  rand(500, 5_000),
      avg_packet_size: jitter(rand(500, 1_000)),
      syn_ratio:      rand(0.15, 0.35),
      ack_ratio:      rand(0.55, 0.80),
      fin_ratio:      rand(0.10, 0.30),
      rst_ratio:      rand(0.01, 0.06),
      src_port_div:   rand(0.10, 0.30),           // few sources (botnet)
      dst_port_div:   rand(0.02, 0.08),           // port 80 / 443
      inter_arrival:  rand(0.5, 15),
      payload_entropy: rand(6.0, 7.5),             // structured HTTP
      is_tcp: 1, is_udp: 0, is_icmp: 0,
    };
  }

  function genSmurf() {
    const mult = intensity * 0.7;
    return {
      packet_rate:    jitter(rand(500, 2_500) * mult),
      byte_rate:      jitter(rand(50_000, 300_000) * mult),
      flow_duration:  rand(5, 100),
      avg_packet_size: jitter(rand(900, 1_200)),   // large ICMP echo
      syn_ratio:      0,
      ack_ratio:      0,
      fin_ratio:      0,
      rst_ratio:      0,
      src_port_div:   rand(0.01, 0.05),            // broadcast
      dst_port_div:   rand(0.01, 0.05),
      inter_arrival:  rand(0.1, 8),
      payload_entropy: rand(1.5, 4.0),
      is_tcp: 0, is_udp: 0, is_icmp: 1,
    };
  }

  const generators = {
    normal: genNormal,
    syn:    genSYNFlood,
    udp:    genUDPFlood,
    http:   genHTTPFlood,
    smurf:  genSmurf,
  };

  // ── Tick ───────────────────────────────────────────────────────────────────

  function tick() {
    tickCount++;

    // Generate 1-5 flows per tick depending on mode & intensity
    const flowCount = mode === 'normal'
      ? randInt(1, 3)
      : Math.max(1, Math.round(intensity * 0.6));

    const results = [];

    for (let i = 0; i < flowCount; i++) {
      // Occasionally inject noise: normal traffic even during attack
      const genMode = (mode !== 'normal' && Math.random() < 0.15)
        ? 'normal' : mode;

      const features = generators[genMode]();
      const inference = window.EdgeML.edgeInfer(features);

      const pktCount = Math.round(features.packet_rate * 0.5); // flows per 500ms tick
      totalPackets += pktCount;
      if (inference.isAttack) totalAttacks++;

      // Update attack type counters
      const modeKey = ['normal', 'syn', 'udp', 'http', 'smurf'][inference.label];
      counts[modeKey]++;

      results.push({
        features,
        inference,
        packetCount: pktCount,
        timestamp:   Date.now(),
        srcIP:       randIP(),
        dstIP:       randIP(),
      });
    }

    // Dispatch tick event for dashboard to consume
    window.dispatchEvent(new CustomEvent('trafficTick', {
      detail: {
        results,
        mode,
        intensity,
        totalPackets,
        totalAttacks,
        counts: { ...counts },
        uptime: Math.floor((Date.now() - startTime) / 1000),
      },
    }));
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  function setMode(newMode) {
    mode = newMode;
    window.dispatchEvent(new CustomEvent('modeChange', { detail: { mode } }));
  }

  function setIntensity(val) {
    intensity = clamp(parseInt(val, 10), 1, 10);
  }

  function start(intervalMs = 500) {
    if (tickInterval) clearInterval(tickInterval);
    startTime    = Date.now();
    tickInterval = setInterval(tick, intervalMs);
    tick(); // immediate first tick
  }

  function stop() {
    clearInterval(tickInterval);
    tickInterval = null;
  }

  function getStats() {
    return { totalPackets, totalAttacks, counts: { ...counts }, mode, intensity };
  }

  return { setMode, setIntensity, start, stop, getStats };

})();

window.TrafficSim = TrafficSim;
