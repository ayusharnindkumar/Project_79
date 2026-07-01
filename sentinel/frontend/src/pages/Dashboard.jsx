import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from 'recharts'
import { Database, ShieldCheck, ShieldAlert, TrendingUp, Activity, Cpu, Pause, Play, RadioTower, Server } from 'lucide-react'
import { format } from 'date-fns'
import { useLiveStats } from '../hooks/useLiveStats'
import { useSSEStream } from '../hooks/useSSEStream'
import StatCard from '../components/ui/StatCard'
import { ThreatBadge, ConfidenceBar } from '../components/ui/ThreatBadge'

// ── Chart theme ──────────────────────────────────────────────────────────────
const CHART_COLORS = { normal: '#00d4ff', attack: '#ff3d3d', grid: 'rgba(14,40,80,0.6)' }

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-bg-panel border border-b-accent rounded-lg p-3 text-xs shadow-xl">
      <div className="font-mono text-t-secondary mb-2">{label}</div>
      {payload.map((p) => (
        <div key={p.dataKey} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          <span className="text-t-secondary">{p.name}:</span>
          <span className="font-semibold font-mono" style={{ color: p.color }}>{p.value}</span>
        </div>
      ))}
    </div>
  )
}

// Generate initial chart data (last 30 buckets)
function genInitialChart() {
  return Array.from({ length: 30 }, (_, i) => ({
    time:   format(new Date(Date.now() - (29 - i) * 1000), 'HH:mm:ss'),
    normal: 0,
    attack: 0,
  }))
}

// ── Recent alerts feed ───────────────────────────────────────────────────────
function AlertFeed({ alerts }) {
  if (!alerts.length) {
    return (
      <div className="flex flex-col items-center justify-center h-40 text-t-muted text-sm">
        <ShieldCheck className="w-8 h-8 mb-2 opacity-30" />
        No records yet
      </div>
    )
  }
  return (
    <div className="space-y-1.5 overflow-y-auto max-h-[360px] pr-1">
      {alerts.map((a, i) => (
        <motion.div
          key={a.id}
          initial={{ opacity: 0, x: 12 }}
          animate={{ opacity: 1, x: 0  }}
          transition={{ delay: i * 0.03 }}
          className={`px-3 py-2 rounded-lg text-xs flex items-center justify-between gap-2
            ${a.label === 'DoS Attack' ? 'alert-row-dos' : 'alert-row-normal'}`}
        >
          <div className="flex items-center gap-2 min-w-0">
            {a.label === 'DoS Attack'
              ? <ShieldAlert className="w-3 h-3 text-c-red   flex-shrink-0" />
              : <ShieldCheck  className="w-3 h-3 text-c-green flex-shrink-0" />}
            <span className="font-mono text-t-secondary truncate">
              {a.protocol_type?.toUpperCase()} · {a.service} · {a.flag}
            </span>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className={`font-semibold ${a.label === 'DoS Attack' ? 'text-c-red' : 'text-c-green'}`}>
              {Math.round(a.confidence * 100)}%
            </span>
            <span className="text-t-muted font-mono">{format(new Date(a.timestamp), 'HH:mm:ss')}</span>
          </div>
        </motion.div>
      ))}
    </div>
  )
}

// ── Threat level bar ─────────────────────────────────────────────────────────
function ThreatLevel({ rate }) {
  const color = rate < 15 ? '#00ff88' : rate < 40 ? '#ffd700' : '#ff3d3d'
  const label = rate < 15 ? 'LOW' : rate < 40 ? 'ELEVATED' : 'CRITICAL'
  return (
    <div className="panel p-4">
      <div className="panel-header !px-0 !pt-0 !pb-3 border-none">
        <Activity className="w-3.5 h-3.5" /> THREAT LEVEL
        <span className="ml-auto font-mono text-sm font-bold" style={{ color }}>{label}</span>
      </div>
      <div className="relative h-3 bg-bg-surface rounded-full overflow-hidden">
        <div
          className="absolute inset-y-0 left-0 rounded-full transition-all duration-700"
          style={{
            width: `${Math.min(rate, 100)}%`,
            background: `linear-gradient(90deg, #00ff88, #ffd700 40%, #ff3d3d)`,
            boxShadow: `0 0 10px ${color}60`,
          }}
        />
      </div>
      <div className="flex justify-between text-[10px] text-t-muted font-mono mt-1">
        <span>0%</span><span>50%</span><span>100%</span>
      </div>
    </div>
  )
}

// ── Dashboard ────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const { stats, recentAlerts, loading, refresh } = useLiveStats(5000)
  const [chartData, setChartData] = useState(genInitialChart)
  const [streaming, setStreaming] = useState(false)
  const [liveRecords, setLiveRecords] = useState([])

  useSSEStream({
    isRunning: streaming,
    speed: 3,
    count: 2000,
    attackRate: 0.28,
    onRecord: (record) => {
      setLiveRecords((prev) => [record, ...prev].slice(0, 24))
      setChartData((prev) => {
        const latest = {
          time: format(new Date(record.timestamp), 'HH:mm:ss'),
          normal: record.label === 'Normal' ? 1 : 0,
          attack: record.label === 'DoS Attack' ? 1 : 0,
        }
        return [...prev.slice(-29), latest]
      })
    },
    onDone: () => {
      setStreaming(false)
      refresh()
    },
    onError: () => setStreaming(false),
  })

  const mergedAlerts = useMemo(() => {
    const seen = new Set()
    return [...liveRecords, ...recentAlerts].filter((record) => {
      const key = record.id ?? `${record.timestamp}-${record.protocol_type}-${record.service}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    }).slice(0, 16)
  }, [liveRecords, recentAlerts])

  const sessionDos = liveRecords.filter((record) => record.label === 'DoS Attack').length

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-5">
        <section className="panel p-5 md:p-6 min-h-[190px]">
          <div className="relative z-10 flex flex-col md:flex-row md:items-end gap-6">
            <div className="flex-1">
              <div className="inline-flex items-center gap-2 rounded-lg border border-c-cyan/20 bg-c-cyan/10 px-3 py-1.5 text-[10px] font-mono uppercase tracking-widest text-c-cyan">
                <RadioTower className="h-3.5 w-3.5" />
                Real-Time Threat Operations
              </div>
              <h2 className="mt-4 text-2xl md:text-4xl font-black text-t-primary">
                Network DoS defense console
              </h2>
              <p className="mt-3 max-w-3xl text-sm leading-6 text-t-secondary">
                Start the live detector to stream records through FastAPI, run real model inference, log each verdict to SQLite, and update this console event-by-event.
              </p>
              <div className="mt-5 flex flex-wrap gap-2">
                <button className={streaming ? 'btn-danger' : 'btn-primary'} onClick={() => setStreaming((value) => !value)}>
                  {streaming ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                  {streaming ? 'Stop Live Detection' : 'Start Live Detection'}
                </button>
                <button className="btn-ghost" onClick={refresh}>
                  <Activity className="w-4 h-4" /> Sync History
                </button>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2 md:w-[330px]">
              {[
                { icon: Server, label: 'API', value: 'online', color: 'text-c-green' },
                { icon: Cpu, label: 'Model', value: 'LR', color: 'text-c-cyan' },
                { icon: Activity, label: 'Stream', value: streaming ? 'live' : 'idle', color: streaming ? 'text-c-green' : 'text-c-orange' },
              ].map(({ icon: Icon, label, value, color }) => (
                <div key={label} className="rounded-lg border border-b-subtle bg-bg-surface/70 p-3 text-center">
                  <Icon className={`mx-auto h-4 w-4 ${color}`} />
                  <div className={`mt-2 font-mono text-sm font-bold ${color}`}>{value}</div>
                  <div className="mt-1 text-[9px] uppercase tracking-widest text-t-muted">{label}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="panel p-5 min-h-[190px]">
          <div className="panel-header !px-0 !pt-0 !pb-3 border-none">
            <ShieldAlert className="w-3.5 h-3.5" /> ACTIVE WATCH
          </div>
          <div className="relative mx-auto h-28 w-28">
            <div className="absolute inset-0 rounded-full border border-c-cyan/20" />
            <div className="absolute inset-3 rounded-full border border-c-green/20" />
            <div className="scanner-ring inset-5" />
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <div className="font-mono text-2xl font-black text-c-red">{sessionDos}</div>
                <div className="text-[9px] uppercase tracking-widest text-t-muted">alerts</div>
              </div>
            </div>
          </div>
          <div className="mt-4 text-center text-xs text-t-secondary">
            This live session has processed <span className="font-mono text-c-cyan">{liveRecords.length}</span> streamed records
          </div>
        </section>
      </div>

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Analyzed"  value={stats.total}      icon={Database}     color="cyan"  />
        <StatCard title="Normal Traffic"  value={stats.normal}     icon={ShieldCheck}  color="green" />
        <StatCard title="DoS Alerts"      value={stats.dos}        icon={ShieldAlert}  color="red"   pulse={stats.dos > 0} />
        <StatCard title="Alert Rate"      value={stats.alert_rate} icon={TrendingUp}   color="orange" suffix="%" />
      </div>

      {/* ── Threat level bar ── */}
      <ThreatLevel rate={stats.alert_rate} />

      {/* ── Chart + feed ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Traffic area chart */}
        <div className="panel lg:col-span-2">
          <div className="panel-header">
            <Activity className="w-3.5 h-3.5" />
            LIVE TRAFFIC MONITOR
            <span className="ml-auto flex items-center gap-1 text-c-green text-[10px]">
              <span className="w-1.5 h-1.5 rounded-full bg-c-green animate-pulse" />
              LIVE
            </span>
          </div>
          <div className="p-4 h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradNormal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradAttack" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ff3d3d" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ff3d3d" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_COLORS.grid} />
                <XAxis dataKey="time" tick={{ fill: '#4a607a', fontSize: 10, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: '#4a607a', fontSize: 10, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  wrapperStyle={{ fontSize: '11px', color: '#8aa0c0', fontFamily: 'JetBrains Mono' }}
                  formatter={(v) => v === 'normal' ? 'Normal' : 'Attack'}
                />
                <Area type="monotone" dataKey="normal" name="normal" stroke="#00d4ff" fill="url(#gradNormal)" strokeWidth={2} dot={false} />
                <Area type="monotone" dataKey="attack" name="attack" stroke="#ff3d3d" fill="url(#gradAttack)" strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent alerts */}
        <div className="panel">
          <div className="panel-header">
            <ShieldAlert className="w-3.5 h-3.5" />
            RECENT PREDICTIONS
            {loading && <span className="ml-auto text-[10px] text-t-muted animate-pulse">loading…</span>}
          </div>
          <div className="p-3">
            <AlertFeed alerts={mergedAlerts} />
          </div>
        </div>
      </div>
    </div>
  )
}
