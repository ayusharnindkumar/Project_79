import { useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity, AlertTriangle, Pause, Play, RotateCcw, ShieldAlert,
  ShieldCheck, SlidersHorizontal,
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { format } from 'date-fns'
import { useSSEStream } from '../hooks/useSSEStream'
import { ThreatBadge } from '../components/ui/ThreatBadge'

function SimTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-bg-panel border border-b-accent rounded-lg p-3 text-xs shadow-xl">
      <div className="font-mono text-t-secondary mb-2">{label}</div>
      {payload.map((item) => (
        <div key={item.dataKey} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ background: item.color }} />
          <span className="text-t-secondary">{item.name}</span>
          <span className="font-mono font-semibold" style={{ color: item.color }}>{item.value}</span>
        </div>
      ))}
    </div>
  )
}

export default function Simulation() {
  const [isRunning, setIsRunning] = useState(false)
  const [speed, setSpeed] = useState(3)
  const [count, setCount] = useState(150)
  const [attackRate, setAttackRate] = useState(0.3)
  const [records, setRecords] = useState([])
  const [error, setError] = useState(null)

  useSSEStream({
    isRunning,
    speed,
    count,
    attackRate,
    onRecord: (record) => {
      setError(null)
      setRecords((prev) => [...prev.slice(-119), record])
    },
    onDone: () => setIsRunning(false),
    onError: () => {
      setIsRunning(false)
      setError('Simulation stream disconnected.')
    },
  })

  const totals = useMemo(() => {
    const dos = records.filter((item) => item.label === 'DoS Attack').length
    return { total: records.length, dos, normal: records.length - dos }
  }, [records])

  const chartData = useMemo(() => {
    const buckets = []
    records.forEach((record, index) => {
      const bucketIndex = Math.floor(index / 5)
      if (!buckets[bucketIndex]) {
        buckets[bucketIndex] = { time: `T+${bucketIndex * 5}`, normal: 0, attack: 0 }
      }
      if (record.label === 'DoS Attack') buckets[bucketIndex].attack += 1
      else buckets[bucketIndex].normal += 1
    })
    return buckets.slice(-24)
  }, [records])

  const reset = () => {
    setIsRunning(false)
    setRecords([])
    setError(null)
  }

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="panel p-5">
          <div className="text-xs uppercase tracking-widest text-t-muted">Processed</div>
          <div className="mt-2 font-mono text-3xl font-bold text-t-primary">{totals.total}</div>
        </div>
        <div className="panel p-5">
          <div className="text-xs uppercase tracking-widest text-t-muted">Normal</div>
          <div className="mt-2 font-mono text-3xl font-bold text-c-green">{totals.normal}</div>
        </div>
        <div className="panel p-5">
          <div className="text-xs uppercase tracking-widest text-t-muted">DoS Alerts</div>
          <div className="mt-2 font-mono text-3xl font-bold text-c-red">{totals.dos}</div>
        </div>
        <div className="panel p-5">
          <div className="text-xs uppercase tracking-widest text-t-muted">Stream State</div>
          <div className="mt-3 flex items-center gap-2 font-mono text-sm">
            <span className={`h-2 w-2 rounded-full ${isRunning ? 'bg-c-green animate-pulse' : 'bg-t-muted'}`} />
            {isRunning ? 'LIVE' : 'IDLE'}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="panel xl:col-span-2">
          <div className="panel-header">
            <Activity className="w-3.5 h-3.5" />
            REAL-TIME TRAFFIC REPLAY
            <div className="ml-auto flex items-center gap-2">
              <button className="btn-ghost btn-sm" onClick={reset}>
                <RotateCcw className="w-3.5 h-3.5" /> Reset
              </button>
              <button className={isRunning ? 'btn-danger btn-sm' : 'btn-primary btn-sm'} onClick={() => setIsRunning((v) => !v)}>
                {isRunning ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                {isRunning ? 'Pause' : 'Start'}
              </button>
            </div>
          </div>
          <div className="p-5 h-[360px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="simNormal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00ff88" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="#00ff88" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="simAttack" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff3d3d" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#ff3d3d" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,212,255,0.10)" />
                <XAxis dataKey="time" tick={{ fill: '#4a607a', fontSize: 10, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: '#4a607a', fontSize: 10, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <Tooltip content={<SimTooltip />} />
                <Area type="monotone" dataKey="normal" name="Normal" stroke="#00ff88" fill="url(#simNormal)" strokeWidth={2} dot={false} />
                <Area type="monotone" dataKey="attack" name="DoS" stroke="#ff3d3d" fill="url(#simAttack)" strokeWidth={2.5} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <SlidersHorizontal className="w-3.5 h-3.5" />
            STREAM CONTROLS
          </div>
          <div className="p-5 space-y-5">
            <label className="block">
              <div className="flex justify-between text-xs text-t-secondary mb-2">
                <span>Speed</span><span className="font-mono text-c-cyan">{speed}/sec</span>
              </div>
              <input className="w-full accent-c-cyan" type="range" min="1" max="10" step="1" value={speed} onChange={(e) => setSpeed(Number(e.target.value))} disabled={isRunning} />
            </label>
            <label className="block">
              <div className="flex justify-between text-xs text-t-secondary mb-2">
                <span>Record Count</span><span className="font-mono text-c-cyan">{count}</span>
              </div>
              <input className="w-full accent-c-cyan" type="range" min="25" max="500" step="25" value={count} onChange={(e) => setCount(Number(e.target.value))} disabled={isRunning} />
            </label>
            <label className="block">
              <div className="flex justify-between text-xs text-t-secondary mb-2">
                <span>Attack Rate</span><span className="font-mono text-c-red">{Math.round(attackRate * 100)}%</span>
              </div>
              <input className="w-full accent-c-red" type="range" min="0" max="0.9" step="0.05" value={attackRate} onChange={(e) => setAttackRate(Number(e.target.value))} disabled={isRunning} />
            </label>
            {error && (
              <div className="rounded-lg border border-c-red/30 bg-c-red/10 p-3 text-sm text-c-red flex gap-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <ShieldAlert className="w-3.5 h-3.5" />
          LIVE ALERT FEED
        </div>
        <div className="p-3 max-h-[360px] overflow-auto terminal space-y-1">
          <AnimatePresence initial={false}>
            {records.slice(-60).reverse().map((record) => (
              <motion.div
                key={`${record.seq}-${record.timestamp}`}
                initial={{ opacity: 0, x: 14 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0 }}
                className={`grid grid-cols-[74px_94px_1fr_92px_82px] gap-3 items-center rounded-lg px-3 py-2 ${
                  record.label === 'DoS Attack' ? 'alert-row-dos' : 'alert-row-normal'
                }`}
              >
                <span className="text-t-muted">#{record.seq}</span>
                <span className="text-t-muted">{format(new Date(record.timestamp), 'HH:mm:ss')}</span>
                <span className="truncate flex items-center gap-2">
                  {record.label === 'DoS Attack'
                    ? <ShieldAlert className="w-3.5 h-3.5 text-c-red" />
                    : <ShieldCheck className="w-3.5 h-3.5 text-c-green" />}
                  {record.protocol_type?.toUpperCase()} / {record.service} / {record.flag}
                </span>
                <ThreatBadge label={record.label} />
                <span className={record.label === 'DoS Attack' ? 'text-c-red' : 'text-c-green'}>
                  {Math.round(record.confidence * 100)}%
                </span>
              </motion.div>
            ))}
          </AnimatePresence>
          {!records.length && (
            <div className="h-32 flex items-center justify-center text-t-muted">
              Start the stream to replay network records.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
