import { useEffect, useMemo, useState } from 'react'
import {
  Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import { Clock, Database, Filter, RefreshCw, Search, ShieldAlert } from 'lucide-react'
import { format } from 'date-fns'
import { getAnalytics, getHistory } from '../api/client'
import { ThreatBadge } from '../components/ui/ThreatBadge'

function ChartTip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-bg-panel border border-b-accent rounded-lg p-3 text-xs shadow-xl">
      <div className="font-mono text-t-secondary mb-2">{label}</div>
      {payload.map((item) => (
        <div key={item.dataKey || item.name} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ background: item.color || item.payload.fill }} />
          <span className="text-t-secondary">{item.name}:</span>
          <span className="font-mono font-semibold text-t-primary">{item.value}</span>
        </div>
      ))}
    </div>
  )
}

export default function History() {
  const [period, setPeriod] = useState('week')
  const [label, setLabel] = useState('')
  const [protocol, setProtocol] = useState('')
  const [query, setQuery] = useState('')
  const [analytics, setAnalytics] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const refresh = async () => {
    setLoading(true)
    setError(null)
    try {
      const [analyticsRes, historyRes] = await Promise.all([
        getAnalytics(period),
        getHistory({ limit: 250, label: label || undefined, protocol: protocol || undefined }),
      ])
      setAnalytics(analyticsRes.data)
      setHistory(historyRes.data.records)
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    refresh()
  }, [period, label, protocol])

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return history
    return history.filter((row) => [
      row.protocol_type, row.service, row.flag, row.label, row.source, String(row.id),
    ].some((value) => String(value).toLowerCase().includes(needle)))
  }, [history, query])

  const protocolData = analytics?.protocol_breakdown?.length
    ? analytics.protocol_breakdown
    : [{ protocol: 'tcp', normal: 0, dos: 0, total: 0 }]

  const sourceData = analytics?.source_breakdown?.map((item, index) => ({
    ...item,
    fill: ['#00d4ff', '#ff3d3d', '#00ff88', '#ff6b35'][index % 4],
  })) ?? []

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="panel p-4">
        <div className="flex flex-col lg:flex-row gap-3 lg:items-center">
          <div className="flex items-center gap-2 text-sm font-semibold text-t-primary">
            <Filter className="w-4 h-4 text-c-cyan" /> Analytics Filters
          </div>
          <div className="flex flex-wrap gap-2 lg:ml-auto">
            <select className="field w-auto" value={period} onChange={(e) => setPeriod(e.target.value)}>
              <option value="day">Last 24 hours</option>
              <option value="week">Last 7 days</option>
              <option value="month">Last 30 days</option>
            </select>
            <select className="field w-auto" value={label} onChange={(e) => setLabel(e.target.value)}>
              <option value="">All labels</option>
              <option value="Normal">Normal</option>
              <option value="DoS Attack">DoS Attack</option>
            </select>
            <select className="field w-auto" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="">All protocols</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
            <button className="btn-ghost" onClick={refresh}>
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="panel p-4 border-c-red/40 bg-c-red/5 text-c-red font-mono text-sm">{error}</div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="panel xl:col-span-2">
          <div className="panel-header">
            <Clock className="w-3.5 h-3.5" />
            ATTACK DISTRIBUTION OVER TIME
          </div>
          <div className="p-5 h-[320px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analytics?.time_series ?? []} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,212,255,0.10)" />
                <XAxis dataKey="time" tick={{ fill: '#4a607a', fontSize: 10, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: '#4a607a', fontSize: 10, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTip />} />
                <Bar dataKey="normal" name="Normal" stackId="a" fill="#00ff88" radius={[2, 2, 0, 0]} />
                <Bar dataKey="dos" name="DoS Attack" stackId="a" fill="#ff3d3d" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <Database className="w-3.5 h-3.5" />
            SOURCE BREAKDOWN
          </div>
          <div className="p-5 h-[320px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={sourceData} cx="50%" cy="50%" innerRadius={56} outerRadius={86} dataKey="count" nameKey="source" paddingAngle={3}>
                  {sourceData.map((item) => <Cell key={item.source} fill={item.fill} />)}
                </Pie>
                <Tooltip content={<ChartTip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <ShieldAlert className="w-3.5 h-3.5" />
          PROTOCOL BREAKDOWN
        </div>
        <div className="p-5 h-[260px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={protocolData} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,212,255,0.10)" />
              <XAxis dataKey="protocol" tick={{ fill: '#8aa0c0', fontSize: 11, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fill: '#4a607a', fontSize: 10, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTip />} />
              <Bar dataKey="normal" name="Normal" fill="#00ff88" radius={[3, 3, 0, 0]} />
              <Bar dataKey="dos" name="DoS Attack" fill="#ff3d3d" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <Database className="w-3.5 h-3.5" />
          PREDICTION LOGS
          <div className="ml-auto relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-t-muted" />
            <input
              className="field pl-9 w-64"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search logs"
            />
          </div>
        </div>
        <div className="overflow-auto max-h-[460px]">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-bg-surface">
              <tr>
                {['ID', 'Time', 'Protocol', 'Service', 'Flag', 'Source', 'Verdict', 'Confidence'].map((head) => (
                  <th key={head} className="px-4 py-3 text-left text-[10px] uppercase tracking-widest text-t-muted">{head}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={row.id} className="border-t border-b-subtle hover:bg-bg-hover">
                  <td className="px-4 py-3 font-mono text-t-muted">#{row.id}</td>
                  <td className="px-4 py-3 font-mono text-t-secondary">{format(new Date(row.timestamp), 'MMM d HH:mm:ss')}</td>
                  <td className="px-4 py-3 font-mono text-c-cyan">{row.protocol_type?.toUpperCase()}</td>
                  <td className="px-4 py-3 font-mono text-t-secondary">{row.service}</td>
                  <td className="px-4 py-3 font-mono text-t-secondary">{row.flag}</td>
                  <td className="px-4 py-3 font-mono text-t-muted">{row.source}</td>
                  <td className="px-4 py-3"><ThreatBadge label={row.label} /></td>
                  <td className={row.label === 'DoS Attack' ? 'px-4 py-3 font-mono text-c-red' : 'px-4 py-3 font-mono text-c-green'}>
                    {Math.round(row.confidence * 100)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!filtered.length && (
            <div className="h-32 flex items-center justify-center text-t-muted">
              {loading ? 'Loading records...' : 'No matching records.'}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
