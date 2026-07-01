import { useEffect, useMemo, useState } from 'react'
import { format } from 'date-fns'
import {
  Activity, Database as DatabaseIcon, Download, Filter, HardDrive,
  RefreshCw, Search, Server, ShieldAlert, Table2,
} from 'lucide-react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { getDatabaseInfo, getHistory } from '../api/client'
import { ThreatBadge } from '../components/ui/ThreatBadge'

function ChartTip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-bg-panel border border-b-accent rounded-lg p-3 text-xs shadow-xl">
      <div className="font-mono text-t-secondary mb-2">{label}</div>
      {payload.map((item) => (
        <div key={item.dataKey || item.name} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ background: item.color }} />
          <span className="text-t-secondary">{item.name}:</span>
          <span className="font-mono font-semibold text-t-primary">{item.value}</span>
        </div>
      ))}
    </div>
  )
}

export default function Database() {
  const [info, setInfo] = useState(null)
  const [records, setRecords] = useState([])
  const [label, setLabel] = useState('')
  const [source, setSource] = useState('')
  const [protocol, setProtocol] = useState('')
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const refresh = async () => {
    setLoading(true)
    setError(null)
    try {
      const [infoRes, historyRes] = await Promise.all([
        getDatabaseInfo(),
        getHistory({
          limit: 500,
          label: label || undefined,
          source: source || undefined,
          protocol: protocol || undefined,
        }),
      ])
      setInfo(infoRes.data)
      setRecords(historyRes.data.records)
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    refresh()
  }, [label, source, protocol])

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return records
    return records.filter((row) => [
      row.id, row.timestamp, row.protocol_type, row.service, row.flag, row.label, row.source,
    ].some((value) => String(value).toLowerCase().includes(needle)))
  }, [records, query])

  const sourceChart = info?.source_counts?.map((item) => ({ name: item.source, count: item.count })) ?? []
  const protocolChart = info?.protocol_counts?.map((item) => ({ name: item.protocol, count: item.count })) ?? []

  const exportCSV = () => {
    const header = 'id,timestamp,protocol_type,service,flag,src_bytes,dst_bytes,label,confidence,source\n'
    const body = filtered.map((row) => [
      row.id,
      row.timestamp,
      row.protocol_type,
      row.service,
      row.flag,
      row.src_bytes,
      row.dst_bytes,
      row.label,
      row.confidence,
      row.source,
    ].join(',')).join('\n')
    const blob = new Blob([header + body], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'sentinel_database_records.csv'
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {[
          { label: 'Database Engine', value: info?.engine ?? 'SQLite', icon: HardDrive, color: 'text-c-cyan' },
          { label: 'Stored Records', value: info?.total_records ?? 0, icon: DatabaseIcon, color: 'text-t-primary' },
          { label: 'Normal Rows', value: info?.normal_records ?? 0, icon: Activity, color: 'text-c-green' },
          { label: 'DoS Rows', value: info?.dos_records ?? 0, icon: ShieldAlert, color: 'text-c-red' },
        ].map(({ label: cardLabel, value, icon: Icon, color }) => (
          <div key={cardLabel} className="panel p-5">
            <div className="flex items-center justify-between">
              <div className="text-xs uppercase tracking-widest text-t-muted">{cardLabel}</div>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <div className={`mt-3 font-mono text-2xl font-black ${color}`}>
              {typeof value === 'number' ? value.toLocaleString() : value}
            </div>
          </div>
        ))}
      </div>

      <div className="panel p-5">
        <div className="panel-header !px-0 !pt-0 !pb-4 border-none">
          <Server className="w-3.5 h-3.5" />
          DATABASE CONNECTION
          <button className="ml-auto btn-ghost btn-sm" onClick={refresh}>
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 text-sm">
          <div className="rounded-lg border border-b-subtle bg-bg-surface/70 p-3">
            <div className="text-[10px] uppercase tracking-widest text-t-muted">Table</div>
            <div className="mt-1 font-mono text-c-cyan">{info?.table ?? 'predictions'}</div>
          </div>
          <div className="rounded-lg border border-b-subtle bg-bg-surface/70 p-3 lg:col-span-2">
            <div className="text-[10px] uppercase tracking-widest text-t-muted">SQLite File</div>
            <div className="mt-1 font-mono text-t-secondary truncate">{info?.database_path ?? 'backend/sentinel.db'}</div>
          </div>
          <div className="rounded-lg border border-b-subtle bg-bg-surface/70 p-3">
            <div className="text-[10px] uppercase tracking-widest text-t-muted">First Record</div>
            <div className="mt-1 font-mono text-t-secondary">
              {info?.first_record_at ? format(new Date(info.first_record_at), 'MMM d, HH:mm:ss') : 'No records'}
            </div>
          </div>
          <div className="rounded-lg border border-b-subtle bg-bg-surface/70 p-3">
            <div className="text-[10px] uppercase tracking-widest text-t-muted">Latest Record</div>
            <div className="mt-1 font-mono text-t-secondary">
              {info?.latest_record_at ? format(new Date(info.latest_record_at), 'MMM d, HH:mm:ss') : 'No records'}
            </div>
          </div>
          <div className="rounded-lg border border-b-subtle bg-bg-surface/70 p-3">
            <div className="text-[10px] uppercase tracking-widest text-t-muted">Mode</div>
            <div className="mt-1 font-mono text-c-green">read / export / filter</div>
          </div>
        </div>
      </div>

      {error && (
        <div className="panel p-4 border-c-red/40 bg-c-red/5 text-c-red font-mono text-sm">{error}</div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <div className="panel">
          <div className="panel-header">
            <Table2 className="w-3.5 h-3.5" /> RECORDS BY SOURCE
          </div>
          <div className="h-64 p-5">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sourceChart} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,212,255,0.10)" />
                <XAxis dataKey="name" tick={{ fill: '#8aa0c0', fontSize: 11, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: '#4a607a', fontSize: 10, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTip />} />
                <Bar dataKey="count" name="Rows" fill="#00d4ff" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="panel">
          <div className="panel-header">
            <Activity className="w-3.5 h-3.5" /> RECORDS BY PROTOCOL
          </div>
          <div className="h-64 p-5">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={protocolChart} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,212,255,0.10)" />
                <XAxis dataKey="name" tick={{ fill: '#8aa0c0', fontSize: 11, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: '#4a607a', fontSize: 10, fontFamily: 'JetBrains Mono' }} tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTip />} />
                <Bar dataKey="count" name="Rows" fill="#00ff88" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <DatabaseIcon className="w-3.5 h-3.5" />
          DATABASE RECORDS
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <select className="field w-auto" value={label} onChange={(event) => setLabel(event.target.value)}>
              <option value="">All labels</option>
              <option value="Normal">Normal</option>
              <option value="DoS Attack">DoS Attack</option>
            </select>
            <select className="field w-auto" value={source} onChange={(event) => setSource(event.target.value)}>
              <option value="">All sources</option>
              <option value="manual">Manual</option>
              <option value="batch">Batch</option>
              <option value="simulation">Simulation</option>
            </select>
            <select className="field w-auto" value={protocol} onChange={(event) => setProtocol(event.target.value)}>
              <option value="">All protocols</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>
        </div>
        <div className="border-b border-b-subtle p-3 flex flex-col md:flex-row gap-3 md:items-center">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-t-muted" />
            <input className="field pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search database rows" />
          </div>
          <button className="btn-primary justify-center" onClick={exportCSV} disabled={!filtered.length}>
            <Download className="w-4 h-4" /> Export Visible Rows
          </button>
        </div>
        <div className="overflow-auto max-h-[520px]">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-bg-surface">
              <tr>
                {['ID', 'Timestamp', 'Protocol', 'Service', 'Flag', 'Source Bytes', 'Dest Bytes', 'Source', 'Verdict', 'Confidence'].map((head) => (
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
                  <td className="px-4 py-3 font-mono text-t-secondary">{Math.round(row.src_bytes ?? 0).toLocaleString()}</td>
                  <td className="px-4 py-3 font-mono text-t-secondary">{Math.round(row.dst_bytes ?? 0).toLocaleString()}</td>
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
            <div className="h-32 flex items-center justify-center gap-2 text-t-muted">
              <Filter className="w-4 h-4" />
              {loading ? 'Loading database records...' : 'No database rows match the current filters.'}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
