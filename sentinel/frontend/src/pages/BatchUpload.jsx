import { useState, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import {
  Upload, FileText, CheckCircle2, AlertTriangle, X, Download,
  Loader2, Table2,
} from 'lucide-react'
import { predictBatch } from '../api/client'
import { ThreatBadge } from '../components/ui/ThreatBadge'
import clsx from 'clsx'

const PIE_COLORS = ['#00d4ff', '#ff3d3d']

function CustomPieTip({ active, payload }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-bg-panel border border-b-accent rounded-lg p-3 text-xs shadow-xl">
      <div className="font-semibold" style={{ color: payload[0].payload.fill }}>{payload[0].name}</div>
      <div className="font-mono text-t-secondary">{payload[0].value} records ({payload[0].payload.percent?.toFixed(1)}%)</div>
    </div>
  )
}

// ── Drop zone ─────────────────────────────────────────────────────────────────
function DropZone({ onFile }) {
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef()

  const handleFile = (f) => {
    if (f && f.name.endsWith('.csv')) onFile(f)
  }

  return (
    <div
      className={clsx(
        'border-2 border-dashed rounded-lg p-8 md:p-16 flex flex-col items-center gap-4',
        'cursor-pointer transition-all duration-200',
        dragging
          ? 'border-c-cyan bg-c-cyan/5 shadow-glow-cyan'
          : 'border-b-accent bg-bg-surface/50 hover:border-c-cyan/50 hover:bg-c-cyan/3',
      )}
      onDragOver  ={(e) => { e.preventDefault(); setDragging(true)  }}
      onDragLeave ={() => setDragging(false)}
      onDrop      ={(e) => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]) }}
      onClick     ={() => inputRef.current.click()}
    >
      <Upload className={clsx('w-12 h-12 transition-colors', dragging ? 'text-c-cyan' : 'text-t-muted')} />
      <div className="text-center">
        <div className="text-lg font-semibold text-t-primary">
          {dragging ? 'Drop it!' : 'Drag & Drop CSV File'}
        </div>
        <div className="text-sm text-t-secondary mt-1">or click to browse · NSL-KDD format</div>
      </div>
      <div className="text-[11px] font-mono text-t-muted bg-bg-panel border border-b-subtle rounded-lg px-3 py-1.5">
        Required columns: protocol_type, service, flag, src_bytes, dst_bytes, …
      </div>
      <input ref={inputRef} type="file" accept=".csv" className="hidden" onChange={(e) => handleFile(e.target.files[0])} />
    </div>
  )
}

// ── Progress bar ──────────────────────────────────────────────────────────────
function ProgressBar({ pct, label }) {
  return (
    <div className="panel p-5 space-y-3">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium text-t-primary flex items-center gap-2">
          <Loader2 className="w-4 h-4 animate-spin text-c-cyan" /> {label}
        </span>
        <span className="font-mono text-c-cyan">{pct}%</span>
      </div>
      <div className="h-2 bg-bg-surface rounded-full overflow-hidden">
        <motion.div
          className="h-full bg-gradient-to-r from-c-cyan to-c-green rounded-full"
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.4 }}
        />
      </div>
    </div>
  )
}

// ── Results table ─────────────────────────────────────────────────────────────
function ResultsTable({ results }) {
  const [sortKey, setSortKey] = useState('row_id')
  const [sortDir, setSortDir] = useState('asc')
  const [filter,  setFilter]  = useState('all')

  const sorted = [...results]
    .filter(r => filter === 'all' || r.label === filter)
    .sort((a, b) => {
      const av = a[sortKey] ?? 0, bv = b[sortKey] ?? 0
      return sortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1)
    })

  const cycle = (key) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('asc') }
  }

  const Th = ({ col, children }) => (
    <th onClick={() => cycle(col)}
        className="px-4 py-2.5 text-left text-[10px] font-semibold text-t-muted uppercase tracking-widest cursor-pointer hover:text-t-primary select-none">
      {children} {sortKey === col ? (sortDir === 'asc' ? '↑' : '↓') : ''}
    </th>
  )

  return (
    <div>
      {/* Filter tabs */}
      <div className="flex gap-2 mb-3">
        {['all', 'Normal', 'DoS Attack'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
                  className={clsx('btn btn-sm', filter === f ? 'btn-primary' : 'btn-ghost')}>
            {f === 'all' ? 'All' : f === 'Normal' ? '✓ Normal' : '⚠ DoS Only'}
          </button>
        ))}
        <span className="ml-auto text-xs text-t-muted font-mono self-center">
          {sorted.length} / {results.length} records
        </span>
      </div>

      <div className="overflow-auto max-h-96 rounded-lg border border-b-subtle">
        <table className="w-full text-xs">
          <thead className="bg-bg-surface sticky top-0">
            <tr>
              <Th col="row_id">#</Th>
              <Th col="protocol_type">Protocol</Th>
              <Th col="service">Service</Th>
              <Th col="flag">Flag</Th>
              <Th col="src_bytes">Src Bytes</Th>
              <Th col="dst_bytes">Dst Bytes</Th>
              <Th col="label">Verdict</Th>
              <Th col="confidence">Confidence</Th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((r) => (
              <tr key={r.row_id}
                  className={clsx('border-t border-b-subtle transition-colors',
                    r.label === 'DoS Attack'
                      ? 'bg-c-red/3 hover:bg-c-red/8'
                      : 'hover:bg-bg-hover')}>
                <td className="px-4 py-2 font-mono text-t-muted">{r.row_id}</td>
                <td className="px-4 py-2 font-mono text-c-cyan">{r.protocol_type}</td>
                <td className="px-4 py-2 font-mono text-t-secondary">{r.service}</td>
                <td className="px-4 py-2 font-mono text-t-secondary">{r.flag}</td>
                <td className="px-4 py-2 font-mono text-t-secondary">{r.src_bytes?.toLocaleString()}</td>
                <td className="px-4 py-2 font-mono text-t-secondary">{r.dst_bytes?.toLocaleString()}</td>
                <td className="px-4 py-2"><ThreatBadge label={r.label} /></td>
                <td className="px-4 py-2 font-mono font-semibold text-right pr-6"
                    style={{ color: r.label === 'DoS Attack' ? '#ff3d3d' : '#00ff88' }}>
                  {Math.round(r.confidence * 100)}%
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Batch Upload Page ─────────────────────────────────────────────────────────
export default function BatchUpload() {
  const [file,     setFile]     = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [progress, setProgress] = useState(0)
  const [results,  setResults]  = useState(null)
  const [error,    setError]    = useState(null)

  const handleFile = useCallback(async (f) => {
    setFile(f)
    setError(null)
    setResults(null)
    setLoading(true)
    setProgress(20)

    const fd = new FormData()
    fd.append('file', f)

    try {
      setProgress(60)
      const { data } = await predictBatch(fd)
      setProgress(100)
      await new Promise(r => setTimeout(r, 400))
      setResults(data)
    } catch (e) {
      setError(e.response?.data?.detail ?? e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  const downloadCSV = () => {
    if (!results) return
    const rows   = results.results.filter(r => !r.error)
    const header = 'row_id,protocol_type,service,flag,src_bytes,dst_bytes,label,confidence\n'
    const body   = rows.map(r =>
      `${r.row_id},${r.protocol_type},${r.service},${r.flag},${r.src_bytes},${r.dst_bytes},${r.label},${(r.confidence * 100).toFixed(1)}%`
    ).join('\n')
    const blob = new Blob([header + body], { type: 'text/csv' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = 'sentinel_results.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  const pieData = results ? [
    { name: 'Normal',     value: results.normal, fill: '#00d4ff', percent: results.normal / results.total * 100 },
    { name: 'DoS Attack', value: results.dos,    fill: '#ff3d3d', percent: results.dos    / results.total * 100 },
  ].filter(d => d.value > 0) : []

  return (
    <div className="space-y-5 animate-fade-in">
      {!results && !loading && (
        <DropZone onFile={handleFile} />
      )}

      {loading && (
        <ProgressBar pct={progress} label={`Analyzing ${file?.name}…`} />
      )}

      <AnimatePresence>
        {results && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="space-y-5"
          >
            {/* Summary + chart */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="panel p-5 lg:col-span-2">
                <div className="panel-header !px-0 !pt-0 border-none !pb-4">
                  <CheckCircle2 className="w-3.5 h-3.5 text-c-green" /> ANALYSIS COMPLETE
                  <div className="ml-auto flex gap-2">
                    <button className="btn-ghost btn-sm" onClick={() => { setResults(null); setFile(null) }}>
                      <Upload className="w-3.5 h-3.5" /> New Upload
                    </button>
                    <button className="btn-primary btn-sm" onClick={downloadCSV}>
                      <Download className="w-3.5 h-3.5" /> Export CSV
                    </button>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { label: 'Total Records', val: results.total,  color: 'text-t-primary' },
                    { label: 'Normal',         val: results.normal, color: 'text-c-green'   },
                    { label: 'DoS Alerts',     val: results.dos,    color: 'text-c-red'     },
                  ].map(({ label, val, color }) => (
                    <div key={label} className="bg-bg-surface rounded-lg p-4 text-center">
                      <div className={clsx('text-3xl font-bold font-mono', color)}>{val.toLocaleString()}</div>
                      <div className="text-xs text-t-muted mt-1">{label}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-4 text-sm text-t-secondary">
                  Alert rate: <span className={clsx('font-semibold font-mono', results.rate > 30 ? 'text-c-red' : 'text-c-green')}>
                    {results.rate}%
                  </span>
                  {' '}of {results.total.toLocaleString()} records flagged as DoS attacks
                </div>
              </div>

              {/* Pie chart */}
              <div className="panel p-5 flex flex-col">
                <div className="panel-header !px-0 !pt-0 border-none !pb-2">
                  <Table2 className="w-3.5 h-3.5" /> DISTRIBUTION
                </div>
                <div className="flex-1 flex items-center">
                  <ResponsiveContainer width="100%" height={160}>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70}
                           dataKey="value" paddingAngle={3}>
                        {pieData.map((d, i) => <Cell key={i} fill={d.fill} opacity={0.9} />)}
                      </Pie>
                      <Tooltip content={<CustomPieTip />} />
                      <Legend
                        formatter={(v) => <span style={{ color: '#8aa0c0', fontSize: 11 }}>{v}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* Results table */}
            <div className="panel p-5">
              <div className="panel-header !px-0 !pt-0 border-none !pb-4">
                <Table2 className="w-3.5 h-3.5" /> DETAILED RESULTS
              </div>
              <ResultsTable results={results.results.filter(r => !r.error)} />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {error && (
        <div className="panel p-4 border-c-red/40 bg-c-red/5 flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-c-red flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-c-red font-semibold text-sm">Upload Failed</div>
            <div className="text-t-secondary text-sm mt-1 font-mono">{error}</div>
          </div>
          <button onClick={() => setError(null)} className="ml-auto text-t-muted hover:text-t-primary">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}
    </div>
  )
}
