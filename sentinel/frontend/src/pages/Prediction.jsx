import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Crosshair, ChevronDown, ChevronUp, Zap, ShieldCheck, ShieldAlert, RefreshCw, Loader2 } from 'lucide-react'
import { predictSingle } from '../api/client'
import { ConfidenceBar } from '../components/ui/ThreatBadge'
import clsx from 'clsx'

// ── Form field definitions ────────────────────────────────────────────────────
const PROTOCOLS = ['tcp', 'udp', 'icmp']
const SERVICES  = ['http','ftp_data','ftp','smtp','ssh','domain_u','auth','finger','telnet','eco_i','ecr_i','other','private','http_443','domain','pop_3','ldap']
const FLAGS     = ['SF','S0','REJ','RSTO','RSTR','SH','S1','S2','S3','OTH','RSTOS0']

const FORM_SECTIONS = [
  {
    id: 'proto', title: 'Network Protocol', fields: [
      { name: 'protocol_type',  label: 'Protocol Type',    type: 'select',   options: PROTOCOLS },
      { name: 'service',        label: 'Service',          type: 'select',   options: SERVICES  },
      { name: 'flag',           label: 'Connection Flag',  type: 'select',   options: FLAGS     },
    ],
  },
  {
    id: 'volume', title: 'Traffic Volume', fields: [
      { name: 'src_bytes', label: 'Source Bytes',      type: 'number', min: 0, step: 1 },
      { name: 'dst_bytes', label: 'Destination Bytes', type: 'number', min: 0, step: 1 },
      { name: 'duration',  label: 'Duration (s)',       type: 'number', min: 0, step: 0.1 },
    ],
  },
  {
    id: 'conn', title: 'Connection Stats', fields: [
      { name: 'count',          label: 'Connection Count',   type: 'number', min: 0, max: 511, step: 1 },
      { name: 'srv_count',      label: 'Service Count',      type: 'number', min: 0, max: 511, step: 1 },
      { name: 'serror_rate',    label: 'SYN Error Rate',     type: 'number', min: 0, max: 1,   step: 0.01 },
      { name: 'same_srv_rate',  label: 'Same Service Rate',  type: 'number', min: 0, max: 1,   step: 0.01 },
      { name: 'diff_srv_rate',  label: 'Diff Service Rate',  type: 'number', min: 0, max: 1,   step: 0.01 },
    ],
  },
  {
    id: 'host', title: 'Host Metrics', fields: [
      { name: 'dst_host_count',        label: 'Dst Host Count',     type: 'number', min: 0, max: 255, step: 1 },
      { name: 'dst_host_srv_count',    label: 'Dst Host Srv Count', type: 'number', min: 0, max: 255, step: 1 },
      { name: 'dst_host_same_srv_rate',label: 'Dst Same Srv Rate',  type: 'number', min: 0, max: 1,   step: 0.01 },
      { name: 'dst_host_serror_rate',  label: 'Dst SYN Error Rate', type: 'number', min: 0, max: 1,   step: 0.01 },
    ],
  },
  {
    id: 'flags', title: 'Binary Flags', fields: [
      { name: 'logged_in',      label: 'Logged In',       type: 'toggle' },
      { name: 'land',           label: 'Land Attack',     type: 'toggle' },
      { name: 'wrong_fragment', label: 'Wrong Fragment',  type: 'number', min: 0, max: 10, step: 1 },
      { name: 'urgent',         label: 'Urgent Packets',  type: 'number', min: 0, max: 10, step: 1 },
    ],
  },
]

// ── Presets ───────────────────────────────────────────────────────────────────
const PRESETS = {
  normal_tcp: {
    label: 'Normal TCP', color: 'green',
    values: {
      protocol_type: 'tcp', service: 'http', flag: 'SF',
      src_bytes: 1286, dst_bytes: 2568, duration: 12.0, land: 0,
      wrong_fragment: 0, urgent: 0, count: 8, srv_count: 8,
      serror_rate: 0.0, srv_serror_rate: 0.0, rerror_rate: 0.0,
      same_srv_rate: 1.0, diff_srv_rate: 0.0, srv_diff_host_rate: 0.0,
      dst_host_count: 200, dst_host_srv_count: 192,
      dst_host_same_srv_rate: 0.96, dst_host_serror_rate: 0.0, logged_in: 1,
    },
  },
  suspicious_udp: {
    label: 'Suspicious UDP', color: 'orange',
    values: {
      protocol_type: 'udp', service: 'private', flag: 'SF',
      src_bytes: 28, dst_bytes: 0, duration: 0, land: 0,
      wrong_fragment: 2, urgent: 0, count: 24, srv_count: 24,
      serror_rate: 0.0, srv_serror_rate: 0.0, rerror_rate: 0.0,
      same_srv_rate: 0.71, diff_srv_rate: 0.06, srv_diff_host_rate: 0.0,
      dst_host_count: 40, dst_host_srv_count: 28,
      dst_host_same_srv_rate: 0.70, dst_host_serror_rate: 0.0, logged_in: 0,
    },
  },
  known_dos: {
    label: 'Known DoS', color: 'red',
    values: {
      protocol_type: 'tcp', service: 'http', flag: 'S0',
      src_bytes: 0, dst_bytes: 0, duration: 0, land: 0,
      wrong_fragment: 0, urgent: 0, count: 511, srv_count: 511,
      serror_rate: 1.0, srv_serror_rate: 1.0, rerror_rate: 0.0,
      same_srv_rate: 1.0, diff_srv_rate: 0.0, srv_diff_host_rate: 0.0,
      dst_host_count: 255, dst_host_srv_count: 255,
      dst_host_same_srv_rate: 1.0, dst_host_serror_rate: 1.0, logged_in: 0,
    },
  },
}

const DEFAULT_VALUES = {
  protocol_type: 'tcp', service: 'http', flag: 'SF',
  src_bytes: 0, dst_bytes: 0, duration: 0, land: 0,
  wrong_fragment: 0, urgent: 0, count: 1, srv_count: 1,
  serror_rate: 0, srv_serror_rate: 0, rerror_rate: 0,
  same_srv_rate: 1, diff_srv_rate: 0, srv_diff_host_rate: 0,
  dst_host_count: 100, dst_host_srv_count: 100,
  dst_host_same_srv_rate: 0.5, dst_host_serror_rate: 0, logged_in: 0,
}

// ── Verdict display ───────────────────────────────────────────────────────────
function Verdict({ result, onReset }) {
  const isDoS = result.label === 'DoS Attack'
  return (
    <motion.div
      key={result.label}
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1   }}
      transition={{ type: 'spring', stiffness: 200, damping: 18 }}
      className={clsx(
        'panel p-8 flex flex-col items-center text-center gap-5',
        isDoS ? 'border-glow-red' : 'border-glow-cyan',
      )}
    >
      {/* Icon */}
      <div className={clsx('relative', isDoS ? 'animate-pulse-glow' : '')}>
        {isDoS
          ? <ShieldAlert className="w-24 h-24 text-c-red" />
          : <ShieldCheck  className="w-24 h-24 text-c-green" />}
        {/* Rings */}
        {[1, 2].map((i) => (
          <span
            key={i}
            className="scanner-ring"
            style={{
              width: '100%', height: '100%',
              top: 0, left: 0,
              borderColor: isDoS ? 'rgba(255,61,61,0.4)' : 'rgba(0,255,136,0.4)',
              animationDelay: `${(i - 1) * 1.2}s`,
            }}
          />
        ))}
      </div>

      {/* Label */}
      <div>
        <div className={clsx('text-4xl font-black tracking-tight font-mono',
          isDoS ? 'text-gradient-red' : 'text-gradient-cyan')}>
          {result.label.toUpperCase()}
        </div>
        <div className="text-t-secondary text-sm mt-1">
          {isDoS ? '⚠ Threat detected — consider blocking this source' : '✓ Traffic classified as benign'}
        </div>
      </div>

      {/* Confidence */}
      <div className="w-full max-w-xs">
        <ConfidenceBar value={result.confidence} label={result.label} />
      </div>

      {/* Probability */}
      <div className="text-xs font-mono text-t-muted">
        DoS probability: <span className={clsx('font-semibold', isDoS ? 'text-c-red' : 'text-c-green')}>
          {(result.probability * 100).toFixed(1)}%
        </span>
        {' '} · threshold: 45%
      </div>

      <button className="btn-ghost btn-sm" onClick={onReset}>
        <RefreshCw className="w-3.5 h-3.5" /> Analyze Another
      </button>
    </motion.div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Prediction() {
  const [values,   setValues]   = useState(DEFAULT_VALUES)
  const [expanded, setExpanded] = useState({ proto: true, volume: true, conn: false, host: false, flags: false })
  const [result,   setResult]   = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState(null)

  const applyPreset = (key) => { setValues(PRESETS[key].values); setResult(null) }
  const toggle      = (id)  => setExpanded(p => ({ ...p, [id]: !p[id] }))
  const setField    = (name, val) => setValues(p => ({ ...p, [name]: val }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true); setError(null); setResult(null)
    try {
      const { data } = await predictSingle(values)
      setResult(data)
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message)
    } finally {
      setLoading(false)
    }
  }

  if (result) return (
    <div className="max-w-lg mx-auto animate-fade-in">
      <Verdict result={result} onReset={() => setResult(null)} />
    </div>
  )

  return (
    <div className="grid grid-cols-1 lg:grid-cols-5 gap-5 animate-fade-in">
      {/* Form column */}
      <form onSubmit={handleSubmit} className="lg:col-span-3 space-y-4">
        {/* Presets */}
        <div className="panel p-4">
          <div className="text-xs font-semibold text-t-secondary uppercase tracking-widest mb-3">Quick Fill Presets</div>
          <div className="flex gap-2 flex-wrap">
            {Object.entries(PRESETS).map(([key, p]) => (
              <button
                key={key} type="button"
                onClick={() => applyPreset(key)}
                className={clsx('btn btn-sm', {
                  'bg-c-green/10 text-c-green  border border-c-green/30  hover:bg-c-green/20':  p.color === 'green',
                  'bg-c-orange/10 text-c-orange border border-c-orange/30 hover:bg-c-orange/20': p.color === 'orange',
                  'bg-c-red/10  text-c-red    border border-c-red/30   hover:bg-c-red/20':   p.color === 'red',
                })}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Collapsible sections */}
        {FORM_SECTIONS.map(({ id, title, fields }) => (
          <div key={id} className="panel">
            <button
              type="button"
              className="panel-header w-full text-left hover:text-t-primary transition-colors"
              onClick={() => toggle(id)}
            >
              <Crosshair className="w-3.5 h-3.5" />
              {title}
              <span className="ml-auto">
                {expanded[id] ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </span>
            </button>
            <AnimatePresence initial={false}>
              {expanded[id] && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  <div className="p-4 grid grid-cols-2 gap-3">
                    {fields.map(({ name, label, type, options, ...rest }) => (
                      <div key={name}>
                        <label className="field-label">{label}</label>
                        {type === 'select' ? (
                          <select
                            className="field"
                            value={values[name] ?? ''}
                            onChange={(e) => setField(name, e.target.value)}
                          >
                            {options.map(o => <option key={o} value={o}>{o}</option>)}
                          </select>
                        ) : type === 'toggle' ? (
                          <button
                            type="button"
                            onClick={() => setField(name, values[name] ? 0 : 1)}
                            className={clsx('w-full py-2 rounded-lg border text-sm font-mono transition-colors', {
                              'bg-c-cyan/10 text-c-cyan border-c-cyan/30':   values[name],
                              'bg-bg-surface text-t-muted border-b-subtle': !values[name],
                            })}
                          >
                            {values[name] ? '1 — Yes' : '0 — No'}
                          </button>
                        ) : (
                          <input
                            type="number"
                            className="field"
                            value={values[name] ?? ''}
                            onChange={(e) => setField(name, parseFloat(e.target.value) || 0)}
                            {...rest}
                          />
                        )}
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        ))}

        {error && (
          <div className="panel p-3 border-c-red/40 bg-c-red/5 text-c-red text-sm font-mono">{error}</div>
        )}

        <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-3 text-base font-semibold">
          {loading
            ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing…</>
            : <><Zap      className="w-4 h-4" />             Classify Traffic</>}
        </button>
      </form>

      {/* Right: info panel */}
      <div className="lg:col-span-2 space-y-4">
        <div className="panel p-5">
          <div className="panel-header !px-0 !pt-0 border-none !pb-3">
            <Crosshair className="w-3.5 h-3.5" /> HOW IT WORKS
          </div>
          <ol className="space-y-3 text-sm text-t-secondary">
            {[
              'Fill in the NSL-KDD traffic features (or use a preset)',
              'The record is sent to the FastAPI backend',
              'Logistic Regression evaluates 19 features through a preprocessing pipeline',
              'DoS probability ≥ 0.45 → flagged as attack',
              'Verdict is displayed with confidence % and logged to the database',
            ].map((step, i) => (
              <li key={i} className="flex gap-3">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-c-cyan/10 text-c-cyan text-xs flex items-center justify-center font-semibold border border-c-cyan/20">
                  {i + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>
        </div>

        <div className="panel p-5">
          <div className="panel-header !px-0 !pt-0 border-none !pb-3">
            <Zap className="w-3.5 h-3.5" /> KEY INDICATORS
          </div>
          <div className="space-y-2 text-xs font-mono">
            {[
              { feat: 'flag = S0',         risk: 'high', desc: 'SYN sent, no reply (neptune)' },
              { feat: 'serror_rate = 1.0', risk: 'high', desc: 'All connections have SYN error' },
              { feat: 'count = 511',       risk: 'med',  desc: 'Max connection count (flood)' },
              { feat: 'src_bytes = 0',     risk: 'med',  desc: 'No data sent (SYN-only scan)' },
              { feat: 'protocol = icmp',   risk: 'low',  desc: 'May indicate smurf/pod' },
            ].map(({ feat, risk, desc }) => (
              <div key={feat} className="flex items-start gap-2">
                <span className={clsx('mt-0.5 w-1.5 h-1.5 rounded-full flex-shrink-0', {
                  'bg-c-red':    risk === 'high',
                  'bg-c-orange': risk === 'med',
                  'bg-c-gold':   risk === 'low',
                })} />
                <div>
                  <span className="text-c-cyan">{feat}</span>
                  <span className="text-t-muted"> — {desc}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
