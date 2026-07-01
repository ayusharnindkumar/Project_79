import clsx from 'clsx'
import { ShieldCheck, ShieldAlert } from 'lucide-react'

export function ThreatBadge({ label, size = 'sm' }) {
  const isDoS = label === 'DoS Attack'
  return (
    <span className={clsx(
      isDoS ? 'badge-dos' : 'badge-normal',
      size === 'lg' && 'text-sm px-3 py-1',
    )}>
      {isDoS
        ? <ShieldAlert className="w-3 h-3" />
        : <ShieldCheck  className="w-3 h-3" />}
      {label}
    </span>
  )
}

export function ConfidenceBar({ value, label }) {
  const isDoS  = label === 'DoS Attack'
  const pct    = Math.round(value * 100)
  return (
    <div>
      <div className="flex justify-between text-xs text-t-secondary mb-1">
        <span>Confidence</span>
        <span className={clsx('font-mono font-semibold', isDoS ? 'text-c-red' : 'text-c-green')}>
          {pct}%
        </span>
      </div>
      <div className="h-1.5 bg-bg-surface rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all duration-500', isDoS ? 'bg-c-red' : 'bg-c-green')}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}
