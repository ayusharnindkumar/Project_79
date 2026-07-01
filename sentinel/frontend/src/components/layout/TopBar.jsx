import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { format } from 'date-fns'
import { Menu, RadioTower, Server, Wifi, WifiOff } from 'lucide-react'
import { getHealth } from '../../api/client'
import clsx from 'clsx'

const PAGE_TITLES = {
  '/dashboard':  'Overview Dashboard',
  '/predict':    'Single Prediction',
  '/batch':      'Batch Upload',
  '/simulation': 'Live Simulation',
  '/history':    'History & Analytics',
  '/database':   'Database Console',
}

export default function TopBar({ onMenu }) {
  const { pathname } = useLocation()
  const [now,     setNow]    = useState(new Date())
  const [online,  setOnline] = useState(true)

  // Clock tick
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  // Backend health check every 10s
  useEffect(() => {
    const check = async () => {
      try { await getHealth(); setOnline(true)  }
      catch { setOnline(false) }
    }
    check()
    const id = setInterval(check, 10000)
    return () => clearInterval(id)
  }, [])

  const title = PAGE_TITLES[pathname] ?? 'Sentinel'

  return (
    <header
      className="flex items-center justify-between gap-4 px-4 md:px-5 py-3 bg-bg-dark/90
                 border-b border-b-subtle flex-shrink-0 backdrop-blur-xl"
    >
      {/* Page title */}
      <div className="flex items-center gap-3 min-w-0">
        <button className="btn-ghost btn-sm !p-2 lg:hidden" onClick={onMenu} aria-label="Open navigation">
          <Menu className="w-4 h-4" />
        </button>
        <div className="min-w-0">
          <div className="text-[10px] md:text-xs text-t-muted font-mono tracking-widest uppercase truncate">
            Sentinel / {title}
          </div>
          <h1 className="text-sm md:text-base font-semibold text-t-primary truncate">{title}</h1>
        </div>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-2 md:gap-4">
        <div className="hidden xl:flex items-center gap-2 rounded-lg border border-b-subtle bg-bg-surface/70 px-3 py-2 text-[11px] font-mono text-t-secondary">
          <RadioTower className="w-3.5 h-3.5 text-c-cyan" />
          SOC FEED
        </div>
        <div className="hidden md:flex items-center gap-2 rounded-lg border border-b-subtle bg-bg-surface/70 px-3 py-2 text-[11px] font-mono text-t-secondary">
          <Server className="w-3.5 h-3.5 text-c-orange" />
          LR-NSL-KDD
        </div>
        {/* API status */}
        <div className={clsx(
          'flex items-center gap-1.5 text-[10px] md:text-[11px] font-mono px-2 md:px-3 py-2 rounded-lg',
          online
            ? 'text-c-green bg-c-green/10 border border-c-green/20'
            : 'text-c-red   bg-c-red/10   border border-c-red/20',
        )}>
          {online ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
          {online ? 'API CONNECTED' : 'API OFFLINE'}
        </div>

        {/* Clock */}
        <div className="hidden sm:block text-right">
          <div className="font-mono text-sm font-semibold text-c-cyan tabular-nums">
            {format(now, 'HH:mm:ss')}
          </div>
          <div className="text-[10px] text-t-muted font-mono">
            {format(now, 'yyyy-MM-dd')} UTC
          </div>
        </div>
      </div>
    </header>
  )
}
