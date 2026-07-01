import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Crosshair, Upload, Activity, Clock, Database, ShieldAlert, X,
} from 'lucide-react'
import clsx from 'clsx'

const NAV = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard'   },
  { to: '/predict',    icon: Crosshair,        label: 'Prediction'  },
  { to: '/batch',      icon: Upload,           label: 'Batch Upload'},
  { to: '/simulation', icon: Activity,         label: 'Live Sim'   },
  { to: '/history',    icon: Clock,            label: 'History'    },
  { to: '/database',   icon: Database,         label: 'Database'   },
]

export default function Sidebar({ open = false, onClose }) {
  return (
    <aside
      className={clsx(
        'fixed inset-y-0 left-0 z-40 w-[248px] flex-shrink-0 flex flex-col bg-bg-dark/95',
        'border-r border-b-subtle shadow-2xl backdrop-blur-xl transition-transform duration-200 lg:relative lg:z-10 lg:translate-x-0',
        open ? 'translate-x-0' : '-translate-x-full',
      )}
      aria-label="Main navigation"
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-b-subtle">
        <div className="relative flex-shrink-0">
          <div className="h-10 w-10 rounded-lg border border-c-cyan/30 bg-c-cyan/10 flex items-center justify-center shadow-glow-cyan">
            <ShieldAlert className="w-6 h-6 text-c-cyan" />
          </div>
          <span className="scanner-ring w-7 h-7 top-0 left-0" style={{ animationDelay: '0s' }} />
          <span className="scanner-ring w-7 h-7 top-0 left-0" style={{ animationDelay: '1.5s' }} />
        </div>
        <div>
          <div className="font-black text-base text-t-primary leading-tight tracking-wide">SENTINEL</div>
          <div className="text-[10px] text-c-cyan tracking-widest uppercase font-mono">DoS Command Center</div>
        </div>
        <button className="ml-auto btn-ghost btn-sm !p-2 lg:hidden" onClick={onClose} aria-label="Close navigation">
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5" role="navigation">
        <div className="text-[9px] font-semibold text-t-muted tracking-widest uppercase px-2 mb-3">
          Navigation
        </div>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            onClick={onClose}
            className={({ isActive }) =>
              clsx('nav-item', isActive && 'active')
            }
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-4 py-4 border-t border-b-subtle">
        <div className="mb-3 rounded-lg border border-b-subtle bg-bg-surface/70 p-3">
          <div className="flex items-center justify-between text-[10px] uppercase tracking-widest text-t-muted">
            <span>Model</span>
            <span className="text-c-green">armed</span>
          </div>
          <div className="mt-2 h-1.5 rounded-full bg-bg-deep overflow-hidden">
            <div className="h-full w-[92%] rounded-full bg-gradient-to-r from-c-cyan via-c-green to-c-orange" />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-c-green animate-pulse" />
          <span className="text-[10px] text-t-muted font-mono">MODEL ONLINE</span>
        </div>
        <div className="text-[9px] text-t-muted mt-1 font-mono">
          LR · threshold=0.45 · NSL-KDD
        </div>
      </div>
    </aside>
  )
}
