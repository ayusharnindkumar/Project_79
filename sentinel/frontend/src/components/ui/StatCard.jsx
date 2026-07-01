import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import clsx from 'clsx'

/**
 * Animated stat counter card.
 * Props: title, value, icon (Lucide component), color, delta, suffix, pulse
 */
export default function StatCard({ title, value, icon: Icon, color = 'cyan', suffix = '', pulse = false }) {
  const colorMap = {
    cyan:   { text: 'text-c-cyan',   glow: 'shadow-glow-cyan',  bg: 'bg-c-cyan/8'  },
    green:  { text: 'text-c-green',  glow: 'shadow-glow-green', bg: 'bg-c-green/8' },
    red:    { text: 'text-c-red',    glow: 'shadow-glow-red',   bg: 'bg-c-red/8'   },
    orange: { text: 'text-c-orange', glow: '',                  bg: 'bg-c-orange/8'},
    gold:   { text: 'text-c-gold',   glow: '',                  bg: 'bg-c-gold/8'  },
  }
  const { text, glow, bg } = colorMap[color] ?? colorMap.cyan

  // Animate the displayed numeric value
  const [displayed, setDisplayed] = useState(0)
  const prevRef  = useRef(0)
  const timerRef = useRef(null)

  useEffect(() => {
    const numVal = typeof value === 'number' ? value : parseFloat(value) || 0
    const prev   = prevRef.current
    prevRef.current = numVal

    if (timerRef.current) clearInterval(timerRef.current)

    const steps    = 20
    const stepVal  = (numVal - prev) / steps
    let   current  = prev
    let   step     = 0

    timerRef.current = setInterval(() => {
      step++
      current += stepVal
      if (step >= steps) {
        setDisplayed(numVal)
        clearInterval(timerRef.current)
      } else {
        setDisplayed(Math.round(current * 10) / 10)
      }
    }, 30)

    return () => clearInterval(timerRef.current)
  }, [value])

  const displayStr = typeof value === 'string' && isNaN(parseFloat(value))
    ? value
    : (Number.isInteger(typeof value === 'number' ? value : parseFloat(value))
        ? Math.round(displayed).toLocaleString()
        : displayed.toFixed(1)) + suffix

  return (
    <motion.div
      className="panel p-5 flex flex-col gap-3"
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      {/* Icon + title */}
      <div className="flex items-start justify-between">
        <div className={clsx('p-2 rounded-lg', bg)}>
          <Icon className={clsx('w-5 h-5', text)} />
        </div>
        {pulse && (
          <span className="relative flex h-2 w-2 mt-1">
            <span className={clsx('animate-ping absolute inline-flex h-full w-full rounded-full opacity-75', bg.replace('/8', '/40'))} />
            <span className={clsx('relative inline-flex rounded-full h-2 w-2', text.replace('text-', 'bg-'))} />
          </span>
        )}
      </div>

      {/* Value */}
      <div>
        <AnimatePresence mode="wait">
          <motion.div
            key={displayStr}
            className={clsx('stat-value', text)}
            initial={{ opacity: 0.6, y: -4 }}
            animate={{ opacity: 1,   y:  0 }}
            transition={{ duration: 0.25 }}
          >
            {displayStr}
          </motion.div>
        </AnimatePresence>
        <div className="text-xs text-t-secondary mt-0.5 font-medium tracking-wide">
          {title}
        </div>
      </div>
    </motion.div>
  )
}
