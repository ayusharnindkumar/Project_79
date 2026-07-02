import { useState, useEffect, useCallback } from 'react'
import { getStats, getHistory } from '../api/client'

const EMPTY_STATS = { total: 0, normal: 0, dos: 0, alert_rate: 0 }

/**
 * Polls /stats and /history every `interval` ms.
 * Returns { stats, recentAlerts, loading, error, refresh }
 */
export function useLiveStats(interval = 5000) {
  const [stats,        setStats]        = useState(EMPTY_STATS)
  const [recentAlerts, setRecentAlerts] = useState([])
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [sRes, hRes] = await Promise.all([
        getStats(),
        getHistory({ limit: 12, offset: 0 }),
      ])
      setStats({ ...EMPTY_STATS, ...(sRes.data ?? {}) })
      setRecentAlerts(Array.isArray(hRes.data?.records) ? hRes.data.records : [])
      setError(null)
    } catch (e) {
      setError(e.message)
      setStats((current) => current ?? EMPTY_STATS)
      setRecentAlerts((current) => Array.isArray(current) ? current : [])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, interval)
    return () => clearInterval(id)
  }, [refresh, interval])

  return { stats, recentAlerts, loading, error, refresh }
}
