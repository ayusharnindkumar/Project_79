import { useEffect, useRef, useCallback } from 'react'
import { getSimulateURL } from '../api/client'

/**
 * Opens an SSE connection to /api/simulate/stream and calls onRecord for each event.
 * Automatically closes the stream when isRunning becomes false.
 *
 * @param {object} opts
 * @param {boolean} opts.isRunning
 * @param {number}  opts.speed        - records per second
 * @param {number}  opts.count        - total records to emit
 * @param {number}  opts.attackRate   - fraction that are attacks
 * @param {function}opts.onRecord     - called with parsed record object
 * @param {function}opts.onDone       - called when stream ends
 * @param {function}opts.onError      - called on error
 */
export function useSSEStream({ isRunning, speed = 1, count = 200, attackRate = 0.3, onRecord, onDone, onError }) {
  const esRef = useRef(null)

  const close = useCallback(() => {
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }
  }, [])

  useEffect(() => {
    if (!isRunning) { close(); return }

    const url = getSimulateURL(speed, count, attackRate)
    const es  = new EventSource(url)
    esRef.current = es

    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.done) { onDone?.(); close() }
        else           { onRecord?.(data) }
      } catch {}
    }

    es.onerror = () => {
      onError?.()
      close()
    }

    return close
  }, [isRunning, speed, count, attackRate])   // eslint-disable-line react-hooks/exhaustive-deps
}
