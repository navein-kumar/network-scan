// useScanStream: subscribe to the live SSE stream for a running scan and keep
// progress, per-host status, the rolling log buffer, and a live finding count
// in React state. Reconnects automatically (3s backoff) until the scan ends.
import { useEffect, useRef, useState } from 'react'
import { openScanStream } from './api'
import { emptySeverity } from './types'
import type { ProgressHost, ScanStatus, SeverityCounts } from './types'

const MAX_LOG_LINES = 500

export interface ScanStreamState {
  connected: boolean
  overall: number
  hostsDone: number
  hostsTotal: number
  hosts: ProgressHost[]
  logs: string[]
  done: { status: ScanStatus; severity: SeverityCounts } | null
  liveFindingCount: number
}

const INITIAL: ScanStreamState = {
  connected: false,
  overall: 0,
  hostsDone: 0,
  hostsTotal: 0,
  hosts: [],
  logs: [],
  done: null,
  liveFindingCount: 0,
}

export function useScanStream(id: string, enabled: boolean): ScanStreamState {
  const [state, setState] = useState<ScanStreamState>(INITIAL)
  const esRef = useRef<EventSource | null>(null)
  const retryRef = useRef<number | undefined>(undefined)
  const closed = useRef(false)

  useEffect(() => {
    if (!enabled || !id) return
    closed.current = false

    function connect() {
      if (closed.current) return
      const es = openScanStream(id, {
        onOpen: () => {
          setState((s) => ({ ...s, connected: true }))
        },
        onProgress: (e) => {
          try {
            const p = JSON.parse(e.data)
            setState((s) => ({
              ...s,
              overall: p.overall ?? s.overall,
              hostsDone: p.hosts_done ?? s.hostsDone,
              hostsTotal: p.hosts_total ?? s.hostsTotal,
              hosts: Array.isArray(p.hosts) ? p.hosts : s.hosts,
            }))
          } catch {
            // ignore malformed progress payloads
          }
        },
        onFinding: () => {
          setState((s) => ({ ...s, liveFindingCount: s.liveFindingCount + 1 }))
        },
        onLog: (e) => {
          try {
            const l = JSON.parse(e.data)
            if (typeof l.line === 'string') {
              setState((s) => {
                const logs = [...s.logs, l.line]
                if (logs.length > MAX_LOG_LINES) logs.splice(0, logs.length - MAX_LOG_LINES)
                return { ...s, logs }
              })
            }
          } catch {
            // ignore malformed log payloads
          }
        },
        onDone: (e) => {
          try {
            const d = JSON.parse(e.data)
            setState((s) => ({
              ...s,
              done: { status: d.status, severity: d.severity ?? emptySeverity() },
              overall: 100,
              connected: true,
            }))
          } catch {
            setState((s) => ({ ...s, done: { status: 'done', severity: emptySeverity() } }))
          }
          closed.current = true
          es.close()
        },
        onError: () => {
          setState((s) => ({ ...s, connected: false }))
          es.close()
          if (!closed.current) {
            retryRef.current = window.setTimeout(connect, 3000)
          }
        },
      })
      esRef.current = es
    }

    connect()
    return () => {
      closed.current = true
      if (retryRef.current) window.clearTimeout(retryRef.current)
      esRef.current?.close()
    }
  }, [id, enabled])

  return state
}
