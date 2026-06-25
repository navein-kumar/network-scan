// usePolling: fetch on mount, re-fetch on an interval, and expose a manual
// reload. Returns the same { data, loading, error, reload } shape every page
// in the app consumes.
import { useCallback, useEffect, useRef, useState, type DependencyList } from 'react'

export interface PollingResult<T> {
  data: T | null
  loading: boolean
  error: string | null
  reload: () => void
}

export function usePolling<T>(
  fetcher: () => Promise<T>,
  interval?: number,
  deps: DependencyList = [],
): PollingResult<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const alive = useRef(true)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  const run = useCallback(async (showLoading: boolean) => {
    if (showLoading) setLoading(true)
    try {
      const result = await fetcherRef.current()
      if (!alive.current) return
      setData(result)
      setError(null)
    } catch (e) {
      if (!alive.current) return
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      if (alive.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    alive.current = true
    run(true)
    let timer: number | undefined
    if (interval && interval > 0) {
      timer = window.setInterval(() => run(false), interval)
    }
    return () => {
      alive.current = false
      if (timer) window.clearInterval(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return {
    data,
    loading,
    error,
    reload: useCallback(() => {
      run(true)
    }, [run]),
  }
}
