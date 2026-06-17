import { useState, useEffect, useRef, useCallback } from 'react'

// ── Generic data fetcher ──────────────────────────────────────────────
export function useFetch(fetcher, deps = []) {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await fetcher()
      setData(result)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, deps) // eslint-disable-line

  useEffect(() => { load() }, [load])
  return { data, loading, error, refetch: load }
}

// ── Auto-refreshing fetcher ───────────────────────────────────────────
export function usePolling(fetcher, intervalMs = 10000, deps = []) {
  const result = useFetch(fetcher, deps)
  useEffect(() => {
    const id = setInterval(result.refetch, intervalMs)
    return () => clearInterval(id)
  }, [intervalMs]) // eslint-disable-line
  return result
}

// ── Server-Sent Events stream ─────────────────────────────────────────
export function useSSE(url, onMessage, maxBuffer = 100) {
  const [connected, setConnected] = useState(false)
  const [items,     setItems]     = useState([])
  const esRef = useRef(null)

  useEffect(() => {
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        onMessage?.(data)
        setItems(prev => [{ ...data, _new: true, _id: Date.now() }, ...prev].slice(0, maxBuffer))
      } catch {}
    }

    return () => { es.close(); setConnected(false) }
  }, [url]) // eslint-disable-line

  return { connected, items, clear: () => setItems([]) }
}
