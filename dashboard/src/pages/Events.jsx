import { useState, useEffect, useRef } from 'react'
import { Radio, Filter, Trash2, Wifi, WifiOff } from 'lucide-react'
import { useSSE } from '../hooks'
import { SeverityBadge, IPCell, TimeCell, EmptyState } from '../components/Badges'

const SEV_OPTIONS   = ['', 'critical', 'high', 'medium', 'low']
const CAT_OPTIONS   = ['', 'authentication', 'privilege_escalation', 'account_management', 'network', 'web', 'system']
const MAX_ROWS      = 200

export default function EventsPage() {
  const [sevFilter, setSevFilter]   = useState('')
  const [catFilter, setCatFilter]   = useState('')
  const [search,    setSearch]      = useState('')
  const [paused,    setPaused]      = useState(false)
  const [allItems,  setAllItems]    = useState([])
  const bottomRef                   = useRef(null)

  const { connected, items: streamItems, clear } = useSSE(
    '/api/events/stream/live',
    null,
    MAX_ROWS
  )

  // Merge stream items → allItems when not paused
  useEffect(() => {
    if (paused) return
    setAllItems(streamItems)
  }, [streamItems, paused])

  // Filter
  const filtered = allItems.filter(e => {
    if (sevFilter && e.severity !== sevFilter) return false
    if (catFilter && e.category !== catFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return (
        (e.source_ip   || '').includes(q) ||
        (e.event_type  || '').includes(q) ||
        (e.message     || '').toLowerCase().includes(q) ||
        (e.username    || '').includes(q)
      )
    }
    return true
  })

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">Live Event Feed</div>
          <div className="page-subtitle">
            Real-time stream · {allItems.length} events buffered
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {/* Connection badge */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12,
            color: connected ? 'var(--ok)' : 'var(--danger)',
            fontFamily: 'var(--font-mono)' }}>
            {connected ? <Wifi size={14} /> : <WifiOff size={14} />}
            {connected ? 'Live' : 'Disconnected'}
          </div>
          <button className={`btn btn-sm ${paused ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setPaused(p => !p)}>
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button className="btn btn-sm btn-ghost" onClick={() => { clear(); setAllItems([]) }}>
            <Trash2 size={13} /> Clear
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative' }}>
          <Filter size={13} style={{ position: 'absolute', left: 10, top: '50%',
            transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input className="input" placeholder="Search IP, type, user..."
            style={{ paddingLeft: 30, width: 220 }}
            value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <select className="input" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="">All severities</option>
          {SEV_OPTIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select className="input" value={catFilter} onChange={e => setCatFilter(e.target.value)}>
          <option value="">All categories</option>
          {CAT_OPTIONS.filter(Boolean).map(c => (
            <option key={c} value={c}>{c.replace(/_/g, ' ')}</option>
          ))}
        </select>
        <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)',
          alignSelf: 'center', fontFamily: 'var(--font-mono)' }}>
          {filtered.length} / {allItems.length}
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto', maxHeight: 'calc(100vh - 260px)', overflowY: 'auto' }}>
          <table className="data-table">
            <thead style={{ position: 'sticky', top: 0, background: 'var(--surface)', zIndex: 1 }}>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Source IP</th>
                <th>User</th>
                <th>Category</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={7}>
                  <EmptyState icon={Radio}
                    message={connected ? 'Waiting for events…' : 'Not connected to stream'}
                    sub={connected ? 'Events will appear here in real time' : 'Check API server'} />
                </td></tr>
              ) : (
                filtered.map((e, i) => (
                  <tr key={e._id || i} className={e._new ? 'row-new' : ''}>
                    <td><TimeCell ts={e.timestamp} /></td>
                    <td><SeverityBadge severity={e.severity || 'low'} /></td>
                    <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                      color: 'var(--text-primary)' }}>{e.event_type}</span></td>
                    <td><IPCell ip={e.source_ip} /></td>
                    <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: 12,
                      color: 'var(--text-secondary)' }}>{e.username || '—'}</span></td>
                    <td><span style={{ fontSize: 11, color: 'var(--text-muted)',
                      textTransform: 'capitalize' }}>{(e.category || '').replace(/_/g,' ')}</span></td>
                    <td style={{ maxWidth: 320 }}>
                      <span style={{ fontSize: 12, color: 'var(--text-secondary)',
                        display: 'block', overflow: 'hidden', textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap' }}>{e.message}</span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  )
}
