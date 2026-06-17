export function SeverityBadge({ severity }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>
}

export function StatusBadge({ status }) {
  const label = status.replace('_', ' ')
  return <span className={`badge badge-${status}`}>{label}</span>
}

export function IPCell({ ip }) {
  if (!ip) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  return (
    <span style={{
      fontFamily: 'var(--font-mono)', fontSize: 12,
      color: 'var(--text-primary)',
    }}>{ip}</span>
  )
}

export function TimeCell({ ts }) {
  if (!ts) return null
  const d = new Date(ts)
  return (
    <span style={{
      fontFamily: 'var(--font-mono)', fontSize: 11,
      color: 'var(--text-muted)',
      whiteSpace: 'nowrap',
    }}>
      {d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
      <span style={{ opacity: .5, marginLeft: 4 }}>
        {d.toLocaleDateString([], { month: 'short', day: 'numeric' })}
      </span>
    </span>
  )
}

export function Spinner() {
  return (
    <div style={{
      width: 18, height: 18,
      border: '2px solid var(--border)',
      borderTopColor: 'var(--accent)',
      borderRadius: '50%',
      animation: 'spin .6s linear infinite',
      display: 'inline-block',
    }} />
  )
}

export function EmptyState({ icon: Icon, message, sub }) {
  return (
    <div className="empty-state">
      {Icon && <Icon size={36} />}
      <div style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{message}</div>
      {sub && <div style={{ fontSize: 12 }}>{sub}</div>}
    </div>
  )
}
