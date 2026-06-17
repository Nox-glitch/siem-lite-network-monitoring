import { useState } from 'react'
import { Bell, CheckCircle, XCircle, Flag, ChevronDown, ChevronUp, Filter } from 'lucide-react'
import { alertsApi } from '../lib/api'
import { useFetch } from '../hooks'
import { useToast } from '../lib/toast'
import { SeverityBadge, StatusBadge, IPCell, TimeCell, EmptyState, Spinner } from '../components/Badges'

const SEV_OPTIONS    = ['', 'critical', 'high', 'medium', 'low']
const STATUS_OPTIONS = ['', 'open', 'acknowledged', 'resolved', 'false_positive']

function AlertRow({ alert, onUpdate }) {
  const [expanded, setExpanded] = useState(false)
  const [notes,    setNotes]    = useState(alert.analyst_notes || '')
  const [saving,   setSaving]   = useState(false)
  const toast = useToast()

  async function action(fn, label) {
    try {
      const updated = await fn(alert.id)
      toast(`Alert ${label}`, 'success')
      onUpdate(updated)
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  async function saveNotes() {
    setSaving(true)
    try {
      const updated = await alertsApi.update(alert.id, { analyst_notes: notes })
      toast('Notes saved', 'success')
      onUpdate(updated)
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      setSaving(false)
    }
  }

  const isOpen = alert.status === 'open'

  return (
    <>
      <tr style={{ cursor: 'pointer' }} onClick={() => setExpanded(e => !e)}>
        <td><TimeCell ts={alert.created_at} /></td>
        <td><SeverityBadge severity={alert.severity} /></td>
        <td>
          <div style={{ fontWeight: 500, color: 'var(--text-primary)', fontSize: 13 }}>
            {alert.rule_name}
          </div>
          {alert.mitre_technique && (
            <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)',
              color: 'var(--text-muted)', marginTop: 2 }}>{alert.mitre_technique}</div>
          )}
        </td>
        <td><IPCell ip={alert.source_ip} /></td>
        <td>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
            color: 'var(--text-muted)' }}>{alert.event_count}×</span>
        </td>
        <td><StatusBadge status={alert.status} /></td>
        <td onClick={e => e.stopPropagation()}>
          <div style={{ display: 'flex', gap: 4 }}>
            {isOpen && (
              <>
                <button className="btn btn-sm btn-ghost"
                  title="Acknowledge"
                  onClick={() => action(alertsApi.acknowledge, 'acknowledged')}>
                  <CheckCircle size={13} color="var(--warn)" />
                </button>
                <button className="btn btn-sm btn-ghost"
                  title="Resolve"
                  onClick={() => action(alertsApi.resolve, 'resolved')}>
                  <CheckCircle size={13} color="var(--ok)" />
                </button>
                <button className="btn btn-sm btn-ghost"
                  title="False positive"
                  onClick={() => action(alertsApi.falsePositive, 'marked as false positive')}>
                  <Flag size={13} color="var(--text-muted)" />
                </button>
              </>
            )}
          </div>
        </td>
        <td>
          {expanded ? <ChevronUp size={14} color="var(--text-muted)" />
                    : <ChevronDown size={14} color="var(--text-muted)" />}
        </td>
      </tr>

      {/* Expanded detail row */}
      {expanded && (
        <tr>
          <td colSpan={8} style={{ background: 'var(--surface-2)', padding: '16px 20px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
              {/* Left: details */}
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.06em',
                  textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 10 }}>
                  Alert Details
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
                  <Row label="Rule ID"        value={alert.rule_id} mono />
                  <Row label="Description"    value={alert.description} />
                  <Row label="MITRE Tactic"   value={alert.mitre_tactic} />
                  <Row label="MITRE Technique" value={alert.mitre_technique} />
                  <Row label="Playbook"       value={alert.playbook_triggered} mono />
                  {alert.playbook_result && (
                    <Row label="Playbook Result"
                      value={JSON.stringify(alert.playbook_result, null, 2)} mono pre />
                  )}
                  {alert.tags?.length > 0 && (
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                      {alert.tags.map(t => (
                        <span key={t} style={{ background: 'var(--border)', color: 'var(--text-muted)',
                          borderRadius: 4, padding: '1px 7px', fontSize: 10,
                          fontFamily: 'var(--font-mono)' }}>{t}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Right: analyst notes */}
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.06em',
                  textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 10 }}>
                  Analyst Notes
                </div>
                <textarea
                  className="input"
                  style={{ width: '100%', minHeight: 100, resize: 'vertical', lineHeight: 1.5 }}
                  placeholder="Add investigation notes…"
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                />
                <button className="btn btn-primary btn-sm" style={{ marginTop: 8 }}
                  onClick={saveNotes} disabled={saving}>
                  {saving ? 'Saving…' : 'Save Notes'}
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function Row({ label, value, mono, pre }) {
  if (!value) return null
  return (
    <div style={{ display: 'flex', gap: 8 }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 120 }}>{label}:</span>
      {pre ? (
        <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)',
          whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{value}</pre>
      ) : (
        <span style={{ fontFamily: mono ? 'var(--font-mono)' : 'inherit',
          fontSize: mono ? 11 : 12, color: 'var(--text-secondary)' }}>{value}</span>
      )}
    </div>
  )
}

export default function AlertsPage() {
  const [sevFilter,    setSevFilter]    = useState('')
  const [statusFilter, setStatusFilter] = useState('open')
  const [search,       setSearch]       = useState('')
  const [page,         setPage]         = useState(1)
  const toast = useToast()

  const params = {
    page, size: 50,
    ...(sevFilter    && { severity: sevFilter }),
    ...(statusFilter && { status:   statusFilter }),
    ...(search       && { search }),
  }

  const { data, loading, refetch } = useFetch(
    () => alertsApi.list(params),
    [page, sevFilter, statusFilter, search]
  )

  function handleUpdate(updated) {
    refetch()
  }

  const alerts = data?.items ?? []
  const total  = data?.total ?? 0

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Alerts</div>
          <div className="page-subtitle">{total} matching alerts</div>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative' }}>
          <Filter size={13} style={{ position: 'absolute', left: 10, top: '50%',
            transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input className="input" placeholder="Search rule, IP..."
            style={{ paddingLeft: 30, width: 200 }}
            value={search} onChange={e => { setSearch(e.target.value); setPage(1) }} />
        </div>
        <select className="input" value={sevFilter}
          onChange={e => { setSevFilter(e.target.value); setPage(1) }}>
          <option value="">All severities</option>
          {SEV_OPTIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select className="input" value={statusFilter}
          onChange={e => { setStatusFilter(e.target.value); setPage(1) }}>
          <option value="">All statuses</option>
          {STATUS_OPTIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
          ))}
        </select>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><Spinner /></div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Source IP</th>
                  <th>Count</th>
                  <th>Status</th>
                  <th>Actions</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 ? (
                  <tr><td colSpan={8}>
                    <EmptyState icon={Bell} message="No alerts found"
                      sub="Try changing filters or time range" />
                  </td></tr>
                ) : (
                  alerts.map(a => (
                    <AlertRow key={a.id} alert={a} onUpdate={handleUpdate} />
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {total > 50 && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
          <button className="btn btn-ghost btn-sm" disabled={page === 1}
            onClick={() => setPage(p => p - 1)}>← Prev</button>
          <span style={{ fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center',
            fontFamily: 'var(--font-mono)' }}>
            {page} / {Math.ceil(total / 50)}
          </span>
          <button className="btn btn-ghost btn-sm" disabled={page >= Math.ceil(total / 50)}
            onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      )}
    </div>
  )
}
