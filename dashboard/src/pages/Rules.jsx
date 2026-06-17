import { useState } from 'react'
import { BookOpen, RefreshCw, ToggleLeft, ToggleRight, Shield } from 'lucide-react'
import { rulesApi } from '../lib/api'
import { useFetch } from '../hooks'
import { useToast } from '../lib/toast'
import { SeverityBadge, EmptyState, Spinner } from '../components/Badges'

const SEV_OPTIONS = ['low', 'medium', 'high', 'critical']

function RuleRow({ rule, onUpdate }) {
  const [editSev, setEditSev] = useState(false)
  const [saving,  setSaving]  = useState(false)
  const toast = useToast()

  async function toggle() {
    setSaving(true)
    try {
      const updated = await rulesApi.update(rule.rule_id, { enabled: !rule.enabled })
      toast(`Rule ${updated.enabled ? 'enabled' : 'disabled'}`, 'success')
      onUpdate(updated)
    } catch (e) {
      toast(e.message, 'error')
    } finally { setSaving(false) }
  }

  async function changeSeverity(sev) {
    setSaving(true)
    setEditSev(false)
    try {
      const updated = await rulesApi.update(rule.rule_id, { severity: sev })
      toast('Severity updated', 'success')
      onUpdate(updated)
    } catch (e) {
      toast(e.message, 'error')
    } finally { setSaving(false) }
  }

  return (
    <tr style={{ opacity: rule.enabled ? 1 : 0.45 }}>
      <td>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
          color: 'var(--accent)' }}>{rule.rule_id}</span>
      </td>
      <td>
        <div style={{ fontWeight: 500, color: 'var(--text-primary)', fontSize: 13 }}>
          {rule.name}
        </div>
        {rule.description && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            {rule.description}
          </div>
        )}
      </td>
      <td>
        {editSev ? (
          <select className="input" autoFocus defaultValue={rule.severity}
            onBlur={() => setEditSev(false)}
            onChange={e => changeSeverity(e.target.value)}
            style={{ padding: '3px 8px', fontSize: 12 }}>
            {SEV_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        ) : (
          <div onClick={() => setEditSev(true)} style={{ cursor: 'pointer' }}
            title="Click to change severity">
            <SeverityBadge severity={rule.severity} />
          </div>
        )}
      </td>
      <td>
        <span style={{ fontSize: 11, color: 'var(--text-muted)',
          textTransform: 'capitalize' }}>{rule.category?.replace(/_/g, ' ')}</span>
      </td>
      <td>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
          color: 'var(--text-muted)' }}>{rule.condition_type}</span>
      </td>
      <td>
        {rule.mitre_technique ? (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10,
            color: 'var(--text-muted)' }}>{rule.mitre_technique}</span>
        ) : '—'}
      </td>
      <td>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12,
          color: rule.fire_count > 0 ? 'var(--warn)' : 'var(--text-muted)' }}>
          {rule.fire_count}
        </span>
      </td>
      <td>
        <button className="btn btn-ghost btn-icon" onClick={toggle} disabled={saving}
          title={rule.enabled ? 'Disable rule' : 'Enable rule'}>
          {rule.enabled
            ? <ToggleRight size={20} color="var(--ok)" />
            : <ToggleLeft  size={20} color="var(--text-muted)" />}
        </button>
      </td>
    </tr>
  )
}

export default function RulesPage() {
  const [syncing, setSyncing] = useState(false)
  const toast  = useToast()

  const { data: rules, loading, refetch } = useFetch(() => rulesApi.list(), [])

  function handleUpdate(updated) {
    refetch()
  }

  async function syncRules() {
    setSyncing(true)
    try {
      const res = await rulesApi.sync()
      toast(`Synced: ${res.inserted} inserted, ${res.updated} updated`, 'success')
      refetch()
    } catch (e) {
      toast(e.message, 'error')
    } finally { setSyncing(false) }
  }

  const ruleList    = rules ?? []
  const enabledCount = ruleList.filter(r => r.enabled).length

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Detection Rules</div>
          <div className="page-subtitle">
            {enabledCount} / {ruleList.length} rules active
          </div>
        </div>
        <button className="btn btn-ghost" onClick={syncRules} disabled={syncing}>
          <RefreshCw size={14} className={syncing ? 'spin' : ''} />
          {syncing ? 'Syncing…' : 'Sync rules.yaml'}
        </button>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}>
            <Spinner />
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Rule</th>
                <th>Severity <span style={{ fontWeight: 400, opacity: .6 }}>(click to edit)</span></th>
                <th>Category</th>
                <th>Type</th>
                <th>MITRE</th>
                <th>Fires</th>
                <th>Enabled</th>
              </tr>
            </thead>
            <tbody>
              {ruleList.length === 0 ? (
                <tr><td colSpan={8}>
                  <EmptyState icon={BookOpen} message="No rules loaded"
                    sub='Click "Sync rules.yaml" to load detection rules' />
                </td></tr>
              ) : (
                ruleList.map(r => (
                  <RuleRow key={r.rule_id} rule={r} onUpdate={handleUpdate} />
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Coverage summary */}
      {ruleList.length > 0 && (
        <div style={{ marginTop: 16, display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
          {['authentication', 'privilege_escalation', 'account_management', 'network'].map(cat => {
            const count   = ruleList.filter(r => r.category === cat).length
            const enabled = ruleList.filter(r => r.category === cat && r.enabled).length
            return (
              <div key={cat} className="card" style={{ padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <Shield size={14} color="var(--accent)" />
                  <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.05em',
                    textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    {cat.replace(/_/g, ' ')}
                  </span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 22,
                  fontWeight: 700, color: 'var(--text-primary)' }}>
                  {enabled}<span style={{ fontSize: 13, color: 'var(--text-muted)',
                    fontWeight: 400 }}>/{count}</span>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
