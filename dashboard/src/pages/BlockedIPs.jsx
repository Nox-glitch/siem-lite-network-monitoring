import { useState } from 'react'
import { Ban, Plus, Unlock, Shield } from 'lucide-react'
import { blockedIpsApi } from '../lib/api'
import { useFetch } from '../hooks'
import { useToast } from '../lib/toast'
import { IPCell, TimeCell, EmptyState, Spinner } from '../components/Badges'

function BlockIPModal({ onClose, onBlocked }) {
  const [ip,     setIp]     = useState('')
  const [reason, setReason] = useState('')
  const [mins,   setMins]   = useState('')
  const [saving, setSaving] = useState(false)
  const toast = useToast()

  async function submit() {
    if (!ip.trim() || !reason.trim()) {
      toast('IP and reason are required', 'error'); return
    }
    setSaving(true)
    try {
      await blockedIpsApi.block({
        ip_address: ip.trim(),
        reason:     reason.trim(),
        ...(mins ? { auto_unblock_after: parseInt(mins) } : {}),
      })
      toast(`${ip} blocked`, 'success')
      onBlocked()
      onClose()
    } catch (e) {
      toast(e.message, 'error')
    } finally { setSaving(false) }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 200,
    }} onClick={onClose}>
      <div className="card" style={{ width: 420, padding: 24 }}
        onClick={e => e.stopPropagation()}>
        <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 20,
          color: 'var(--text-primary)' }}>Block IP Address</div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.06em',
              textTransform: 'uppercase', color: 'var(--text-muted)',
              display: 'block', marginBottom: 6 }}>IP Address *</label>
            <input className="input" style={{ width: '100%' }}
              placeholder="e.g. 1.2.3.4"
              value={ip} onChange={e => setIp(e.target.value)} />
          </div>
          <div>
            <label style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.06em',
              textTransform: 'uppercase', color: 'var(--text-muted)',
              display: 'block', marginBottom: 6 }}>Reason *</label>
            <input className="input" style={{ width: '100%' }}
              placeholder="Why is this IP being blocked?"
              value={reason} onChange={e => setReason(e.target.value)} />
          </div>
          <div>
            <label style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.06em',
              textTransform: 'uppercase', color: 'var(--text-muted)',
              display: 'block', marginBottom: 6 }}>Auto-unblock after (minutes)</label>
            <input className="input" style={{ width: '100%' }} type="number" min="0"
              placeholder="Leave blank for permanent block"
              value={mins} onChange={e => setMins(e.target.value)} />
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 20 }}>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-danger" onClick={submit} disabled={saving}>
            <Ban size={14} />
            {saving ? 'Blocking…' : 'Block IP'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function BlockedIPsPage() {
  const [showModal,   setShowModal]   = useState(false)
  const [activeOnly,  setActiveOnly]  = useState(true)
  const toast = useToast()

  const { data, loading, refetch } = useFetch(
    () => blockedIpsApi.list(activeOnly),
    [activeOnly]
  )

  async function unblock(ip) {
    try {
      await blockedIpsApi.unblock(ip)
      toast(`${ip} unblocked`, 'success')
      refetch()
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  const ips = data ?? []

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Blocked IPs</div>
          <div className="page-subtitle">{ips.length} {activeOnly ? 'active' : 'total'} blocks</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className={`btn btn-sm ${activeOnly ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setActiveOnly(true)}>Active</button>
          <button
            className={`btn btn-sm ${!activeOnly ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setActiveOnly(false)}>All</button>
          <button className="btn btn-danger" onClick={() => setShowModal(true)}>
            <Plus size={14} /> Block IP
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 16 }}>
        {[
          { label: 'Active Blocks',    value: ips.filter(i => i.is_active).length,  color: 'var(--danger)' },
          { label: 'Auto-unblock Set', value: ips.filter(i => i.auto_unblock_after).length, color: 'var(--warn)' },
          { label: 'From Alerts',      value: ips.filter(i => i.alert_id).length,    color: 'var(--accent)' },
        ].map(c => (
          <div key={c.label} className="card" style={{
            display: 'flex', alignItems: 'center', gap: 14, padding: '14px 18px'
          }}>
            <Shield size={22} color={c.color} />
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 26,
                fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                {c.value}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 3 }}>
                {c.label}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><Spinner /></div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Blocked At</th>
                <th>Auto-unblock</th>
                <th>Alert ID</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {ips.length === 0 ? (
                <tr><td colSpan={7}>
                  <EmptyState icon={Shield} message="No blocked IPs"
                    sub="Blocks appear here automatically when playbooks fire, or add one manually" />
                </td></tr>
              ) : (
                ips.map(ip => (
                  <tr key={ip.id}>
                    <td><IPCell ip={ip.ip_address} /></td>
                    <td style={{ maxWidth: 280 }}>
                      <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        {ip.reason}
                      </span>
                    </td>
                    <td><TimeCell ts={ip.blocked_at} /></td>
                    <td>
                      {ip.auto_unblock_after ? (
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                          color: 'var(--warn)' }}>{ip.auto_unblock_after}m</span>
                      ) : (
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Never</span>
                      )}
                    </td>
                    <td>
                      {ip.alert_id
                        ? <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                            color: 'var(--accent)' }}>#{ip.alert_id}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>Manual</span>}
                    </td>
                    <td>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        padding: '2px 8px', borderRadius: 99, fontSize: 11,
                        fontFamily: 'var(--font-mono)', fontWeight: 600,
                        background: ip.is_active ? 'rgba(239,68,68,.12)' : 'rgba(148,163,184,.1)',
                        color: ip.is_active ? 'var(--danger)' : 'var(--text-muted)',
                      }}>
                        {ip.is_active ? 'BLOCKED' : 'UNBLOCKED'}
                      </span>
                    </td>
                    <td>
                      {ip.is_active && (
                        <button className="btn btn-ghost btn-sm"
                          onClick={() => unblock(ip.ip_address)}
                          title="Unblock this IP">
                          <Unlock size={13} />
                          Unblock
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>

      {showModal && (
        <BlockIPModal onClose={() => setShowModal(false)} onBlocked={refetch} />
      )}
    </div>
  )
}
