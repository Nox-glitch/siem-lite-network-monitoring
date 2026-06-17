import { useState, useEffect } from 'react'
import { Bell, BellOff, Thermometer, Cpu, Wifi, CheckCheck, X } from 'lucide-react'
import { networkApi } from '../lib/networkApi'
import { useSSE } from '../hooks'
import { useToast } from '../lib/toast'

const METRIC_ICON = {
  temperature_c:      Thermometer,
  cpu_percent:        Cpu,
  memory_percent:     Cpu,
  bandwidth_in_mbps:  Wifi,
  latency_ms:         Wifi,
}

const LEVEL_COLOR = {
  warn:     'var(--warn)',
  critical: 'var(--danger)',
}

const LEVEL_BG = {
  warn:     'rgba(245,158,11,.12)',
  critical: 'rgba(239,68,68,.15)',
}

function NotifItem({ notif, onAck }) {
  const Icon = METRIC_ICON[notif.metric] || Bell
  const ts   = new Date(notif.created_at)

  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 10,
      padding: '10px 14px',
      borderBottom: '1px solid var(--border)',
      background: notif.acknowledged ? 'transparent' : LEVEL_BG[notif.level],
      opacity: notif.acknowledged ? 0.5 : 1,
      transition: 'opacity .2s',
    }}>
      <div style={{
        width: 30, height: 30, borderRadius: 6, flexShrink: 0,
        background: LEVEL_BG[notif.level],
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <Icon size={14} color={LEVEL_COLOR[notif.level]} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, color: 'var(--text-primary)',
          fontWeight: notif.acknowledged ? 400 : 500 }}>
          {notif.message}
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)', marginTop: 3 }}>
          {ts.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          {' · '}
          <span style={{ color: LEVEL_COLOR[notif.level], textTransform: 'uppercase',
            fontWeight: 600 }}>{notif.level}</span>
        </div>
      </div>
      {!notif.acknowledged && (
        <button onClick={() => onAck(notif.id)}
          style={{ background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--text-muted)', padding: 4, borderRadius: 4,
            flexShrink: 0 }}
          title="Acknowledge">
          <X size={13} />
        </button>
      )}
    </div>
  )
}

export default function NotificationPanel() {
  const [open,  setOpen]  = useState(false)
  const [notifs, setNotifs] = useState([])
  const [pulse, setPulse]  = useState(false)
  const toast = useToast()

  async function load() {
    try {
      const data = await networkApi.notifications({ unacked_only: false, limit: 50 })
      setNotifs(data)
    } catch {}
  }

  useEffect(() => { load() }, [])

  // Live notifications via SSE
  useSSE('/api/network/stream/notifications', (data) => {
    setNotifs(prev => [
      {
        id:           data.notif_id,
        device_id:    data.device_id,
        metric:       data.metric,
        value:        data.value,
        threshold:    data.threshold,
        level:        data.level,
        message:      data.message,
        acknowledged: false,
        created_at:   data.timestamp,
      },
      ...prev,
    ].slice(0, 100))

    // Pulse the bell
    setPulse(true)
    setTimeout(() => setPulse(false), 2000)

    // Toast notification
    const icon = data.level === 'critical' ? '🔴' : '🟡'
    toast(`${icon} ${data.message}`, data.level === 'critical' ? 'error' : 'success')
  })

  const unacked = notifs.filter(n => !n.acknowledged).length

  async function ack(id) {
    try {
      await networkApi.ackNotif(id)
      setNotifs(prev => prev.map(n => n.id === id ? { ...n, acknowledged: true } : n))
    } catch (e) { toast(e.message, 'error') }
  }

  async function ackAll() {
    try {
      await networkApi.ackAll()
      setNotifs(prev => prev.map(n => ({ ...n, acknowledged: true })))
      toast('All notifications acknowledged', 'success')
    } catch (e) { toast(e.message, 'error') }
  }

  return (
    <div style={{ position: 'relative' }}>
      {/* Bell button */}
      <button onClick={() => setOpen(o => !o)}
        style={{
          position: 'fixed', bottom: 28, right: 28, zIndex: 150,
          width: 48, height: 48, borderRadius: '50%',
          background: unacked > 0 ? 'var(--danger)' : 'var(--surface-2)',
          border: `2px solid ${unacked > 0 ? 'var(--danger)' : 'var(--border)'}`,
          cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: unacked > 0 ? '0 0 16px rgba(239,68,68,.4)' : '0 2px 8px rgba(0,0,0,.3)',
          transform: pulse ? 'scale(1.15)' : 'scale(1)',
          transition: 'all .2s',
        }}>
        {unacked > 0
          ? <Bell size={20} color="#fff" />
          : <BellOff size={20} color="var(--text-muted)" />}
        {unacked > 0 && (
          <span style={{
            position: 'absolute', top: -4, right: -4,
            background: '#fff', color: 'var(--danger)',
            borderRadius: 99, fontSize: 10, fontWeight: 700,
            fontFamily: 'var(--font-mono)', padding: '1px 5px',
            minWidth: 18, textAlign: 'center',
          }}>{unacked > 99 ? '99+' : unacked}</span>
        )}
      </button>

      {/* Dropdown panel */}
      {open && (
        <div style={{
          position: 'fixed', bottom: 90, right: 28, zIndex: 160,
          width: 380, maxHeight: 480,
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: '0 8px 32px rgba(0,0,0,.4)',
          display: 'flex', flexDirection: 'column',
          overflow: 'hidden',
        }}>
          {/* Panel header */}
          <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ fontSize: 13, fontWeight: 600 }}>
              Network Notifications
              {unacked > 0 && (
                <span style={{ marginLeft: 8, fontSize: 11, fontFamily: 'var(--font-mono)',
                  background: 'rgba(239,68,68,.15)', color: 'var(--danger)',
                  padding: '1px 7px', borderRadius: 99 }}>{unacked} new</span>
              )}
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              {unacked > 0 && (
                <button className="btn btn-ghost btn-sm" onClick={ackAll} title="Acknowledge all">
                  <CheckCheck size={13} /> All
                </button>
              )}
              <button className="btn btn-ghost btn-sm" onClick={() => setOpen(false)}>
                <X size={13} />
              </button>
            </div>
          </div>

          {/* Notification list */}
          <div style={{ overflowY: 'auto', flex: 1 }}>
            {notifs.length === 0 ? (
              <div style={{ padding: 32, textAlign: 'center',
                color: 'var(--text-muted)', fontSize: 12 }}>
                <BellOff size={28} style={{ opacity: .3, display: 'block', margin: '0 auto 8px' }} />
                No notifications
              </div>
            ) : (
              notifs.map(n => (
                <NotifItem key={n.id} notif={n} onAck={ack} />
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
