import { useState } from 'react'
import {
  Router, Server, Wifi, Shield, MonitorCheck,
  Plus, Thermometer, Cpu, Activity, Globe, Trash2, Settings
} from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid
} from 'recharts'
import { networkApi } from '../lib/networkApi'
import { usePolling, useFetch, useSSE } from '../hooks'
import { useToast } from '../lib/toast'
import { Spinner, EmptyState } from '../components/Badges'

// ── Constants ─────────────────────────────────────────────────────────────────

const TYPE_ICON = {
  router:       Router,
  switch:       MonitorCheck,
  firewall:     Shield,
  access_point: Wifi,
  server:       Server,
  other:        Globe,
}

const STATUS_COLOR = {
  online:   'var(--ok)',
  offline:  'var(--danger)',
  warning:  'var(--warn)',
  critical: '#ef4444',
}

const STATUS_BG = {
  online:   'rgba(16,185,129,.12)',
  offline:  'rgba(239,68,68,.12)',
  warning:  'rgba(245,158,11,.12)',
  critical: 'rgba(239,68,68,.2)',
}

// ── Gauge component ───────────────────────────────────────────────────────────

function Gauge({ value, max = 100, label, unit = '%', warn, critical, size = 64 }) {
  if (value == null) return (
    <div style={{ textAlign: 'center', width: size }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{label}</div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</div>
    </div>
  )
  const pct   = Math.min(100, (value / max) * 100)
  const color = critical && value >= critical ? 'var(--danger)'
              : warn     && value >= warn     ? 'var(--warn)'
              : 'var(--ok)'
  const r = size / 2 - 5
  const circ = 2 * Math.PI * r
  const dash = (pct / 100) * circ

  return (
    <div style={{ textAlign: 'center', width: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size/2} cy={size/2} r={r}
          fill="none" stroke="var(--border)" strokeWidth={5} />
        <circle cx={size/2} cy={size/2} r={r}
          fill="none" stroke={color} strokeWidth={5}
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray .4s ease' }} />
      </svg>
      <div style={{ marginTop: -size * 0.55, fontSize: 13, fontFamily: 'var(--font-mono)',
        fontWeight: 700, color }}>
        {Math.round(value)}{unit}
      </div>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{label}</div>
    </div>
  )
}

// ── Metric mini-chart ─────────────────────────────────────────────────────────

function MiniChart({ data, dataKey, color = 'var(--accent)', height = 60 }) {
  if (!data?.length) return null
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id={`grad-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor={color} stopOpacity={0.3} />
            <stop offset="95%" stopColor={color} stopOpacity={0}   />
          </linearGradient>
        </defs>
        <XAxis dataKey="timestamp" hide />
        <YAxis hide />
        <Tooltip
          contentStyle={{ background: 'var(--surface-2)', border: '1px solid var(--border)',
            borderRadius: 6, fontSize: 11, fontFamily: 'JetBrains Mono' }}
          labelFormatter={() => ''}
          formatter={v => [v?.toFixed(1), dataKey]}
        />
        <Area type="monotone" dataKey={dataKey}
          stroke={color} strokeWidth={1.5}
          fill={`url(#grad-${dataKey})`} dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

// ── Add device modal ──────────────────────────────────────────────────────────

function AddDeviceModal({ onClose, onAdded }) {
  const [form, setForm] = useState({
    name: '', ip_address: '', device_type: 'router',
    vendor: '', model: '', location: '',
  })
  const [saving, setSaving] = useState(false)
  const toast = useToast()

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  async function submit() {
    if (!form.name || !form.ip_address) {
      toast('Name and IP are required', 'error'); return
    }
    setSaving(true)
    try {
      await networkApi.addDevice(form)
      toast(`${form.name} added`, 'success')
      onAdded(); onClose()
    } catch (e) { toast(e.message, 'error') }
    finally { setSaving(false) }
  }

  const field = (label, key, type = 'text', options = null) => (
    <div>
      <label style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.06em',
        textTransform: 'uppercase', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
        {label}
      </label>
      {options ? (
        <select className="input" style={{ width: '100%' }}
          value={form[key]} onChange={e => set(key, e.target.value)}>
          {options.map(o => <option key={o} value={o}>{o}</option>)}
        </select>
      ) : (
        <input className="input" style={{ width: '100%' }} type={type}
          value={form[key]} onChange={e => set(key, e.target.value)} />
      )}
    </div>
  )

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 200 }}
      onClick={onClose}>
      <div className="card" style={{ width: 460, padding: 24 }} onClick={e => e.stopPropagation()}>
        <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 20 }}>Add Network Device</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
          {field('Device Name *', 'name')}
          {field('IP Address *', 'ip_address')}
          {field('Type', 'device_type', 'text',
            ['router', 'switch', 'firewall', 'access_point', 'server', 'other'])}
          {field('Vendor', 'vendor')}
          {field('Model', 'model')}
          {field('Location', 'location')}
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 20 }}>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={saving}>
            <Plus size={14} /> {saving ? 'Adding…' : 'Add Device'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Device card ───────────────────────────────────────────────────────────────

function DeviceCard({ device, onClick }) {
  const Icon   = TYPE_ICON[device.device_type] || Globe
  const m      = device.latest_metrics || {}
  const t      = device.thresholds || {}
  const status = device.status

  return (
    <div className="card" style={{ cursor: 'pointer', transition: 'border-color .15s',
      borderColor: status !== 'online' ? STATUS_COLOR[status] : 'var(--border)' }}
      onClick={() => onClick(device)}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 14 }}>
        <div style={{ width: 36, height: 36, borderRadius: 8,
          background: STATUS_BG[status] || 'var(--surface-2)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <Icon size={18} color={STATUS_COLOR[status]} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {device.name}
          </div>
          <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)',
            color: 'var(--text-muted)' }}>{device.ip_address}</div>
        </div>
        <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px',
          borderRadius: 99, background: STATUS_BG[status],
          color: STATUS_COLOR[status], textTransform: 'uppercase',
          fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
          {status}
        </span>
      </div>

      {/* Gauges row */}
      <div style={{ display: 'flex', justifyContent: 'space-around',
        padding: '10px 0', borderTop: '1px solid var(--border)',
        borderBottom: '1px solid var(--border)', marginBottom: 10 }}>
        <Gauge value={m.temperature_c} label="Temp" unit="°C"
          warn={t.temp_warn} critical={t.temp_critical} max={100} />
        <Gauge value={m.cpu_percent}   label="CPU"  unit="%"
          warn={t.cpu_warn}  critical={t.cpu_critical} />
        <Gauge value={m.memory_percent} label="RAM" unit="%"
          warn={t.mem_warn}  critical={t.mem_critical} />
      </div>

      {/* Bottom stats */}
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
        <span style={{ color: 'var(--text-muted)' }}>
          ↓ <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
            {m.bandwidth_in_mbps?.toFixed(0) ?? '—'}
          </span> Mbps
        </span>
        <span style={{ color: 'var(--text-muted)' }}>
          ↑ <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
            {m.bandwidth_out_mbps?.toFixed(0) ?? '—'}
          </span> Mbps
        </span>
        <span style={{ color: 'var(--text-muted)' }}>
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
            {m.latency_ms?.toFixed(1) ?? '—'}
          </span> ms
        </span>
        <span style={{ color: 'var(--text-muted)' }}>
          Up <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
            {device.uptime_hours}h
          </span>
        </span>
      </div>

      {device.location && (
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 8 }}>
          📍 {device.location}
        </div>
      )}
    </div>
  )
}

// ── Device detail panel ───────────────────────────────────────────────────────

function DeviceDetail({ device, onClose, onRefresh }) {
  const [tab,     setTab]     = useState('metrics')
  const [thresh,  setThresh]  = useState(device.thresholds || {})
  const [saving,  setSaving]  = useState(false)
  const toast = useToast()

  const { data: metricData } = usePolling(
    () => networkApi.metrics(device.id, { hours: 1 }),
    15000, [device.id]
  )

  async function saveThresholds() {
    setSaving(true)
    try {
      await networkApi.setThresholds(device.id, thresh)
      toast('Thresholds saved', 'success')
      onRefresh()
    } catch (e) { toast(e.message, 'error') }
    finally { setSaving(false) }
  }

  const TABS = ['metrics', 'thresholds', 'info']

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.6)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 200 }}
      onClick={onClose}>
      <div className="card" style={{ width: 680, maxHeight: '88vh', overflowY: 'auto',
        padding: 0 }} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{ padding: '18px 20px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontWeight: 600, fontSize: 15 }}>{device.name}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)' }}>
              {device.ip_address} · {device.vendor} {device.model}
            </div>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>✕</button>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 2, padding: '10px 20px 0',
          borderBottom: '1px solid var(--border)' }}>
          {TABS.map(t => (
            <button key={t} onClick={() => setTab(t)}
              style={{ padding: '6px 14px', borderRadius: '6px 6px 0 0',
                fontSize: 12, fontWeight: 500, border: 'none',
                background: tab === t ? 'var(--surface-2)' : 'transparent',
                color: tab === t ? 'var(--text-primary)' : 'var(--text-muted)',
                borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
                cursor: 'pointer', textTransform: 'capitalize' }}>
              {t}
            </button>
          ))}
        </div>

        <div style={{ padding: 20 }}>
          {tab === 'metrics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {[
                { key: 'temperature_c',     label: 'Temperature (°C)', color: '#ef4444' },
                { key: 'cpu_percent',       label: 'CPU (%)',          color: 'var(--accent)' },
                { key: 'memory_percent',    label: 'Memory (%)',       color: 'var(--purple)' },
                { key: 'bandwidth_in_mbps', label: 'Bandwidth In (Mbps)', color: 'var(--ok)' },
                { key: 'latency_ms',        label: 'Latency (ms)',     color: 'var(--warn)' },
              ].map(({ key, label, color }) => (
                <div key={key}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)',
                    fontWeight: 600, marginBottom: 4 }}>{label}</div>
                  <MiniChart data={metricData} dataKey={key} color={color} height={70} />
                </div>
              ))}
            </div>
          )}

          {tab === 'thresholds' && (
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
                Set warn/critical thresholds. Notifications fire when a metric stays above
                critical for {thresh.duration_seconds || 60}s.
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[
                  ['Temperature Warn (°C)',   'temp_warn'],
                  ['Temperature Critical (°C)', 'temp_critical'],
                  ['CPU Warn (%)',             'cpu_warn'],
                  ['CPU Critical (%)',         'cpu_critical'],
                  ['Memory Warn (%)',          'mem_warn'],
                  ['Memory Critical (%)',      'mem_critical'],
                  ['Bandwidth Warn (Mbps)',    'bandwidth_warn'],
                  ['Bandwidth Critical (Mbps)', 'bandwidth_critical'],
                  ['Latency Warn (ms)',        'latency_warn'],
                  ['Latency Critical (ms)',    'latency_critical'],
                ].map(([label, key]) => (
                  <div key={key}>
                    <label style={{ fontSize: 11, color: 'var(--text-muted)',
                      display: 'block', marginBottom: 4, fontWeight: 600 }}>{label}</label>
                    <input className="input" type="number" style={{ width: '100%' }}
                      value={thresh[key] ?? ''}
                      onChange={e => setThresh(t => ({ ...t, [key]: parseFloat(e.target.value) }))} />
                  </div>
                ))}
              </div>
              <button className="btn btn-primary" style={{ marginTop: 16 }}
                onClick={saveThresholds} disabled={saving}>
                {saving ? 'Saving…' : 'Save Thresholds'}
              </button>
            </div>
          )}

          {tab === 'info' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
              {[
                ['Type',      device.device_type],
                ['Vendor',    device.vendor],
                ['Model',     device.model],
                ['Location',  device.location],
                ['Status',    device.status],
                ['Uptime',    `${device.uptime_hours}h`],
                ['Last Seen', device.last_seen ? new Date(device.last_seen).toLocaleString() : '—'],
                ['Added',     device.added_at  ? new Date(device.added_at).toLocaleString()  : '—'],
              ].map(([label, value]) => (
                <div key={label} style={{ display: 'flex', gap: 12 }}>
                  <span style={{ color: 'var(--text-muted)', minWidth: 100 }}>{label}</span>
                  <span style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                    {value || '—'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function NetworkPage() {
  const [showAdd,    setShowAdd]    = useState(false)
  const [selected,   setSelected]   = useState(null)
  const [typeFilter, setTypeFilter] = useState('')
  const toast = useToast()

  const { data: summary,  refetch: refetchSummary } = usePolling(() => networkApi.summary(), 15000)
  const { data: devices,  loading, refetch }        = usePolling(() => networkApi.devices(
    typeFilter ? { device_type: typeFilter } : {}
  ), 30000, [typeFilter])

  // Live metric updates via SSE — update device cards in real time
  useSSE('/api/network/stream/metrics', (data) => {
    // Trigger re-fetch every 30s via polling; SSE just keeps sidebar dot alive
  })

  const deviceList = devices ?? []
  const s = summary || {}

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">Network Devices</div>
          <div className="page-subtitle">
            {s.total_devices ?? 0} devices · {s.online ?? 0} online · {s.warning ?? 0} warnings
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <select className="input" value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}>
            <option value="">All types</option>
            {['router','switch','firewall','access_point','server'].map(t => (
              <option key={t} value={t}>{t.replace('_',' ')}</option>
            ))}
          </select>
          <button className="btn btn-primary" onClick={() => setShowAdd(true)}>
            <Plus size={14} /> Add Device
          </button>
        </div>
      </div>

      {/* Summary KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Total Devices',  value: s.total_devices,          color: 'var(--accent)' },
          { label: 'Online',         value: s.online,                  color: 'var(--ok)' },
          { label: 'Warnings',       value: s.warning,                 color: 'var(--warn)' },
          { label: 'Offline',        value: s.offline,                 color: 'var(--danger)' },
          { label: 'Unacked Alerts', value: s.unacked_notifications,   color: '#ef4444' },
        ].map(k => (
          <div key={k.label} className="card" style={{ padding: '14px 16px' }}>
            <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.06em',
              textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 6 }}>
              {k.label}
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 28,
              fontWeight: 700, color: k.color }}>{k.value ?? '—'}</div>
          </div>
        ))}
      </div>

      {/* Device grid */}
      {loading && !deviceList.length ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><Spinner /></div>
      ) : deviceList.length === 0 ? (
        <EmptyState icon={Router} message="No devices found"
          sub='Click "Add Device" to register your first network device' />
      ) : (
        <div style={{ display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 14 }}>
          {deviceList.map(d => (
            <DeviceCard key={d.id} device={d} onClick={setSelected} />
          ))}
        </div>
      )}

      {showAdd && (
        <AddDeviceModal onClose={() => setShowAdd(false)}
          onAdded={() => { refetch(); refetchSummary() }} />
      )}

      {selected && (
        <DeviceDetail device={selected} onClose={() => setSelected(null)}
          onRefresh={() => { refetch(); setSelected(null) }} />
      )}
    </div>
  )
}
