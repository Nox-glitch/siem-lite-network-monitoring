import { useState } from 'react'
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts'
import { AlertTriangle, Radio, Shield, Ban, TrendingUp } from 'lucide-react'
import { statsApi } from '../lib/api'
import { usePolling } from '../hooks'
import { SeverityBadge, Spinner, IPCell } from '../components/Badges'

const WINDOW_OPTIONS = [
  { label: '1h',  value: 1  },
  { label: '6h',  value: 6  },
  { label: '24h', value: 24 },
  { label: '7d',  value: 168 },
]

const SEV_COLORS = {
  critical: '#ef4444',
  high:     '#fb923c',
  medium:   '#f59e0b',
  low:      '#10b981',
}

function KpiCard({ icon: Icon, label, value, sub, color = 'var(--accent)' }) {
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.06em',
          textTransform: 'uppercase', color: 'var(--text-muted)' }}>{label}</span>
        <Icon size={16} color={color} />
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 32, fontWeight: 700,
        color: 'var(--text-primary)', lineHeight: 1 }}>{value ?? '—'}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{sub}</div>}
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)',
      borderRadius: 6, padding: '8px 12px', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: 4 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.color || 'var(--accent)' }}>
          {p.value} events
        </div>
      ))}
    </div>
  )
}

export default function DashboardPage() {
  const [window, setWindow] = useState(24)
  const { data, loading } = usePolling(() => statsApi.dashboard(window), 15000, [window])

  const stats    = data
  const sevData  = stats ? Object.entries(stats.events_by_severity)
    .map(([name, value]) => ({ name, value })) : []
  const timeData = stats?.events_over_time?.map(p => ({
    time: p.timestamp.slice(11, 16),
    count: p.count,
  })) ?? []

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">Dashboard</div>
          <div className="page-subtitle">Security overview — last {window}h</div>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {WINDOW_OPTIONS.map(o => (
            <button key={o.value}
              className={`btn btn-sm ${window === o.value ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setWindow(o.value)}>{o.label}</button>
          ))}
        </div>
      </div>

      {loading && !stats ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><Spinner /></div>
      ) : (
        <>
          {/* KPI row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 20 }}>
            <KpiCard icon={Radio}         label="Events"         value={stats?.total_events_24h}  sub={`last ${window}h`} />
            <KpiCard icon={AlertTriangle} label="Alerts"         value={stats?.total_alerts_24h}  sub={`last ${window}h`} color="var(--warn)" />
            <KpiCard icon={AlertTriangle} label="Open Alerts"    value={stats?.open_alerts}       sub="need triage"  color="var(--danger)" />
            <KpiCard icon={TrendingUp}    label="Critical Alerts" value={stats?.critical_alerts}  sub="open" color="#ef4444" />
            <KpiCard icon={Ban}           label="Blocked IPs"    value={stats?.blocked_ips}       sub="active blocks" color="var(--purple)" />
          </div>

          {/* Charts row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 12, marginBottom: 20 }}>
            {/* Timeline */}
            <div className="card">
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16,
                color: 'var(--text-secondary)' }}>Events over time</div>
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={timeData}>
                  <defs>
                    <linearGradient id="evGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="var(--accent)" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="var(--accent)" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: 'var(--text-muted)',
                    fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false}
                    interval="preserveStartEnd" />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)',
                    fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} width={28} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="count" stroke="var(--accent)"
                    strokeWidth={2} fill="url(#evGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Severity breakdown */}
            <div className="card">
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16,
                color: 'var(--text-secondary)' }}>Events by severity</div>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={sevData} layout="vertical">
                  <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-muted)',
                    fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 11,
                    fill: 'var(--text-secondary)' }} axisLine={false} tickLine={false} width={60} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="value" radius={[0,4,4,0]}>
                    {sevData.map(entry => (
                      <Cell key={entry.name} fill={SEV_COLORS[entry.name] || 'var(--accent)'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Bottom row: top IPs + top event types + alert status */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            {/* Top IPs */}
            <div className="card">
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 14,
                color: 'var(--text-secondary)' }}>Top source IPs</div>
              <table className="data-table">
                <thead><tr><th>IP</th><th style={{ textAlign: 'right' }}>Events</th></tr></thead>
                <tbody>
                  {(stats?.top_source_ips ?? []).slice(0, 8).map(row => (
                    <tr key={row.source_ip}>
                      <td><IPCell ip={row.source_ip} /></td>
                      <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)',
                        fontSize: 12, color: 'var(--accent)' }}>{row.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Top event types */}
            <div className="card">
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 14,
                color: 'var(--text-secondary)' }}>Top event types</div>
              <table className="data-table">
                <thead><tr><th>Type</th><th style={{ textAlign: 'right' }}>Count</th></tr></thead>
                <tbody>
                  {(stats?.top_event_types ?? []).slice(0, 8).map(row => (
                    <tr key={row.event_type}>
                      <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: 11,
                        color: 'var(--text-primary)' }}>{row.event_type}</span></td>
                      <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)',
                        fontSize: 12, color: 'var(--warn)' }}>{row.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Alert status breakdown */}
            <div className="card">
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 14,
                color: 'var(--text-secondary)' }}>Alert status</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {Object.entries(stats?.alerts_by_status ?? {}).map(([status, count]) => (
                  <div key={status} style={{ display: 'flex', alignItems: 'center',
                    justifyContent: 'space-between' }}>
                    <SeverityBadge severity={status} />
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14,
                      fontWeight: 700, color: 'var(--text-primary)' }}>{count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
