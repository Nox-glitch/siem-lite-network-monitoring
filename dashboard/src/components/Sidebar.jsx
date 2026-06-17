import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Radio, Bell, ShieldAlert,
  BookOpen, Ban, Activity, Network
} from 'lucide-react'

const NAV = [
  { to: '/',            icon: LayoutDashboard, label: 'Dashboard'   },
  { to: '/events',      icon: Radio,           label: 'Live Events' },
  { to: '/alerts',      icon: Bell,            label: 'Alerts'      },
  { to: '/rules',       icon: BookOpen,        label: 'Rules'       },
  { to: '/blocked-ips', icon: Ban,             label: 'Blocked IPs' },
  { to: '/network',     icon: Network,         label: 'Network'     },
]

export default function Sidebar({ openAlerts = 0, connected = false }) {
  return (
    <aside style={{
      position: 'fixed', top: 0, left: 0, bottom: 0,
      width: 'var(--sidebar-w)',
      background: 'var(--surface)',
      borderRight: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column',
      zIndex: 100,
    }}>
      {/* Logo */}
      <div style={{
        padding: '20px 20px 16px',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldAlert size={22} color="var(--accent)" />
          <span style={{
            fontFamily: 'var(--font-mono)',
            fontWeight: 700,
            fontSize: 15,
            color: 'var(--text-primary)',
            letterSpacing: '-0.02em',
          }}>SIEM Lite</span>
        </div>
        {/* Live status */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          marginTop: 10, fontSize: 11,
          color: connected ? 'var(--ok)' : 'var(--text-muted)',
        }}>
          <div className={`pulse-dot${connected ? '' : ' danger'}`}
               style={{ width: 6, height: 6 }} />
          {connected ? 'Live' : 'Disconnected'}
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '12px 10px', display: 'flex', flexDirection: 'column', gap: 2 }}>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} end={to === '/'}
            style={({ isActive }) => ({
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '9px 12px',
              borderRadius: 'var(--radius-md)',
              fontSize: 13, fontWeight: 500,
              color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
              background: isActive ? 'var(--surface-2)' : 'transparent',
              border: isActive ? '1px solid var(--border)' : '1px solid transparent',
              transition: 'all .15s',
              textDecoration: 'none',
            })}
          >
            <Icon size={16} />
            <span style={{ flex: 1 }}>{label}</span>
            {label === 'Alerts' && openAlerts > 0 && (
              <span style={{
                background: 'var(--danger)',
                color: '#fff',
                borderRadius: 99,
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                fontWeight: 700,
                padding: '1px 6px',
                minWidth: 18,
                textAlign: 'center',
              }}>{openAlerts > 99 ? '99+' : openAlerts}</span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div style={{
        padding: '14px 20px',
        borderTop: '1px solid var(--border)',
        fontSize: 11,
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Activity size={12} />
          v1.0.0
        </div>
      </div>
    </aside>
  )
}
