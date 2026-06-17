import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar       from './components/Sidebar'
import DashboardPage from './pages/Dashboard'
import EventsPage    from './pages/Events'
import AlertsPage    from './pages/Alerts'
import RulesPage     from './pages/Rules'
import BlockedIPsPage from './pages/BlockedIPs'
import NetworkPage     from './pages/Network'
import { ToastProvider } from './lib/toast'
import { alertsApi }     from './lib/api'
import NotificationPanel from './components/NotificationPanel'

// Spin animation for sync button
const spinStyle = document.createElement('style')
spinStyle.textContent = `
  @keyframes spin { to { transform: rotate(360deg); } }
  .spin { animation: spin .8s linear infinite; }
`
document.head.appendChild(spinStyle)

function AppShell() {
  const [openAlerts, setOpenAlerts]   = useState(0)
  const [sseConnected, setSseConnected] = useState(false)

  // Poll open alert count every 15s
  useEffect(() => {
    async function loadCount() {
      try {
        const res = await alertsApi.list({ status: 'open', size: 1 })
        setOpenAlerts(res.total)
      } catch {}
    }
    loadCount()
    const id = setInterval(loadCount, 15000)
    return () => clearInterval(id)
  }, [])

  // Watch SSE connection for sidebar status dot
  useEffect(() => {
    const es = new EventSource('/api/events/stream/live')
    es.onopen  = () => setSseConnected(true)
    es.onerror = () => setSseConnected(false)
    return () => es.close()
  }, [])

  return (
    <div className="app-shell">
      <Sidebar openAlerts={openAlerts} connected={sseConnected} />
      <main className="main-content">
        <div className="page-body">
          <Routes>
            <Route path="/"            element={<DashboardPage />} />
            <Route path="/events"      element={<EventsPage />} />
            <Route path="/alerts"      element={<AlertsPage />} />
            <Route path="/rules"       element={<RulesPage />} />
            <Route path="/blocked-ips" element={<BlockedIPsPage />} />
            <Route path="/network"      element={<NetworkPage />} />
          </Routes>
        </div>
      </main>
      <NotificationPanel />
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <AppShell />
      </ToastProvider>
    </BrowserRouter>
  )
}
