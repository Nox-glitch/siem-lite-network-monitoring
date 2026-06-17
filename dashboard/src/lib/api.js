// SIEM Lite — API client
// All backend calls go through here. Base URL proxied via Vite in dev.

const BASE = import.meta.env.VITE_API_URL || ''

async function req(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

// ── Events ────────────────────────────────────────────────────────────
export const eventsApi = {
  list:   (params = {}) => req(`/api/events?${new URLSearchParams(params)}`),
  get:    (id)          => req(`/api/events/${id}`),
}

// ── Alerts ────────────────────────────────────────────────────────────
export const alertsApi = {
  list:          (params = {}) => req(`/api/alerts?${new URLSearchParams(params)}`),
  get:           (id)          => req(`/api/alerts/${id}`),
  update:        (id, body)    => req(`/api/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  acknowledge:   (id)          => req(`/api/alerts/${id}/acknowledge`,    { method: 'POST' }),
  resolve:       (id)          => req(`/api/alerts/${id}/resolve`,        { method: 'POST' }),
  falsePositive: (id)          => req(`/api/alerts/${id}/false-positive`, { method: 'POST' }),
}

// ── Stats ─────────────────────────────────────────────────────────────
export const statsApi = {
  dashboard: (hours = 24) => req(`/api/stats/dashboard?window_hours=${hours}`),
  topIPs:    (hours = 24) => req(`/api/stats/top-ips?hours=${hours}`),
  mitre:     ()           => req('/api/stats/mitre'),
}

// ── Rules ─────────────────────────────────────────────────────────────
export const rulesApi = {
  list:   ()           => req('/api/rules'),
  update: (id, body)   => req(`/api/rules/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  sync:   ()           => req('/api/rules/sync',  { method: 'POST' }),
}

// ── Blocked IPs ───────────────────────────────────────────────────────
export const blockedIpsApi = {
  list:   ()         => req('/api/blocked-ips'),
  block:  (body)     => req('/api/blocked-ips',        { method: 'POST',   body: JSON.stringify(body) }),
  unblock:(ip)       => req(`/api/blocked-ips/${ip}`,  { method: 'DELETE' }),
}
