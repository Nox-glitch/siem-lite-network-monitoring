// SIEM Lite — Network API client

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

export const networkApi = {
  summary:      ()              => req('/api/network/summary'),
  devices:      (params = {})  => req(`/api/network/devices?${new URLSearchParams(params)}`),
  addDevice:    (body)          => req('/api/network/devices',                    { method: 'POST',   body: JSON.stringify(body) }),
  getDevice:    (id)            => req(`/api/network/devices/${id}`),
  updateDevice: (id, body)      => req(`/api/network/devices/${id}`,              { method: 'PATCH',  body: JSON.stringify(body) }),
  deleteDevice: (id)            => req(`/api/network/devices/${id}`,              { method: 'DELETE' }),
  metrics:      (id, params={}) => req(`/api/network/devices/${id}/metrics?${new URLSearchParams(params)}`),
  getThresholds:(id)            => req(`/api/network/devices/${id}/thresholds`),
  setThresholds:(id, body)      => req(`/api/network/devices/${id}/thresholds`,   { method: 'PATCH',  body: JSON.stringify(body) }),
  notifications:(params={})     => req(`/api/network/notifications?${new URLSearchParams(params)}`),
  ackNotif:     (id)            => req(`/api/network/notifications/${id}/ack`,    { method: 'POST' }),
  ackAll:       ()              => req('/api/network/notifications/ack-all',      { method: 'POST' }),
}
