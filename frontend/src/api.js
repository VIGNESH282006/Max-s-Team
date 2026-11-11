// Thin client for the Flask API in app.py. All paths are proxied by Vite.
async function request(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  let body = null
  try { body = await res.json() } catch { /* empty body */ }
  if (!res.ok) {
    const msg = (body && (body.error || body.message)) || `${res.status} ${res.statusText}`
    throw new Error(msg)
  }
  return body
}

export const api = {
  state: () => request('/api/state'),
  retrainingQueue: () => request('/api/retraining_queue'),
  ingest: (log) => request('/api/ingest', { method: 'POST', body: JSON.stringify(log) }),
  action: (kind, incidentId) =>
    request(`/api/action/${kind}`, { method: 'POST', body: JSON.stringify({ incident_id: incidentId }) }),
  undo: (incidentId) => request(`/api/contain/undo/${incidentId}`, { method: 'POST' }),
  // label: 'anomaly' (confirm threat) or 'normal' (false positive)
  feedback: (incidentId, label) =>
    request('/api/feedback', { method: 'POST', body: JSON.stringify({ incident_id: incidentId, analyst_label: label }) }),
  reset: () => request('/api/reset', { method: 'POST' }),
}
