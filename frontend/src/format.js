export const ACTIONS = {
  isolate: { label: 'Isolate host', short: 'Isolate', color: 'var(--series-1)' },
  revoke: { label: 'Revoke credentials', short: 'Revoke', color: 'var(--series-2)' },
  honeypot: { label: 'Route to honeypot', short: 'Honeypot', color: 'var(--series-3)' },
}

export const SEVERITY = {
  critical: { label: 'Critical', tone: 'critical' },
  high: { label: 'High', tone: 'serious' },
  medium: { label: 'Medium', tone: 'warning' },
  low: { label: 'Low', tone: 'good' },
}

export function severityOf(inc) {
  const raw = String(inc?.threat_level || '').toLowerCase()
  if (SEVERITY[raw]) return raw
  const p = inc?.ml_probability ?? 0
  if (p >= 0.97) return 'critical'
  if (p >= 0.85) return 'high'
  if (p >= 0.6) return 'medium'
  return 'low'
}

export const titleCase = (s) =>
  String(s || '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())

export const fmtTime = (iso) =>
  iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—'

export const fmtMs = (ms) => {
  if (ms == null || Number.isNaN(ms)) return '—'
  if (ms < 1) return `${ms.toFixed(2)} ms`
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

export const fmtPct = (x, d = 1) => (x == null ? '—' : `${(x * 100).toFixed(d)}%`)

export const fmtMoney = (n) =>
  new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0, notation: 'compact' }).format(n || 0)

export const median = (arr) => {
  const a = arr.filter((x) => x != null && !Number.isNaN(x)).sort((x, y) => x - y)
  if (!a.length) return null
  const m = Math.floor(a.length / 2)
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2
}

export const attackLabel = (inc) =>
  titleCase(inc?.attack_type_classification || inc?.log?.attack_type || 'Unknown')

export const isUndone = (inc) => ['undo', 'rolled_back', 'undone', 'reverted'].includes(String(inc?.status || '').toLowerCase())
