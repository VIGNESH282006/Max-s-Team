import { useState } from 'react'
import { AlertOctagon, AlertTriangle, ShieldAlert, ShieldCheck, ArrowRight } from 'lucide-react'
import { ACTIONS, SEVERITY } from '../format.js'

const SEV_ICON = { critical: AlertOctagon, high: ShieldAlert, medium: AlertTriangle, low: ShieldCheck }

export function SeverityBadge({ level }) {
  const s = SEVERITY[level] || SEVERITY.medium
  const Icon = SEV_ICON[level] || AlertTriangle
  return (
    <span className={`badge tone-${s.tone}`}>
      <Icon size={13} aria-hidden /> {s.label}
    </span>
  )
}

export function ActionChip({ action }) {
  const a = ACTIONS[action] || { short: action || '—', color: 'var(--text-3)' }
  return (
    <span className="action-chip">
      <span className="swatch" style={{ background: a.color }} aria-hidden /> {a.short}
    </span>
  )
}

export function Flow({ from, to }) {
  return (
    <span className="flow mono">
      {from || '—'} <ArrowRight size={12} aria-hidden /> {to || '—'}
    </span>
  )
}

export function Card({ title, sub, right, children, bodyClass = 'card-body', className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || right) && (
        <header className="card-head">
          <div>
            {title && <h2 className="card-title">{title}</h2>}
            {sub && <p className="card-sub">{sub}</p>}
          </div>
          {right && <div className="right">{right}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  )
}

export function Empty({ icon: Icon, title, text, action }) {
  return (
    <div className="empty">
      {Icon && <div className="empty-icon"><Icon size={22} aria-hidden /></div>}
      <h3>{title}</h3>
      {text && <p>{text}</p>}
      {action}
    </div>
  )
}

/** Horizontal bar list with a hover tooltip; values in text ink, colour on the mark only. */
export function BarList({ rows, format = (v) => v, unit = '', max }) {
  const [tip, setTip] = useState(null)
  const top = max ?? Math.max(1, ...rows.map((r) => r.value))
  return (
    <div className="bars" onMouseLeave={() => setTip(null)}>
      {rows.map((r) => (
        <div
          key={r.label}
          className="bar-row"
          onMouseMove={(e) => setTip({ x: e.clientX, y: e.clientY, r })}
        >
          <span className="label" title={r.label}>{r.label}</span>
          <div className="bar-track">
            <div className="bar-fill" style={{ width: `${(r.value / top) * 100}%`, background: r.color || 'var(--series-1)' }} />
          </div>
          <span className="value">{format(r.value)}</span>
        </div>
      ))}
      {tip && (
        <div className="tooltip" style={{ left: tip.x + 14, top: tip.y + 12 }}>
          <b>{tip.r.label}</b>: {format(tip.r.value)}{unit}
          {tip.r.note && <div style={{ opacity: 0.75 }}>{tip.r.note}</div>}
        </div>
      )}
    </div>
  )
}

export function Toasts({ items }) {
  return (
    <div className="toast-wrap" role="status" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className="toast">{t.icon}{t.text}</div>
      ))}
    </div>
  )
}
