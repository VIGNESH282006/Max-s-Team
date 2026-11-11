import { useMemo, useState } from 'react'
import { Radar, Cpu, Sigma, BrainCircuit, ShieldCheck, Undo2, ThumbsUp, ThumbsDown, Copy, Check, Inbox, Search, Globe2 } from 'lucide-react'
import { Card, Empty, SeverityBadge, ActionChip, Flow } from '../components/ui.jsx'
import { ACTIONS, severityOf, attackLabel, fmtMs, fmtTime, fmtPct, fmtMoney, isUndone, titleCase } from '../format.js'

function Trace({ inc }) {
  const t = inc.pipeline_timing_ms || {}
  const shapCount = (inc.top_features || []).filter((f) => !String(f.feature).startsWith('OSINT_')).length
  const steps = [
    { icon: Radar, name: 'Threat intel', meta: inc.osint_is_ioc ? 'IOC match' : 'No IOC match', ms: t.data_fetch_osint },
    { icon: Cpu, name: 'ML ensemble', meta: `p(anomaly) ${fmtPct(inc.ml_probability)}`, ms: t.ml_load_train_reason },
    { icon: Sigma, name: 'SHAP explain', meta: `${shapCount} factors ranked`, ms: null },
    { icon: BrainCircuit, name: 'LLM reasoning', meta: 'Decision in strict JSON', ms: t.llm_claude_reasoning },
    { icon: ShieldCheck, name: 'Containment', meta: ACTIONS[inc.containment_action]?.label || '—', ms: t.frontend_prepare },
  ]
  return (
    <div className="trace" aria-label="Pipeline trace">
      {steps.map((s) => (
        <div key={s.name} className="trace-step done">
          <div className="trace-node"><s.icon size={14} aria-hidden /></div>
          <div className="trace-name">{s.name}</div>
          <div className="trace-meta">{s.meta}</div>
          <div className="trace-ms">{s.ms == null ? 'incl. above' : fmtMs(s.ms)}</div>
        </div>
      ))}
    </div>
  )
}

function Shap({ features }) {
  const rows = features.filter((f) => typeof f.impact === 'number' && !String(f.feature).startsWith('OSINT_')).slice(0, 8)
  if (!rows.length) return <p className="muted">No feature attributions recorded for this event.</p>
  const max = Math.max(...rows.map((r) => Math.abs(r.impact)), 1e-6)
  return (
    <>
      <div className="legend" style={{ marginBottom: 12 }}>
        <span><span className="swatch" style={{ background: 'var(--div-pos)' }} />Pushes toward anomaly</span>
        <span><span className="swatch" style={{ background: 'var(--div-neg)' }} />Pushes toward normal</span>
      </div>
      <div className="shap">
        {rows.map((r) => {
          const w = `${(Math.abs(r.impact) / max) * 100}%`
          return (
            <div className="shap-row" key={r.feature} title={`${r.feature} = ${r.value} · SHAP ${r.impact.toFixed(4)}`}>
              <span className="name">{r.feature}<small>{typeof r.value === 'number' ? +r.value.toFixed(2) : r.value}</small></span>
              <div className="shap-half neg">{r.impact < 0 && <div className="shap-bar" style={{ width: w }} />}</div>
              <div className="shap-half pos">{r.impact >= 0 && <div className="shap-bar" style={{ width: w }} />}</div>
              <span className="val">{r.impact >= 0 ? '+' : ''}{r.impact.toFixed(3)}</span>
            </div>
          )
        })}
      </div>
    </>
  )
}

function Yara({ rule }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try { await navigator.clipboard.writeText(rule); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* clipboard blocked */ }
  }
  return (
    <Card title="Generated YARA rule" sub="Detects similar activity in future"
      right={<button className="btn btn-sm" onClick={copy}>{copied ? <Check size={14} /> : <Copy size={14} />}{copied ? 'Copied' : 'Copy'}</button>}>
      <pre className="code">{rule || '// No rule generated'}</pre>
    </Card>
  )
}

function Detail({ inc, onUndo, onFeedback, busy }) {
  const undone = isUndone(inc)
  const labelled = inc.analyst_label
  const osint = inc.osint_findings || []
  return (
    <div className="detail">
      <section className="card">
        <div className="detail-head">
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <span className="mono muted">{inc.incident_id}</span>
              <SeverityBadge level={severityOf(inc)} />
              {undone ? <span className="badge tone-neutral">Containment undone</span>
                : <span className="badge tone-good"><ShieldCheck size={13} /> Contained</span>}
              {labelled && <span className={`badge ${labelled === 'normal' ? 'tone-warning' : 'tone-accent'}`}>
                {labelled === 'normal' ? 'Marked false positive' : 'Confirmed threat'}</span>}
            </div>
            <h2 className="detail-title">{attackLabel(inc)}</h2>
            <Flow from={inc.log?.source_ip} to={inc.log?.dest_ip} />
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn" onClick={() => onFeedback(inc.incident_id, 'anomaly')} disabled={busy || !!labelled}><ThumbsUp size={15} />Confirm threat</button>
            <button className="btn" onClick={() => onFeedback(inc.incident_id, 'normal')} disabled={busy || !!labelled}><ThumbsDown size={15} />False positive</button>
            <button className="btn btn-danger" onClick={() => onUndo(inc.incident_id)} disabled={busy || undone}><Undo2 size={15} />Undo action</button>
          </div>
        </div>
        <div className="facts">
          <div className="fact"><div className="fact-k">Detected</div><div className="fact-v">{fmtTime(inc.created_at)}</div></div>
          <div className="fact"><div className="fact-k">Action taken</div><div className="fact-v"><ActionChip action={inc.containment_action} /></div></div>
          <div className="fact"><div className="fact-k">Protocol · port</div><div className="fact-v mono">{inc.log?.protocol || '—'} · {inc.log?.dest_port ?? '—'}</div></div>
          <div className="fact"><div className="fact-k">Contained in</div><div className="fact-v mono">{fmtMs(inc.pipeline_total_ms)}</div></div>
        </div>
      </section>

      <Card title="Pipeline trace" sub="How this event moved through the system">
        <Trace inc={inc} />
      </Card>

      <div className="grid-2">
        <Card title="Why it was flagged" sub="SHAP contribution of each feature to the anomaly score">
          <Shap features={inc.top_features || []} />
        </Card>
        <Card title="Threat intelligence" sub={osint.length ? `${osint.length} indicator match${osint.length > 1 ? 'es' : ''}` : 'Checked against IOC lists'}>
          {osint.length ? osint.map((o, k) => (
            <dl className="osint" key={k} style={{ marginTop: k ? 10 : 0 }}>
              <dt>Indicator</dt><dd className="mono">{o.indicator}</dd>
              <dt>Type</dt><dd>{titleCase(o.type)}</dd>
              <dt>Severity</dt><dd><SeverityBadge level={o.severity === 'critical' ? 'critical' : o.severity === 'high' ? 'high' : 'medium'} /></dd>
              <dt>Categories</dt><dd className="tags">{(o.categories || []).map((c) => <span className="tag" key={c}>{c}</span>)}</dd>
              <dt>Sources</dt><dd className="tags">{(o.sources || []).map((c) => <span className="tag" key={c}>{c}</span>)}</dd>
            </dl>
          )) : <Empty icon={Globe2} title="No indicator matches" text="The source and destination were not found in any threat-intel list. The decision came from the ML ensemble alone." />}
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Analyst briefing" sub="Written by the LLM from the event, SHAP factors and OSINT">
          <p className="narrative">{inc.play_by_play_narrative || inc.llm_explanation}</p>
          <h3 style={{ fontSize: 13, margin: '18px 0 10px' }}>Reasoning steps</h3>
          <ol className="steps">{(inc.interrogation_log || []).map((s, k) => <li key={k}>{s}</li>)}</ol>
        </Card>
        <div className="detail" style={{ gap: 20 }}>
          <Card title="Recommended next steps">
            <ul className="checklist">{(inc.recommended_soc_actions || []).map((s, k) => <li key={k}><Check size={15} aria-hidden />{s}</li>)}</ul>
            <div className="muted" style={{ marginTop: 14, fontSize: 12.5 }}>Estimated breach cost avoided: <b style={{ color: 'var(--text)' }}>{fmtMoney(inc.estimated_roi_saved)}</b></div>
          </Card>
          <Yara rule={inc.generated_yara_rule} />
        </div>
      </div>
    </div>
  )
}

export default function Incidents({ incidents, selectedId, onSelect, onUndo, onFeedback, busy }) {
  const [q, setQ] = useState('')
  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase()
    if (!s) return incidents
    return incidents.filter((i) => [i.incident_id, attackLabel(i), i.log?.source_ip, i.log?.dest_ip, i.containment_action].join(' ').toLowerCase().includes(s))
  }, [incidents, q])
  const selected = incidents.find((i) => i.incident_id === selectedId) || filtered[0]

  if (!incidents.length) {
    return <Card><Empty icon={Inbox} title="Queue is clear" text="Incidents appear here the moment the pipeline flags an event." /></Card>
  }

  return (
    <div className="workspace">
      <section className="card">
        <header className="card-head" style={{ gap: 8 }}>
          <Search size={15} className="muted" aria-hidden />
          <label htmlFor="q" className="sr-only">Filter incidents</label>
          <input id="q" className="input" style={{ height: 32, flex: 1, border: 0, padding: 0 }} placeholder="Filter by IP, type, action…" value={q} onChange={(e) => setQ(e.target.value)} />
          <span className="pill num">{filtered.length}</span>
        </header>
        <div className="inc-list" role="listbox" aria-label="Incidents">
          {filtered.map((i) => (
            <button key={i.incident_id} className="inc-item" role="option" aria-selected={selected?.incident_id === i.incident_id} onClick={() => onSelect(i.incident_id)}>
              <span className="inc-title">{attackLabel(i)}</span>
              <SeverityBadge level={severityOf(i)} />
              <span className="inc-meta">
                <span className="inc-id">{i.incident_id}</span>
                <span className="mono">{i.log?.source_ip}</span>
                <ActionChip action={i.containment_action} />
                <span style={{ marginLeft: 'auto' }} className="num">{fmtTime(i.created_at)}</span>
              </span>
            </button>
          ))}
          {!filtered.length && <Empty title="No matches" text="Try a different IP address or attack type." />}
        </div>
      </section>
      {selected && <Detail inc={selected} onUndo={onUndo} onFeedback={onFeedback} busy={busy} />}
    </div>
  )
}
