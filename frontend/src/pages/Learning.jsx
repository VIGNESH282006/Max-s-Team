import { RefreshCcw, GraduationCap, Terminal } from 'lucide-react'
import { Card, Empty } from '../components/ui.jsx'
import { fmtTime, titleCase } from '../format.js'

const MODEL = [
  ['Known-attack classifier', 'Random Forest · 150 trees · max depth 12'],
  ['Zero-day detector', 'Isolation Forest · 100 trees · trained on normal traffic only'],
  ['Adversarial hardening', '3 evasion variants per training attack (IP spoofing, port hopping, slow-and-low, off-hours shift)'],
  ['Explainability', 'SHAP TreeExplainer · top contributing features per alert'],
  ['Reasoning', 'Claude LLM · strict JSON decision · rule-based fallback'],
  ['Training data', 'CIC-IDS2017 flows mapped to a common log schema'],
]

export default function Learning({ queue }) {
  const items = queue?.recent_items || []
  const total = (queue?.anomaly_labels || 0) + (queue?.normal_labels || 0)
  return (
    <>
      <div className="kpis" style={{ gridTemplateColumns: 'repeat(3, minmax(0,1fr))' }}>
        <div className="card kpi"><div className="kpi-label">Corrections queued</div><div className="kpi-value num">{total}</div><div className="kpi-foot">Waiting for the next retrain</div></div>
        <div className="card kpi"><div className="kpi-label">Confirmed threats</div><div className="kpi-value num">{queue?.anomaly_labels || 0}</div><div className="kpi-foot">Labelled anomaly by an analyst</div></div>
        <div className="card kpi"><div className="kpi-label">False positives</div><div className="kpi-value num">{queue?.normal_labels || 0}</div><div className="kpi-foot">Relabelled as normal traffic</div></div>
      </div>
      <div className="grid-2">
        <Card title="Retraining queue" sub="Analyst labels fed back into model training" bodyClass="">
          {items.length ? (
            <table className="table">
              <thead><tr><th>Incident</th><th>Label</th><th>Attack type</th><th>Source</th><th>Labelled at</th></tr></thead>
              <tbody>
                {items.map((r, k) => (
                  <tr key={k} style={{ cursor: 'default' }}>
                    <td className="mono">{r.incident_id}</td>
                    <td><span className={`badge ${r.label === 'normal' || r.label === 0 ? 'tone-warning' : 'tone-accent'}`}>{r.label === 'normal' || r.label === 0 ? 'False positive' : 'Confirmed'}</span></td>
                    <td>{titleCase(r.attack_type)}</td>
                    <td className="mono">{r.source_ip || '—'}</td>
                    <td className="muted num">{fmtTime(r.feedback_timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <Empty icon={GraduationCap} title="No corrections yet" text="Open an incident and mark it as a confirmed threat or a false positive. Labels collect here for the next retraining run." />}
        </Card>
        <div className="detail">
          <Card title="Detection model" sub="Ensemble used for every event">
            <dl className="osint" style={{ gridTemplateColumns: '150px 1fr', border: 0, padding: 0, gap: '10px 14px' }}>
              {MODEL.map(([k, v]) => [<dt key={k}>{k}</dt>, <dd key={k + 'v'} style={{ fontWeight: 500 }}>{v}</dd>])}
            </dl>
          </Card>
          <Card title="Retrain with corrections" right={<RefreshCcw size={15} className="muted" />}>
            <p className="muted" style={{ marginTop: 0 }}>Retraining merges the base data with analyst labels and replaces the models only if held-out accuracy does not drop.</p>
            <pre className="code" style={{ maxHeight: 'none' }}><Terminal size={12} style={{ verticalAlign: -1, marginRight: 6 }} />python retrain_pipeline.py</pre>
          </Card>
        </div>
      </div>
    </>
  )
}
