import { useMemo } from 'react'
import { Siren, ShieldCheck, Timer, Radar, UserCheck, Play, Activity } from 'lucide-react'
import { Card, BarList, Empty, SeverityBadge, ActionChip, Flow } from '../components/ui.jsx'
import { ACTIONS, severityOf, attackLabel, fmtMs, fmtTime, median, isUndone } from '../format.js'

function Kpi({ icon: Icon, label, value, foot }) {
  return (
    <div className="card kpi">
      <div className="kpi-label"><Icon size={15} aria-hidden /> {label}</div>
      <div className="kpi-value num">{value}</div>
      <div className="kpi-foot">{foot}</div>
    </div>
  )
}

export default function Overview({ incidents, queue, onOpen, onDemo, streaming }) {
  const stats = useMemo(() => {
    const total = incidents.length
    const contained = incidents.filter((i) => !isUndone(i)).length
    const totals = incidents.map((i) => i.pipeline_total_ms)
    const ioc = incidents.filter((i) => i.osint_is_ioc || (i.osint_findings || []).length).length
    const byAction = Object.keys(ACTIONS).map((k) => ({
      label: ACTIONS[k].label, value: incidents.filter((i) => i.containment_action === k).length, color: ACTIONS[k].color,
    }))
    const typeMap = {}
    incidents.forEach((i) => { const t = attackLabel(i); typeMap[t] = (typeMap[t] || 0) + 1 })
    const byType = Object.entries(typeMap).sort((a, b) => b[1] - a[1]).slice(0, 6)
      .map(([label, value]) => ({ label, value, color: 'var(--series-1)' }))
    const stage = (k) => median(incidents.map((i) => i.pipeline_timing_ms?.[k]))
    const stages = [
      { label: 'OSINT lookup', value: stage('data_fetch_osint') },
      { label: 'ML + SHAP', value: stage('ml_load_train_reason') },
      { label: 'LLM reasoning', value: stage('llm_claude_reasoning') },
      { label: 'Response prep', value: stage('frontend_prepare') },
    ].map((s) => ({ ...s, value: s.value ?? 0, color: 'var(--series-1)' }))
    const sev = { critical: 0, high: 0, medium: 0, low: 0 }
    incidents.forEach((i) => { sev[severityOf(i)]++ })
    return { total, contained, med: median(totals), ioc, byAction, byType, stages, sev }
  }, [incidents])

  const labels = (queue?.anomaly_labels || 0) + (queue?.normal_labels || 0)

  if (!incidents.length) {
    return (
      <Card>
        <Empty
          icon={Activity}
          title="No incidents yet"
          text="The console is connected and watching. Stream sample network and authentication logs through the pipeline to see detection, explanation and containment in action."
          action={<button className="btn btn-primary" onClick={onDemo} disabled={streaming}><Play size={15} /> Stream demo traffic</button>}
        />
      </Card>
    )
  }

  return (
    <>
      <div className="kpis">
        <Kpi icon={Siren} label="Incidents detected" value={stats.total}
          foot={`${stats.sev.critical} critical · ${stats.sev.high} high`} />
        <Kpi icon={ShieldCheck} label="Auto-contained" value={`${Math.round((stats.contained / stats.total) * 100)}%`}
          foot={`${stats.contained} of ${stats.total} still in effect`} />
        <Kpi icon={Timer} label="Median time to contain" value={fmtMs(stats.med)}
          foot="Log received → action taken" />
        <Kpi icon={Radar} label="Threat-intel matches" value={stats.ioc}
          foot="Known-bad indicators (OSINT)" />
        <Kpi icon={UserCheck} label="Analyst corrections" value={labels}
          foot={`${queue?.normal_labels || 0} false positives queued`} />
      </div>

      <div className="grid-3">
        <Card title="Containment actions" sub="Chosen by the LLM per incident">
          <BarList rows={stats.byAction} />
        </Card>
        <Card title="Detections by attack type" sub="Top 6 classifications">
          <BarList rows={stats.byType} />
        </Card>
        <Card title="Where the time goes" sub="Median per pipeline stage">
          <BarList rows={stats.stages} format={fmtMs} />
        </Card>
      </div>

      <Card title="Latest incidents" sub="Select a row to open the investigation" bodyClass=""
        right={<span className="pill live" style={{ color: 'var(--good)' }}><span className="dot" />Live</span>}>
        <div style={{ overflowX: 'auto' }}>
          <table className="table">
            <thead><tr><th>Incident</th><th>Time</th><th>Severity</th><th>Attack type</th><th>Source → target</th><th>Action</th><th className="num" style={{ textAlign: 'right' }}>Contained in</th></tr></thead>
            <tbody>
              {incidents.slice(0, 8).map((i) => (
                <tr key={i.incident_id} onClick={() => onOpen(i.incident_id)} tabIndex={0}
                  onKeyDown={(e) => e.key === 'Enter' && onOpen(i.incident_id)}>
                  <td className="mono">{i.incident_id}</td>
                  <td className="muted num">{fmtTime(i.created_at)}</td>
                  <td><SeverityBadge level={severityOf(i)} /></td>
                  <td style={{ fontWeight: 550 }}>{attackLabel(i)}</td>
                  <td><Flow from={i.log?.source_ip} to={i.log?.dest_ip} /></td>
                  <td><ActionChip action={i.containment_action} /></td>
                  <td className="mono" style={{ textAlign: 'right' }}>{fmtMs(i.pipeline_total_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}
