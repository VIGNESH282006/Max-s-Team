import { useEffect, useMemo, useRef, useState } from 'react'
import { Network } from 'vis-network/standalone'
import { Share2 } from 'lucide-react'
import { Card, Empty, ActionChip, SeverityBadge } from '../components/ui.jsx'
import { ACTIONS, attackLabel, severityOf, fmtTime } from '../format.js'

const isInternal = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip || '')
const HEX = { isolate: '#2a78d6', revoke: '#eb6834', honeypot: '#1baf7a' }

export default function ThreatMap({ incidents, onOpen }) {
  const el = useRef(null)
  const [picked, setPicked] = useState(null)

  const graph = useMemo(() => {
    const nodes = new Map(); const edges = new Map()
    incidents.forEach((i) => {
      const s = i.log?.source_ip; const d = i.log?.dest_ip
      if (!s || !d) return
      ;[s, d].forEach((ip) => {
        if (!nodes.has(ip)) nodes.set(ip, { ip, hits: 0, role: new Set() })
        nodes.get(ip).hits++
      })
      nodes.get(s).role.add('source'); nodes.get(d).role.add('target')
      const k = `${s}>${d}>${i.containment_action}`
      const e = edges.get(k) || { from: s, to: d, action: i.containment_action, n: 0 }
      e.n++; edges.set(k, e)
    })
    return { nodes: [...nodes.values()], edges: [...edges.values()] }
  }, [incidents])

  useEffect(() => {
    if (!el.current || !graph.nodes.length) return undefined
    const nodes = graph.nodes.map((n) => {
      const attacker = n.role.has('source') && !isInternal(n.ip)
      const internalSrc = n.role.has('source') && isInternal(n.ip)
      const color = attacker ? '#d03b3b' : internalSrc ? '#ec835a' : '#2a78d6'
      return {
        id: n.ip,
        label: `${n.ip}\n${attacker ? 'External source' : internalSrc ? 'Internal source' : 'Internal asset'}`,
        shape: 'dot', size: 9 + Math.min(11, n.hits * 0.8),
        color: { background: color, border: '#ffffff', highlight: { background: color, border: '#101828' }, hover: { background: color, border: '#101828' } },
        borderWidth: 3, shadow: { enabled: true, color: 'rgba(16,24,40,0.18)', size: 6, x: 0, y: 2 },
        font: { face: 'Inter Variable, Inter, sans-serif', size: 13, color: '#344054', background: 'rgba(255,255,255,0.9)', vadjust: 4 },
      }
    })
    const edges = graph.edges.map((e, k) => ({
      id: k, from: e.from, to: e.to, arrows: { to: { enabled: true, scaleFactor: 0.6 } },
      color: { color: HEX[e.action] || '#98a2b3', opacity: 0.85 }, width: 1.5 + Math.min(4, e.n * 0.6),
      smooth: { type: 'curvedCW', roundness: 0.15 },
      title: `${ACTIONS[e.action]?.label || e.action} · ${e.n} incident${e.n > 1 ? 's' : ''}`,
    }))
    const net = new Network(el.current, { nodes, edges }, {
      physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -60, springLength: 160 }, stabilization: { iterations: 200 } },
      interaction: { hover: true, tooltipDelay: 120 },
    })
    net.once('stabilizationIterationsDone', () => net.setOptions({ physics: false }))
    net.on('click', (p) => setPicked(p.nodes[0] || null))
    return () => net.destroy()
  }, [graph])

  if (!incidents.length) {
    return <Card><Empty icon={Share2} title="Nothing to map yet" text="The attack graph is drawn from incident source and target addresses as they arrive." /></Card>
  }

  const busiest = [...graph.nodes].sort((a, b) => b.hits - a.hits)[0]?.ip
  const sel = picked || busiest
  const related = sel ? incidents.filter((i) => i.log?.source_ip === sel || i.log?.dest_ip === sel) : []

  return (
    <div className="map-wrap">
      <Card title="Attack graph" sub="Nodes are hosts; arrows show flagged traffic, coloured by the containment applied" bodyClass=""
        right={<div className="legend">{Object.entries(ACTIONS).map(([k, a]) => <span key={k}><span className="swatch" style={{ background: a.color }} />{a.short}</span>)}</div>}>
        <div ref={el} className="network" role="img" aria-label="Network graph of hosts involved in incidents" />
      </Card>
      <Card title={<span className="mono" style={{ fontSize: 14 }}>{sel}</span>} sub={`${related.length} related incident${related.length === 1 ? '' : 's'} · click any host to inspect`}>
        <div className="legend" style={{ flexDirection: 'column', gap: 8, marginBottom: 16 }}>
          <span><span className="swatch" style={{ background: '#d03b3b', borderRadius: '50%' }} />External source (attacker)</span>
          <span><span className="swatch" style={{ background: '#ec835a', borderRadius: '50%' }} />Internal source (possible lateral movement)</span>
          <span><span className="swatch" style={{ background: '#2a78d6', borderRadius: '50%' }} />Internal asset (target)</span>
        </div>
        {related.slice(0, 8).map((i) => (
          <button key={i.incident_id} className="inc-item" style={{ padding: '10px 0' }} onClick={() => onOpen(i.incident_id)}>
            <span className="inc-title" style={{ fontSize: 13 }}>{attackLabel(i)}</span>
            <SeverityBadge level={severityOf(i)} />
            <span className="inc-meta"><span className="inc-id">{i.incident_id}</span><ActionChip action={i.containment_action} /><span style={{ marginLeft: 'auto' }}>{fmtTime(i.created_at)}</span></span>
          </button>
        ))}
      </Card>
    </div>
  )
}
