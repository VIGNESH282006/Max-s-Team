import { useCallback, useEffect, useRef, useState } from 'react'
import { LayoutDashboard, Siren, Share2, GraduationCap, ShieldCheck, Play, RotateCcw, LogOut, WifiOff, CheckCircle2, Square } from 'lucide-react'
import { api } from './api.js'
import demoEvents from './data/demoEvents.json'
import Login from './components/Login.jsx'
import { Toasts } from './components/ui.jsx'
import Overview from './pages/Overview.jsx'
import Incidents from './pages/Incidents.jsx'
import ThreatMap from './pages/ThreatMap.jsx'
import Learning from './pages/Learning.jsx'

const PAGES = {
  overview: { label: 'Overview', icon: LayoutDashboard, sub: 'Live posture of the autonomous Level-1 analyst' },
  incidents: { label: 'Incidents', icon: Siren, sub: 'Investigate, explain and correct automated decisions' },
  map: { label: 'Attack graph', icon: Share2, sub: 'How flagged traffic moves between hosts' },
  learning: { label: 'Learning loop', icon: GraduationCap, sub: 'Analyst feedback and the detection model' },
}

const store = {
  get: (k) => { try { return localStorage.getItem(k) } catch { return null } },
  set: (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v) } catch { /* storage blocked */ } },
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export default function App() {
  const [user, setUser] = useState(() => store.get('soc_user'))
  const [page, setPage] = useState('overview')
  const [incidents, setIncidents] = useState([])
  const [queue, setQueue] = useState(null)
  const [status, setStatus] = useState('loading') // loading | ok | offline
  const [selectedId, setSelectedId] = useState(null)
  const [busy, setBusy] = useState(false)
  const [stream, setStream] = useState(null) // { done, total }
  const [toasts, setToasts] = useState([])
  const stopRef = useRef(false)

  const toast = useCallback((text, ok = true) => {
    const id = Math.random()
    setToasts((t) => [...t, { id, text, icon: ok ? <CheckCircle2 size={15} /> : <WifiOff size={15} /> }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200)
  }, [])

  const refresh = useCallback(async () => {
    try {
      const [s, q] = await Promise.all([api.state(), api.retrainingQueue().catch(() => null)])
      setIncidents(s.incidents || [])
      if (q) setQueue(q)
      setStatus('ok')
    } catch {
      setStatus('offline')
    }
  }, [])

  useEffect(() => {
    if (!user) return
    refresh()
    const t = setInterval(refresh, 2500)
    return () => clearInterval(t)
  }, [user, refresh])

  async function runDemo() {
    stopRef.current = false
    setStream({ done: 0, total: demoEvents.length })
    let flagged = 0
    for (let k = 0; k < demoEvents.length; k++) {
      if (stopRef.current) break
      try {
        const r = await api.ingest(demoEvents[k])
        if (r?.status === 'anomaly') flagged++
      } catch {
        toast('Could not reach the detection API', false); break
      }
      setStream({ done: k + 1, total: demoEvents.length })
      if (k % 3 === 0) refresh()
      await sleep(450)
    }
    setStream(null); refresh()
    toast(`Stream finished · ${flagged} incidents raised`)
  }

  async function resetAll() {
    setBusy(true)
    try { await api.reset(); setSelectedId(null); await refresh(); toast('Console reset') }
    catch (e) { toast(e.message, false) }
    setBusy(false)
  }

  async function undo(id) {
    setBusy(true)
    try { await api.undo(id); await refresh(); toast(`Containment undone for ${id}`) }
    catch (e) { toast(e.message, false) }
    setBusy(false)
  }

  async function feedback(id, label) {
    setBusy(true)
    try { await api.feedback(id, label); await refresh(); toast(label === 'normal' ? `${id} marked as false positive` : `${id} confirmed as threat`) }
    catch (e) { toast(e.message, false) }
    setBusy(false)
  }

  const openIncident = (id) => { setSelectedId(id); setPage('incidents') }

  if (!user) return <Login onLogin={(u) => { store.set('soc_user', u); setUser(u) }} />

  const P = PAGES[page]
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={18} aria-hidden /></div>
          <div><div className="brand-name">Agentic SOC</div><div className="brand-sub">Autonomous L1 analyst</div></div>
        </div>
        <nav className="nav" aria-label="Main">
          <div className="nav-label">Monitor</div>
          {Object.entries(PAGES).map(([k, p]) => (
            <button key={k} className="nav-item" aria-current={page === k ? 'page' : undefined} onClick={() => setPage(k)}>
              <p.icon size={17} aria-hidden /> {p.label}
              {k === 'incidents' && incidents.length > 0 && <span className="count num">{incidents.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="avatar">{user.slice(0, 2).toUpperCase()}</div>
          <div style={{ minWidth: 0 }}><div className="user-name">{user}</div><div className="user-role">SOC analyst</div></div>
          <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto' }} aria-label="Sign out" onClick={() => { store.set('soc_user', null); setUser(null) }}><LogOut size={15} /></button>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div>
            <h1 className="page-title">{P.label}</h1>
            <p className="page-sub">{P.sub}</p>
          </div>
          <div className="topbar-actions">
            {status === 'ok' && <span className="pill live" style={{ color: 'var(--good)' }}><span className="dot" />Pipeline online</span>}
            {status === 'offline' && <span className="pill" style={{ color: 'var(--critical)' }}><WifiOff size={13} />API offline</span>}
            {stream ? (
              <>
                <div className="progress" aria-label="Stream progress"><div style={{ width: `${(stream.done / stream.total) * 100}%` }} /></div>
                <span className="muted num" style={{ fontSize: 12.5 }}>{stream.done}/{stream.total}</span>
                <button className="btn" onClick={() => { stopRef.current = true }}><Square size={13} />Stop</button>
              </>
            ) : (
              <button className="btn btn-primary" onClick={runDemo} disabled={status !== 'ok'}><Play size={15} />Stream demo traffic</button>
            )}
            <button className="btn" onClick={resetAll} disabled={busy || !!stream || status !== 'ok'}><RotateCcw size={14} />Reset</button>
          </div>
        </header>

        <main className="content">
          {status === 'offline' && (
            <div className="banner tone-critical" role="alert">
              <WifiOff size={16} />
              Can’t reach the detection API at localhost:8000. Start it with <span className="mono">python app.py</span>.
              <button className="btn btn-sm" onClick={refresh}>Retry</button>
            </div>
          )}
          {status === 'loading' ? (
            <div className="kpis">{[...Array(5)].map((_, k) => <div key={k} className="card kpi"><div className="skeleton" style={{ height: 70 }} /></div>)}</div>
          ) : (
            <>
              {page === 'overview' && <Overview incidents={incidents} queue={queue} onOpen={openIncident} onDemo={runDemo} streaming={!!stream || status !== 'ok'} />}
              {page === 'incidents' && <Incidents incidents={incidents} selectedId={selectedId} onSelect={setSelectedId} onUndo={undo} onFeedback={feedback} busy={busy} />}
              {page === 'map' && <ThreatMap incidents={incidents} onOpen={openIncident} />}
              {page === 'learning' && <Learning queue={queue} />}
            </>
          )}
        </main>
      </div>
      <Toasts items={toasts} />
    </div>
  )
}
