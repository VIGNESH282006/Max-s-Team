import { useState } from 'react'
import { ShieldCheck, LogIn } from 'lucide-react'

const STAGES = ['OSINT threat-intel lookup', 'Random Forest + Isolation Forest scoring', 'SHAP explanation of every alert', 'LLM reasoning and containment decision', 'Automated playbook and analyst feedback']

export default function Login({ onLogin }) {
  const [user, setUser] = useState('analyst')
  const [pass, setPass] = useState('')
  const [err, setErr] = useState('')

  function submit(e) {
    e.preventDefault()
    if (!user.trim() || pass.length < 4) {
      setErr('Enter your username and a password of at least 4 characters.')
      return
    }
    onLogin(user.trim())
  }

  return (
    <div className="login">
      <aside className="login-side">
        <div className="brand" style={{ padding: 0 }}>
          <div className="brand-mark"><ShieldCheck size={18} /></div>
          <div className="brand-name" style={{ color: '#fff' }}>Agentic SOC</div>
        </div>
        <h1>An autonomous Level-1 analyst for your security operations centre.</h1>
        <p>Every log is checked, scored, explained and contained in milliseconds, with the analyst kept in the loop.</p>
        <div className="login-pipeline">
          {STAGES.map((s, i) => (
            <div key={s}><span>{i + 1}</span>{s}</div>
          ))}
        </div>
      </aside>
      <main className="login-form-wrap">
        <form className="login-form" onSubmit={submit} noValidate>
          <div>
            <h2 style={{ margin: 0, fontSize: 22, letterSpacing: '-0.015em' }}>Sign in</h2>
            <p className="muted" style={{ margin: '4px 0 0' }}>Use your SOC analyst account.</p>
          </div>
          <div className="field">
            <label htmlFor="u">Username</label>
            <input id="u" className="input" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="username" />
          </div>
          <div className="field">
            <label htmlFor="p">Password</label>
            <input id="p" type="password" className="input" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="current-password" />
          </div>
          {err && <div className="error-text" role="alert">{err}</div>}
          <button className="btn btn-primary" style={{ height: 40, justifyContent: 'center' }} type="submit">
            <LogIn size={16} /> Sign in
          </button>
        </form>
      </main>
    </div>
  )
}
