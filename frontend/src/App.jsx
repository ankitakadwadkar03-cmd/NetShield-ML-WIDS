import { useState } from 'react'
import './App.css'

const sidebarItems = [
  'Dashboard',
  'WiFi Scan',
  'Live Monitor',
  'ML Detection',
  'Incidents',
  'Reports',
  'Settings',
]

const dashboardCards = [
  ['Security Score', '--'],
  ['Active Threats', '--'],
  ['Networks Found', '--'],
  ['Packets Analyzed', '--'],
]

function App() {
  const [activeView, setActiveView] = useState('Dashboard')

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <span className="brand-mark">NS</span>
          <div>
            <p className="brand-name">NetShield</p>
            <p className="brand-subtitle">WiFi IDS</p>
          </div>
        </div>

        <nav className="nav-list">
          {sidebarItems.map((item) => (
            <button
              className={item === activeView ? 'nav-item active' : 'nav-item'}
              key={item}
              onClick={() => setActiveView(item)}
              type="button"
            >
              {item}
            </button>
          ))}
        </nav>
      </aside>

      <div className="workspace">
        <header className="top-header">
          <div>
            <p className="eyebrow">ML-Based WiFi Intrusion Detection</p>
            <h1>NetShield</h1>
            <p className="page-title">{activeView}</p>
          </div>
          <div className="header-status">
            <span className="status-dot"></span>
            Monitoring not started
          </div>
        </header>

        <main className="main-content">
          {activeView === 'Dashboard' ? (
            <section className="dashboard-view" aria-label="Dashboard overview">
              <div className="metric-grid">
                {dashboardCards.map(([label, value]) => (
                  <article className="metric-card" key={label}>
                    <p>{label}</p>
                    <strong>{value}</strong>
                  </article>
                ))}
              </div>

              <div className="panel-grid">
                <section className="panel">
                  <h2>Current Monitoring</h2>
                  <dl className="status-list">
                    <div>
                      <dt>Status</dt>
                      <dd>Not Started</dd>
                    </div>
                    <div>
                      <dt>Network</dt>
                      <dd>None Selected</dd>
                    </div>
                    <div>
                      <dt>Interface</dt>
                      <dd>Not Selected</dd>
                    </div>
                  </dl>
                </section>

                <section className="panel">
                  <h2>Latest Detection</h2>
                  <p className="empty-state">No traffic has been analyzed yet.</p>
                </section>
              </div>
            </section>
          ) : (
            <section className="placeholder-view">
              <p className="eyebrow">{activeView}</p>
              <h2>{activeView}</h2>
              <p>This section is ready for future NetShield functionality.</p>
            </section>
          )}
        </main>
      </div>
    </div>
  )
}

export default App
