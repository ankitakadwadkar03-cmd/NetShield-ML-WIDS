import { useEffect, useState } from 'react'
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

const API_BASE_URL = 'http://127.0.0.1:5000/api'

const getValue = (source, keys) => {
  for (const key of keys) {
    if (source?.[key] !== undefined && source[key] !== null && source[key] !== '') {
      return source[key]
    }
  }

  return null
}

const normalizeList = (payload, key) => {
  if (Array.isArray(payload)) {
    return payload
  }

  if (Array.isArray(payload?.[key])) {
    return payload[key]
  }

  if (Array.isArray(payload?.data)) {
    return payload.data
  }

  return []
}

const formatValue = (value) => value ?? 'Not reported'

function App() {
  const [activeView, setActiveView] = useState('Dashboard')
  const [interfaces, setInterfaces] = useState([])
  const [networks, setNetworks] = useState([])
  const [wifiScanLoading, setWifiScanLoading] = useState(false)
  const [wifiScanError, setWifiScanError] = useState('')

  useEffect(() => {
    if (activeView !== 'WiFi Scan') {
      return
    }

    const controller = new AbortController()

    const loadWifiScanData = async () => {
      setWifiScanLoading(true)
      setWifiScanError('')

      try {
        const [interfacesResponse, networksResponse] = await Promise.all([
          fetch(`${API_BASE_URL}/interfaces`, { signal: controller.signal }),
          fetch(`${API_BASE_URL}/networks`, { signal: controller.signal }),
        ])

        if (!interfacesResponse.ok || !networksResponse.ok) {
          throw new Error('The NetShield backend returned an error while loading WiFi scan data.')
        }

        const [interfacesPayload, networksPayload] = await Promise.all([
          interfacesResponse.json(),
          networksResponse.json(),
        ])

        setInterfaces(normalizeList(interfacesPayload, 'interfaces'))
        setNetworks(normalizeList(networksPayload, 'networks'))
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setInterfaces([])
        setNetworks([])
        setWifiScanError(
          'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setWifiScanLoading(false)
        }
      }
    }

    loadWifiScanData()

    return () => controller.abort()
  }, [activeView])

  const wirelessAdapter = interfaces[0] ?? null

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
          ) : activeView === 'WiFi Scan' ? (
            <section className="wifi-scan-view" aria-label="WiFi scan">
              {wifiScanError ? <p className="error-banner">{wifiScanError}</p> : null}

              <section className="panel adapter-panel">
                <h2>Wireless Adapter</h2>
                {wifiScanLoading ? (
                  <p className="muted-text">Loading adapter details...</p>
                ) : wirelessAdapter ? (
                  <dl className="status-list">
                    <div>
                      <dt>Adapter Status</dt>
                      <dd>{formatValue(getValue(wirelessAdapter, ['status', 'adapter_status']))}</dd>
                    </div>
                    <div>
                      <dt>Interface Name</dt>
                      <dd>{formatValue(getValue(wirelessAdapter, ['name', 'interface', 'interface_name']))}</dd>
                    </div>
                    <div>
                      <dt>Mode</dt>
                      <dd>{formatValue(getValue(wirelessAdapter, ['mode']))}</dd>
                    </div>
                    <div>
                      <dt>Channel</dt>
                      <dd>{formatValue(getValue(wirelessAdapter, ['channel']))}</dd>
                    </div>
                  </dl>
                ) : (
                  <div className="empty-state">
                    <p>No wireless adapter detected.</p>
                    <p>Connect a compatible monitor-mode WiFi adapter to start scanning.</p>
                  </div>
                )}
              </section>

              <section className="panel networks-panel">
                <h2>Networks</h2>
                {wifiScanLoading ? (
                  <p className="muted-text">Loading scanned networks...</p>
                ) : networks.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>SSID</th>
                          <th>BSSID</th>
                          <th>Vendor</th>
                          <th>Channel</th>
                          <th>Signal</th>
                          <th>Security</th>
                          <th>Analysis Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {networks.map((network, index) => (
                          <tr key={getValue(network, ['bssid', 'BSSID']) ?? index}>
                            <td>{formatValue(getValue(network, ['ssid', 'SSID']))}</td>
                            <td>{formatValue(getValue(network, ['bssid', 'BSSID']))}</td>
                            <td>{formatValue(getValue(network, ['vendor', 'Vendor']))}</td>
                            <td>{formatValue(getValue(network, ['channel', 'Channel']))}</td>
                            <td>{formatValue(getValue(network, ['signal', 'Signal']))}</td>
                            <td>{formatValue(getValue(network, ['security', 'Security']))}</td>
                            <td>
                              {formatValue(
                                getValue(network, [
                                  'analysis_status',
                                  'analysisStatus',
                                  'Analysis Status',
                                ]),
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="empty-state">No scanned networks are available.</p>
                )}
              </section>
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
