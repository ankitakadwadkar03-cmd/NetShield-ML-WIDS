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
const ACTIVE_SCANNER_STATES = ['starting', 'running', 'stopping']

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

const normalizeScannerStatus = (payload) => payload?.scanner ?? payload?.status ?? payload ?? {}

const getInterfaceName = (source) => getValue(source, ['name', 'interface', 'interface_name'])

const getScannerState = (scannerStatus) =>
  String(getValue(scannerStatus, ['state', 'scanner_state', 'status']) ?? 'stopped').toLowerCase()

function App() {
  const [activeView, setActiveView] = useState('Dashboard')
  const [interfaces, setInterfaces] = useState([])
  const [networks, setNetworks] = useState([])
  const [scannerStatus, setScannerStatus] = useState({})
  const [selectedInterfaceName, setSelectedInterfaceName] = useState('')
  const [wifiScanLoading, setWifiScanLoading] = useState(false)
  const [wifiScanError, setWifiScanError] = useState('')
  const [scannerActionLoading, setScannerActionLoading] = useState(false)

  const fetchJson = async (path, options = {}) => {
    const response = await fetch(`${API_BASE_URL}${path}`, options)

    if (!response.ok) {
      throw new Error(`Request failed: ${path}`)
    }

    return response.json()
  }

  const updateSelectedInterface = (availableInterfaces) => {
    setSelectedInterfaceName((currentInterfaceName) => {
      if (availableInterfaces.some((adapter) => getInterfaceName(adapter) === currentInterfaceName)) {
        return currentInterfaceName
      }

      return getInterfaceName(availableInterfaces[0]) ?? ''
    })
  }

  const loadInterfaces = async (signal) => {
    const interfacesPayload = await fetchJson('/interfaces', { signal })
    const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')

    setInterfaces(availableInterfaces)
    updateSelectedInterface(availableInterfaces)
  }

  const loadNetworks = async (signal) => {
    const networksPayload = await fetchJson('/networks', { signal })
    setNetworks(normalizeList(networksPayload, 'networks'))
  }

  const loadScannerStatus = async (signal) => {
    const statusPayload = await fetchJson('/scanner/status', { signal })
    const normalizedStatus = normalizeScannerStatus(statusPayload)

    setScannerStatus(normalizedStatus)

    return normalizedStatus
  }

  useEffect(() => {
    if (activeView !== 'WiFi Scan') {
      return
    }

    const controller = new AbortController()

    const loadWifiScanData = async () => {
      setWifiScanLoading(true)
      setWifiScanError('')

      try {
        const [interfacesPayload, networksPayload, statusPayload] = await Promise.all([
          fetchJson('/interfaces', { signal: controller.signal }),
          fetchJson('/networks', { signal: controller.signal }),
          fetchJson('/scanner/status', { signal: controller.signal }),
        ])

        const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')

        setInterfaces(availableInterfaces)
        setNetworks(normalizeList(networksPayload, 'networks'))
        setScannerStatus(normalizeScannerStatus(statusPayload))
        updateSelectedInterface(availableInterfaces)
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

  useEffect(() => {
    if (activeView !== 'WiFi Scan') {
      return
    }

    let activePollController = null

    const pollWifiScan = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      Promise.all([loadScannerStatus(controller.signal), loadInterfaces(controller.signal)])
        .then(([latestScannerStatus]) => {
          if (ACTIVE_SCANNER_STATES.includes(getScannerState(latestScannerStatus))) {
            return loadNetworks(controller.signal)
          }

          return null
        })
        .catch((error) => {
          if (error.name !== 'AbortError') {
            setWifiScanError(
              'Unable to refresh scanner data from http://127.0.0.1:5000. Check that the Flask backend is running.',
            )
          }
        })

    }

    const intervalId = setInterval(pollWifiScan, 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView])

  const wirelessAdapter =
    interfaces.find((adapter) => getInterfaceName(adapter) === selectedInterfaceName) ?? interfaces[0] ?? null
  const selectedInterface = getInterfaceName(wirelessAdapter)
  const scannerState = getScannerState(scannerStatus)
  const isScannerActive = ACTIVE_SCANNER_STATES.includes(scannerState)
  const isScannerStarting = scannerState === 'starting'
  const isScannerRunning = scannerState === 'running'
  const isScannerStopping = scannerState === 'stopping'
  const startScanDisabled =
    !selectedInterface ||
    scannerActionLoading ||
    isScannerStarting ||
    isScannerRunning ||
    isScannerStopping
  const stopScanDisabled = !isScannerActive || scannerActionLoading
  const selectableInterfaces = interfaces.filter((adapter) => getInterfaceName(adapter))

  const handleStartScan = async () => {
    if (startScanDisabled) {
      return
    }

    setScannerActionLoading(true)
    setWifiScanError('')

    try {
      await fetchJson('/scanner/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedInterface }),
      })
      await loadScannerStatus()
      await loadNetworks()
    } catch {
      setWifiScanError('Unable to start the scanner. Check the selected interface and Flask backend logs.')
    } finally {
      setScannerActionLoading(false)
    }
  }

  const handleStopScan = async () => {
    if (stopScanDisabled) {
      return
    }

    setScannerActionLoading(true)
    setWifiScanError('')

    try {
      await fetchJson('/scanner/stop', { method: 'POST' })
      await Promise.all([loadScannerStatus(), loadNetworks()])
      const interfacesPayload = await fetchJson('/interfaces')
      setInterfaces(normalizeList(interfacesPayload, 'interfaces'))
    } catch {
      setWifiScanError('Unable to stop the scanner. Check that the Flask backend is running.')
    } finally {
      setScannerActionLoading(false)
    }
  }

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
                <div className="panel-header">
                  <h2>Wireless Adapter</h2>
                  <div className="scan-actions">
                    <button
                      className="scan-button primary"
                      disabled={startScanDisabled}
                      onClick={handleStartScan}
                      type="button"
                    >
                      Start Scan
                    </button>
                    <button
                      className="scan-button"
                      disabled={stopScanDisabled}
                      onClick={handleStopScan}
                      type="button"
                    >
                      Stop Scan
                    </button>
                  </div>
                </div>
                {wifiScanLoading ? (
                  <p className="muted-text">Loading adapter details...</p>
                ) : wirelessAdapter ? (
                  <>
                    {selectableInterfaces.length > 1 ? (
                      <label className="interface-select">
                        <span>Selected Interface</span>
                        <select
                          onChange={(event) => setSelectedInterfaceName(event.target.value)}
                          value={selectedInterfaceName}
                        >
                          {selectableInterfaces.map((adapter) => {
                            const adapterName = getInterfaceName(adapter)

                            return (
                              <option key={adapterName} value={adapterName}>
                                {adapterName}
                              </option>
                            )
                          })}
                        </select>
                      </label>
                    ) : null}
                    <dl className="status-list">
                      <div>
                        <dt>Adapter Status</dt>
                        <dd>{formatValue(getValue(wirelessAdapter, ['status', 'adapter_status']))}</dd>
                      </div>
                      <div>
                        <dt>Interface Name</dt>
                        <dd>{formatValue(selectedInterface)}</dd>
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
                  </>
                ) : (
                  <div className="empty-state">
                    <p>No wireless adapter detected.</p>
                    <p>Connect a compatible monitor-mode WiFi adapter to start scanning.</p>
                  </div>
                )}
              </section>

              <section className="panel scanner-panel">
                <h2>Scanner Status</h2>
                <dl className="status-list scanner-status-list">
                  <div>
                    <dt>Scanner State</dt>
                    <dd>{formatValue(getValue(scannerStatus, ['state', 'scanner_state', 'status']))}</dd>
                  </div>
                  <div>
                    <dt>Interface</dt>
                    <dd>{formatValue(getValue(scannerStatus, ['interface', 'interface_name']))}</dd>
                  </div>
                  <div>
                    <dt>Current Channel</dt>
                    <dd>{formatValue(getValue(scannerStatus, ['current_channel', 'channel']))}</dd>
                  </div>
                  <div>
                    <dt>Sweep Number</dt>
                    <dd>{formatValue(getValue(scannerStatus, ['sweep_number', 'sweep']))}</dd>
                  </div>
                  <div>
                    <dt>Channels Completed</dt>
                    <dd>
                      {formatValue(
                        getValue(scannerStatus, [
                          'channels_completed',
                          'completed_channels',
                        ]),
                      )}
                      {' / '}
                      {formatValue(
                        getValue(scannerStatus, ['total_channels', 'channels_total']),
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>Networks Discovered</dt>
                    <dd>
                      {formatValue(
                        getValue(scannerStatus, [
                          'networks_discovered',
                          'network_count',
                          'networks_found',
                        ]),
                      )}
                    </dd>
                  </div>
                </dl>
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
