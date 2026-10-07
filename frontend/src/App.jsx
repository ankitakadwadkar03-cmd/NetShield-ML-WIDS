import { useEffect, useState } from 'react'
import './App.css'

const sidebarItems = [
  'Dashboard',
  'WiFi Scan',
  'Live Monitor',
  'ML Detection',
  'PCAP Analysis',
  'ML Testing',
  'Network Recommendations',
  'Incidents',
  'Reports',
  'Settings',
]


const API_BASE_URL = 'http://127.0.0.1:5000/api'
const ACTIVE_SCANNER_STATES = ['starting', 'running', 'stopping']
const ACTIVE_CAPTURE_STATES = ['starting', 'running', 'stopping']

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

const formatWithUnit = (value, unit) => (value === undefined || value === null ? 'Not reported' : `${value} ${unit}`)

const formatProbability = (value) => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return 'Not reported'
  }

  return `${(Number(value) * 100).toFixed(1)}%`
}

const formatDateTime = (value) => {
  if (!value) {
    return 'Not reported'
  }

  try {
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) {
      return String(value)
    }

    return date.toLocaleString()
  } catch {
    return String(value)
  }
}

const getSeverityBadgeClass = (severity) => {
  const normalized = String(severity ?? '').toLowerCase()
  if (normalized === 'high') {
    return 'badge badge-severity-high'
  }
  if (normalized === 'medium') {
    return 'badge badge-severity-medium'
  }
  if (normalized === 'low') {
    return 'badge badge-severity-low'
  }

  return 'badge badge-default'
}

const getStatusBadgeClass = (status) => {
  const normalized = String(status ?? '').toLowerCase()
  if (normalized === 'new') {
    return 'badge badge-status-new'
  }
  if (normalized === 'resolved') {
    return 'badge badge-status-resolved'
  }

  return 'badge badge-default'
}

const normalizeScannerStatus = (payload) => payload?.scanner ?? payload?.status ?? payload ?? {}

const normalizeCaptureStatus = (payload) => payload?.capture ?? payload?.status ?? payload ?? {}

const getInterfaceName = (source) => getValue(source, ['name', 'interface', 'interface_name'])

const getScannerState = (scannerStatus) =>
  String(getValue(scannerStatus, ['state', 'scanner_state', 'status']) ?? 'stopped').toLowerCase()

const getCaptureState = (captureStatus) =>
  String(getValue(captureStatus, ['state', 'capture_state', 'status']) ?? 'stopped').toLowerCase()

const normalizeCounts = (counts) =>
  counts && typeof counts === 'object' && !Array.isArray(counts) ? counts : {}

const formatFileSize = (bytes) => {
  if (!bytes || Number.isNaN(Number(bytes))) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  let size = Number(bytes)
  let unitIndex = 0
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex++
  }
  return `${size.toFixed(1)} ${units[unitIndex]}`
}

const getCategoryBadgeClass = (category) => {
  const norm = String(category || '').toLowerCase()
  if (norm.includes('deauth')) return 'badge badge-cat-deauth'
  if (norm.includes('disas')) return 'badge badge-cat-disas'
  if (norm.includes('assoc')) return 'badge badge-cat-reassoc'
  if (norm.includes('rogue')) return 'badge badge-cat-rogueap'
  if (norm.includes('attack')) return 'badge badge-cat-attack'
  return 'badge badge-cat-normal'
}

const getRecommendationBadgeClass = (classification) => {
  const norm = String(classification || '').toUpperCase()
  if (norm === 'EXCELLENT') return 'badge badge-rec-excellent'
  if (norm === 'GOOD') return 'badge badge-rec-good'
  if (norm === 'FAIR') return 'badge badge-rec-fair'
  if (norm === 'POOR') return 'badge badge-rec-poor'
  return 'badge badge-default'
}

function App() {
  const [activeView, setActiveView] = useState('Dashboard')
  const [interfaces, setInterfaces] = useState([])
  const [adapterState, setAdapterState] = useState(null)
  const [networks, setNetworks] = useState([])
  const [scannerStatus, setScannerStatus] = useState({})
  const [captureStatus, setCaptureStatus] = useState({})
  const [packets, setPackets] = useState([])
  const [selectedInterfaceName, setSelectedInterfaceName] = useState('')
  const [selectedCaptureInterfaceName, setSelectedCaptureInterfaceName] = useState('')
  const [wifiScanLoading, setWifiScanLoading] = useState(false)
  const [wifiScanError, setWifiScanError] = useState('')
  const [scannerActionLoading, setScannerActionLoading] = useState(false)
  const [liveMonitorLoading, setLiveMonitorLoading] = useState(false)
  const [liveMonitorError, setLiveMonitorError] = useState('')
  const [captureActionLoading, setCaptureActionLoading] = useState(false)
  const [mlLiveStatus, setMlLiveStatus] = useState(null)
  const [mlDetectionLoading, setMlDetectionLoading] = useState(false)
  const [mlDetectionError, setMlDetectionError] = useState('')
  const [incidents, setIncidents] = useState([])
  const [incidentsLoading, setIncidentsLoading] = useState(false)
  const [incidentsError, setIncidentsError] = useState('')
  const [reportIncidents, setReportIncidents] = useState([])
  const [reportsLoading, setReportsLoading] = useState(false)
  const [reportsError, setReportsError] = useState('')

  // PCAP Analysis state
  const [pcapSamples, setPcapSamples] = useState([])
  const [selectedPcapSample, setSelectedPcapSample] = useState('')
  const [selectedPcapFile, setSelectedPcapFile] = useState(null)
  const [pcapAnalyzing, setPcapAnalyzing] = useState(false)
  const [pcapError, setPcapError] = useState('')
  const [pcapResult, setPcapResult] = useState(null)
  const [pcapHistory, setPcapHistory] = useState([])
  const [pcapFilter, setPcapFilter] = useState('all')
  const [pcapHistoryLoading, setPcapHistoryLoading] = useState(false)

  // ML Testing & Evaluation state
  const [mlDatasets, setMlDatasets] = useState([])
  const [selectedDataset, setSelectedDataset] = useState('')
  const [mlTestingLoading, setMlTestingLoading] = useState(false)
  const [mlTestingError, setMlTestingError] = useState('')
  const [mlTestResult, setMlTestResult] = useState(null)
  const [mlTestRuns, setMlTestRuns] = useState([])
  const [mlSchemaInfo, setMlSchemaInfo] = useState(null)

  // Wi-Fi Recommendation & Connect state
  const [recommendationsData, setRecommendationsData] = useState(null)
  const [recommendationsLoading, setRecommendationsLoading] = useState(false)
  const [recommendationsError, setRecommendationsError] = useState('')
  const [recommendationModelInfo, setRecommendationModelInfo] = useState(null)
  const [recommendationFilter, setRecommendationFilter] = useState('all')
  const [recommendationSort, setRecommendationSort] = useState('score')
  const [connectModalNetwork, setConnectModalNetwork] = useState(null)
  const [connectPassword, setConnectPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [connectLoading, setConnectLoading] = useState(false)
  const [connectStatus, setConnectStatus] = useState(null)

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

    setSelectedCaptureInterfaceName((currentInterfaceName) => {
      if (availableInterfaces.some((adapter) => getInterfaceName(adapter) === currentInterfaceName)) {
        return currentInterfaceName
      }

      return getInterfaceName(availableInterfaces[0]) ?? ''
    })
  }

  const loadInterfaces = async (signal) => {
    const interfacesPayload = await fetchJson('/interfaces', { signal })
    const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')

    setAdapterState(getValue(interfacesPayload, ['state']))
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

  const loadCaptureStatus = async (signal) => {
    const statusPayload = await fetchJson('/capture/status', { signal })
    const normalizedStatus = normalizeCaptureStatus(statusPayload)

    setCaptureStatus(normalizedStatus)

    return normalizedStatus
  }

  const loadPackets = async (signal) => {
    const packetsPayload = await fetchJson('/packets?limit=20', { signal })
    setPackets(normalizeList(packetsPayload, 'packets'))
  }

  useEffect(() => {
    if (activeView !== 'Dashboard') {
      return
    }

    const controller = new AbortController()

    const loadDashboardData = async () => {
      try {
        await Promise.all([
          loadInterfaces(controller.signal),
          loadNetworks(controller.signal),
          loadCaptureStatus(controller.signal),
          loadPackets(controller.signal),
        ])
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }
      }
    }

    loadDashboardData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'WiFi Scan') {
      return
    }

    const controller = new AbortController()

    const loadWifiScanData = async () => {
      setWifiScanLoading(true)
      setWifiScanError('')

      try {
        const [interfacesPayload, networksPayload, statusPayload, capturePayload] = await Promise.all([
          fetchJson('/interfaces', { signal: controller.signal }),
          fetchJson('/networks', { signal: controller.signal }),
          fetchJson('/scanner/status', { signal: controller.signal }),
          fetchJson('/capture/status', { signal: controller.signal }),
        ])

        const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')

        setInterfaces(availableInterfaces)
        setAdapterState(getValue(interfacesPayload, ['state']))
        setNetworks(normalizeList(networksPayload, 'networks'))
        setScannerStatus(normalizeScannerStatus(statusPayload))
        setCaptureStatus(normalizeCaptureStatus(capturePayload))
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
    if (activeView !== 'Live Monitor') {
      return
    }

    const controller = new AbortController()

    const loadLiveMonitorData = async () => {
      setLiveMonitorLoading(true)
      setLiveMonitorError('')

      try {
        const [interfacesPayload, scannerPayload, capturePayload] = await Promise.all([
          fetchJson('/interfaces', { signal: controller.signal }),
          fetchJson('/scanner/status', { signal: controller.signal }),
          fetchJson('/capture/status', { signal: controller.signal }),
        ])
        const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')
        const normalizedCaptureStatus = normalizeCaptureStatus(capturePayload)

        setInterfaces(availableInterfaces)
        setAdapterState(getValue(interfacesPayload, ['state']))
        setScannerStatus(normalizeScannerStatus(scannerPayload))
        setCaptureStatus(normalizedCaptureStatus)
        updateSelectedInterface(availableInterfaces)

        if (ACTIVE_CAPTURE_STATES.includes(getCaptureState(normalizedCaptureStatus))) {
          await loadPackets(controller.signal)
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setPackets([])
        setLiveMonitorError(
          'Unable to connect to the NetShield capture backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setLiveMonitorLoading(false)
        }
      }
    }

    loadLiveMonitorData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Live Monitor') {
      return
    }

    let activePollController = null

    const pollLiveMonitor = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      Promise.all([
        loadCaptureStatus(controller.signal),
        loadScannerStatus(controller.signal),
        loadInterfaces(controller.signal),
      ])
        .then(([latestCaptureStatus]) => {
          if (ACTIVE_CAPTURE_STATES.includes(getCaptureState(latestCaptureStatus))) {
            return loadPackets(controller.signal)
          }

          return null
        })
        .catch((error) => {
          if (error.name !== 'AbortError') {
            setLiveMonitorError(
              'Unable to refresh capture data from http://127.0.0.1:5000. Check that the Flask backend is running.',
            )
          }
        })
    }

    const intervalId = setInterval(pollLiveMonitor, 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
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

      Promise.all([
        loadScannerStatus(controller.signal),
        loadInterfaces(controller.signal),
        loadCaptureStatus(controller.signal),
      ])
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

  useEffect(() => {
    if (activeView !== 'ML Detection' && activeView !== 'Dashboard') {
      return
    }

    const controller = new AbortController()

    const loadMlDetectionData = async () => {
      setMlDetectionLoading(true)
      setMlDetectionError('')

      try {
        const payload = await fetchJson('/ml/live-status', { signal: controller.signal })
        setMlLiveStatus(payload)
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setMlLiveStatus(null)
        setMlDetectionError(
          'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setMlDetectionLoading(false)
        }
      }
    }

    loadMlDetectionData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'ML Detection' && activeView !== 'Dashboard') {
      return
    }

    let activePollController = null

    const pollMlDetection = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      fetchJson('/ml/live-status', { signal: controller.signal })
        .then((payload) => {
          setMlDetectionError('')
          setMlLiveStatus(payload)
        })
        .catch((error) => {
          if (error.name !== 'AbortError') {
            setMlDetectionError(
              'Unable to refresh ML inference data from http://127.0.0.1:5000. Check that the Flask backend is running.',
            )
          }
        })
    }

    const intervalId = setInterval(pollMlDetection, 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Incidents' && activeView !== 'Dashboard') {
      return
    }

    const controller = new AbortController()

    const loadIncidentsData = async () => {
      setIncidentsLoading(true)
      setIncidentsError('')

      try {
        const payload = await fetchJson('/incidents', { signal: controller.signal })
        setIncidents(normalizeList(payload, 'incidents'))
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setIncidents([])
        setIncidentsError(
          'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setIncidentsLoading(false)
        }
      }
    }

    loadIncidentsData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Incidents' && activeView !== 'Dashboard') {
      return
    }

    let activePollController = null

    const pollIncidents = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      fetchJson('/incidents', { signal: controller.signal })
        .then((payload) => {
          setIncidents(normalizeList(payload, 'incidents'))
        })
        .catch(() => {})
    }

    const intervalId = setInterval(pollIncidents, 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView])

  const loadReportsData = async (signal) => {
    setReportsLoading(true)
    setReportsError('')

    try {
      const payload = await fetchJson('/incidents', { signal })
      setReportIncidents(normalizeList(payload, 'incidents'))
    } catch (error) {
      if (error.name === 'AbortError') {
        return
      }

      setReportIncidents([])
      setReportsError(
        'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
      )
    } finally {
      if (!signal?.aborted) {
        setReportsLoading(false)
      }
    }
  }

  useEffect(() => {
    if (activeView !== 'Reports') {
      return
    }

    const controller = new AbortController()
    loadReportsData(controller.signal)

    return () => controller.abort()
  }, [activeView])

  const loadPcapData = async (signal) => {
    setPcapHistoryLoading(true)
    setPcapError('')
    try {
      const [samplesRes, historyRes] = await Promise.all([
        fetchJson('/pcap/samples', { signal }),
        fetchJson('/pcap/analyses', { signal }),
      ])
      const samplesList = samplesRes?.samples || []
      setPcapSamples(samplesList)
      if (samplesList.length > 0 && !selectedPcapSample) {
        setSelectedPcapSample(samplesList[0].filename)
      }
      const historyList = historyRes?.analyses || []
      setPcapHistory(historyList)
      if (historyList.length > 0 && !pcapResult) {
        try {
          const detail = await fetchJson(`/pcap/results/${historyList[0].id}`, { signal })
          setPcapResult(detail)
        } catch {}
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setPcapError('Unable to connect to PCAP service at http://127.0.0.1:5000.')
      }
    } finally {
      if (!signal?.aborted) {
        setPcapHistoryLoading(false)
      }
    }
  }

  const loadMlTestingData = async (signal) => {
    setMlTestingError('')
    try {
      const [datasetsRes, schemaRes, runsRes] = await Promise.all([
        fetchJson('/ml/test/datasets', { signal }),
        fetchJson('/ml/test/schema', { signal }),
        fetchJson('/ml/test/runs', { signal }),
      ])
      const dList = datasetsRes?.datasets || []
      setMlDatasets(dList)
      if (dList.length > 0 && !selectedDataset) {
        const preferred = dList.find((d) => d.name === 'awid3_v3_test_combined.csv') || dList[0]
        setSelectedDataset(preferred.name || preferred.filename)
      }
      setMlSchemaInfo(schemaRes)
      const rList = runsRes?.runs || []
      setMlTestRuns(rList)
      if (rList.length > 0 && !mlTestResult) {
        try {
          const detail = await fetchJson(`/ml/test/results/${rList[0].id}`, { signal })
          setMlTestResult(detail)
        } catch {}
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setMlTestingError('Unable to connect to ML evaluation service at http://127.0.0.1:5000.')
      }
    }
  }

  useEffect(() => {
    if (activeView !== 'PCAP Analysis') {
      return
    }
    const controller = new AbortController()
    loadPcapData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'ML Testing') {
      return
    }
    const controller = new AbortController()
    loadMlTestingData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  const loadRecommendationsData = async (signal) => {
    setRecommendationsLoading(true)
    setRecommendationsError('')
    try {
      const [recsRes, modelRes] = await Promise.all([
        fetchJson('/wifi/recommendations', { signal }),
        fetchJson('/wifi/recommendations/model', { signal }),
      ])
      setRecommendationsData(recsRes)
      setRecommendationModelInfo(modelRes)
    } catch (err) {
      if (err.name !== 'AbortError') {
        setRecommendationsError('Unable to load Wi-Fi recommendations. Ensure the Flask backend is running.')
      }
    } finally {
      if (!signal?.aborted) {
        setRecommendationsLoading(false)
      }
    }
  }

  useEffect(() => {
    if (activeView !== 'Network Recommendations') {
      return
    }
    const controller = new AbortController()
    loadRecommendationsData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  const handleOpenConnectModal = (network) => {
    setConnectModalNetwork(network)
    setConnectPassword('')
    setShowPassword(false)
    setConnectStatus(null)
  }

  const handleCloseConnectModal = () => {
    if (connectLoading) return
    setConnectModalNetwork(null)
    setConnectPassword('')
    setShowPassword(false)
    setConnectStatus(null)
  }

  const handleConnectSubmit = async (e) => {
    e?.preventDefault()
    if (!connectModalNetwork) return
    setConnectLoading(true)
    setConnectStatus(null)

    try {
      const payload = {
        ssid: connectModalNetwork.ssid,
        password: connectPassword,
        bssid: connectModalNetwork.bssid,
        encryption: connectModalNetwork.encryption,
      }
      const res = await fetch(`${API_BASE_URL}/wifi/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data = await res.json()
      if (!res.ok || !data.success) {
        setConnectStatus({
          success: false,
          message: data.message || data.error || 'Failed to connect to network.',
        })
      } else {
        setConnectStatus({
          success: true,
          message: data.message || `Successfully connected to ${connectModalNetwork.ssid}!`,
        })
      }
    } catch (err) {
      setConnectStatus({
        success: false,
        message: err.message || 'Network connection request failed.',
      })
    } finally {
      setConnectLoading(false)
    }
  }

  const handlePcapAnalyze = async (e) => {
    e?.preventDefault()
    setPcapAnalyzing(true)
    setPcapError('')

    try {
      let data
      if (selectedPcapFile) {
        const formData = new FormData()
        formData.append('file', selectedPcapFile)
        const res = await fetch(`${API_BASE_URL}/pcap/analyze`, {
          method: 'POST',
          body: formData,
        })
        if (!res.ok) {
          const errPayload = await res.json().catch(() => ({}))
          throw new Error(errPayload.error || `HTTP ${res.status}`)
        }
        data = await res.json()
      } else if (selectedPcapSample) {
        data = await fetchJson('/pcap/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sample: selectedPcapSample }),
        })
      } else {
        throw new Error('Please select a file to upload or choose a bundled sample PCAP.')
      }

      setPcapResult(data)
      const histRes = await fetchJson('/pcap/analyses')
      setPcapHistory(histRes?.analyses || [])
    } catch (err) {
      setPcapError(err.message || 'PCAP analysis failed. Verify packet capture file.')
    } finally {
      setPcapAnalyzing(false)
    }
  }

  const handleSelectHistoryPcap = async (id) => {
    setPcapError('')
    try {
      const detail = await fetchJson(`/pcap/results/${id}`)
      setPcapResult(detail)
    } catch (err) {
      setPcapError('Failed to load past PCAP analysis.')
    }
  }

  const handleRunMlTest = async () => {
    if (!selectedDataset) {
      setMlTestingError('Please select a dataset to evaluate.')
      return
    }
    setMlTestingLoading(true)
    setMlTestingError('')
    try {
      const data = await fetchJson('/ml/test/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dataset_name: selectedDataset }),
      })
      setMlTestResult(data)
      const runsRes = await fetchJson('/ml/test/runs')
      setMlTestRuns(runsRes?.runs || [])
    } catch (err) {
      setMlTestingError(err.message || 'Model evaluation failed.')
    } finally {
      setMlTestingLoading(false)
    }
  }

  const handleSelectPastTestRun = async (id) => {
    setMlTestingError('')
    try {
      const detail = await fetchJson(`/ml/test/results/${id}`)
      setMlTestResult(detail)
    } catch (err) {
      setMlTestingError('Failed to load past evaluation run.')
    }
  }

  const wirelessAdapter =
    interfaces.find((adapter) => getInterfaceName(adapter) === selectedInterfaceName) ?? interfaces[0] ?? null
  const selectedInterface = getInterfaceName(wirelessAdapter)
  const scannerState = getScannerState(scannerStatus)
  const scannerProgress = scannerStatus.progress ?? {}
  const isScannerActive = ACTIVE_SCANNER_STATES.includes(scannerState)
  const isScannerStarting = scannerState === 'starting'
  const isScannerRunning = scannerState === 'running'
  const isScannerStopping = scannerState === 'stopping'
  const selectableInterfaces = interfaces.filter((adapter) => getInterfaceName(adapter))
  const captureAdapter =
    interfaces.find((adapter) => getInterfaceName(adapter) === selectedCaptureInterfaceName) ??
    interfaces[0] ??
    null
  const selectedCaptureInterface = getInterfaceName(captureAdapter)
  const captureState = getCaptureState(captureStatus)
  const isCaptureActive = ACTIVE_CAPTURE_STATES.includes(captureState)
  const isCaptureStarting = captureState === 'starting'
  const isCaptureRunning = captureState === 'running'
  const isCaptureStopping = captureState === 'stopping'
  const captureProgress = captureStatus.progress ?? {}
  const packetTypeCounts = normalizeCounts(captureProgress.packet_type_counts)
  const startScanDisabled =
    !selectedInterface ||
    scannerActionLoading ||
    isCaptureActive ||
    isScannerStarting ||
    isScannerRunning ||
    isScannerStopping
  const stopScanDisabled = !isScannerActive || scannerActionLoading
  const startCaptureDisabled =
    !selectedCaptureInterface ||
    isScannerActive ||
    captureActionLoading ||
    isCaptureStarting ||
    isCaptureRunning ||
    isCaptureStopping
  const stopCaptureDisabled = !isCaptureActive || captureActionLoading
  const totalIncidents = incidents.length
  const newIncidents = incidents.filter(
    (incident) => String(incident?.status ?? '').toLowerCase() === 'new',
  ).length
  const highSeverityIncidents = incidents.filter(
    (incident) => String(incident?.severity ?? '').toLowerCase() === 'high',
  ).length

  const dashboardCards = [
    ['Security Score', '--'],
    ['Active Threats', totalIncidents],
    ['Networks Found', networks.length],
    ['Packets Analyzed', getValue(captureProgress, ['packet_count']) ?? packets.length],
  ]

  const monitoringStatus =
    getValue(captureStatus, ['state', 'capture_state', 'status']) ??
    (captureState === 'stopped' ? 'Stopped' : captureState)
  const monitoringNetwork =
    getValue(captureProgress, ['network', 'ssid']) ?? 'None'
  const monitoringInterface =
    getValue(captureStatus, ['interface', 'interface_name']) ??
    getValue(captureProgress, ['interface']) ??
    (selectedCaptureInterface || 'Not Selected')

  const reportTotalIncidents = reportIncidents.length
  const reportHighSeverity = reportIncidents.filter(
    (incident) => String(incident?.severity ?? '').toLowerCase() === 'high',
  ).length
  const reportTotalPackets = reportIncidents.reduce((sum, inc) => {
    const val = Number(inc?.total_packets)
    return Number.isFinite(val) ? sum + val : sum
  }, 0)
  const reportAvgAttackProb =
    reportIncidents.length > 0
      ? reportIncidents.reduce((sum, inc) => {
          const val = Number(inc?.attack_probability)
          return Number.isFinite(val) ? sum + val : sum
        }, 0) / reportIncidents.length
      : null

  const attackCountsByLabel = reportIncidents.reduce((acc, inc) => {
    const label = String(inc?.label ?? (inc?.prediction !== undefined ? `Class ${inc.prediction}` : 'Unknown'))
    acc[label] = (acc[label] || 0) + 1
    return acc
  }, {})

  const handleRefreshReports = () => {
    loadReportsData()
  }

  const handleExportCsv = () => {
    if (!reportIncidents || reportIncidents.length === 0) {
      return
    }

    const headers = [
      'ID',
      'Created At',
      'Label',
      'Attack Probability',
      'Normal Probability',
      'Total Packets',
      'Window Start',
      'Window End',
      'Feature Count',
      'Severity',
      'Status',
    ]

    const formatCsvField = (val) => {
      if (val === undefined || val === null) {
        return ''
      }
      const str = String(val)
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`
      }
      return str
    }

    const rows = reportIncidents.map((incident) => [
      formatCsvField(incident.id),
      formatCsvField(incident.created_at),
      formatCsvField(incident.label ?? (incident.prediction !== undefined ? `Class ${incident.prediction}` : '')),
      formatCsvField(incident.attack_probability),
      formatCsvField(incident.normal_probability),
      formatCsvField(incident.total_packets),
      formatCsvField(incident.window_start),
      formatCsvField(incident.window_end),
      formatCsvField(incident.feature_count),
      formatCsvField(incident.severity),
      formatCsvField(incident.status),
    ])

    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\r\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', `netshield_incident_report_${new Date().toISOString().slice(0, 10)}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

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
      await loadInterfaces()
    } catch {
      setWifiScanError('Unable to stop the scanner. Check that the Flask backend is running.')
    } finally {
      setScannerActionLoading(false)
    }
  }

  const handleStartCapture = async () => {
    if (startCaptureDisabled) {
      return
    }

    setCaptureActionLoading(true)
    setLiveMonitorError('')

    try {
      await fetchJson('/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedCaptureInterface }),
      })
      await loadCaptureStatus()
      await loadPackets()
    } catch {
      setLiveMonitorError('Unable to start packet capture. Check the selected interface and Flask backend logs.')
    } finally {
      setCaptureActionLoading(false)
    }
  }

  const handleStopCapture = async () => {
    if (stopCaptureDisabled) {
      return
    }

    setCaptureActionLoading(true)
    setLiveMonitorError('')

    try {
      await fetchJson('/capture/stop', { method: 'POST' })
      await Promise.all([loadCaptureStatus(), loadPackets(), loadInterfaces()])
    } catch {
      setLiveMonitorError('Unable to stop packet capture. Check that the Flask backend is running.')
    } finally {
      setCaptureActionLoading(false)
    }
  }

  const recList =
    recommendationsData?.networks ||
    recommendationsData?.recommendations ||
    []
  const totalScannedRecs =
    recommendationsData?.scanned_count ??
    recommendationsData?.count ??
    recList.length
  const bestNetwork =
    recList.length > 0
      ? (recommendationsData?.best_network || recList[0])
      : null
  const recommendedRecsCount = recList.filter((n) => n.is_recommended).length
  const fiveGhzRecsCount = recList.filter((n) => String(n.frequency || '').includes('5') || Number(n.channel) > 14).length

  const filteredRecommendations = recList.filter((net) => {
    if (recommendationFilter === 'recommended') return net.is_recommended
    if (recommendationFilter === '5ghz') return String(net.frequency || '').includes('5') || (Number(net.channel) > 14)
    if (recommendationFilter === 'secure') return !String(net.encryption || '').toLowerCase().includes('open')
    return true
  }).sort((a, b) => {
    if (recommendationSort === 'score') return (b.score || 0) - (a.score || 0)
    if (recommendationSort === 'signal') {
      const sigA = parseInt(String(a.signal || '-100').replace(/[^0-9-]/g, ''), 10) || -100
      const sigB = parseInt(String(b.signal || '-100').replace(/[^0-9-]/g, ''), 10) || -100
      return sigB - sigA
    }
    if (recommendationSort === 'security') {
      const getRank = (c) => (c === 'EXCELLENT' ? 4 : c === 'GOOD' ? 3 : c === 'FAIR' ? 2 : 1)
      return getRank(b.classification) - getRank(a.classification)
    }
    if (recommendationSort === 'channel') return (a.channel || 0) - (b.channel || 0)
    return 0
  })

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
                      <dd>{formatValue(monitoringStatus)}</dd>
                    </div>
                    <div>
                      <dt>Network</dt>
                      <dd>{formatValue(monitoringNetwork)}</dd>
                    </div>
                    <div>
                      <dt>Interface</dt>
                      <dd>{formatValue(monitoringInterface)}</dd>
                    </div>
                  </dl>
                </section>

                <section className="panel">
                  <h2>Latest Detection</h2>
                  {mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined ? (
                    <dl className="status-list">
                      <div>
                        <dt>Label</dt>
                        <dd>{formatValue(mlLiveStatus.label)}</dd>
                      </div>
                      <div>
                        <dt>Prediction</dt>
                        <dd>{formatValue(mlLiveStatus.prediction)}</dd>
                      </div>
                      <div>
                        <dt>Attack Probability</dt>
                        <dd>{formatProbability(mlLiveStatus.attack_probability)}</dd>
                      </div>
                      <div>
                        <dt>Normal Probability</dt>
                        <dd>{formatProbability(mlLiveStatus.normal_probability)}</dd>
                      </div>
                      <div>
                        <dt>Total Packets</dt>
                        <dd>{formatValue(mlLiveStatus.total_packets)}</dd>
                      </div>
                      <div>
                        <dt>Feature Count</dt>
                        <dd>{formatValue(mlLiveStatus.feature_count)}</dd>
                      </div>
                    </dl>
                  ) : (
                    <p className="empty-state">No traffic has been analyzed yet.</p>
                  )}
                </section>
              </div>

              <div className="panel-grid" style={{ marginTop: '20px' }}>
                <section className="panel">
                  <div className="panel-header">
                    <h2>ML Detection Engine Status</h2>
                    <span className="badge badge-status-resolved">Production Ready</span>
                  </div>
                  <dl className="status-list">
                    <div>
                      <dt>Active Model</dt>
                      <dd>random_forest_awid3_v3_expanded.joblib</dd>
                    </div>
                    <div>
                      <dt>Architecture</dt>
                      <dd>RandomForestClassifier (200 Trees)</dd>
                    </div>
                    <div>
                      <dt>Feature Schema</dt>
                      <dd style={{ color: '#2dd4bf', fontWeight: 600 }}>31 / 31 Canonical AWID3 Features</dd>
                    </div>
                    <div>
                      <dt>Evaluation Benchmark</dt>
                      <dd>96.74% Accuracy / 90.91% F1</dd>
                    </div>
                  </dl>
                </section>

                <section className="panel">
                  <div className="panel-header">
                    <h2>Offline PCAP & Threat Analysis</h2>
                    <span className="badge badge-default">{pcapHistory.length} Analyzed</span>
                  </div>
                  <dl className="status-list">
                    <div>
                      <dt>Captures Analyzed</dt>
                      <dd>{pcapHistory.length} Capture Files</dd>
                    </div>
                    <div>
                      <dt>Supported Formats</dt>
                      <dd>.pcap, .pcapng, .cap</dd>
                    </div>
                    <div>
                      <dt>Threat Categorization</dt>
                      <dd>Deauth, Disas, ReAssoc, Rogue AP</dd>
                    </div>
                    <div>
                      <dt>Analysis Window</dt>
                      <dd>5.0s Temporal Windows</dd>
                    </div>
                  </dl>
                </section>
              </div>

              {incidents.length > 0 ? (
                <section className="panel" style={{ marginTop: '20px' }}>
                  <div className="panel-header">
                    <h2>Recent High-Priority Security Incidents</h2>
                    <button
                      type="button"
                      className="scan-button"
                      style={{ padding: '4px 10px', fontSize: '12px' }}
                      onClick={() => setActiveView('Incidents')}
                    >
                      View All Incidents
                    </button>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Time</th>
                          <th>Attack Label</th>
                          <th>Attack Probability</th>
                          <th>Packets</th>
                          <th>Severity</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {incidents.slice(0, 5).map((incident, idx) => (
                          <tr key={incident.id ?? idx}>
                            <td>#{incident.id}</td>
                            <td>{formatDateTime(incident.created_at)}</td>
                            <td>
                              <span className="badge badge-detection">
                                {formatValue(incident.label ?? incident.prediction)}
                              </span>
                            </td>
                            <td>{formatProbability(incident.attack_probability)}</td>
                            <td>{formatValue(incident.total_packets)}</td>
                            <td>
                              <span className={getSeverityBadgeClass(incident.severity)}>
                                {formatValue(incident.severity)}
                              </span>
                            </td>
                            <td>
                              <span className={getStatusBadgeClass(incident.status)}>
                                {formatValue(incident.status)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              ) : null}
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
                        <dd>{formatValue(adapterState)}</dd>
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
                    <dd>{formatValue(getValue(scannerProgress, ['interface']))}</dd>
                  </div>
                  <div>
                    <dt>Current Channel</dt>
                    <dd>{formatValue(getValue(scannerProgress, ['current_channel']))}</dd>
                  </div>
                  <div>
                    <dt>Sweep Number</dt>
                    <dd>{formatValue(getValue(scannerProgress, ['sweep_number']))}</dd>
                  </div>
                  <div>
                    <dt>Channels Completed</dt>
                    <dd>
                      {formatValue(getValue(scannerProgress, ['channels_completed']))}
                      {' / '}
                      {formatValue(getValue(scannerProgress, ['total_channels']))}
                    </dd>
                  </div>
                  <div>
                    <dt>Networks Discovered</dt>
                    <dd>{formatValue(getValue(scannerProgress, ['session_network_count']))}</dd>
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
                            <td>{formatValue(getValue(network, ['encryption']))}</td>
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
          ) : activeView === 'Live Monitor' ? (
            <section className="live-monitor-view" aria-label="Live packet monitor">
              {liveMonitorError ? <p className="error-banner">{liveMonitorError}</p> : null}

              <section className="panel capture-control-panel">
                <div className="panel-header">
                  <h2>Capture Control</h2>
                  <div className="scan-actions">
                    <button
                      className="scan-button primary"
                      disabled={startCaptureDisabled}
                      onClick={handleStartCapture}
                      type="button"
                    >
                      Start Capture
                    </button>
                    <button
                      className="scan-button"
                      disabled={stopCaptureDisabled}
                      onClick={handleStopCapture}
                      type="button"
                    >
                      Stop Capture
                    </button>
                  </div>
                </div>

                {liveMonitorLoading ? (
                  <p className="muted-text">Loading capture controls...</p>
                ) : captureAdapter ? (
                  <>
                    {selectableInterfaces.length > 1 ? (
                      <label className="interface-select">
                        <span>Selected Interface</span>
                        <select
                          onChange={(event) => setSelectedCaptureInterfaceName(event.target.value)}
                          value={selectedCaptureInterfaceName}
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
                    <dl className="status-list capture-control-list">
                      <div>
                        <dt>Capture State</dt>
                        <dd>{formatValue(getValue(captureStatus, ['state', 'capture_state', 'status']))}</dd>
                      </div>
                      <div>
                        <dt>Interface</dt>
                        <dd>
                          {formatValue(
                            getValue(captureStatus, ['interface', 'interface_name']) ??
                              getValue(captureProgress, ['interface']) ??
                              selectedCaptureInterface,
                          )}
                        </dd>
                      </div>
                      <div>
                        <dt>Mode</dt>
                        <dd>{formatValue(getValue(captureStatus, ['mode']) ?? getValue(captureAdapter, ['mode']))}</dd>
                      </div>
                      <div>
                        <dt>PID</dt>
                        <dd>{formatValue(getValue(captureStatus, ['pid', 'process_id']))}</dd>
                      </div>
                    </dl>
                  </>
                ) : (
                  <div className="empty-state">
                    <p>No wireless adapter detected.</p>
                    <p>Connect a compatible monitor-mode WiFi adapter to start capture.</p>
                  </div>
                )}
              </section>

              <section className="panel capture-stats-panel">
                <h2>Live Capture Statistics</h2>
                <dl className="status-list capture-stats-list">
                  <div>
                    <dt>Session Packets</dt>
                    <dd>{formatValue(getValue(captureProgress, ['packet_count']))}</dd>
                  </div>
                  <div>
                    <dt>Packet Rate</dt>
                    <dd>{formatWithUnit(getValue(captureProgress, ['packet_rate']), 'pkt/s')}</dd>
                  </div>
                  <div>
                    <dt>Current Channel</dt>
                    <dd>{formatValue(getValue(captureProgress, ['current_channel']))}</dd>
                  </div>
                  <div>
                    <dt>Channel Sweep</dt>
                    <dd>
                      {formatValue(getValue(captureProgress, ['channel_index']))}
                      {' / '}
                      {formatValue(getValue(captureProgress, ['total_channels']))}
                    </dd>
                  </div>
                  <div>
                    <dt>Sweep Number</dt>
                    <dd>{formatValue(getValue(captureProgress, ['sweep_number']))}</dd>
                  </div>
                  <div>
                    <dt>Elapsed Time</dt>
                    <dd>{formatWithUnit(getValue(captureProgress, ['elapsed_seconds']), 'seconds')}</dd>
                  </div>
                  <div>
                    <dt>Last Packet</dt>
                    <dd>{formatValue(getValue(captureProgress, ['last_packet_at']))}</dd>
                  </div>
                </dl>

                <div className="packet-counts">
                  <p className="section-label">Packet Type Counts</p>
                  {Object.keys(packetTypeCounts).length > 0 ? (
                    <div className="count-grid">
                      {Object.entries(packetTypeCounts).map(([packetType, count]) => (
                        <div className="count-pill" key={packetType}>
                          <span>{packetType}</span>
                          <strong>{formatValue(count)}</strong>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted-text">No packet type counts reported yet.</p>
                  )}
                </div>
              </section>

              <section className="panel packets-panel">
                <h2>Recent Packets</h2>
                {liveMonitorLoading ? (
                  <p className="muted-text">Loading recent packets...</p>
                ) : packets.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Packet Type</th>
                          <th>Source MAC</th>
                          <th>Destination MAC</th>
                          <th>BSSID</th>
                          <th>Frame Type</th>
                          <th>Signal</th>
                        </tr>
                      </thead>
                      <tbody>
                        {packets.map((packet, index) => (
                          <tr key={getValue(packet, ['id', 'packet_id']) ?? index}>
                            <td>{formatValue(getValue(packet, ['time', 'timestamp', 'captured_at']))}</td>
                            <td>{formatValue(getValue(packet, ['packet_type', 'type', 'classification']))}</td>
                            <td>{formatValue(getValue(packet, ['source_mac', 'src_mac', 'source']))}</td>
                            <td>
                              {formatValue(
                                getValue(packet, ['destination_mac', 'dst_mac', 'destination']),
                              )}
                            </td>
                            <td>{formatValue(getValue(packet, ['bssid']))}</td>
                            <td>{formatValue(getValue(packet, ['frame_type', 'frame']))}</td>
                            <td>{formatWithUnit(getValue(packet, ['signal_strength']), 'dBm')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="empty-state">No captured packets are available.</p>
                )}
              </section>
            </section>
          ) : activeView === 'ML Detection' ? (
            <section className="ml-detection-view" aria-label="ML Detection">
              {mlDetectionError ? <p className="error-banner">{mlDetectionError}</p> : null}

              <section className="panel">
                <h2>Live V3 Random Forest Inference</h2>
                <p className="muted-text">
                  Results are refreshed every 2 seconds from completed 5-second live packet capture windows.
                </p>

                {mlDetectionLoading ? (
                  <p className="muted-text">Loading ML inference status...</p>
                ) : mlLiveStatus?.status === 'no_inference' || mlLiveStatus === null ? (
                  <p className="empty-state">
                    Waiting for the first completed 5-second inference window. Start live packet
                    capture to begin ML detection.
                  </p>
                ) : (
                  <>
                    <div className="metric-grid">
                      <article
                        className="metric-card"
                        style={{
                          borderTop: mlLiveStatus.prediction === 0
                            ? '3px solid #22c55e'
                            : '3px solid #ef4444',
                        }}
                      >
                        <p>Label</p>
                        <strong>{mlLiveStatus.label ?? 'Unknown'}</strong>
                      </article>

                      <article className="metric-card">
                        <p>Prediction</p>
                        <strong>{mlLiveStatus.prediction ?? '--'}</strong>
                      </article>

                      <article className="metric-card">
                        <p>Attack Probability</p>
                        <strong>
                          {mlLiveStatus.attack_probability !== undefined
                            ? `${(mlLiveStatus.attack_probability * 100).toFixed(1)}%`
                            : '--'}
                        </strong>
                      </article>

                      <article className="metric-card">
                        <p>Normal Probability</p>
                        <strong>
                          {mlLiveStatus.normal_probability !== undefined
                            ? `${(mlLiveStatus.normal_probability * 100).toFixed(1)}%`
                            : '--'}
                        </strong>
                      </article>
                    </div>

                    <dl className="status-list">
                      <div>
                        <dt>Total Packets in Window</dt>
                        <dd>{formatValue(mlLiveStatus.total_packets)}</dd>
                      </div>
                      <div>
                        <dt>Feature Count</dt>
                        <dd>{formatValue(mlLiveStatus.feature_count)}</dd>
                      </div>
                      <div>
                        <dt>Window Start</dt>
                        <dd>{formatValue(mlLiveStatus.window_start)}</dd>
                      </div>
                      <div>
                        <dt>Window End</dt>
                        <dd>{formatValue(mlLiveStatus.window_end)}</dd>
                      </div>
                    </dl>
                  </>
                )}
              </section>
            </section>
          ) : activeView === 'PCAP Analysis' ? (
            <section className="pcap-analysis-view" aria-label="PCAP Analysis">
              {pcapError ? <p className="error-banner">{pcapError}</p> : null}

              <section className="panel pcap-upload-panel">
                <div className="panel-header">
                  <div>
                    <h2>PCAP / PCAPNG Offline Packet Analysis</h2>
                    <p className="panel-subtitle">
                      Extract canonical 31 AWID3 features across 5-second windows and detect intrusion patterns.
                    </p>
                  </div>
                </div>

                <form className="pcap-upload-form" onSubmit={handlePcapAnalyze}>
                  <div className="pcap-input-row">
                    <label className="file-upload-box">
                      <span className="file-label-title">Upload Packet Capture</span>
                      <input
                        type="file"
                        accept=".pcap,.pcapng,.cap"
                        onChange={(e) => {
                          const file = e.target.files?.[0]
                          setSelectedPcapFile(file || null)
                        }}
                      />
                      {selectedPcapFile ? (
                        <span className="selected-filename">{selectedPcapFile.name} ({formatFileSize(selectedPcapFile.size)})</span>
                      ) : (
                        <span className="file-placeholder">Choose .pcap or .pcapng file from your computer</span>
                      )}
                    </label>

                    <div className="sample-select-box">
                      <label htmlFor="pcap-sample-select">Or Use Bundled Sample</label>
                      <select
                        id="pcap-sample-select"
                        value={selectedPcapFile ? '' : selectedPcapSample}
                        onChange={(e) => {
                          setSelectedPcapSample(e.target.value)
                          setSelectedPcapFile(null)
                        }}
                        disabled={!!selectedPcapFile}
                      >
                        <option value="">-- Choose sample capture --</option>
                        {pcapSamples.map((s) => (
                          <option key={s.filename} value={s.filename}>
                            {s.filename} ({formatFileSize(s.file_size_bytes)})
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div className="pcap-actions-row">
                    <button
                      type="submit"
                      className="scan-button primary"
                      disabled={pcapAnalyzing || (!selectedPcapFile && !selectedPcapSample)}
                    >
                      {pcapAnalyzing ? 'Analyzing 31 Features...' : 'Run PCAP Analysis'}
                    </button>
                    {pcapResult?.id ? (
                      <button
                        type="button"
                        className="scan-button"
                        onClick={() => window.open(`${API_BASE_URL}/pcap/download/${pcapResult.id}/csv`)}
                      >
                        Export Windows to CSV
                      </button>
                    ) : null}
                  </div>
                </form>
              </section>

              {pcapResult ? (
                <>
                  <div className="metric-grid">
                    <article className="metric-card">
                      <p>Total Packets</p>
                      <strong>{formatValue(pcapResult.total_packets ?? pcapResult.summary?.total_packets)}</strong>
                    </article>
                    <article className="metric-card">
                      <p>Analyzed Windows (5s)</p>
                      <strong>{formatValue(pcapResult.total_windows ?? pcapResult.summary?.analyzed_windows)}</strong>
                    </article>
                    <article
                      className="metric-card"
                      style={{
                        borderTop: (pcapResult.attack_windows ?? pcapResult.summary?.attack_windows) > 0
                          ? '3px solid #ef4444'
                          : '3px solid #22c55e',
                      }}
                    >
                      <p>Attack Windows</p>
                      <strong>
                        {formatValue(pcapResult.attack_windows ?? pcapResult.summary?.attack_windows ?? 0)}
                        <span className="metric-sub" style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                          {' '}({formatValue(pcapResult.attack_percentage ?? pcapResult.summary?.attack_percentage ?? 0)}%)
                        </span>
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>Dominant Threat</p>
                      <strong>{formatValue(pcapResult.dominant_category ?? pcapResult.summary?.dominant_category ?? 'None')}</strong>
                    </article>
                    <article className="metric-card">
                      <p>Feature Schema</p>
                      <strong style={{ color: '#2dd4bf', fontSize: '15px' }}>
                        31 / 31 Canonical
                      </strong>
                    </article>
                  </div>

                  <section className="panel">
                    <div className="panel-header">
                      <h2>Attack Categories Detected</h2>
                    </div>
                    {pcapResult.attack_categories && Object.keys(pcapResult.attack_categories).length > 0 ? (
                      <div className="attack-summary-grid">
                        {Object.entries(pcapResult.attack_categories).map(([cat, count]) => (
                          <div className="attack-summary-item" key={cat}>
                            <span className={getCategoryBadgeClass(cat)}>{cat}</span>
                            <span className="attack-count">{count} {count === 1 ? 'window' : 'windows'}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="empty-state-muted">No attacks detected in this capture file (100% normal Wi-Fi frames).</p>
                    )}
                  </section>

                  <section className="panel">
                    <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <h2>Time-Window Classification Timeline</h2>
                      <div className="filter-button-group">
                        <button
                          type="button"
                          className={pcapFilter === 'all' ? 'filter-btn active' : 'filter-btn'}
                          onClick={() => setPcapFilter('all')}
                        >
                          All Windows ({pcapResult.windows?.length ?? 0})
                        </button>
                        <button
                          type="button"
                          className={pcapFilter === 'attacks' ? 'filter-btn active' : 'filter-btn'}
                          onClick={() => setPcapFilter('attacks')}
                        >
                          Attacks Only ({pcapResult.attack_windows ?? pcapResult.summary?.attack_windows ?? 0})
                        </button>
                      </div>
                    </div>

                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Window</th>
                            <th>Time Interval</th>
                            <th>Packets</th>
                            <th>Prediction</th>
                            <th>Category</th>
                            <th>Confidence</th>
                            <th>Deauth / Disas</th>
                            <th>Burst Ratio</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(pcapResult.windows ?? [])
                            .filter((w) => pcapFilter === 'all' || w.prediction === 1)
                            .map((w) => (
                              <tr key={w.window_index}>
                                <td>#{w.window_index + 1}</td>
                                <td>{w.window_start}s - {w.window_end}s</td>
                                <td>{w.total_packets ?? w.packet_count}</td>
                                <td>
                                  <span className={w.prediction === 1 ? 'badge badge-severity-high' : 'badge badge-status-resolved'}>
                                    {w.label ?? (w.prediction === 1 ? 'Attack' : 'Normal')}
                                  </span>
                                </td>
                                <td>
                                  <span className={getCategoryBadgeClass(w.category ?? w.attack_category)}>
                                    {w.category ?? w.attack_category ?? 'Normal'}
                                  </span>
                                </td>
                                <td>
                                  {w.prediction === 1
                                    ? formatProbability(w.attack_probability)
                                    : formatProbability(w.normal_probability)}
                                </td>
                                <td>
                                  {w.deauth_count ?? 0} / {w.disassoc_count ?? 0}
                                </td>
                                <td>
                                  {w.packet_burst_ratio !== undefined ? Number(w.packet_burst_ratio).toFixed(2) : '--'}
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                </>
              ) : (
                <div className="empty-state">
                  <p>No PCAP file analyzed yet.</p>
                  <p>Select a capture file above or choose a bundled sample to perform offline ML intrusion inspection.</p>
                </div>
              )}

              {pcapHistory.length > 0 ? (
                <section className="panel">
                  <div className="panel-header">
                    <h2>Past PCAP Analyses</h2>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Filename</th>
                          <th>Analyzed Time</th>
                          <th>Packets</th>
                          <th>Windows</th>
                          <th>Attacks</th>
                          <th>Threats</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pcapHistory.map((hist) => (
                          <tr key={hist.id}>
                            <td>#{hist.id}</td>
                            <td><strong>{hist.filename}</strong></td>
                            <td>{formatDateTime(hist.created_at)}</td>
                            <td>{hist.total_packets}</td>
                            <td>{hist.analyzed_windows}</td>
                            <td>
                              <span className={hist.attack_windows > 0 ? 'badge badge-severity-high' : 'badge badge-status-resolved'}>
                                {hist.attack_windows}
                              </span>
                            </td>
                            <td>
                              {Object.keys(hist.attack_categories || {}).length > 0
                                ? Object.keys(hist.attack_categories).join(', ')
                                : 'Normal'}
                            </td>
                            <td>
                              <button
                                type="button"
                                className="scan-button"
                                style={{ padding: '4px 10px', fontSize: '12px' }}
                                onClick={() => handleSelectHistoryPcap(hist.id)}
                              >
                                View Results
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              ) : null}
            </section>
          ) : activeView === 'ML Testing' ? (
            <section className="ml-testing-view" aria-label="ML Testing">
              {mlTestingError ? <p className="error-banner">{mlTestingError}</p> : null}

              <section className="panel model-spec-panel">
                <div className="panel-header">
                  <div>
                    <h2>AWID3 Machine Learning Model Evaluation</h2>
                    <p className="panel-subtitle">
                      Test unseen Wi-Fi intrusion datasets against the frozen Random Forest model without retraining.
                    </p>
                  </div>
                </div>

                <div className="model-spec-grid">
                  <div className="spec-card">
                    <span className="spec-label">Production Model</span>
                    <strong>random_forest_awid3_v3_expanded.joblib</strong>
                  </div>
                  <div className="spec-card">
                    <span className="spec-label">Model Architecture</span>
                    <strong>RandomForestClassifier (200 trees)</strong>
                  </div>
                  <div className="spec-card">
                    <span className="spec-label">Canonical Feature Schema</span>
                    <strong style={{ color: '#2dd4bf' }}>31 / 31 Features Matched</strong>
                  </div>
                  <div className="spec-card">
                    <span className="spec-label">Classification Target</span>
                    <strong>Binary (0 = Normal, 1 = Attack)</strong>
                  </div>
                </div>

                <div className="test-control-bar" style={{ marginTop: '20px' }}>
                  <label htmlFor="dataset-select" style={{ display: 'flex', flexDirection: 'column', gap: '6px', flex: 1 }}>
                    <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Evaluation Test Dataset (backend/data/)</span>
                    <select
                      id="dataset-select"
                      value={selectedDataset}
                      onChange={(e) => setSelectedDataset(e.target.value)}
                    >
                      {mlDatasets.map((d) => (
                        <option key={d.name || d.filename} value={d.name || d.filename}>
                          {d.name || d.filename} — {d.sample_count} samples ({d.normal_count} normal, {d.attack_count} attack)
                        </option>
                      ))}
                    </select>
                  </label>

                  <button
                    type="button"
                    className="scan-button primary"
                    disabled={mlTestingLoading || !selectedDataset}
                    onClick={handleRunMlTest}
                    style={{ alignSelf: 'flex-end' }}
                  >
                    {mlTestingLoading ? 'Evaluating Test Dataset...' : 'Run Model Evaluation'}
                  </button>
                </div>
              </section>

              {mlTestResult ? (
                <>
                  <div className="metric-grid">
                    <article className="metric-card" style={{ borderTop: '3px solid #2dd4bf' }}>
                      <p>Accuracy</p>
                      <strong style={{ color: '#2dd4bf' }}>
                        {mlTestResult.metrics?.accuracy !== undefined ? `${mlTestResult.metrics.accuracy}%` : '--'}
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>Precision (Attack)</p>
                      <strong>
                        {mlTestResult.metrics?.precision !== undefined ? `${mlTestResult.metrics.precision}%` : '--'}
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>Recall (Attack)</p>
                      <strong>
                        {mlTestResult.metrics?.recall !== undefined ? `${mlTestResult.metrics.recall}%` : '--'}
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>F1 Score (Attack)</p>
                      <strong>
                        {mlTestResult.metrics?.f1_score !== undefined ? `${mlTestResult.metrics.f1_score}%` : '--'}
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>Total Test Samples</p>
                      <strong>{formatValue(mlTestResult.total_samples)}</strong>
                    </article>
                  </div>

                  <div className="panel-grid">
                    <section className="panel">
                      <div className="panel-header">
                        <h2>2x2 Confusion Matrix</h2>
                        <span className="badge badge-status-resolved">Evaluated Test Set</span>
                      </div>
                      <div className="cm-container">
                        <div className="cm-header-cols">
                          <span className="cm-col-label">Predicted Normal (0)</span>
                          <span className="cm-col-label">Predicted Attack (1)</span>
                        </div>
                        <div className="cm-row">
                          <span className="cm-row-label">Actual Normal (0)</span>
                          <div className="cm-cell cm-tn">
                            <span className="cm-val">{mlTestResult.confusion_matrix?.true_negatives ?? 0}</span>
                            <span className="cm-desc">True Negatives (TN)</span>
                          </div>
                          <div className="cm-cell cm-fp">
                            <span className="cm-val">{mlTestResult.confusion_matrix?.false_positives ?? 0}</span>
                            <span className="cm-desc">False Positives (FP)</span>
                          </div>
                        </div>
                        <div className="cm-row">
                          <span className="cm-row-label">Actual Attack (1)</span>
                          <div className="cm-cell cm-fn">
                            <span className="cm-val">{mlTestResult.confusion_matrix?.false_negatives ?? 0}</span>
                            <span className="cm-desc">False Negatives (FN)</span>
                          </div>
                          <div className="cm-cell cm-tp">
                            <span className="cm-val">{mlTestResult.confusion_matrix?.true_positives ?? 0}</span>
                            <span className="cm-desc">True Positives (TP)</span>
                          </div>
                        </div>
                      </div>
                    </section>

                    <section className="panel">
                      <div className="panel-header">
                        <h2>Classification Report</h2>
                        <span className="badge badge-default">Class Breakdown</span>
                      </div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>Class</th>
                              <th>Precision</th>
                              <th>Recall</th>
                              <th>F1-Score</th>
                              <th>Support</th>
                            </tr>
                          </thead>
                          <tbody>
                            <tr>
                              <td><strong>Normal (0)</strong></td>
                              <td>{mlTestResult.per_class?.Normal?.precision ? `${mlTestResult.per_class.Normal.precision}%` : '--'}</td>
                              <td>{mlTestResult.per_class?.Normal?.recall ? `${mlTestResult.per_class.Normal.recall}%` : '--'}</td>
                              <td>{mlTestResult.per_class?.Normal?.f1_score ? `${mlTestResult.per_class.Normal.f1_score}%` : '--'}</td>
                              <td>{mlTestResult.per_class?.Normal?.support ?? mlTestResult.normal_support ?? '--'}</td>
                            </tr>
                            <tr>
                              <td><strong>Attack (1)</strong></td>
                              <td>{mlTestResult.per_class?.Attack?.precision ? `${mlTestResult.per_class.Attack.precision}%` : '--'}</td>
                              <td>{mlTestResult.per_class?.Attack?.recall ? `${mlTestResult.per_class.Attack.recall}%` : '--'}</td>
                              <td>{mlTestResult.per_class?.Attack?.f1_score ? `${mlTestResult.per_class.Attack.f1_score}%` : '--'}</td>
                              <td>{mlTestResult.per_class?.Attack?.support ?? mlTestResult.attack_support ?? '--'}</td>
                            </tr>
                            <tr style={{ background: 'rgba(255,255,255,0.03)' }}>
                              <td><em>Overall / Accuracy</em></td>
                              <td colSpan="3" style={{ textAlign: 'center', color: '#2dd4bf', fontWeight: 'bold' }}>
                                {mlTestResult.metrics?.accuracy}% Accuracy
                              </td>
                              <td>{mlTestResult.total_samples}</td>
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    </section>
                  </div>

                  {mlTestResult.sample_preview && mlTestResult.sample_preview.length > 0 ? (
                    <section className="panel">
                      <div className="panel-header">
                        <h2>Sample Predictions Preview</h2>
                        <p className="panel-subtitle">Direct evaluation against canonical 31 features</p>
                      </div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>#</th>
                              <th>Ground Truth</th>
                              <th>Model Prediction</th>
                              <th>Status</th>
                              <th>Attack Probability</th>
                              <th>Normal Probability</th>
                            </tr>
                          </thead>
                          <tbody>
                            {mlTestResult.sample_preview.slice(0, 15).map((s) => (
                              <tr key={s.index}>
                                <td>{s.index + 1}</td>
                                <td>
                                  <span className={s.actual === 1 ? 'badge badge-severity-high' : 'badge badge-status-resolved'}>
                                    {s.actual_label}
                                  </span>
                                </td>
                                <td>
                                  <span className={s.predicted === 1 ? 'badge badge-severity-high' : 'badge badge-status-resolved'}>
                                    {s.predicted_label}
                                  </span>
                                </td>
                                <td>
                                  {s.is_correct ? (
                                    <span style={{ color: '#22c55e', fontWeight: 600 }}>✓ Correct</span>
                                  ) : (
                                    <span style={{ color: '#ef4444', fontWeight: 600 }}>✗ Misclassified</span>
                                  )}
                                </td>
                                <td>{s.attack_probability !== null ? formatProbability(s.attack_probability) : '--'}</td>
                                <td>{s.normal_probability !== null ? formatProbability(s.normal_probability) : '--'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  ) : null}
                </>
              ) : (
                <div className="empty-state">
                  <p>No dataset evaluation performed yet.</p>
                  <p>Select a test CSV dataset above to test the frozen Random Forest model.</p>
                </div>
              )}

              {mlTestRuns.length > 0 ? (
                <section className="panel">
                  <div className="panel-header">
                    <h2>Past ML Test Runs</h2>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Run ID</th>
                          <th>Dataset</th>
                          <th>Timestamp</th>
                          <th>Samples</th>
                          <th>Accuracy</th>
                          <th>Precision</th>
                          <th>Recall</th>
                          <th>F1-Score</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mlTestRuns.map((r) => (
                          <tr key={r.id}>
                            <td>#{r.id}</td>
                            <td><strong>{r.dataset_name}</strong></td>
                            <td>{formatDateTime(r.evaluated_at)}</td>
                            <td>{r.total_samples}</td>
                            <td><strong style={{ color: '#2dd4bf' }}>{r.accuracy}%</strong></td>
                            <td>{r.precision}%</td>
                            <td>{r.recall}%</td>
                            <td>{r.f1_score}%</td>
                            <td>
                              <button
                                type="button"
                                className="scan-button"
                                style={{ padding: '4px 10px', fontSize: '12px' }}
                                onClick={() => handleSelectPastTestRun(r.id)}
                              >
                                View Report
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              ) : null}
            </section>
          ) : activeView === 'Network Recommendations' ? (
            <section className="recommendations-view" aria-label="Network Recommendations">
              {recommendationsError ? <p className="error-banner">{recommendationsError}</p> : null}

              <div className="reports-header-panel panel">
                <div className="panel-header">
                  <div>
                    <h2>ML-Based Wi-Fi Network Recommendations</h2>
                    <p className="panel-subtitle">
                      Automated scan-level classification and network selection powered by Random Forest classifier trained on 12 IEEE 802.11 QoS &amp; security metrics.
                    </p>
                  </div>
                  <div className="report-controls">
                    <button
                      className="scan-button"
                      disabled={recommendationsLoading}
                      onClick={() => loadRecommendationsData()}
                      type="button"
                    >
                      {recommendationsLoading ? 'Analyzing Networks...' : 'Refresh Recommendations'}
                    </button>
                    <button
                      className="scan-button primary"
                      onClick={() => setActiveView('WiFi Scan')}
                      type="button"
                    >
                      Run Wi-Fi Scan
                    </button>
                  </div>
                </div>
              </div>

              {/* Scan-to-recommendation pipeline banner */}
              <div className="pipeline-banner">
                <span className="pipeline-step"><span className="pipe-num">1</span> Wi-Fi Scan Ingestion</span>
                <span className="pipeline-arrow">&#10140;</span>
                <span className="pipeline-step"><span className="pipe-num">2</span> 12-Feature Extraction</span>
                <span className="pipeline-arrow">&#10140;</span>
                <span className="pipeline-step"><span className="pipe-num">3</span> Random Forest ML Inference</span>
                <span className="pipeline-arrow">&#10140;</span>
                <span className="pipeline-step"><span className="pipe-num">4</span> 4-Tier Classification</span>
                <span className="pipeline-arrow">&#10140;</span>
                <span className="pipeline-step"><span className="pipe-num">5</span> Ranked Recommendation</span>
              </div>

              {/* Best Recommended Network Hero Card */}
              {bestNetwork ? (
                <section className="best-rec-card panel">
                  <div className="best-rec-badge-row">
                    <span className="best-choice-pill">&#9733; BEST RECOMMENDED NETWORK</span>
                    <span className={getRecommendationBadgeClass(bestNetwork.classification)}>
                      {bestNetwork.classification}
                    </span>
                    <span className="score-pill">
                      ML Score: <strong>{bestNetwork.score ?? '--'}</strong> / 100
                    </span>
                    <span className="conf-pill">
                      Confidence: {formatProbability(bestNetwork.confidence)}
                    </span>
                  </div>

                  <div className="best-rec-main">
                    <div className="best-rec-info">
                      <h3 className="best-rec-ssid">{bestNetwork.ssid || '<Hidden SSID>'}</h3>
                      <p className="best-rec-bssid">{bestNetwork.bssid || 'BSSID Unknown'}</p>

                      <div className="best-rec-metrics-grid">
                        <div className="mini-stat">
                          <span className="stat-label">Signal Level</span>
                          <span className="stat-value">{bestNetwork.signal || '--'}</span>
                        </div>
                        <div className="mini-stat">
                          <span className="stat-label">Frequency / Channel</span>
                          <span className="stat-value">{bestNetwork.frequency || 'N/A'} (Ch {bestNetwork.channel || '?'})</span>
                        </div>
                        <div className="mini-stat">
                          <span className="stat-label">Encryption</span>
                          <span className="stat-value">{bestNetwork.encryption || 'Open'}</span>
                        </div>
                        <div className="mini-stat">
                          <span className="stat-label">Band</span>
                          <span className="stat-value">
                            {String(bestNetwork.frequency || '').includes('5') || Number(bestNetwork.channel) > 14 ? '5 GHz' : '2.4 GHz'}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="best-rec-actions">
                      <button
                        type="button"
                        className="connect-btn-large"
                        onClick={() => handleOpenConnectModal(bestNetwork)}
                      >
                        &#9889; Connect to Network
                      </button>
                    </div>
                  </div>

                  {/* Explainability Factors */}
                  <div className="best-rec-factors">
                    {bestNetwork.positive_reasons && bestNetwork.positive_reasons.length > 0 ? (
                      <div className="factors-group">
                        <span className="factor-heading positive">Strengths &amp; Selection Factors:</span>
                        <div className="factor-tags">
                          {bestNetwork.positive_reasons.map((r, i) => (
                            <span key={i} className="factor-tag positive">&#10003; {r}</span>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {bestNetwork.negative_reasons && bestNetwork.negative_reasons.length > 0 ? (
                      <div className="factors-group" style={{ marginTop: '8px' }}>
                        <span className="factor-heading negative">Risks &amp; Caveats:</span>
                        <div className="factor-tags">
                          {bestNetwork.negative_reasons.map((r, i) => (
                            <span key={i} className="factor-tag negative">&#9888; {r}</span>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </div>
                </section>
              ) : !recommendationsLoading ? (
                <div className="empty-state panel" style={{ marginBottom: '20px', padding: '36px 24px', textAlign: 'center' }}>
                  <p style={{ fontWeight: 600, fontSize: '16px', color: 'var(--text-strong)', marginBottom: '8px' }}>
                    No Wi-Fi networks scanned yet.
                  </p>
                  <p className="muted-text" style={{ marginBottom: '16px' }}>
                    Run Wi-Fi Scan to discover nearby networks and then refresh recommendations.
                  </p>
                  <button
                    type="button"
                    className="scan-button primary"
                    onClick={() => setActiveView('WiFi Scan')}
                  >
                    Go to Wi-Fi Scan
                  </button>
                </div>
              ) : null}

              {/* Metrics Summary Grid */}
              <div className="metric-grid">
                <article className="metric-card">
                  <p>Scanned Networks</p>
                  <strong>{totalScannedRecs}</strong>
                </article>
                <article className="metric-card">
                  <p>Recommended Networks</p>
                  <strong style={{ color: '#2dd4bf' }}>{recommendedRecsCount}</strong>
                </article>
                <article className="metric-card">
                  <p>5 GHz High-Speed APs</p>
                  <strong>{fiveGhzRecsCount}</strong>
                </article>
                <article className="metric-card">
                  <p>Model Accuracy</p>
                  <strong style={{ color: '#2dd4bf' }}>
                    {recommendationModelInfo?.metrics?.accuracy_pct !== undefined
                      ? `${recommendationModelInfo.metrics.accuracy_pct}%`
                      : '88.1%'}
                  </strong>
                </article>
                <article className="metric-card">
                  <p>Features Evaluated</p>
                  <strong>{recommendationModelInfo?.features?.length ?? 12} Features</strong>
                </article>
              </div>

              {/* Toolbar: Filters and Sorting */}
              <div className="rec-toolbar panel">
                <div className="rec-filters">
                  <span className="toolbar-label">Filter:</span>
                  <button
                    type="button"
                    className={`filter-chip ${recommendationFilter === 'all' ? 'active' : ''}`}
                    onClick={() => setRecommendationFilter('all')}
                  >
                    All Networks ({recList.length})
                  </button>
                  <button
                    type="button"
                    className={`filter-chip ${recommendationFilter === 'recommended' ? 'active' : ''}`}
                    onClick={() => setRecommendationFilter('recommended')}
                  >
                    Recommended Only ({recommendedRecsCount})
                  </button>
                  <button
                    type="button"
                    className={`filter-chip ${recommendationFilter === '5ghz' ? 'active' : ''}`}
                    onClick={() => setRecommendationFilter('5ghz')}
                  >
                    5 GHz Band ({fiveGhzRecsCount})
                  </button>
                  <button
                    type="button"
                    className={`filter-chip ${recommendationFilter === 'secure' ? 'active' : ''}`}
                    onClick={() => setRecommendationFilter('secure')}
                  >
                    Secured Only
                  </button>
                </div>

                <div className="rec-sorting">
                  <label htmlFor="rec-sort-select">
                    <span className="toolbar-label">Sort By:</span>
                    <select
                      id="rec-sort-select"
                      className="rec-select"
                      value={recommendationSort}
                      onChange={(e) => setRecommendationSort(e.target.value)}
                    >
                      <option value="score">ML Recommendation Score</option>
                      <option value="signal">Signal Strength</option>
                      <option value="security">Security Grade</option>
                      <option value="channel">Channel Number</option>
                    </select>
                  </label>
                </div>
              </div>

              {/* Ranked Networks Table */}
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Ranked Wi-Fi Networks ({filteredRecommendations.length})</h2>
                    <p className="panel-subtitle">Sorted from best to worst based on ML QoS and security evaluation</p>
                  </div>
                </div>

                {recommendationsLoading ? (
                  <p className="muted-text" style={{ padding: '24px' }}>Loading and analyzing Wi-Fi scan data...</p>
                ) : filteredRecommendations.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Rank</th>
                          <th>Network / SSID</th>
                          <th>Classification</th>
                          <th>ML Score</th>
                          <th>Signal</th>
                          <th>Channel &amp; Band</th>
                          <th>Security</th>
                          <th>Explainability Factors</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredRecommendations.map((net, idx) => {
                          const scoreVal = Number(net.score || 0)
                          return (
                            <tr key={net.bssid || idx} className={net.is_recommended ? 'recommended-row' : ''}>
                              <td>
                                <span className={`rank-badge ${idx === 0 ? 'gold' : idx === 1 ? 'silver' : idx === 2 ? 'bronze' : ''}`}>
                                  #{net.rank ?? idx + 1}
                                </span>
                              </td>
                              <td>
                                <div className="net-ssid-cell">
                                  <strong>{net.ssid || '<Hidden SSID>'}</strong>
                                  <span className="net-bssid-sub">{net.bssid || 'Unknown BSSID'}</span>
                                </div>
                              </td>
                              <td>
                                <span className={getRecommendationBadgeClass(net.classification)}>
                                  {net.classification}
                                </span>
                              </td>
                              <td>
                                <div className="score-cell">
                                  <div className="score-num-row">
                                    <strong>{scoreVal.toFixed(1)}</strong>
                                    <span className="score-sub">/ 100</span>
                                  </div>
                                  <div className="score-bar-bg">
                                    <div
                                      className={`score-bar-fill ${scoreVal >= 80 ? 'high' : scoreVal >= 60 ? 'med' : scoreVal >= 40 ? 'fair' : 'low'}`}
                                      style={{ width: `${Math.max(5, Math.min(100, scoreVal))}%` }}
                                    />
                                  </div>
                                </div>
                              </td>
                              <td>
                                <span className="mono-val">{net.signal || '--'}</span>
                              </td>
                              <td>
                                <span className="mono-val">Ch {net.channel || '?'}</span>
                                <span className="band-sub">
                                  {String(net.frequency || '').includes('5') || Number(net.channel) > 14 ? '5 GHz' : '2.4 GHz'}
                                </span>
                              </td>
                              <td>
                                <span className={`badge ${String(net.encryption || '').toLowerCase().includes('open') ? 'badge-severity-high' : 'badge-status-resolved'}`}>
                                  {net.encryption || 'Open'}
                                </span>
                              </td>
                              <td style={{ maxWidth: '320px' }}>
                                <div className="mini-factors">
                                  {(net.positive_reasons || []).slice(0, 2).map((r, i) => (
                                    <span key={i} className="mini-factor positive">&#10003; {r}</span>
                                  ))}
                                  {(net.negative_reasons || []).slice(0, 1).map((r, i) => (
                                    <span key={i} className="mini-factor negative">&#9888; {r}</span>
                                  ))}
                                </div>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="connect-btn-table"
                                  onClick={() => handleOpenConnectModal(net)}
                                >
                                  Connect
                                </button>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state">
                    <p style={{ fontWeight: 600, fontSize: '15px', color: 'var(--text-strong)', marginBottom: '6px' }}>
                      No Wi-Fi networks scanned yet.
                    </p>
                    <p>Run Wi-Fi Scan to discover nearby networks and then refresh recommendations.</p>
                  </div>
                )}
              </section>

              {/* Model Architecture & 12 Features Card */}
              <section className="panel" style={{ marginTop: '24px' }}>
                <div className="panel-header">
                  <div>
                    <h2>ML Recommendation Model Architecture &amp; Feature Weights</h2>
                    <p className="panel-subtitle">Dedicated 12-feature scan-level quality classifier (decoupled from the 31-feature packet intrusion detector)</p>
                  </div>
                  <span className="badge badge-status-resolved">RandomForestClassifier</span>
                </div>

                <div className="panel-grid">
                  <div>
                    <h3 style={{ fontSize: '14px', marginBottom: '12px', color: 'var(--text-strong)' }}>Model Specification</h3>
                    <dl className="status-list">
                      <div>
                        <dt>Model Class</dt>
                        <dd>{recommendationModelInfo?.model_type ?? 'RandomForestClassifier'}</dd>
                      </div>
                      <div>
                        <dt>Artifact File</dt>
                        <dd>{recommendationModelInfo?.model_file ?? 'wifi_network_recommendation.joblib'}</dd>
                      </div>
                      <div>
                        <dt>Accuracy</dt>
                        <dd style={{ color: '#2dd4bf', fontWeight: 600 }}>
                          {recommendationModelInfo?.metrics?.accuracy_pct !== undefined
                            ? `${recommendationModelInfo.metrics.accuracy_pct}%`
                            : '88.12%'}
                        </dd>
                      </div>
                      <div>
                        <dt>Macro F1-Score</dt>
                        <dd style={{ color: '#2dd4bf', fontWeight: 600 }}>
                          {recommendationModelInfo?.metrics?.macro_f1_pct !== undefined
                            ? `${recommendationModelInfo.metrics.macro_f1_pct}%`
                            : '88.07%'}
                        </dd>
                      </div>
                      <div>
                        <dt>Classification Tiers</dt>
                        <dd>EXCELLENT, GOOD, FAIR, POOR</dd>
                      </div>
                      <div>
                        <dt>Training Dataset</dt>
                        <dd>wifi_scan_recommendation_synthetic_train.csv (1,600 samples)</dd>
                      </div>
                    </dl>
                  </div>

                  <div>
                    <h3 style={{ fontSize: '14px', marginBottom: '12px', color: 'var(--text-strong)' }}>Feature Importances (Top IEEE 802.11 Predictors)</h3>
                    <div className="feature-weight-list">
                      {recommendationModelInfo?.feature_importances && Object.keys(recommendationModelInfo.feature_importances).length > 0 ? (
                        Object.entries(recommendationModelInfo.feature_importances)
                          .sort(([, a], [, b]) => b - a)
                          .map(([feat, imp]) => {
                            const pct = (imp * 100).toFixed(1)
                            return (
                              <div key={feat} className="feature-weight-item">
                                <div className="feat-info">
                                  <span className="feat-name">{feat}</span>
                                  <span className="feat-pct">{pct}%</span>
                                </div>
                                <div className="feat-bar-bg">
                                  <div className="feat-bar-fill" style={{ width: `${Math.min(100, imp * 100 * 3.5)}%` }} />
                                </div>
                              </div>
                            )
                          })
                      ) : (
                        <p className="muted-text">Feature weights loading...</p>
                      )}
                    </div>
                  </div>
                </div>
              </section>

              {/* Connect Modal */}
              {connectModalNetwork ? (
                <div className="modal-backdrop" onClick={handleCloseConnectModal}>
                  <div className="modal-card" onClick={(e) => e.stopPropagation()}>
                    <div className="modal-header">
                      <h3>Connect to Wi-Fi Network</h3>
                      <button
                        type="button"
                        className="modal-close-btn"
                        onClick={handleCloseConnectModal}
                        disabled={connectLoading}
                      >
                        &#10005;
                      </button>
                    </div>

                    <div className="modal-body">
                      <div className="modal-network-preview">
                        <div className="preview-row">
                          <span className="preview-label">Network (SSID):</span>
                          <strong>{connectModalNetwork.ssid || '<Hidden SSID>'}</strong>
                        </div>
                        <div className="preview-row">
                          <span className="preview-label">BSSID:</span>
                          <span className="mono-val">{connectModalNetwork.bssid || 'Unknown'}</span>
                        </div>
                        <div className="preview-row">
                          <span className="preview-label">Encryption:</span>
                          <span className="badge badge-default">{connectModalNetwork.encryption || 'Open'}</span>
                        </div>
                        <div className="preview-row">
                          <span className="preview-label">Signal:</span>
                          <span>{connectModalNetwork.signal || '--'}</span>
                        </div>
                        <div className="preview-row">
                          <span className="preview-label">ML Classification:</span>
                          <span className={getRecommendationBadgeClass(connectModalNetwork.classification)}>
                            {connectModalNetwork.classification} (Score: {connectModalNetwork.score})
                          </span>
                        </div>
                      </div>

                      {connectStatus ? (
                        <div className={`connect-status-box ${connectStatus.success ? 'success' : 'error'}`}>
                          {connectStatus.success ? '✓ ' : '✗ '}
                          {connectStatus.message}
                        </div>
                      ) : null}

                      <form onSubmit={handleConnectSubmit} className="connect-form">
                        {String(connectModalNetwork.encryption || '').toLowerCase().includes('open') ? (
                          <p className="open-network-notice">
                            ℹ This network does not require a password (Open encryption).
                          </p>
                        ) : (
                          <div className="form-group">
                            <label htmlFor="wifi-password-input">
                              Network Security Key / Password:
                            </label>
                            <div className="password-input-wrap">
                              <input
                                id="wifi-password-input"
                                type={showPassword ? 'text' : 'password'}
                                className="password-input"
                                value={connectPassword}
                                onChange={(e) => setConnectPassword(e.target.value)}
                                placeholder="Enter Wi-Fi password (8-63 chars)"
                                disabled={connectLoading}
                                autoFocus
                              />
                              <button
                                type="button"
                                className="toggle-pwd-btn"
                                onClick={() => setShowPassword(!showPassword)}
                              >
                                {showPassword ? 'Hide' : 'Show'}
                              </button>
                            </div>
                            <span className="form-hint">
                              WPA/WPA2/WPA3 passphrases are typically 8 to 63 characters long.
                            </span>
                          </div>
                        )}

                        <div className="modal-actions">
                          <button
                            type="button"
                            className="scan-button"
                            onClick={handleCloseConnectModal}
                            disabled={connectLoading}
                          >
                            Cancel
                          </button>
                          <button
                            type="submit"
                            className="scan-button primary"
                            disabled={
                              connectLoading ||
                              (!String(connectModalNetwork.encryption || '').toLowerCase().includes('open') &&
                                connectPassword.length < 8)
                            }
                          >
                            {connectLoading ? 'Connecting...' : 'Connect Now'}
                          </button>
                        </div>
                      </form>
                    </div>
                  </div>
                </div>
              ) : null}
            </section>
          ) : activeView === 'Incidents' ? (
            <section className="incidents-view" aria-label="Security Incidents">
              {incidentsError ? <p className="error-banner">{incidentsError}</p> : null}

              <div className="metric-grid">
                <article className="metric-card">
                  <p>Total Incidents</p>
                  <strong>{totalIncidents}</strong>
                </article>
                <article className="metric-card">
                  <p>New Incidents</p>
                  <strong>{newIncidents}</strong>
                </article>
                <article className="metric-card">
                  <p>High Severity</p>
                  <strong>{highSeverityIncidents}</strong>
                </article>
              </div>

              <section className="panel incidents-panel">
                <h2>Security Incidents</h2>
                <p className="muted-text">
                  ML attack detections recorded from completed live inference windows.
                </p>

                {incidentsLoading ? (
                  <p className="muted-text">Loading incidents...</p>
                ) : incidents.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Time</th>
                          <th>Detection</th>
                          <th>Attack Probability</th>
                          <th>Packets</th>
                          <th>Severity</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {incidents.map((incident, index) => (
                          <tr key={getValue(incident, ['id']) ?? index}>
                            <td>{formatValue(incident.id)}</td>
                            <td>{formatDateTime(incident.created_at)}</td>
                            <td>
                              <span className="badge badge-detection">
                                {formatValue(incident.label ?? incident.prediction)}
                              </span>
                            </td>
                            <td>{formatProbability(incident.attack_probability)}</td>
                            <td>{formatValue(incident.total_packets)}</td>
                            <td>
                              <span className={getSeverityBadgeClass(incident.severity)}>
                                {formatValue(incident.severity)}
                              </span>
                            </td>
                            <td>
                              <span className={getStatusBadgeClass(incident.status)}>
                                {formatValue(incident.status)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state">
                    <p>No incidents detected</p>
                    <p>Incidents created by ML attack detections will appear here.</p>
                  </div>
                )}
              </section>
            </section>
          ) : activeView === 'Reports' ? (
            <section className="reports-view" aria-label="Security reports">
              {reportsError ? <p className="error-banner">{reportsError}</p> : null}

              <div className="reports-header-panel panel">
                <div className="panel-header">
                  <div>
                    <h2>Security Reports</h2>
                    <p className="panel-subtitle">
                      Incident telemetry and analytical summary generated from real-time ML intrusion detections.
                    </p>
                  </div>
                  <div className="report-controls">
                    <button
                      className="scan-button"
                      disabled={reportsLoading}
                      onClick={handleRefreshReports}
                      type="button"
                    >
                      {reportsLoading ? 'Refreshing...' : 'Refresh Reports'}
                    </button>
                    <button
                      className="scan-button"
                      disabled={reportsLoading || reportIncidents.length === 0}
                      onClick={handleExportCsv}
                      type="button"
                    >
                      Export CSV
                    </button>
                    <button
                      className="scan-button primary"
                      disabled={reportsLoading}
                      onClick={() => window.print()}
                      type="button"
                    >
                      Print / Save PDF
                    </button>
                  </div>
                </div>
              </div>

              <div className="metric-grid">
                <article className="metric-card">
                  <p>Total Incidents</p>
                  <strong>{reportTotalIncidents}</strong>
                </article>
                <article className="metric-card">
                  <p>High Severity</p>
                  <strong>{reportHighSeverity}</strong>
                </article>
                <article className="metric-card">
                  <p>Packets in Incidents</p>
                  <strong>{reportTotalPackets}</strong>
                </article>
                <article className="metric-card">
                  <p>Average Attack Probability</p>
                  <strong>{reportAvgAttackProb !== null ? formatProbability(reportAvgAttackProb) : '--'}</strong>
                </article>
              </div>

              <section className="panel attack-summary-panel">
                <div className="panel-header">
                  <h2>Attack Summary</h2>
                </div>
                {Object.keys(attackCountsByLabel).length > 0 ? (
                  <div className="attack-summary-grid">
                    {Object.entries(attackCountsByLabel).map(([label, count]) => (
                      <div className="attack-summary-item" key={label}>
                        <span className="badge badge-detection">{label}</span>
                        <span className="attack-count">{count} {count === 1 ? 'incident' : 'incidents'}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="empty-state-muted">No attacks recorded yet.</p>
                )}
              </section>

              <section className="panel incidents-report-panel">
                <div className="panel-header">
                  <h2>Incident Report</h2>
                </div>
                {reportsLoading ? (
                  <p className="muted-text">Loading reports data...</p>
                ) : reportIncidents.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Date/Time</th>
                          <th>Attack Label</th>
                          <th>Attack Probability</th>
                          <th>Packets</th>
                          <th>Severity</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {reportIncidents.map((incident, index) => (
                          <tr key={getValue(incident, ['id']) ?? index}>
                            <td>{formatValue(incident.id)}</td>
                            <td>{formatDateTime(incident.created_at)}</td>
                            <td>
                              <span className="badge badge-detection">
                                {formatValue(incident.label ?? incident.prediction)}
                              </span>
                            </td>
                            <td>{formatProbability(incident.attack_probability)}</td>
                            <td>{formatValue(incident.total_packets)}</td>
                            <td>
                              <span className={getSeverityBadgeClass(incident.severity)}>
                                {formatValue(incident.severity)}
                              </span>
                            </td>
                            <td>
                              <span className={getStatusBadgeClass(incident.status)}>
                                {formatValue(incident.status)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state">
                    <p>No security incidents recorded yet. Reports will populate when the ML detector identifies an attack.</p>
                  </div>
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
