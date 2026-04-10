import { useEffect, useState, useCallback } from 'react'
import axios from 'axios'
import RiskCard from './components/RiskCard'
import AlertFeed from './components/AlertFeed'
import GraphPanel from './components/GraphPanel'

const api = axios.create({ baseURL: 'http://localhost:8000' })

function StatusDot({ ok, label }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={`relative inline-flex w-2 h-2 rounded-full ${ok ? 'bg-green-400' : 'bg-red-500'}`}>
        {ok && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-50" />}
      </span>
      <span className={ok ? 'text-green-400' : 'text-red-400'}>{label}</span>
    </span>
  )
}

export default function App() {
  const [status, setStatus]   = useState(null)
  const [result, setResult]   = useState(null)
  const [graph, setGraph]     = useState({ nodes: [], edges: [] })
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)
  const [autoRefresh, setAutoRefresh] = useState(false)

  useEffect(() => {
    api.get('/api/status')
      .then(r => setStatus(r.data))
      .catch(() => setStatus(null))
  }, [])

  const fetchGraph = useCallback(() =>
    api.get('/api/graph').then(r => setGraph(r.data)).catch(() => {}), [])

  const fetchAnalyze = useCallback(async () => {
    if (loading) return
    setLoading(true)
    setError(null)
    try {
      const r = await api.get('/api/analyze')
      setResult(r.data)
      await fetchGraph()
    } catch {
      setError('Analysis failed. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }, [loading, fetchGraph])

  useEffect(() => {
    if (!autoRefresh) return
    const interval = setInterval(fetchAnalyze, 5000)
    return () => clearInterval(interval)
  }, [autoRefresh, fetchAnalyze])

  const simulate = async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await api.post('/api/simulate', { count: 1 })
      setResult(r.data[0])
      await fetchGraph()
    } catch {
      setError('Simulation failed. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white p-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-8 gap-4">
        <div>
          <h1 className="text-2xl font-black tracking-tight text-white">
            TraceShield <span className="text-blue-400">X++</span>
          </h1>
          <p className="text-gray-500 text-xs mt-1">Cybersecurity Forensics & Anti-Forensics Detection</p>
        </div>
        <div className="flex items-center gap-4 text-xs bg-gray-900 px-4 py-2 rounded-xl border border-gray-800">
          <StatusDot ok={status?.neo4j}        label="Neo4j" />
          <StatusDot ok={status?.model_loaded} label="Model" />
          {status?.dataset_rows != null && (
            <span className="text-gray-600 border-l border-gray-700 pl-3">{status.dataset_rows} rows</span>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-3 mb-8">
        <button onClick={fetchAnalyze} disabled={loading}
          className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-sm font-semibold transition-all duration-200 active:scale-95">
          {loading
            ? <span className="flex items-center gap-2"><span className="w-3 h-3 border border-white border-t-transparent rounded-full animate-spin" />Analyzing...</span>
            : 'Analyze Sample'}
        </button>
        <button onClick={simulate} disabled={loading}
          className="px-5 py-2 rounded-xl bg-purple-700 hover:bg-purple-600 disabled:opacity-40 text-sm font-semibold transition-all duration-200 active:scale-95">
          {loading
            ? <span className="flex items-center gap-2"><span className="w-3 h-3 border border-white border-t-transparent rounded-full animate-spin" />Simulating...</span>
            : 'Simulate Attack'}
        </button>
        <button onClick={() => setAutoRefresh(v => !v)}
          className={`px-5 py-2 rounded-xl text-sm font-semibold transition-all duration-200 border ${autoRefresh ? 'bg-green-900 border-green-700 text-green-300' : 'bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500'}`}>
          {autoRefresh ? '⏸ Live: ON' : '▶ Live: OFF'}
        </button>
      </div>

      {error && (
        <div className="mb-6 px-4 py-3 rounded-xl bg-red-950 border border-red-800 text-red-300 text-sm">
          {error}
        </div>
      )}

      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 transition-all duration-500 ease-in-out">
          <RiskCard
            risk_score={result.risk_score}
            risk_level={result.risk_level}
            risk_color={result.risk_color}
            anomaly={result.anomaly}
            anomaly_score={result.anomaly_score}
            summary={result.summary}
          />
          <AlertFeed
            flags={result.readable_flags?.length ? result.readable_flags : result.flags}
            rawFlags={result.flags}
            breakdown={result.breakdown}
            timeline={result.timeline || []}
          />
          <div className="lg:col-span-2">
            <GraphPanel nodes={graph.nodes} edges={graph.edges}
              features={result?.features}
              onCleared={() => setGraph({ nodes: [], edges: [] })} />
          </div>
        </div>
      )}

      {!result && (
        <div className="text-center py-24 text-gray-700">
          <p className="text-5xl mb-4">🛡</p>
          <p className="text-sm">Click "Analyze Sample" or "Simulate Attack" to begin.</p>
        </div>
      )}
    </div>
  )
}
