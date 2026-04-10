import axios from 'axios'

const NODE_META = {
  User:    { bg: 'bg-blue-600',   text: 'text-white',    label: 'User' },
  Process: { bg: 'bg-purple-600', text: 'text-white',    label: 'Process' },
  File:    { bg: 'bg-yellow-500', text: 'text-gray-900', label: 'File' },
  Node:    { bg: 'bg-gray-700',   text: 'text-gray-200', label: 'Node' },
}

function getNodeType(node) {
  const name = (node.id || node.properties?.name || '').toString()
  if (name.startsWith('user_'))    return 'User'
  if (name.startsWith('process_')) return 'Process'
  if (name.startsWith('/'))        return 'File'
  return 'Node'
}

// Build a local demo graph from the last analysis result when Neo4j is offline
function buildLocalGraph(features) {
  if (!features) return { nodes: [], edges: [] }
  const uid = Math.floor(Math.random() * 9000) + 1000
  const pid = Math.floor(Math.random() * 900) + 100
  const nodes = [
    { id: `user_${uid}`,    properties: { name: `user_${uid}` } },
    { id: `process_${pid}`, properties: { name: `process_${pid}` } },
    { id: '/var/log/auth.log', properties: { name: '/var/log/auth.log' } },
  ]
  const edges = [
    { source: `user_${uid}`,    type: 'EXECUTED', target: `process_${pid}` },
    { source: `process_${pid}`, type: 'ACCESSED', target: '/var/log/auth.log' },
  ]
  return { nodes, edges }
}

export default function GraphPanel({ nodes = [], edges = [], onCleared, features = null }) {
  const isNeo4jEmpty = nodes.length === 0
  const display = isNeo4jEmpty && features
    ? buildLocalGraph(features)
    : { nodes, edges }

  const handleClear = async () => {
    try {
      await axios.delete('http://localhost:8000/api/graph/clear')
      if (onCleared) onCleared()
    } catch (e) {
      console.error('Failed to clear graph', e)
    }
  }

  return (
    <div className="bg-gray-900 rounded-2xl shadow-lg p-6 border border-gray-800 transition-all duration-500">
      {/* Header */}
      <div className="flex items-start justify-between mb-1">
        <div>
          <h2 className="text-white text-sm font-semibold">Attack Relationship Graph</h2>
          <p className="text-gray-500 text-xs mt-0.5">
            {isNeo4jEmpty && features
              ? 'Simulated graph — connect Neo4j for live data'
              : 'Visualizing system interactions'}
          </p>
        </div>
        <button onClick={handleClear}
          className="text-xs px-3 py-1 rounded-lg bg-red-900 text-red-300 border border-red-700 hover:bg-red-800 transition-colors">
          Clear Graph
        </button>
      </div>

      {/* Legend */}
      <div className="flex gap-4 mt-3 mb-5">
        {[['User','bg-blue-600'],['Process','bg-purple-600'],['File','bg-yellow-500']].map(([label, bg]) => (
          <span key={label} className="flex items-center gap-1.5 text-xs text-gray-400">
            <span className={`w-2.5 h-2.5 rounded-full ${bg}`} />{label}
          </span>
        ))}
        {isNeo4jEmpty && features && (
          <span className="ml-auto text-xs text-yellow-600 italic">⚠ Neo4j offline — showing simulated graph</span>
        )}
      </div>

      {display.nodes.length === 0 ? (
        <p className="text-gray-600 text-sm text-center py-10">
          Run analysis to visualize attack relationships
        </p>
      ) : (
        <div className="space-y-5">
          {/* Nodes */}
          <div>
            <p className="text-gray-500 text-xs mb-2 uppercase tracking-widest">
              Nodes ({display.nodes.length})
            </p>
            <div className="flex flex-wrap gap-2">
              {display.nodes.map((node, i) => {
                const type = getNodeType(node)
                const meta = NODE_META[type]
                return (
                  <span key={i}
                    className={`text-xs px-3 py-1.5 rounded-full font-mono font-semibold ${meta.bg} ${meta.text}`}>
                    {node.id}
                  </span>
                )
              })}
            </div>
          </div>

          {/* Edges */}
          {display.edges.length > 0 && (
            <div>
              <p className="text-gray-500 text-xs mb-2 uppercase tracking-widest">
                Relationships ({display.edges.length})
              </p>
              <div className="space-y-2">
                {display.edges.map((edge, i) => (
                  <div key={i}
                    className="flex items-center gap-2 text-xs font-mono bg-gray-800 rounded-lg px-3 py-2 transition-all duration-300">
                    <span className="text-blue-400 font-semibold">{edge.source}</span>
                    <span className="text-gray-600">──</span>
                    <span className="text-orange-400 font-bold uppercase tracking-wide">{edge.type}</span>
                    <span className="text-gray-600">──▶</span>
                    <span className="text-yellow-400 font-semibold">{edge.target}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
