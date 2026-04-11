import { useState } from 'react'

const STATUS_COLORS = {
  EXTREME_RISK: { bg: 'bg-red-950/40',    text: 'text-red-400',    border: 'border-red-800/60',    dot: 'bg-red-500' },
  HIGH_RISK:    { bg: 'bg-orange-950/40', text: 'text-orange-400', border: 'border-orange-800/60', dot: 'bg-orange-500' },
  SUSPICIOUS:   { bg: 'bg-yellow-950/40', text: 'text-yellow-400', border: 'border-yellow-800/60', dot: 'bg-yellow-500' },
  NORMAL:       { bg: 'bg-[#0D1323]/60',  text: 'text-[#39FF14]',  border: 'border-[#1E2D4A]',     dot: 'bg-[#39FF14]' },
}

const MAX_EVENTS = 100

function ActionBadge({ action }) {
  if (action === 'blocked')
    return <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 uppercase mono-text">BLOCKED</span>
  if (action === 'redirected_to_honeypot')
    return <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800 uppercase mono-text">HONEYPOT</span>
  if (action === 'flagged')
    return <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-yellow-950 text-yellow-400 border border-yellow-800 uppercase mono-text">FLAGGED</span>
  return null
}

/**
 * LiveFeed — real-time event stream panel.
 *
 * Props:
 *   events   — shared event array from App (persists across navigation)
 *   onEvents — setter for shared event array
 *
 * Falls back to local state if props not provided.
 */
export default function LiveFeed({ events: externalEvents, onEvents, wsStatus = 'disconnected' }) {
  const [localEvents, setLocalEvents] = useState([])

  // Use external (App-level) state if provided, else local
  const events    = externalEvents ?? localEvents

  const wsIndicator = {
    connected:    { color: 'text-[#39FF14]', dot: 'bg-[#39FF14]', pulse: true,  label: 'Live: Connected' },
    disconnected: { color: 'text-[#94A3B8]', dot: 'bg-[#1E2D4A]', pulse: false, label: 'Live: Disconnected' },
    error:        { color: 'text-[#FF003C]', dot: 'bg-[#FF003C]', pulse: false, label: 'Live: Error' },
  }[wsStatus]

  return (
    <div className="rounded-xl border border-[#1E2D4A] bg-[#0D1323]/60 p-5">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <i className="ph ph-broadcast text-[#00F0FF] text-base" />
          <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
            Live Event Stream
          </span>
          {events.length > 0 && (
            <span className="text-[9px] text-[#94A3B8] mono-text">({events.length})</span>
          )}
        </div>
        <span className={`flex items-center gap-1.5 text-[11px] mono-text font-bold ${wsIndicator.color}`}>
          <span className={`w-2 h-2 rounded-full ${wsIndicator.dot} ${wsIndicator.pulse ? 'animate-pulse' : ''}`} />
          {wsIndicator.label}
        </span>
      </div>

      {/* Event list */}
      {events.length === 0 ? (
        <p className="text-[#1E2D4A] text-xs text-center py-6 mono-text">
          {wsStatus === 'connected'
            ? 'Waiting for events... POST to /ingest to see live data.'
            : 'Connecting to event stream...'}
        </p>
      ) : (
        <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
          {events.map((ev, i) => {
            const c       = STATUS_COLORS[ev.status] || STATUS_COLORS.NORMAL
            const actions = ev?.actions || []
            return (
              <div key={i}
                className={`rounded-lg border px-3 py-2 text-xs mono-text ${c.bg} ${c.border}`}>
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${c.dot}`} />
                    <span className={`font-bold ${c.text}`}>{ev.status}</span>
                    <span className="text-[#94A3B8]">{ev.ip}</span>
                    <span className="text-[#1E2D4A]">→</span>
                    <span className="text-[#E2E8F0]">{ev.device}</span>
                  </div>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {actions.map((a, j) => <ActionBadge key={j} action={a} />)}
                    <span className="text-[#94A3B8] text-[10px]">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-4 mt-1 text-[10px] text-[#94A3B8]">
                  <span>score <span className="text-[#E2E8F0]">{ev.risk_score?.toFixed(1)}</span></span>
                  <span>ml <span className="text-[#00F0FF]">{ev.ml_score?.toFixed(1)}</span></span>
                  {(ev?.log_score ?? 0) > 0 && (
                    <span>logs <span className="text-yellow-400">{ev.log_score?.toFixed(1)}</span></span>
                  )}
                  {ev?.reason && ev.reason !== 'N/A' && (
                    <span className="text-[#1E2D4A] truncate max-w-[240px]">{ev.reason}</span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
