import { useEffect, useState } from 'react'

const LEVEL_META = {
  CRITICAL: { icon: '🔥', glow: 'shadow-[0_0_30px_rgba(226,75,74,0.4)]',  border: 'border-red-800' },
  HIGH:     { icon: '⚠️', glow: 'shadow-[0_0_30px_rgba(239,159,39,0.35)]', border: 'border-orange-800' },
  MEDIUM:   { icon: '⚡', glow: 'shadow-[0_0_30px_rgba(250,199,117,0.3)]', border: 'border-yellow-800' },
  LOW:      { icon: '✅', glow: 'shadow-[0_0_20px_rgba(151,196,89,0.25)]', border: 'border-green-900' },
}

export default function RiskCard({ risk_score, risk_level, risk_color, anomaly, anomaly_score, summary }) {
  const [displayed, setDisplayed] = useState(0)

  useEffect(() => {
    if (risk_score == null) return
    setDisplayed(0)
    const steps = 40
    const increment = risk_score / steps
    let current = 0
    const timer = setInterval(() => {
      current += increment
      if (current >= risk_score) {
        setDisplayed(risk_score)
        clearInterval(timer)
      } else {
        setDisplayed(parseFloat(current.toFixed(1)))
      }
    }, 20)
    return () => clearInterval(timer)
  }, [risk_score])

  if (risk_score == null) return null

  const meta = LEVEL_META[risk_level] || LEVEL_META.LOW

  return (
    <div className={`bg-gray-900 rounded-2xl p-6 border transition-all duration-500 ${meta.border} ${meta.glow}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-gray-400 text-sm uppercase tracking-widest">Risk Score</h2>
        <span className="text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wide"
          style={{ backgroundColor: risk_color + '22', color: risk_color, border: `1px solid ${risk_color}` }}>
          {meta.icon} {risk_level}
        </span>
      </div>

      <div className="text-6xl font-black mb-4 tabular-nums transition-all duration-300" style={{ color: risk_color }}>
        {displayed}
        <span className="text-2xl text-gray-500 font-normal"> / 100</span>
      </div>

      <div className="flex items-center gap-3 mb-4">
        <span className="text-gray-400 text-sm">Anomaly:</span>
        <span className={`text-xs font-bold px-3 py-1 rounded-full ${anomaly ? 'bg-red-900 text-red-300 border border-red-700' : 'bg-green-900 text-green-300 border border-green-700'}`}>
          {anomaly ? 'YES' : 'NO'}
        </span>
        <span className="text-gray-500 text-xs">score: {anomaly_score}</span>
      </div>

      {summary && (
        <p className="text-gray-300 text-sm leading-relaxed border-t border-gray-800 pt-4 transition-all duration-300">
          {summary}
        </p>
      )}
    </div>
  )
}
