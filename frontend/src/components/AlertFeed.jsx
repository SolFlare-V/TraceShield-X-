const RAW_SEVERITY = {
  BRUTE_FORCE:       'HIGH',
  LOW_REPUTATION_IP: 'HIGH',
  LONG_SESSION:      'MEDIUM',
  ODD_ACCESS_TIME:   'MEDIUM',
}

const BAR_LABELS = [
  { key: 'ml_contribution',          label: 'ML Model',    color: 'bg-purple-500' },
  { key: 'rule_contribution',        label: 'Rules',       color: 'bg-red-500' },
  { key: 'ip_contribution',          label: 'IP Rep',      color: 'bg-orange-500' },
  { key: 'brute_force_contribution', label: 'Brute Force', color: 'bg-yellow-500' },
]

export default function AlertFeed({ flags = [], rawFlags = [], breakdown = {}, timeline = [] }) {
  return (
    <div className="bg-gray-900 rounded-2xl shadow-lg p-6 border border-gray-800 space-y-6 transition-all duration-500">
      <h2 className="text-gray-400 text-sm uppercase tracking-widest">Alert Feed</h2>

      {/* Flag badges */}
      <div>
        <p className="text-gray-500 text-xs mb-2">Triggered Rules</p>
        {flags.length === 0 ? (
          <p className="text-green-500 text-sm flex items-center gap-2">
            <span>✅</span> No immediate threats, monitoring system...
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {flags.map((flag, i) => {
              const raw = rawFlags[i] || ''
              const sev = RAW_SEVERITY[raw] || 'MEDIUM'
              const isHigh = sev === 'HIGH'
              return (
                <span key={i} className={`text-xs font-bold px-3 py-1 rounded-full border flex items-center gap-1 transition-all duration-300 ${
                  isHigh
                    ? 'bg-red-900 text-red-300 border-red-700'
                    : 'bg-yellow-900 text-yellow-300 border-yellow-700'
                }`}>
                  {isHigh ? '🔴' : '🟡'} {flag}
                </span>
              )
            })}
          </div>
        )}
      </div>

      {/* Attack Timeline */}
      {timeline.length > 0 && (
        <div>
          <p className="text-gray-500 text-xs mb-3 uppercase tracking-widest">Attack Timeline</p>
          <div className="ml-2 border-l border-gray-700 pl-4 space-y-4">
            {timeline.map((event, i) => (
              <div key={i} className="relative flex items-start gap-3 animate-fade-in">
                <span className={`absolute -left-[1.35rem] mt-1 w-3 h-3 rounded-full border-2 border-gray-900 ${
                  i === 0 ? 'bg-orange-500' : 'bg-gray-500'
                }`} />
                <p className={`text-sm leading-snug ${i === 0 ? 'text-orange-300 font-medium' : 'text-gray-400'}`}>
                  {event}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Breakdown bars */}
      {Object.keys(breakdown).length > 0 && (
        <div>
          <p className="text-gray-500 text-xs mb-3 uppercase tracking-widest">Score Breakdown</p>
          <div className="space-y-2">
            {BAR_LABELS.map(({ key, label, color }) => {
              const val = breakdown[key] ?? 0
              const pct = Math.min((val / 40) * 100, 100)
              return (
                <div key={key}>
                  <div className="flex justify-between text-xs text-gray-400 mb-1">
                    <span>{label}</span><span>{val}</span>
                  </div>
                  <div className="w-full bg-gray-800 rounded-full h-2">
                    <div className={`${color} h-2 rounded-full transition-all duration-500 ease-in-out`}
                      style={{ width: `${pct}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
