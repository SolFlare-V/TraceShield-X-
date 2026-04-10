const RAW_SEVERITY = {
  BRUTE_FORCE:       'HIGH',
  LOW_REPUTATION_IP: 'HIGH',
  LONG_SESSION:      'MEDIUM',
  ODD_ACCESS_TIME:   'MEDIUM',
}

const BAR_LABELS = [
  { key: 'ml_contribution',          label: 'ML Model Inference',   color: '#B026FF' },
  { key: 'rule_contribution',        label: 'Heuristic Rules',      color: '#FF003C' },
  { key: 'ip_contribution',          label: 'IP Reputation DB',     color: '#FFEA00' },
  { key: 'brute_force_contribution', label: 'Auth Pattern Analysis', color: '#00F0FF' },
]

export default function AlertFeed({ flags = [], rawFlags = [], breakdown = {}, timeline = [] }) {
  const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });

  return (
    <div className="cyber-panel h-full flex flex-col space-y-8">
      <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-3">
         <h2 className="panel-title text-sm m-0">Event_Log_Stream</h2>
         <div className="flex items-center gap-2 mono-text text-[10px] text-[#39FF14]">
            <span className="w-2 h-2 rounded-full bg-[#39FF14] animate-pulse" />
            LIVE_FEED
         </div>
      </div>

      {/* Flag badges */}
      <section>
        <div className="flex items-center gap-2 mb-4">
           <i className="ph ph-list-bullets text-[#00F0FF]" />
           <p className="text-[#94A3B8] text-[10px] uppercase tracking-widest font-bold font-['Rajdhani']">Triggered Security Rules</p>
        </div>
        
        {flags.length === 0 ? (
          <div className="bg-[#05080F] border border-[#111A2E] p-4 rounded flex items-center gap-3">
            <i className="ph ph-shield-check text-[#39FF14] text-xl" />
            <p className="text-[#39FF14] text-xs mono-text">
               NO_THREATS_DETECTED:: System integrity verified. Continuous monitoring active.
            </p>
          </div>
        ) : (
          <div className="flex flex-wrap gap-3">
            {flags.map((flag, i) => {
              const raw = rawFlags[i] || ''
              const sev = RAW_SEVERITY[raw] || 'MEDIUM'
              const isHigh = sev === 'HIGH'
              return (
                <div key={i} className={`flex items-center gap-2 px-3 py-1.5 rounded border border-l-4 transition-all duration-300 ${
                  isHigh ? 'badge-critical' : 'badge-medium'
                }`}>
                  <i className={`ph ${isHigh ? 'ph-warning-diamond' : 'ph-info'} text-base`} />
                  <span className="text-[11px] font-bold tracking-wider uppercase font-['Rajdhani']">{flag}</span>
                </div>
              )
            })}
          </div>
        )}
      </section>

      {/* Attack Timeline / Terminal Output */}
      {timeline.length > 0 && (
        <section className="flex-1 flex flex-col">
          <div className="flex items-center gap-2 mb-4">
             <i className="ph ph-clock-counter-clockwise text-[#00F0FF]" />
             <p className="text-[#94A3B8] text-[10px] uppercase tracking-widest font-bold font-['Rajdhani']">Incident Chronology</p>
          </div>
          <div className="bg-[#05080F] border border-[#111A2E] rounded p-4 font-['JetBrains_Mono'] text-[12px] flex-1 overflow-y-auto max-h-[250px] relative scrollbar-custom">
             <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-[#00F0FF]/20 to-transparent" />
             <div className="space-y-3">
                {timeline.map((event, i) => (
                  <div key={i} className="flex gap-4 group">
                    <span className="text-[#64748B] opacity-50 flex-shrink-0">[{timestamp}]</span>
                    <div className="flex-1">
                       <span className={`font-bold mr-2 ${i === 0 ? 'text-[#FF003C]' : 'text-[#00F0FF]'}`}>
                          {i === 0 ? 'CRIT' : 'INFO'}
                       </span>
                       <span className={`${i === 0 ? 'text-[#E2E8F0]' : 'text-[#94A3B8]'} group-hover:text-white transition-colors`}>
                          {event}
                       </span>
                    </div>
                  </div>
                ))}
                <div className="flex items-center">
                   <span className="text-[#64748B] opacity-50 mr-4">[{timestamp}]</span>
                   <span className="text-[#00F0FF] font-bold mr-2">WAIT</span>
                   <span className="text-[#94A3B8]">Awaiting next sequence...</span>
                   <span className="terminal-cursor" />
                </div>
             </div>
          </div>
        </section>
      )}

      {/* Breakdown bars */}
      {Object.keys(breakdown).length > 0 && (
        <section>
          <div className="flex items-center gap-2 mb-4">
             <i className="ph ph-chart-pie text-[#00F0FF]" />
             <p className="text-[#94A3B8] text-[10px] uppercase tracking-widest font-bold font-['Rajdhani']">Vector Contribution</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4">
            {BAR_LABELS.map(({ key, label, color }) => {
              const val = breakdown[key] ?? 0
              const pct = Math.min((val / 40) * 100, 100)
              return (
                <div key={key}>
                  <div className="flex justify-between text-[10px] mono-text mb-1.5">
                    <span className="text-[#94A3B8]">{label}</span>
                    <span style={{ color }}>{val.toFixed(1)}%</span>
                  </div>
                  <div className="progress-track bg-[#1E2D4A]/30 h-1">
                    <div 
                       className="h-full rounded-full transition-all duration-700 ease-out"
                       style={{ width: `${pct}%`, backgroundColor: color, boxShadow: `0 0 10px ${color}66` }} 
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </section>
      )}
    </div>
  )
}
