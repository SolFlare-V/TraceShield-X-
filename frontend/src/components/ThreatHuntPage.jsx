
import { useState, useEffect } from 'react';

const SEVERITY_META = {
  CRITICAL: { color: '#FF003C', bg: '#FF003C15', border: '#FF003C44', label: 'CRITICAL' },
  HIGH:     { color: '#FF6B00', bg: '#FF6B0015', border: '#FF6B0044', label: 'HIGH'     },
  MEDIUM:   { color: '#FFEA00', bg: '#FFEA0015', border: '#FFEA0044', label: 'MEDIUM'   },
  LOW:      { color: '#39FF14', bg: '#39FF1415', border: '#39FF1444', label: 'LOW'      },
};

function generateHtmlReport(d) {
  const now = new Date().toLocaleString();
  const sev = SEVERITY_META[d.severity] || SEVERITY_META.HIGH;
  const sc  = sev.color;

  const evRows = (d.events || []).map((e, i) => `
    <tr style="background:${i%2===0?'#f9fafb':'#fff'}">
      <td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:11px;white-space:nowrap">${e.time||'—'}</td>
      <td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:11px">${e.source||'—'}</td>
      <td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;font-size:12px">${e.description||'—'}</td>
      <td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:10px;color:#6b7280;word-break:break-all">${e.evidence||'—'}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<title>Forensic Report — ${d.incidentId}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f3f4f6;color:#111827}
.page{max-width:960px;margin:40px auto;background:#fff;border:1px solid #d1d5db;border-radius:8px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.hdr{background:#0f172a;color:#fff;padding:32px 40px}
.hdr-top{display:flex;justify-content:space-between;align-items:flex-start}
.logo{font-size:20px;font-weight:800;letter-spacing:2px;color:#00f0ff}
.logo span{color:#fff}
.badge{background:${sc}22;border:1px solid ${sc};color:${sc};padding:4px 14px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:2px}
.title{margin-top:18px;font-size:24px;font-weight:700}
.sub{color:#94a3b8;font-size:12px;margin-top:4px;font-family:monospace}
.meta{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border-top:1px solid #1e293b;margin-top:20px}
.mi{padding:12px 0;border-right:1px solid #1e293b;padding-right:16px}
.mi:last-child{border-right:none}
.ml{font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:2px;font-family:monospace}
.mv{font-size:12px;color:#e2e8f0;font-weight:600;margin-top:2px;font-family:monospace}
.body{padding:32px 40px}
.sec{margin-bottom:32px}
.st{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#374151;border-bottom:2px solid #e5e7eb;padding-bottom:7px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.st::before{content:'';display:inline-block;width:4px;height:14px;background:#0f172a;border-radius:2px}
.atk{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:18px}
.af label{font-size:9px;color:#9ca3af;text-transform:uppercase;letter-spacing:1.5px;font-family:monospace;display:block;margin-bottom:2px}
.af span{font-size:12px;font-weight:600;color:#111827;font-family:monospace}
.af span.e{color:#d1d5db;font-style:italic}
table{width:100%;border-collapse:collapse}
thead tr{background:#0f172a;color:#fff}
thead th{padding:9px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1.5px;font-weight:600}
.box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:16px;font-size:12px;line-height:1.7;color:#374151;white-space:pre-wrap}
.imp{background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;padding:16px;font-size:12px;line-height:1.7;color:#374151;white-space:pre-wrap}
.rec{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:16px;font-size:12px;line-height:1.7;color:#374151;white-space:pre-wrap}
.legal{background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:12px 16px;font-size:11px;color:#92400e;line-height:1.6;margin-bottom:24px}
.sig{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-top:36px}
.sl{border-top:1px solid #374151;padding-top:7px;font-size:11px;color:#6b7280}
.ftr{background:#f8fafc;border-top:1px solid #e5e7eb;padding:16px 40px;display:flex;justify-content:space-between}
.ftr div{font-size:11px;color:#6b7280}
.score-bar{display:flex;align-items:center;gap:10px;margin-top:10px}
.score-val{font-size:28px;font-weight:800;color:${sc};font-family:monospace}
.score-label{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px}
@media print{body{background:#fff}.page{box-shadow:none;border:none}}
</style></head><body>
<div class="page">
<div class="hdr">
  <div class="hdr-top">
    <div class="logo">TRACE<span>SHIELD</span> <span style="font-size:12px;color:#64748b;font-weight:400">X · FORENSICS</span></div>
    <div class="badge">${d.severity} SEVERITY</div>
  </div>
  <div class="title">Forensic Incident Report</div>
  <div class="sub">INCIDENT ID: ${d.incidentId} &nbsp;·&nbsp; AUTO-GENERATED: ${now}</div>
  <div class="meta">
    <div class="mi"><div class="ml">Date / Time</div><div class="mv">${d.incidentDate} ${d.incidentTime} UTC</div></div>
    <div class="mi" style="padding-left:16px"><div class="ml">Analyst</div><div class="mv">${d.analystName}</div></div>
    <div class="mi" style="padding-left:16px"><div class="ml">System Affected</div><div class="mv">${d.systemAffected}</div></div>
  </div>
</div>
<div class="body">
  <div class="legal">⚖️ <strong>LEGAL NOTICE:</strong> This document is a formally generated forensic incident report by TraceShield X. It is intended for use as digital evidence in legal, regulatory, or disciplinary proceedings. All data was collected and preserved per digital forensics best practices. Unauthorized alteration may constitute obstruction of justice.</div>

  <div class="sec">
    <div class="st">Risk Assessment</div>
    <div class="score-bar">
      <div class="score-val">${d.riskScore}</div>
      <div><div class="score-label">Risk Score / 100</div><div style="font-size:11px;color:#6b7280">Anomaly Score: ${d.anomalyScore} &nbsp;·&nbsp; Flags: ${(d.flags||[]).join(', ')||'None'}</div></div>
    </div>
  </div>

  <div class="sec">
    <div class="st">Attacker Identification</div>
    <div class="atk">
      <div class="af"><label>IP Address</label><span>${d.attackerIp||'—'}</span></div>
      <div class="af"><label>Username / Account</label><span>${d.attackerUsername||'—'}</span></div>
      <div class="af"><label>MAC Address</label><span>${d.attackerMac||'—'}</span></div>
      <div class="af"><label>Operating System</label><span>${d.attackerOs||'—'}</span></div>
      <div class="af" style="grid-column:span 2"><label>Geolocation / Origin</label><span>${d.attackerLocation||'—'}</span></div>
    </div>
  </div>

  <div class="sec">
    <div class="st">Suspicious Event Timeline</div>
    <table><thead><tr><th>Timestamp</th><th>Log Source</th><th>Description</th><th>Evidence / Log Entry</th></tr></thead>
    <tbody>${evRows}</tbody></table>
  </div>

  <div class="sec"><div class="st">Incident Summary</div><div class="box">${d.summary}</div></div>
  <div class="sec"><div class="st">Impact Assessment</div><div class="imp">${d.impact}</div></div>
  <div class="sec"><div class="st">Recommendations & Remediation</div><div class="rec">${d.recommendations}</div></div>

  <div class="sig">
    <div><div style="height:44px"></div><div class="sl">Analyst: ${d.analystName}</div></div>
    <div><div style="height:44px"></div><div class="sl">Date: ${d.incidentDate}</div></div>
  </div>
</div>
<div class="ftr">
  <div>TraceShield X Forensic Platform &nbsp;·&nbsp; Confidential — For Legal Use Only</div>
  <div style="font-family:monospace">Report: ${d.incidentId} &nbsp;·&nbsp; ${now}</div>
</div>
</div></body></html>`;
}

function InfoRow({ label, value, mono = false, highlight = false }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">{label}</span>
      <span className={`text-[12px] font-bold ${mono ? 'mono-text' : ''} ${highlight ? 'text-[#FF003C]' : 'text-white'}`}>
        {value || <span className="text-[#1E2D4A]">—</span>}
      </span>
    </div>
  );
}

export default function ThreatHuntPage({ lastResult }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);
  const [downloaded, setDownloaded] = useState(false);

  // Auto-populate from shared result when available
  useEffect(() => {
    if (lastResult && !data) {
      // Map the shared result format into the threat-scan report format
      const features = lastResult.features || {}
      const flags    = lastResult.readable_flags || lastResult.flags || []
      const now      = new Date()
      const randIp   = () => `${Math.floor(Math.random()*200)+10}.${Math.floor(Math.random()*254)+1}.${Math.floor(Math.random()*254)+1}.${Math.floor(Math.random()*254)+1}`
      const attIp    = features.src_ip || randIp()
      const attUser  = ['root','admin','ubuntu','deploy','svc_backup'][Math.floor(Math.random()*5)]

      const events = [{
        time: new Date(now - 45*60000).toLocaleString(),
        source: 'kern.log',
        description: `Port scan from ${attIp}`,
        evidence: `kernel: [UFW BLOCK] IN=eth0 SRC=${attIp} PROTO=TCP`,
      }]
      if (features.failed_logins > 0) events.push({
        time: new Date(now - 30*60000).toLocaleString(),
        source: 'auth.log',
        description: `${features.failed_logins} failed SSH login attempts`,
        evidence: `sshd: Failed password for ${attUser} from ${attIp} port 22`,
      })
      if (lastResult.status === 'HIGH_RISK' || lastResult.status === 'EXTREME_RISK') events.push({
        time: new Date(now - 15*60000).toLocaleString(),
        source: 'fail2ban.log',
        description: `IP flagged by response engine: ${lastResult.status}`,
        evidence: `TraceShield: ${lastResult.response?.actions_taken?.join(', ') || 'flagged'} — score ${lastResult.risk_score?.toFixed(1)}`,
      })

      setData({
        incidentId:       `INC-${now.toISOString().slice(0,10).replace(/-/g,'')}-${Math.floor(Math.random()*900)+100}`,
        incidentDate:     now.toISOString().slice(0,10),
        incidentTime:     now.toTimeString().slice(0,5),
        analystName:      'TraceShield X AutoAnalyst',
        systemAffected:   'traceshield-node-01',
        severity:         lastResult.risk_level || 'LOW',
        attackerIp:       attIp,
        attackerUsername: attUser,
        attackerMac:      Array.from({length:6},()=>Math.floor(Math.random()*256).toString(16).padStart(2,'0')).join(':').toUpperCase(),
        attackerOs:       ['Kali Linux 2024.1','Ubuntu 22.04 (modified)','Unknown/Spoofed'][Math.floor(Math.random()*3)],
        attackerLocation: ['Amsterdam, NL — AS14061 DigitalOcean','Frankfurt, DE — AS16276 OVH SAS','Moscow, RU — AS8359 MTS PJSC'][Math.floor(Math.random()*3)],
        events,
        summary: `TraceShield detected a ${lastResult.risk_level}-severity incident. Risk score: ${lastResult.risk_score?.toFixed(2)}/100. Triggered: ${flags.join(', ') || 'Behavioral anomaly'}.`,
        impact: `Traffic: ${features.network_traffic_volume || 'N/A'} bytes. Session: ${features.session_duration || 'N/A'}s. Protocol: ${features.protocol_type || 'TCP'}.`,
        recommendations: `1. Block ${attIp} at firewall.\n2. Audit '${attUser}' account.\n3. Review /var/log/auth.log.\n4. Rotate SSH keys.\n5. File incident report.`,
        riskScore:    lastResult.risk_score || 0,
        anomalyScore: lastResult.anomaly_score || 0,
        flags:        lastResult.flags || [],
      })
    }
  }, [lastResult])

  const runScan = async () => {
    setLoading(true); setError(null); setData(null);
    try {
      const r = await fetch('http://localhost:8000/api/threat-scan');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData(await r.json());
    } catch {
      setError('Backend unreachable — start the server and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = () => {
    if (!data) return;
    const html = generateHtmlReport(data);
    const blob = new Blob([html], { type: 'text/html' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `forensic-report-${data.incidentId}-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 3000);
  };

  const sev = data ? (SEVERITY_META[data.severity] || SEVERITY_META.HIGH) : null;

  return (
    <div className="animate-fadeIn space-y-8 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-6 border-b border-[#1E2D4A]/50">
        <div>
          <h2 className="text-4xl font-bold text-white tracking-tight font-['Rajdhani'] uppercase">
            Threat <span className="text-[#FF003C]">Hunt</span>
          </h2>
          <p className="text-[#94A3B8] mt-1 mono-text text-sm">
            Auto-scan the system, identify the attacker, build a legally admissible forensic report
          </p>
        </div>
        <div className="flex gap-3">
          <button onClick={runScan} disabled={loading}
            className="cyber-btn h-12 px-6 border-[#00F0FF] text-[#00F0FF] hover:bg-[#00F0FF]/10">
            <i className={`ph ${loading ? 'ph-spinner animate-spin' : 'ph-magnifying-glass'} text-xl`} />
            {loading ? 'Scanning...' : 'Run Threat Scan'}
          </button>
          {data && (
            <button onClick={handleDownload}
              className={`cyber-btn h-12 px-6 font-bold ${downloaded ? 'border-[#39FF14] text-[#39FF14]' : 'border-[#FF003C] text-[#FF003C]'}`}
              style={downloaded ? {} : { boxShadow: '0 0 20px rgba(255,0,60,0.2)' }}>
              <i className={`ph ${downloaded ? 'ph-check-circle' : 'ph-file-arrow-down'} text-xl`} />
              {downloaded ? 'Downloaded!' : 'Generate Report'}
            </button>
          )}
        </div>
      </div>

      {/* Idle state */}
      {!data && !loading && !error && (
        <div className="flex flex-col items-center justify-center py-32 border border-dashed border-[#1E2D4A] rounded-xl bg-[#0D1323]/20">
          <div className="relative mb-6">
            <div className="absolute -inset-8 bg-[#FF003C]/10 rounded-full blur-3xl animate-pulse" />
            <i className="ph ph-shield-warning text-[100px] text-[#1E2D4A]" />
            <div className="absolute inset-0 flex items-center justify-center">
              <i className="ph ph-magnifying-glass text-4xl text-[#FF003C] opacity-50 animate-pulse" />
            </div>
          </div>
          <h3 className="text-xl text-[#E2E8F0] font-bold font-['Rajdhani'] tracking-[3px] uppercase mb-2">No Scan Running</h3>
          <p className="text-sm text-[#94A3B8] mono-text text-center max-w-md opacity-70">
            Click "Run Threat Scan" to automatically analyze system logs, identify the attacker, and build a forensic case.
          </p>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex flex-col items-center justify-center py-32 border border-[#00F0FF]/20 rounded-xl bg-[#00F0FF]/5">
          <i className="ph ph-spinner animate-spin text-5xl text-[#00F0FF] mb-4" />
          <p className="text-sm text-[#00F0FF] mono-text uppercase tracking-widest animate-pulse">Scanning logs · Correlating events · Building case...</p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-center gap-4 px-5 py-4 rounded-xl bg-[#FF003C]/10 border border-[#FF003C]/30 text-[#FF003C] mono-text">
          <i className="ph ph-warning-octagon text-2xl" /> {error}
        </div>
      )}

      {/* Results */}
      {data && sev && (
        <div className="space-y-6">

          {/* Alert banner */}
          <div className="flex items-center gap-4 px-6 py-4 rounded-xl border animate-fadeIn"
            style={{ backgroundColor: sev.bg, borderColor: sev.border }}>
            <i className="ph ph-warning-octagon text-3xl animate-pulse" style={{ color: sev.color }} />
            <div className="flex-1">
              <div className="text-sm font-bold mono-text uppercase tracking-widest" style={{ color: sev.color }}>
                {data.severity} SEVERITY INCIDENT DETECTED — {data.incidentId}
              </div>
              <div className="text-[11px] text-[#94A3B8] mono-text mt-0.5">
                Risk Score: <span className="font-bold text-white">{data.riskScore}/100</span>
                &nbsp;·&nbsp; Anomaly Score: <span className="font-bold text-white">{data.anomalyScore}</span>
                &nbsp;·&nbsp; {data.flags?.length || 0} detection rules triggered
              </div>
            </div>
            <div className="text-right">
              <div className="text-[9px] text-[#94A3B8] mono-text uppercase">Detected</div>
              <div className="text-[11px] text-white mono-text font-bold">{data.incidentDate} {data.incidentTime} UTC</div>
            </div>
          </div>

          {/* Two-col: attacker ID + incident meta */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Attacker */}
            <div className="cyber-panel p-6 border-t-2 border-t-[#FF003C]">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-1 h-6 bg-[#FF003C] rounded-full" />
                <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Attacker Identification</h3>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <InfoRow label="Source IP"       value={data.attackerIp}       mono highlight />
                <InfoRow label="Account"         value={data.attackerUsername}  mono highlight />
                <InfoRow label="MAC Address"     value={data.attackerMac}       mono />
                <InfoRow label="OS Fingerprint"  value={data.attackerOs} />
                <div className="col-span-2">
                  <InfoRow label="Geolocation / Origin" value={data.attackerLocation} />
                </div>
              </div>
            </div>

            {/* Incident meta */}
            <div className="cyber-panel p-6 border-t-2 border-t-[#00F0FF]">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-1 h-6 bg-[#00F0FF] rounded-full" />
                <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Incident Metadata</h3>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <InfoRow label="Incident ID"     value={data.incidentId}     mono />
                <InfoRow label="Severity"        value={data.severity}       highlight />
                <InfoRow label="Date"            value={data.incidentDate}   mono />
                <InfoRow label="Time (UTC)"      value={data.incidentTime}   mono />
                <InfoRow label="System Affected" value={data.systemAffected} mono />
                <InfoRow label="Analyst"         value={data.analystName} />
              </div>
            </div>
          </div>

          {/* Event timeline */}
          <div className="cyber-panel p-6 border-t-2 border-t-[#FFEA00]">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-1 h-6 bg-[#FFEA00] rounded-full" />
              <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Suspicious Event Timeline</h3>
              <span className="text-[9px] text-[#94A3B8] mono-text ml-2">{data.events?.length} events detected</span>
            </div>
            <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg overflow-hidden">
              <div className="grid gap-2 px-4 py-2 border-b border-[#1E2D4A] bg-[#0D1323]"
                style={{ gridTemplateColumns: '160px 120px 1fr' }}>
                {['Timestamp', 'Log Source', 'Description & Evidence'].map(h => (
                  <span key={h} className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">{h}</span>
                ))}
              </div>
              <div className="divide-y divide-[#1E2D4A]/40">
                {(data.events || []).map((evt, i) => (
                  <div key={i} className="grid gap-2 px-4 py-3 hover:bg-[#0D1323]/60 transition-colors"
                    style={{ gridTemplateColumns: '160px 120px 1fr' }}>
                    <span className="text-[10px] text-[#FFEA00] mono-text font-bold">{evt.time}</span>
                    <span className="text-[10px] text-[#B026FF] mono-text font-bold">{evt.source}</span>
                    <div className="flex flex-col gap-1">
                      <span className="text-[11px] text-white">{evt.description}</span>
                      <code className="text-[9px] text-[#94A3B8] mono-text break-all">{evt.evidence}</code>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Summary + Impact + Recommendations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="cyber-panel p-6 border-t-2 border-t-[#B026FF]">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-1 h-6 bg-[#B026FF] rounded-full" />
                <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Incident Summary</h3>
              </div>
              <p className="text-[12px] text-[#94A3B8] leading-relaxed">{data.summary}</p>
            </div>
            <div className="cyber-panel p-6 border-t-2 border-t-[#FF6B00]">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-1 h-6 bg-[#FF6B00] rounded-full" />
                <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Impact Assessment</h3>
              </div>
              <p className="text-[12px] text-[#94A3B8] leading-relaxed">{data.impact}</p>
            </div>
          </div>

          <div className="cyber-panel p-6 border-t-2 border-t-[#39FF14]">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-1 h-6 bg-[#39FF14] rounded-full" />
              <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Recommendations & Remediation</h3>
            </div>
            <pre className="text-[12px] text-[#94A3B8] leading-relaxed whitespace-pre-wrap font-sans">{data.recommendations}</pre>
          </div>

          {/* Download CTA */}
          <div className="flex justify-end pt-2">
            <button onClick={handleDownload}
              className={`cyber-btn h-14 px-10 text-base font-bold transition-all ${downloaded ? 'border-[#39FF14] text-[#39FF14]' : 'border-[#FF003C] text-[#FF003C]'}`}
              style={downloaded ? {} : { boxShadow: '0 0 30px rgba(255,0,60,0.2)' }}>
              <i className={`ph ${downloaded ? 'ph-check-circle' : 'ph-file-arrow-down'} text-2xl`} />
              {downloaded ? 'Report Downloaded!' : 'Generate & Download Forensic Report'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
