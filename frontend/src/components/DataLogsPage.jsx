import { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const ingest = axios.create({ baseURL: 'http://127.0.0.1:8001' })

const STATUS_META = {
  EXTREME_RISK: { label: 'EXTREME RISK', color: 'text-[#FF003C]', bg: 'bg-[#FF003C]/10', border: 'border-[#FF003C]/40', dot: 'bg-[#FF003C]' },
  HIGH_RISK:    { label: 'HIGH RISK',    color: 'text-orange-400', bg: 'bg-orange-900/20', border: 'border-orange-700/40', dot: 'bg-orange-400' },
  SUSPICIOUS:   { label: 'SUSPICIOUS',   color: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-700/40', dot: 'bg-yellow-400' },
  NORMAL:       { label: 'NORMAL',       color: 'text-[#39FF14]',  bg: 'bg-[#39FF14]/5',  border: 'border-[#39FF14]/20',  dot: 'bg-[#39FF14]' },
}

// ── Log Upload Panel ──────────────────────────────────────────────────────────
function LogUploadPanel() {
  const [file, setFile]         = useState(null)
  const [status, setStatus]     = useState('idle')   // idle | uploading | done | error
  const [summary, setSummary]   = useState(null)
  const [results, setResults]   = useState([])
  const [dragOver, setDragOver] = useState(false)
  const [selected, setSelected] = useState(null)    // selected IP row for detail
  const inputRef = useRef(null)

  const handleFile = (f) => {
    if (!f) return
    setFile(f)
    setSummary(null)
    setResults([])
    setSelected(null)
    setStatus('idle')
  }

  const upload = async () => {
    if (!file) return
    setStatus('uploading')
    setSummary(null)
    setResults([])
    setSelected(null)
    try {
      const form = new FormData()
      form.append('file', file)
      const r = await ingest.post('/dataset/upload', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setSummary(r.data.summary)
      setResults(r.data.results || [])
      setStatus('done')
    } catch (e) {
      setStatus('error')
    }
  }

  const reset = () => { setFile(null); setSummary(null); setResults([]); setSelected(null); setStatus('idle') }

  return (
    <div className="rounded-xl border border-[#1E2D4A] bg-[#0D1323]/60 p-5 mb-6">
      {/* Header */}
      <div className="flex items-center gap-2 mb-4">
        <i className="ph ph-upload-simple text-[#00F0FF] text-lg" />
        <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
          Log File Analysis
        </span>
        <span className="ml-auto text-[10px] text-[#1E2D4A] mono-text">
          auth.log · syslog · audit.log · kern.log · any format
        </span>
      </div>

      {/* Drop zone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files[0]) }}
        onClick={() => inputRef.current?.click()}
        className={`relative flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed cursor-pointer transition-all py-6
          ${dragOver ? 'border-[#00F0FF] bg-[#00F0FF]/5' : file ? 'border-[#39FF14]/50 bg-[#39FF14]/5' : 'border-[#1E2D4A] hover:border-[#00F0FF]/40 hover:bg-[#00F0FF]/5'}`}
      >
        <input ref={inputRef} type="file" accept=".log,.txt,text/plain" className="hidden"
          onChange={e => handleFile(e.target.files[0])} />
        {file ? (
          <>
            <i className="ph ph-file-text text-3xl text-[#39FF14]" />
            <span className="text-sm font-bold text-[#39FF14] mono-text">{file.name}</span>
            <span className="text-[10px] text-[#94A3B8] mono-text">{(file.size / 1024).toFixed(1)} KB · click to change</span>
          </>
        ) : (
          <>
            <i className="ph ph-cloud-arrow-up text-3xl text-[#1E2D4A]" />
            <span className="text-sm text-[#94A3B8] mono-text">Drop log file here or click to browse</span>
            <span className="text-[10px] text-[#1E2D4A] mono-text">.log · .txt · any Linux log format</span>
          </>
        )}
      </div>

      {/* Action bar */}
      <div className="flex items-center gap-3 mt-3 flex-wrap">
        <button onClick={upload} disabled={!file || status === 'uploading'}
          className="cyber-btn h-9 px-5 text-[11px] disabled:opacity-40 disabled:cursor-not-allowed">
          {status === 'uploading'
            ? <><i className="ph ph-spinner animate-spin text-sm" /> Analyzing...</>
            : <><i className="ph ph-magnifying-glass text-sm" /> Analyze Log</>}
        </button>
        {file && <button onClick={reset} className="text-[11px] text-[#94A3B8] hover:text-[#FF003C] mono-text transition-colors">
          <i className="ph ph-x text-xs" /> Clear
        </button>}

        {status === 'done' && summary && (
          <div className="flex items-center gap-4 ml-auto text-[11px] mono-text flex-wrap">
            <span className="text-[#94A3B8]"><span className="text-white font-bold">{summary.total_lines?.toLocaleString()}</span> lines</span>
            <span className="text-[#94A3B8]"><span className="text-[#00F0FF] font-bold">{summary.valid_events?.toLocaleString()}</span> events</span>
            <span className="text-[#94A3B8]"><span className="text-[#00F0FF] font-bold">{summary.unique_ips}</span> IPs</span>
            <span className={`font-bold ${summary.anomalies > 0 ? 'text-[#FF003C]' : 'text-[#39FF14]'}`}>
              {summary.anomalies} anomalies detected
            </span>
            <span className="text-[#39FF14]"><i className="ph ph-broadcast" /> Streamed to Live Feed</span>
          </div>
        )}
        {status === 'error' && (
          <span className="ml-auto text-[11px] text-[#FF003C] mono-text">
            <i className="ph ph-warning-octagon" /> Upload failed — is port 8001 running?
          </span>
        )}
      </div>

      {/* ── Results table ── */}
      {status === 'done' && results.length > 0 && (
        <div className="mt-5">
          <div className="flex items-center gap-2 mb-3">
            <i className="ph ph-table text-[#00F0FF] text-sm" />
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
              Per-IP Detection Results
            </span>
            <span className="ml-auto text-[10px] text-[#94A3B8] mono-text">click a row for details</span>
          </div>

          {/* Table header */}
          <div className="grid grid-cols-12 gap-2 px-3 py-2 text-[9px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text border-b border-[#1E2D4A]">
            <div className="col-span-3">IP Address</div>
            <div className="col-span-2">Status</div>
            <div className="col-span-1 text-right">Score</div>
            <div className="col-span-2">Actions</div>
            <div className="col-span-4">Signals</div>
          </div>

          {/* Table rows */}
          <div className="max-h-72 overflow-y-auto">
            {results.map((r, i) => {
              const m = STATUS_META[r.status] || STATUS_META.NORMAL
              const isSelected = selected === i
              return (
                <div key={i} onClick={() => setSelected(isSelected ? null : i)}
                  className={`grid grid-cols-12 gap-2 px-3 py-2.5 cursor-pointer transition-all border-b border-[#1E2D4A]/30 mono-text text-[11px]
                    ${isSelected ? 'bg-[#00F0FF]/5 border-l-2 border-l-[#00F0FF]' : 'hover:bg-[#121A2F]'}`}>

                  {/* IP */}
                  <div className="col-span-3 flex items-center gap-1.5">
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${m.dot}`} />
                    <span className="text-[#E2E8F0] font-bold truncate">{r.ip}</span>
                  </div>

                  {/* Status badge */}
                  <div className="col-span-2">
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${m.bg} ${m.border} ${m.color}`}>
                      {m.label}
                    </span>
                  </div>

                  {/* Score */}
                  <div className={`col-span-1 text-right font-bold ${m.color}`}>
                    {r.risk_score?.toFixed(1)}
                  </div>

                  {/* Actions */}
                  <div className="col-span-2 flex gap-1 flex-wrap">
                    {(r.actions || []).map((a, j) => (
                      <span key={j} className="text-[9px] px-1 py-0.5 rounded bg-[#1E2D4A] text-[#94A3B8] uppercase">{a}</span>
                    ))}
                  </div>

                  {/* Reason / signals */}
                  <div className="col-span-4 text-[#94A3B8] truncate">{r.reason || '—'}</div>
                </div>
              )
            })}
          </div>

          {/* ── Detail panel for selected row ── */}
          {selected !== null && results[selected] && (() => {
            const r = results[selected]
            const m = STATUS_META[r.status] || STATUS_META.NORMAL
            const f = r.features || {}
            return (
              <div className={`mt-3 rounded-lg border p-4 ${m.bg} ${m.border}`}>
                <div className="flex items-center justify-between mb-3">
                  <span className={`text-sm font-bold mono-text ${m.color}`}>{r.ip}</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${m.bg} ${m.border} ${m.color}`}>{m.label}</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[11px] mono-text mb-3">
                  <div><div className="text-[#94A3B8] text-[9px] uppercase mb-0.5">Risk Score</div><div className={`font-bold text-lg ${m.color}`}>{r.risk_score?.toFixed(2)}</div></div>
                  <div><div className="text-[#94A3B8] text-[9px] uppercase mb-0.5">Failed Logins</div><div className="font-bold text-white">{f.failed_logins ?? 0}</div></div>
                  <div><div className="text-[#94A3B8] text-[9px] uppercase mb-0.5">Sudo Attempts</div><div className="font-bold text-white">{f.sudo_attempts ?? 0}</div></div>
                  <div><div className="text-[#94A3B8] text-[9px] uppercase mb-0.5">Suspicious Cmds</div><div className="font-bold text-white">{f.suspicious_commands ?? 0}</div></div>
                  <div><div className="text-[#94A3B8] text-[9px] uppercase mb-0.5">Sensitive Files</div><div className="font-bold text-white">{f.sensitive_file_accesses ?? 0}</div></div>
                  <div><div className="text-[#94A3B8] text-[9px] uppercase mb-0.5">Port Scans</div><div className="font-bold text-white">{f.port_scans ?? 0}</div></div>
                  <div><div className="text-[#94A3B8] text-[9px] uppercase mb-0.5">Priv Escalation</div><div className="font-bold text-white">{f.privilege_escalations ?? 0}</div></div>
                  <div><div className="text-[#94A3B8] text-[9px] uppercase mb-0.5">Total Events</div><div className="font-bold text-white">{f.total_events ?? 0}</div></div>
                </div>
                {f.usernames?.length > 0 && (
                  <div className="text-[11px] mono-text mb-2">
                    <span className="text-[#94A3B8] text-[9px] uppercase">Usernames seen: </span>
                    <span className="text-[#00F0FF]">{f.usernames.join(', ')}</span>
                  </div>
                )}
                <div className="text-[11px] mono-text">
                  <span className="text-[#94A3B8] text-[9px] uppercase">Signals: </span>
                  <span className="text-[#E2E8F0]">{r.reason || 'none'}</span>
                </div>
                {(r.actions || []).length > 0 && (
                  <div className="flex gap-2 mt-2">
                    {r.actions.map((a, j) => (
                      <span key={j} className={`text-[9px] font-bold px-2 py-0.5 rounded border uppercase ${m.bg} ${m.border} ${m.color}`}>{a}</span>
                    ))}
                  </div>
                )}
              </div>
            )
          })()}
        </div>
      )}
    </div>
  )
}

// ── Log source definitions ────────────────────────────────────────────────────
const LOG_SOURCES = [
  { id: 'auth',    label: 'auth.log',       icon: 'ph-lock-key',        color: '#00F0FF', path: '/var/log/auth.log' },
  { id: 'syslog',  label: 'syslog',         icon: 'ph-terminal-window', color: '#39FF14', path: '/var/log/syslog' },
  { id: 'kern',    label: 'kern.log',       icon: 'ph-cpu',             color: '#B026FF', path: '/var/log/kern.log' },
  { id: 'audit',   label: 'audit.log',      icon: 'ph-shield-warning',  color: '#FF6B00', path: '/var/log/audit/audit.log' },
  { id: 'cron',    label: 'cron.log',       icon: 'ph-clock',           color: '#FFEA00', path: '/var/log/cron.log' },
  { id: 'dpkg',    label: 'dpkg.log',       icon: 'ph-package',         color: '#94A3B8', path: '/var/log/dpkg.log' },
  { id: 'apache',  label: 'apache2/access', icon: 'ph-globe',           color: '#00F0FF', path: '/var/log/apache2/access.log' },
  { id: 'fail2ban',label: 'fail2ban.log',   icon: 'ph-prohibit',        color: '#FF003C', path: '/var/log/fail2ban.log' },
];

const LEVELS = ['ALL', 'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'];

const LEVEL_META = {
  CRITICAL: { color: '#FF003C', bg: 'bg-[#FF003C]/10', border: 'border-[#FF003C]/40' },
  ERROR:    { color: '#FF6B00', bg: 'bg-[#FF6B00]/10', border: 'border-[#FF6B00]/40' },
  WARNING:  { color: '#FFEA00', bg: 'bg-[#FFEA00]/10', border: 'border-[#FFEA00]/40' },
  INFO:     { color: '#00F0FF', bg: 'bg-[#00F0FF]/10', border: 'border-[#00F0FF]/40' },
  DEBUG:    { color: '#94A3B8', bg: 'bg-[#94A3B8]/10', border: 'border-[#94A3B8]/40' },
};

// ── Synthetic log generator ───────────────────────────────────────────────────
const LOG_TEMPLATES = {
  auth: [
    { level: 'INFO',     msg: 'sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2' },
    { level: 'WARNING',  msg: 'sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2' },
    { level: 'CRITICAL', msg: 'sshd[{pid}]: Failed password for root from {ip} port {port} ssh2 (attempt {n})' },
    { level: 'INFO',     msg: 'sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash' },
    { level: 'WARNING',  msg: 'pam_unix(sshd:auth): authentication failure; user={user} rhost={ip}' },
    { level: 'ERROR',    msg: 'sshd[{pid}]: error: maximum authentication attempts exceeded for {user} from {ip}' },
    { level: 'INFO',     msg: 'pam_unix(sshd:session): session opened for user {user} by (uid=0)' },
    { level: 'CRITICAL', msg: 'su: FAILED su for root by {user}' },
  ],
  syslog: [
    { level: 'INFO',    msg: 'systemd[1]: Started Session {n} of user {user}.' },
    { level: 'INFO',    msg: 'kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=22' },
    { level: 'WARNING', msg: 'systemd[1]: Unit ssh.service entered failed state.' },
    { level: 'INFO',    msg: 'CRON[{pid}]: (root) CMD (/usr/lib/cron/run-crons)' },
    { level: 'ERROR',   msg: 'kernel: EXT4-fs error (device sda1): ext4_find_entry:1455' },
    { level: 'DEBUG',   msg: 'NetworkManager[{pid}]: <info> device (eth0): state change: activated' },
    { level: 'WARNING', msg: 'rsyslogd: imuxsock lost {n} messages due to rate-limiting' },
  ],
  kern: [
    { level: 'INFO',     msg: 'kernel: [UFW ALLOW] IN=lo OUT= SRC=127.0.0.1 DST=127.0.0.1 PROTO=TCP' },
    { level: 'WARNING',  msg: 'kernel: possible SYN flooding on port 22. Sending cookies.' },
    { level: 'CRITICAL', msg: 'kernel: Out of memory: Kill process {pid} ({user}) score {n} or sacrifice child' },
    { level: 'ERROR',    msg: 'kernel: ACPI Error: AE_NOT_FOUND, While evaluating Sleep State' },
    { level: 'DEBUG',    msg: 'kernel: audit: type=1400 audit({ts}): apparmor="ALLOWED" operation="open"' },
  ],
  audit: [
    { level: 'WARNING',  msg: 'type=SYSCALL msg=audit({ts}): arch=c000003e syscall=59 exe="/bin/bash" key="exec"' },
    { level: 'CRITICAL', msg: 'type=USER_AUTH msg=audit({ts}): pid={pid} uid=0 auid=1000 res=failed' },
    { level: 'WARNING',  msg: 'type=OPEN msg=audit({ts}): pid={pid} uid=1000 path="/etc/shadow" flags=O_RDONLY' },
    { level: 'INFO',     msg: 'type=LOGIN msg=audit({ts}): pid={pid} uid=0 old-auid=4294967295 auid=1000' },
    { level: 'CRITICAL', msg: 'type=EXECVE msg=audit({ts}): argc=3 a0="rm" a1="-rf" a2="/var/log"' },
    { level: 'ERROR',    msg: 'type=AVC msg=audit({ts}): apparmor="DENIED" operation="exec" name="/usr/bin/python3"' },
  ],
  cron: [
    { level: 'INFO',    msg: 'cron[{pid}]: (root) CMD (run-parts /etc/cron.hourly)' },
    { level: 'INFO',    msg: 'cron[{pid}]: ({user}) CMD (/usr/bin/python3 /opt/backup.py)' },
    { level: 'WARNING', msg: 'cron[{pid}]: ({user}) MAIL (mailed {n} bytes of output but got status 0x0001)' },
    { level: 'ERROR',   msg: 'cron[{pid}]: (CRON) error (grandchild #{n} failed with exit status 1)' },
  ],
  dpkg: [
    { level: 'INFO',    msg: 'status installed openssh-server:{arch} 1:8.9p1-3ubuntu0.6' },
    { level: 'INFO',    msg: 'configure libssl3:amd64 3.0.2-0ubuntu1.15 <none>' },
    { level: 'WARNING', msg: 'trigproc man-db:amd64 2.10.2-1 <none> -- triggered' },
    { level: 'ERROR',   msg: 'status half-configured python3-pip:all 22.0.2+dfsg-1 -- dependency problem' },
  ],
  apache: [
    { level: 'INFO',    msg: '{ip} - - [{ts}] "GET /index.html HTTP/1.1" 200 1234' },
    { level: 'WARNING', msg: '{ip} - - [{ts}] "GET /wp-admin HTTP/1.1" 404 512' },
    { level: 'ERROR',   msg: '{ip} - - [{ts}] "POST /login HTTP/1.1" 401 256 (brute force suspected)' },
    { level: 'CRITICAL',msg: '{ip} - - [{ts}] "GET /../../../etc/passwd HTTP/1.1" 400 0 (path traversal)' },
  ],
  fail2ban: [
    { level: 'INFO',     msg: 'fail2ban.filter [WARNING]: Found {ip} - {ts}' },
    { level: 'WARNING',  msg: 'fail2ban.actions: Ban {ip}' },
    { level: 'INFO',     msg: 'fail2ban.actions: Unban {ip}' },
    { level: 'CRITICAL', msg: 'fail2ban.filter [WARNING]: {ip} already banned — repeated offender' },
  ],
};

const USERS = ['root', 'admin', 'deploy', 'www-data', 'ubuntu', 'user01', 'svc_backup'];
const ARCHS  = ['amd64', 'i386', 'arm64'];

function rnd(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randIp() { return `${rnd(1,254)}.${rnd(1,254)}.${rnd(1,254)}.${rnd(1,254)}`; }
function randPid() { return rnd(1000, 65000); }
function randUser() { return USERS[rnd(0, USERS.length - 1)]; }
function fmtTs(d) {
  return d.toLocaleString('en-GB', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit', second:'2-digit' }).replace(',','');
}

let _idCounter = 1;
function generateLog(sourceId, overrideLevel) {
  const templates = LOG_TEMPLATES[sourceId] || LOG_TEMPLATES.syslog;
  const tpl = templates[rnd(0, templates.length - 1)];
  const now = new Date(Date.now() - rnd(0, 3600000));
  const msg = tpl.msg
    .replace(/{pid}/g, randPid())
    .replace(/{ip}/g, randIp())
    .replace(/{user}/g, randUser())
    .replace(/{port}/g, rnd(1024, 65535))
    .replace(/{n}/g, rnd(1, 99))
    .replace(/{ts}/g, `${Math.floor(now.getTime()/1000)}.${rnd(100,999)}`)
    .replace(/{arch}/g, ARCHS[rnd(0, 2)]);
  const src = LOG_SOURCES.find(s => s.id === sourceId);
  return {
    id: _idCounter++,
    ts: now,
    tsStr: fmtTs(now),
    source: sourceId,
    sourcePath: src?.path || '/var/log/syslog',
    level: overrideLevel || tpl.level,
    msg,
    pid: randPid(),
    host: 'traceshield-node-01',
  };
}

function generateBatch(sourceId, count = 80) {
  return Array.from({ length: count }, () => generateLog(sourceId))
    .sort((a, b) => b.ts - a.ts);
}

// ── Component ─────────────────────────────────────────────────────────────────
export default function DataLogsPage() {
  const [activeSource, setActiveSource]   = useState('auth');
  const [logs, setLogs]                   = useState(() => generateBatch('auth'));
  const [levelFilter, setLevelFilter]     = useState('ALL');
  const [search, setSearch]               = useState('');
  const [selectedLog, setSelectedLog]     = useState(null);
  const [liveMode, setLiveMode]           = useState(true);
  const [sourceCounts, setSourceCounts]   = useState({});
  const tableRef = useRef(null);

  // Generate counts per source
  useEffect(() => {
    const counts = {};
    LOG_SOURCES.forEach(s => {
      counts[s.id] = { total: rnd(120, 4000), critical: rnd(0, 12), error: rnd(0, 30) };
    });
    setSourceCounts(counts);
  }, []);

  // Switch source
  useEffect(() => {
    setLogs(generateBatch(activeSource, 80));
    setSelectedLog(null);
    setLevelFilter('ALL');
    setSearch('');
  }, [activeSource]);

  // Live mode — append a new log every 2s
  useEffect(() => {
    if (!liveMode) return;
    const interval = setInterval(() => {
      setLogs(prev => {
        const newLog = generateLog(activeSource);
        return [newLog, ...prev].slice(0, 200);
      });
    }, 2000);
    return () => clearInterval(interval);
  }, [liveMode, activeSource]);

  const filtered = logs.filter(l => {
    if (levelFilter !== 'ALL' && l.level !== levelFilter) return false;
    if (search && !l.msg.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const critCount = filtered.filter(l => l.level === 'CRITICAL').length;
  const errCount  = filtered.filter(l => l.level === 'ERROR').length;
  const warnCount = filtered.filter(l => l.level === 'WARNING').length;

  const src = LOG_SOURCES.find(s => s.id === activeSource);

  return (
    <div className="animate-fadeIn flex flex-col gap-0 h-full" style={{ minHeight: '80vh' }}>
      {/* Log file upload panel */}
      <LogUploadPanel />

      {/* Page header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-6 border-b border-[#1E2D4A]/50 mb-6">
        <div>
          <h2 className="text-4xl font-bold text-white tracking-tight font-['Rajdhani'] uppercase">
            System <span className="text-[#39FF14]">Event Viewer</span>
          </h2>
          <p className="text-[#94A3B8] mt-1 mono-text text-sm">Linux log inspector — /var/log/* · Real-time stream</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={() => setLogs(generateBatch(activeSource, 80))}
            className="cyber-btn h-9 px-4 text-[11px]">
            <i className="ph ph-arrows-clockwise text-sm" /> Refresh
          </button>
          <button onClick={() => setLiveMode(v => !v)}
            className={`cyber-btn h-9 px-4 text-[11px] ${liveMode ? 'border-[#39FF14] text-[#39FF14]' : ''}`}>
            <i className={`ph ${liveMode ? 'ph-broadcast' : 'ph-antenna-off'} text-sm`} />
            {liveMode ? 'Live: ON' : 'Live: OFF'}
          </button>
        </div>
      </div>

      <div className="flex gap-4 flex-1 min-h-0" style={{ height: 'calc(100vh - 260px)' }}>

        {/* Left panel — log sources (like Windows Event Viewer tree) */}
        <div className="w-52 flex-shrink-0 bg-[#0D1323] border border-[#1E2D4A] rounded-xl overflow-hidden flex flex-col">
          <div className="px-3 py-2.5 border-b border-[#1E2D4A] bg-[#070B14]">
            <span className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Log Sources</span>
          </div>
          <div className="flex-1 overflow-y-auto py-1">
            {LOG_SOURCES.map(s => {
              const counts = sourceCounts[s.id] || {};
              const isActive = activeSource === s.id;
              return (
                <button key={s.id} onClick={() => setActiveSource(s.id)}
                  className={`w-full flex items-center gap-2.5 px-3 py-2.5 text-left transition-all group
                    ${isActive ? 'bg-[#00F0FF]/10 border-l-2 border-[#00F0FF]' : 'border-l-2 border-transparent hover:bg-[#121A2F]'}`}>
                  <i className={`ph ${s.icon} text-base flex-shrink-0`} style={{ color: isActive ? s.color : '#94A3B8' }} />
                  <div className="flex-1 min-w-0">
                    <div className={`text-[11px] font-bold mono-text truncate ${isActive ? 'text-white' : 'text-[#94A3B8] group-hover:text-white'}`}>
                      {s.label}
                    </div>
                    {counts.critical > 0 && (
                      <div className="text-[8px] text-[#FF003C] mono-text">{counts.critical} critical</div>
                    )}
                  </div>
                  {counts.critical > 0 && (
                    <div className="w-1.5 h-1.5 rounded-full bg-[#FF003C] flex-shrink-0 animate-pulse" />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Main area */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">

          {/* Toolbar */}
          <div className="flex flex-wrap items-center gap-3 bg-[#0D1323] border border-[#1E2D4A] rounded-xl px-4 py-3">
            {/* Source path */}
            <div className="flex items-center gap-2 mr-2">
              <i className={`ph ${src?.icon} text-sm`} style={{ color: src?.color }} />
              <code className="text-[10px] mono-text text-[#94A3B8]">{src?.path}</code>
            </div>
            <div className="w-px h-5 bg-[#1E2D4A]" />
            {/* Level filter */}
            <div className="flex gap-1">
              {LEVELS.map(l => {
                const meta = LEVEL_META[l] || {};
                const isActive = levelFilter === l;
                return (
                  <button key={l} onClick={() => setLevelFilter(l)}
                    className={`text-[9px] font-bold mono-text px-2.5 py-1 rounded border transition-all
                      ${isActive
                        ? `${meta.bg || 'bg-[#00F0FF]/10'} ${meta.border || 'border-[#00F0FF]/40'}`
                        : 'border-[#1E2D4A] text-[#94A3B8] hover:border-[#1E2D4A] hover:text-white'}`}
                    style={isActive && meta.color ? { color: meta.color } : {}}>
                    {l}
                  </button>
                );
              })}
            </div>
            <div className="w-px h-5 bg-[#1E2D4A]" />
            {/* Search */}
            <div className="flex items-center gap-2 bg-[#070B14] border border-[#1E2D4A] rounded px-3 py-1.5 flex-1 min-w-[160px]">
              <i className="ph ph-magnifying-glass text-[#94A3B8] text-sm" />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Filter logs..."
                className="bg-transparent text-[11px] text-white mono-text outline-none w-full placeholder-[#94A3B8]/50" />
              {search && <button onClick={() => setSearch('')}><i className="ph ph-x text-[#94A3B8] text-xs" /></button>}
            </div>
            {/* Stats */}
            <div className="flex gap-3 ml-auto">
              {critCount > 0 && <span className="text-[9px] font-bold text-[#FF003C] mono-text">{critCount} CRIT</span>}
              {errCount  > 0 && <span className="text-[9px] font-bold text-[#FF6B00] mono-text">{errCount} ERR</span>}
              {warnCount > 0 && <span className="text-[9px] font-bold text-[#FFEA00] mono-text">{warnCount} WARN</span>}
              <span className="text-[9px] text-[#94A3B8] mono-text">{filtered.length} events</span>
            </div>
          </div>

          {/* Log table + detail pane */}
          <div className="flex-1 flex gap-3 min-h-0">

            {/* Log table */}
            <div className={`flex flex-col bg-[#070B14] border border-[#1E2D4A] rounded-xl overflow-hidden transition-all ${selectedLog ? 'w-[55%]' : 'w-full'}`}>
              {/* Table header */}
              <div className="grid gap-2 px-4 py-2 border-b border-[#1E2D4A] bg-[#0D1323] flex-shrink-0"
                style={{ gridTemplateColumns: '90px 70px 1fr 60px' }}>
                {['Timestamp', 'Level', 'Message', 'PID'].map(h => (
                  <span key={h} className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">{h}</span>
                ))}
              </div>
              {/* Rows */}
              <div ref={tableRef} className="flex-1 overflow-y-auto divide-y divide-[#1E2D4A]/30">
                {filtered.length === 0 ? (
                  <div className="flex items-center justify-center py-20 text-[#94A3B8] mono-text text-sm">
                    No events match the current filter
                  </div>
                ) : filtered.map(log => {
                  const meta = LEVEL_META[log.level] || LEVEL_META.DEBUG;
                  const isSelected = selectedLog?.id === log.id;
                  return (
                    <div key={log.id} onClick={() => setSelectedLog(isSelected ? null : log)}
                      className={`grid gap-2 px-4 py-2 cursor-pointer transition-colors group
                        ${isSelected ? 'bg-[#00F0FF]/5 border-l-2 border-[#00F0FF]' : 'hover:bg-[#121A2F] border-l-2 border-transparent'}`}
                      style={{ gridTemplateColumns: '90px 70px 1fr 60px' }}>
                      <span className="text-[9px] text-[#94A3B8] mono-text truncate">{log.tsStr}</span>
                      <span className={`text-[9px] font-bold mono-text px-1.5 py-0.5 rounded border w-fit h-fit ${meta.bg} ${meta.border}`}
                        style={{ color: meta.color }}>{log.level}</span>
                      <span className="text-[10px] text-[#E2E8F0] mono-text truncate">{log.msg}</span>
                      <span className="text-[9px] text-[#94A3B8] mono-text">{log.pid}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Detail pane — like Windows Event Viewer bottom panel */}
            {selectedLog && (
              <div className="w-[45%] flex-shrink-0 bg-[#0D1323] border border-[#1E2D4A] rounded-xl overflow-hidden flex flex-col">
                <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#1E2D4A] bg-[#070B14] flex-shrink-0">
                  <span className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Event Detail</span>
                  <button onClick={() => setSelectedLog(null)} className="text-[#94A3B8] hover:text-white transition-colors">
                    <i className="ph ph-x text-sm" />
                  </button>
                </div>
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                  {/* Level badge */}
                  {(() => {
                    const meta = LEVEL_META[selectedLog.level] || LEVEL_META.DEBUG;
                    return (
                      <div className={`flex items-center gap-3 p-3 rounded-lg border ${meta.bg} ${meta.border}`}>
                        <i className={`ph ${selectedLog.level === 'CRITICAL' ? 'ph-warning-octagon animate-pulse' : selectedLog.level === 'ERROR' ? 'ph-x-circle' : selectedLog.level === 'WARNING' ? 'ph-warning' : 'ph-info'} text-xl`}
                          style={{ color: meta.color }} />
                        <div>
                          <div className="text-[11px] font-bold mono-text uppercase" style={{ color: meta.color }}>{selectedLog.level}</div>
                          <div className="text-[9px] text-[#94A3B8] mono-text">{selectedLog.tsStr}</div>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Fields */}
                  {[
                    { label: 'Source',    value: selectedLog.sourcePath },
                    { label: 'Host',      value: selectedLog.host },
                    { label: 'PID',       value: selectedLog.pid },
                    { label: 'Event ID',  value: `EVT-${String(selectedLog.id).padStart(6,'0')}` },
                  ].map(f => (
                    <div key={f.label} className="flex flex-col gap-0.5">
                      <span className="text-[8px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">{f.label}</span>
                      <span className="text-[11px] text-white mono-text">{f.value}</span>
                    </div>
                  ))}

                  {/* Full message */}
                  <div className="flex flex-col gap-1.5">
                    <span className="text-[8px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Full Message</span>
                    <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg p-3">
                      <code className="text-[10px] text-[#B026FF] mono-text break-all leading-relaxed whitespace-pre-wrap">
                        {selectedLog.msg}
                      </code>
                    </div>
                  </div>

                  {/* Raw log line */}
                  <div className="flex flex-col gap-1.5">
                    <span className="text-[8px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Raw Entry</span>
                    <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg p-3">
                      <code className="text-[9px] text-[#39FF14] mono-text break-all leading-relaxed">
                        {selectedLog.tsStr} {selectedLog.host} {selectedLog.msg}
                      </code>
                    </div>
                  </div>

                  {/* Threat note for critical/error */}
                  {(selectedLog.level === 'CRITICAL' || selectedLog.level === 'ERROR') && (
                    <div className="flex items-start gap-3 bg-[#FF003C]/10 border border-[#FF003C]/30 rounded-lg p-3">
                      <i className="ph ph-shield-warning text-[#FF003C] text-lg flex-shrink-0 mt-0.5" />
                      <div>
                        <div className="text-[10px] font-bold text-[#FF003C] mono-text uppercase mb-1">Threat Indicator</div>
                        <p className="text-[10px] text-[#94A3B8] leading-relaxed">
                          {selectedLog.level === 'CRITICAL'
                            ? 'This event indicates a high-severity security incident. Immediate investigation recommended — correlate with auth.log and audit.log for full attack chain.'
                            : 'Error-level event detected. May indicate service disruption or failed attack attempt. Review surrounding log context.'}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
