"""
build_dataset.py — Convert linux-logs-70-privOnly-log.txt into intrusion_data.csv
Run once: python build_dataset.py
"""
import csv, re, random, os

LOG_FILE = "backend/data/linux-logs-70-privOnly-log.txt"
OUT_FILE = "backend/data/intrusion_data.csv"

ACTORS = {
    "mayur":    {"ip": "10.0.1.42",  "rep": 0.82},
    "ubuntu":   {"ip": "10.0.1.55",  "rep": 0.91},
    "deploy":   {"ip": "10.0.1.67",  "rep": 0.88},
    "admin":    {"ip": "10.0.1.23",  "rep": 0.75},
    "www-data": {"ip": "10.0.1.88",  "rep": 0.70},
    "root":     {"ip": "127.0.0.1",  "rep": 0.10},
}

RE_SUDO_ACTOR  = re.compile(r'sudo\s*:\s*([a-zA-Z0-9_\-]+)\s*:', re.I)
RE_PAM_ACTOR   = re.compile(r'session opened for user root by ([a-zA-Z0-9_\-]+)\(', re.I)
RE_PRIV_ESC    = re.compile(
    r'COMMAND=/bin/bash|COMMAND=/bin/sh'
    r'|session opened for user root'
    r'|incorrect password attempt', re.I)
RE_SUDO        = re.compile(r'sudo\s*:.*COMMAND=', re.I)
RE_FAILED      = re.compile(r'Failed password|authentication failure|incorrect password', re.I)
RE_SUCCESS     = re.compile(r'session opened for user|Accepted password', re.I)
RE_TIMESTAMP   = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')

with open(LOG_FILE) as f:
    lines = [l.strip() for l in f if l.strip()]

rows = []
for line in lines:
    # Determine actor
    actor = None
    m = RE_SUDO_ACTOR.search(line)
    if m and m.group(1).lower() not in ('pam_unix','pam','session'):
        actor = m.group(1).lower()
    if not actor:
        m = RE_PAM_ACTOR.search(line)
        if m:
            actor = m.group(1).lower()

    info = ACTORS.get(actor, {"ip": f"10.0.{random.randint(2,9)}.{random.randint(1,254)}", "rep": round(random.uniform(0.1, 0.5), 2)})

    priv_esc   = 1 if RE_PRIV_ESC.search(line) else 0
    sudo_att   = 1 if RE_SUDO.search(line) else 0
    failed     = 1 if RE_FAILED.search(line) else 0
    success    = 1 if RE_SUCCESS.search(line) else 0

    # Derive attack name
    if "COMMAND=/bin/bash" in line or "COMMAND=/bin/sh" in line:
        name = "Privilege Escalation"
        attack_detected = 1
    elif "session opened for user root" in line:
        name = "Root Session Opened"
        attack_detected = 1
    elif "incorrect password" in line.lower():
        name = "Failed Sudo Attempt"
        attack_detected = 1
    elif sudo_att:
        name = "Sudo Command"
        attack_detected = 0
    elif failed:
        name = "Failed Login"
        attack_detected = 1
    elif success:
        name = "Successful Login"
        attack_detected = 0
    else:
        name = "System Event"
        attack_detected = 0

    # Derive numeric features
    login_attempts   = (2 if sudo_att else 0) + (failed * 3) + (1 if success else 0)
    failed_logins    = failed * 2 + (1 if "incorrect password" in line.lower() else 0)
    session_duration = 600 if priv_esc else (120 if sudo_att else random.randint(10, 180))
    unusual_time     = 1 if priv_esc else 0
    ip_rep           = info["rep"] if attack_detected else round(random.uniform(0.05, 0.3), 2)
    traffic          = random.randint(80000, 200000) if priv_esc else random.randint(500, 5000)
    packet_size      = random.randint(512, 2048) if priv_esc else random.randint(64, 512)

    ts_m = RE_TIMESTAMP.match(line)
    timestamp = ts_m.group(1) if ts_m else "Apr 11 00:00:00"

    rows.append({
        "src_ip":                 info["ip"],
        "name":                   name,
        "protocol_type":          "TCP",
        "login_attempts":         login_attempts,
        "failed_logins":          failed_logins,
        "session_duration":       session_duration,
        "ip_reputation_score":    ip_rep,
        "unusual_time_access":    unusual_time,
        "network_traffic_volume": traffic,
        "network_packet_size":    packet_size,
        "attack_detected":        attack_detected,
        "privilege_escalation":   priv_esc,
        "sudo_attempt":           sudo_att,
        "actor":                  actor or "system",
        "raw_log":                line,
        "log_timestamp":          timestamp,
    })

os.makedirs("backend/data", exist_ok=True)
with open(OUT_FILE, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print(f"Written {len(rows)} rows to {OUT_FILE}")
attacks = sum(1 for r in rows if r["attack_detected"])
priv    = sum(1 for r in rows if r["privilege_escalation"])
print(f"  attack_detected={attacks}, privilege_escalation={priv}")
