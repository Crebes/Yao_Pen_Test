#!/usr/bin/env python3
"""
Yao Pentest Wizard — Live Dashboard Server
Serves the dashboard UI and proxies status/log data from the active batch run.
Usage: python3 dashboard.py [port]   (default port 8888)
"""
import json, os, glob, sys, re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8888

def find_active_batch():
    """Return the most recently modified batch directory."""
    dirs = sorted(glob.glob(os.path.join(BASE, "batch_*")), key=os.path.getmtime, reverse=True)
    return dirs[0] if dirs else None

def get_status():
    batch_dir = find_active_batch()
    if not batch_dir:
        return {"error": "No batch run found. Start a scan first."}
    status_file = os.path.join(batch_dir, "status.json")
    if os.path.exists(status_file):
        try:
            return json.load(open(status_file))
        except Exception:
            pass
    # Reconstruct status from checkpoint + scan dirs if status.json missing
    return reconstruct_status(batch_dir)

def reconstruct_status(batch_dir):
    """Build status from checkpoint.json and scan output directories."""
    targets_file = os.path.join(BASE, "targets.json")
    try:
        targets = json.load(open(targets_file))["targets"]
    except Exception:
        return {"error": "Could not load targets.json"}

    checkpoint = []
    cp_file = os.path.join(batch_dir, "checkpoint.json")
    if os.path.exists(cp_file):
        try:
            checkpoint = json.load(open(cp_file)).get("completed", [])
        except Exception:
            pass

    complete = os.path.exists(os.path.join(batch_dir, "batch_complete"))
    target_states = []
    running_idx = None

    for i, t in enumerate(targets):
        url = t["url"]
        host = url.replace("https://","").replace("http://","")
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", host)

        # Find most recent scan dir for this target
        scan_dirs = sorted(glob.glob(os.path.join(BASE, f"pentest_{safe}_*")),
                           key=os.path.getmtime, reverse=True)
        scan_dir  = scan_dirs[0] if scan_dirs else None

        # Determine status
        if url in checkpoint:
            nmap_txt = os.path.join(scan_dir, "nmap.txt") if scan_dir else None
            if nmap_txt and os.path.exists(nmap_txt):
                txt = open(nmap_txt).read()
                if "503" in txt:
                    status = "offline"
                elif "Failed to resolve" in txt or "0 hosts up" in txt:
                    status = "unreachable"
                else:
                    status = "complete"
            else:
                status = "complete"
        else:
            status = "running" if not complete else "queued"
            if status == "running" and running_idx is None:
                running_idx = i

        # Read findings from summary.json
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        grade = None
        report_path = None
        if scan_dir and os.path.exists(os.path.join(scan_dir, "summary.json")):
            try:
                s = json.load(open(os.path.join(scan_dir, "summary.json")))
                counts = s.get("findings_by_severity", counts)
            except Exception:
                pass
            rp = os.path.join(scan_dir, "report.html")
            if os.path.exists(rp):
                report_path = rp
                # Grade
                nc, nh = counts.get("CRITICAL",0), counts.get("HIGH",0)
                risk = nc*10+nh*5+counts.get("MEDIUM",0)*2+counts.get("LOW",0)
                if nc>=2: grade="F"
                elif nc==1: grade="D"
                elif nh>=3: grade="C"
                elif nh>=1: grade="B"
                elif risk>0: grade="B+"
                else: grade="A"

        target_states.append({
            "idx": i+1, "url": url, "mode": t["mode"],
            "notes": t.get("notes",""), "status": status,
            "scan_dir": scan_dir or "",
            "report_path": report_path or "",
            "counts": counts, "grade": grade,
        })

    # Detect current module from log
    current_module = ""
    log_file = "/tmp/batch-master.log"
    if os.path.exists(log_file):
        try:
            lines = open(log_file).readlines()
            for line in reversed(lines[-50:]):
                m = re.search(r"▶\s+(.+?)\s+\[", line)
                if m:
                    current_module = m.group(1).strip()
                    break
        except Exception:
            pass

    done_count = sum(1 for t in target_states if t["status"] in ("complete","offline","unreachable"))
    current = next((t for t in target_states if t["status"]=="running"), None)

    return {
        "batch_dir": batch_dir,
        "complete": complete,
        "total": len(targets),
        "done": done_count,
        "current_url": current["url"] if current else "",
        "current_module": current_module,
        "targets": target_states,
    }

def get_log_tail(lines=80):
    log_file = "/tmp/batch-master.log"
    if not os.path.exists(log_file):
        return "Log file not found. Batch may not be running."
    try:
        all_lines = open(log_file, errors="replace").readlines()
        tail = all_lines[-lines:]
        # Strip ANSI colour codes
        ansi = re.compile(r'\x1b\[[0-9;]*[mK]|\x1b\]|\x0f|\r')
        return "".join(ansi.sub("", l) for l in tail)
    except Exception as e:
        return f"Error reading log: {e}"

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Yao Pentest — Live Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#0f1923;color:#e2e8f0;font-size:14px}
  .tabs{display:flex;gap:0;background:#0a1520;border-bottom:1px solid #1e3a5f}
  .tab{padding:10px 24px;cursor:pointer;font-size:0.85em;font-weight:600;color:#4a7a9b;border-bottom:3px solid transparent;transition:all 0.2s}
  .tab.active{color:#64c8ff;border-bottom-color:#64c8ff}
  .tab:hover{color:#e2e8f0}
  .tab-content{display:none}.tab-content.active{display:block}
  .setup-con{padding:24px 32px;max-width:800px}
  .setup-card{background:#1a2a3a;border-radius:10px;padding:20px 24px;margin-bottom:16px;border:1px solid #1e3a5f}
  .setup-card h3{font-size:1em;font-weight:700;color:#fff;margin-bottom:8px}
  .setup-card p{color:#8fb3c8;font-size:0.88em;line-height:1.6;margin-bottom:14px}
  .btn{display:inline-flex;align-items:center;gap:8px;padding:10px 22px;border-radius:8px;font-size:0.88em;font-weight:700;cursor:pointer;border:none;transition:all 0.2s}
  .btn-primary{background:#2980b9;color:#fff}.btn-primary:hover{background:#3498db}
  .btn-success{background:#27ae60;color:#fff}.btn-success:hover{background:#2ecc71}
  .btn-danger{background:#c0392b;color:#fff}.btn-danger:hover{background:#e74c3c}
  .btn:disabled{opacity:0.5;cursor:not-allowed}
  .tool-status{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-top:12px}
  .tool-item{background:#0f2030;border-radius:6px;padding:8px 12px;font-size:0.82em;display:flex;align-items:center;gap:8px}
  .tool-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
  .dot-ok{background:#27ae60}.dot-missing{background:#e74c3c}.dot-unknown{background:#555}
  .install-log{background:#0a1520;border-radius:6px;padding:12px;font-family:monospace;font-size:0.75em;color:#8fb3c8;max-height:200px;overflow-y:auto;margin-top:12px;white-space:pre-wrap;display:none}
  .scan-form{display:flex;flex-direction:column;gap:12px}
  .form-row{display:flex;gap:12px;flex-wrap:wrap}
  .form-group{display:flex;flex-direction:column;gap:4px;flex:1;min-width:200px}
  .form-group label{font-size:0.78em;font-weight:600;color:#64a6d6;text-transform:uppercase;letter-spacing:0.5px}
  .form-group input,.form-group select{background:#0f2030;border:1px solid #1e3a5f;border-radius:6px;padding:8px 12px;color:#e2e8f0;font-size:0.88em;outline:none}
  .form-group input:focus,.form-group select:focus{border-color:#2980b9}
  .form-group input::placeholder{color:#4a7a9b}
  .hdr{background:linear-gradient(135deg,#1a2a3a,#0f3460);padding:20px 32px;border-bottom:1px solid #1e3a5f;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
  .hdr h1{font-size:1.3em;font-weight:700;color:#fff}
  .hdr .sub{color:#64a6d6;font-size:0.82em;margin-top:2px}
  .tick{font-size:0.75em;color:#4a7a9b;margin-top:4px}
  .overall{background:#1a2a3a;padding:16px 32px;border-bottom:1px solid #1e3a5f}
  .prog-bar{height:8px;background:#0f2030;border-radius:4px;overflow:hidden;margin-top:8px}
  .prog-fill{height:100%;background:linear-gradient(90deg,#2ecc71,#27ae60);border-radius:4px;transition:width 0.5s ease}
  .prog-label{font-size:0.8em;color:#64a6d6;margin-top:4px}
  .current-scan{background:#1e3a5f;border-radius:6px;padding:10px 16px;margin-top:10px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  .spinner{width:16px;height:16px;border:2px solid #4a7a9b;border-top-color:#64c8ff;border-radius:50%;animation:spin 0.8s linear infinite;flex-shrink:0}
  @keyframes spin{to{transform:rotate(360deg)}}
  .con{padding:20px 32px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}
  .card{background:#1a2a3a;border-radius:10px;padding:16px;border:1px solid #1e3a5f;transition:border-color 0.3s}
  .card.running{border-color:#3498db;box-shadow:0 0 12px rgba(52,152,219,0.2)}
  .card.complete{border-color:#27ae60}
  .card.offline{border-color:#8e44ad}
  .card.unreachable{border-color:#555}
  .card-header{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .badge{padding:2px 9px;border-radius:10px;font-size:0.72em;font-weight:700;white-space:nowrap}
  .badge-running{background:#3498db;color:#fff;animation:pulse 1.5s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.6}}
  .badge-complete{background:#27ae60;color:#fff}
  .badge-offline{background:#8e44ad;color:#fff}
  .badge-unreachable{background:#555;color:#ccc}
  .badge-queued{background:#2c3e50;color:#888}
  .badge-skipped{background:#27ae60;color:#fff;opacity:0.7}
  .badge-mode-staging{background:#b45309;color:#fff}
  .badge-mode-production{background:#1a7a4a;color:#fff}
  .url{font-weight:600;color:#e2e8f0;font-size:0.88em;margin-top:8px;word-break:break-all}
  .counts{display:flex;gap:10px;margin-top:10px;flex-wrap:wrap}
  .count{text-align:center}
  .count .n{font-size:1.3em;font-weight:800}
  .count .l{font-size:0.65em;font-weight:700;text-transform:uppercase}
  .grade-pill{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1em;font-weight:900;color:#fff;flex-shrink:0}
  .module-row{margin-top:10px;font-size:0.8em;color:#64a6d6;display:flex;align-items:center;gap:6px}
  .report-link{display:inline-block;margin-top:10px;font-size:0.8em;color:#3498db;text-decoration:none;border:1px solid #3498db;padding:3px 10px;border-radius:6px}
  .report-link:hover{background:#3498db;color:#fff}
  .log-section{margin-top:24px;background:#0a1520;border-radius:10px;border:1px solid #1e3a5f;overflow:hidden}
  .log-header{background:#1a2a3a;padding:10px 16px;font-size:0.8em;font-weight:700;color:#64a6d6;display:flex;justify-content:space-between;align-items:center}
  .log-body{padding:12px 16px;font-family:'Courier New',monospace;font-size:0.75em;color:#8fb3c8;max-height:300px;overflow-y:auto;white-space:pre-wrap;word-break:break-word;line-height:1.5}
  .complete-banner{background:#1a4a2e;border:1px solid #27ae60;border-radius:8px;padding:14px 20px;margin-bottom:20px;color:#2ecc71;font-weight:700;font-size:1.05em}
</style>
</head>
<body>

<div class="hdr">
  <div>
    <h1>&#x1F6E1; Yao Pentest Wizard — Live Dashboard</h1>
    <div class="sub" id="batch-dir">Loading...</div>
    <div class="tick" id="last-tick">Connecting...</div>
  </div>
  <div style="text-align:right;">
    <div style="font-size:1.8em;font-weight:800;color:#2ecc71;" id="done-count">—</div>
    <div style="font-size:0.72em;color:#64a6d6;" id="done-label">of — targets</div>
  </div>
</div>

<div class="tabs">
  <div class="tab active" onclick="showTab('scan')">&#x1F4CA; Scan Progress</div>
  <div class="tab" onclick="showTab('setup')">&#x2699;&#xFE0F; Setup &amp; Tools</div>
</div>

<div id="tab-scan" class="tab-content active">
<div class="overall">
  <div class="prog-bar"><div class="prog-fill" id="prog-fill" style="width:0%"></div></div>
  <div class="prog-label" id="prog-label">Starting...</div>
  <div class="current-scan" id="current-scan" style="display:none;">
    <div class="spinner"></div>
    <div>
      <div style="font-size:0.82em;font-weight:700;color:#64c8ff;" id="current-url"></div>
      <div style="font-size:0.75em;color:#4a7a9b;margin-top:2px;" id="current-module"></div>
    </div>
  </div>
</div>

<div class="con">
  <div id="complete-banner" style="display:none;" class="complete-banner">
    &#x2705; Batch scan complete — all targets processed.
  </div>
  <div class="grid" id="grid"></div>
  <div class="log-section">
    <div class="log-header">
      <span>&#x1F4CB; Live Log</span>
      <span id="log-status" style="font-weight:400;color:#4a7a9b;">—</span>
    </div>
    <div class="log-body" id="log-body">Waiting for log data...</div>
  </div>
</div>

</div><!-- end tab-scan -->

<div id="tab-setup" class="tab-content">
<div class="setup-con">

  <div class="setup-card">
    <h3>&#x1F527; Tool Status</h3>
    <p>Check which pentest tools are installed in WSL Ubuntu 24.04.</p>
    <button class="btn btn-primary" onclick="checkTools()">&#x1F50D; Check Tools</button>
    <div class="tool-status" id="tool-status"></div>
  </div>

  <div class="setup-card">
    <h3>&#x2B07;&#xFE0F; Install / Update All Tools</h3>
    <p>Installs or updates: nmap, nikto, hydra, ffuf, testssl.sh, jwt_tool inside WSL Ubuntu 24.04.
       Safe to re-run — existing tools are upgraded, not reinstalled from scratch.</p>
    <button class="btn btn-success" id="install-btn" onclick="runInstall()">&#x26A1; Install / Update Tools</button>
    <div class="install-log" id="install-log"></div>
  </div>

  <div class="setup-card">
    <h3>&#x1F680; Run a New Batch Scan</h3>
    <p>Starts a new full batch scan against all targets in targets.json.
       Discovery runs first to pick up any new subdomains.</p>
    <button class="btn btn-primary" onclick="runBatch()">&#x25B6; Start Batch Scan</button>
    <div id="batch-launch-msg" style="margin-top:10px;font-size:0.82em;color:#64a6d6;"></div>
  </div>

  <div class="setup-card">
    <h3>&#x1F310; Quick Single Scan</h3>
    <p>Scan a single target URL immediately.</p>
    <div class="scan-form">
      <div class="form-row">
        <div class="form-group" style="flex:2;">
          <label>Target URL</label>
          <input type="text" id="scan-url" placeholder="https://app.example.com">
        </div>
        <div class="form-group">
          <label>Mode</label>
          <select id="scan-mode">
            <option value="staging">Staging (full + Hydra)</option>
            <option value="production">Production (read-only)</option>
          </select>
        </div>
      </div>
      <div>
        <button class="btn btn-primary" onclick="runSingleScan()">&#x25B6; Scan Now</button>
      </div>
      <div id="single-scan-msg" style="font-size:0.82em;color:#64a6d6;"></div>
    </div>
  </div>

</div>
</div><!-- end tab-setup -->

<script>
function showTab(name) {
  document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".tab").forEach(el => el.classList.remove("active"));
  document.getElementById("tab-"+name).classList.add("active");
  event.target.classList.add("active");
}

async function checkTools() {
  document.getElementById("tool-status").innerHTML = "<div style='color:#4a7a9b;font-size:0.82em;'>Checking...</div>";
  const res  = await fetch("/tools");
  const data = await res.json();
  const html = Object.entries(data).map(([t, path]) => {
    const ok = !!path;
    return `<div class="tool-item">
      <div class="tool-dot ${ok?'dot-ok':'dot-missing'}"></div>
      <div>
        <div style="font-weight:600;color:${ok?'#2ecc71':'#e74c3c'};">${t}</div>
        <div style="color:#4a7a9b;font-size:0.78em;">${path || 'NOT INSTALLED'}</div>
      </div>
    </div>`;
  }).join("");
  document.getElementById("tool-status").innerHTML = html;
}

async function runInstall() {
  const btn = document.getElementById("install-btn");
  const log = document.getElementById("install-log");
  btn.disabled = true; btn.textContent = "Installing...";
  log.style.display = "block"; log.textContent = "Starting installation...\n";
  const res = await fetch("/install", {method:"POST"});
  const reader = res.body.getReader(); const dec = new TextDecoder();
  while(true) {
    const {done, value} = await reader.read();
    if(done) break;
    log.textContent += dec.decode(value);
    log.scrollTop = log.scrollHeight;
  }
  btn.disabled = false; btn.textContent = "&#x26A1; Install / Update Tools";
  checkTools();
}

async function runBatch() {
  const msg = document.getElementById("batch-launch-msg");
  msg.textContent = "Launching batch scan...";
  const res = await fetch("/run-batch", {method:"POST"});
  const data = await res.json();
  msg.textContent = data.message;
  if(data.ok) showTab("scan");
}

async function runSingleScan() {
  const url  = document.getElementById("scan-url").value.trim();
  const mode = document.getElementById("scan-mode").value;
  const msg  = document.getElementById("single-scan-msg");
  if(!url) { msg.textContent = "Please enter a target URL."; return; }
  msg.textContent = "Launching scan...";
  const res  = await fetch("/run-scan", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({url, mode})});
  const data = await res.json();
  msg.textContent = data.message;
}

const GRADE_COLORS = {A:"#27ae60","B+":"#2ecc71",B:"#f39c12",C:"#e67e22",D:"#e74c3c",F:"#c0392b"};
const SEV_COLORS   = {CRITICAL:"#c0392b",HIGH:"#e67e22",MEDIUM:"#d4a017",LOW:"#27ae60",INFO:"#2980b9"};

function gradeColor(g){ return GRADE_COLORS[g] || "#555"; }

function renderCard(t) {
  const statusClass = t.status;
  let badge = "";
  switch(t.status) {
    case "running":     badge=`<span class="badge badge-running">&#9679; RUNNING</span>`; break;
    case "complete":    badge=`<span class="badge badge-complete">&#10003; DONE</span>`; break;
    case "offline":     badge=`<span class="badge badge-offline">&#9679; OFFLINE</span>`; break;
    case "unreachable": badge=`<span class="badge badge-unreachable">UNREACHABLE</span>`; break;
    case "queued":      badge=`<span class="badge badge-queued">QUEUED</span>`; break;
    default:            badge=`<span class="badge badge-skipped">&#10003; SKIPPED</span>`; break;
  }
  const modeBadge = `<span class="badge badge-mode-${t.mode}">${t.mode.toUpperCase()}</span>`;

  let body = `<div class="url">${t.url}</div>`;

  if (t.status === "running") {
    body += `<div class="module-row"><div class="spinner" style="width:12px;height:12px;border-width:2px;"></div><span id="mod-${t.idx}">Scanning...</span></div>`;
  }

  if (t.status === "complete" && t.counts) {
    const c = t.counts;
    const gc = gradeColor(t.grade);
    body += `<div style="display:flex;align-items:center;gap:12px;margin-top:10px;">`;
    if (t.grade) body += `<div class="grade-pill" style="background:${gc};">${t.grade}</div>`;
    body += `<div class="counts">`;
    for (const [sev, label] of [["CRITICAL","CRIT"],["HIGH","HIGH"],["MEDIUM","MED"],["LOW","LOW"]]) {
      const n = c[sev] || 0;
      const col = n > 0 ? SEV_COLORS[sev] : "#3a4a5a";
      body += `<div class="count"><div class="n" style="color:${col};">${n}</div><div class="l" style="color:${col};">${label}</div></div>`;
    }
    body += `</div></div>`;
    if (t.report_path) {
      const rel = t.report_path.replace(/\\/g,"/");
      body += `<a class="report-link" href="/report?path=${encodeURIComponent(rel)}" target="_blank">&#x2197; Open Report</a>`;
    }
  }

  if (t.status === "offline")     body += `<div style="margin-top:8px;font-size:0.78em;color:#8e44ad;">HTTP 503 — service is down</div>`;
  if (t.status === "unreachable") body += `<div style="margin-top:8px;font-size:0.78em;color:#888;">DNS resolution failed — verify URL</div>`;

  return `<div class="card ${statusClass}" id="card-${t.idx}">
    <div class="card-header">${badge}${modeBadge}<span style="color:#4a7a9b;font-size:0.75em;margin-left:auto;">#${t.idx}</span></div>
    ${body}
  </div>`;
}

let lastLog = "";
async function refresh() {
  try {
    const [statusRes, logRes] = await Promise.all([
      fetch("/status"),
      fetch("/log")
    ]);
    const status = await statusRes.json();
    const log    = await logRes.text();

    if (status.error) {
      document.getElementById("prog-label").textContent = status.error;
      return;
    }

    // Header
    document.getElementById("batch-dir").textContent = status.batch_dir || "";
    document.getElementById("done-count").textContent = status.done;
    document.getElementById("done-label").textContent = `of ${status.total} targets`;
    document.getElementById("last-tick").textContent  = `Last updated: ${new Date().toLocaleTimeString()}`;

    // Progress bar
    const pct = status.total > 0 ? Math.round(status.done / status.total * 100) : 0;
    document.getElementById("prog-fill").style.width = pct + "%";
    document.getElementById("prog-label").textContent = status.complete
      ? `Complete — ${status.done}/${status.total} targets scanned`
      : `${status.done} of ${status.total} complete (${pct}%)`;

    // Current scan
    const cs = document.getElementById("current-scan");
    if (status.current_url && !status.complete) {
      cs.style.display = "flex";
      document.getElementById("current-url").textContent = status.current_url;
      document.getElementById("current-module").textContent = status.current_module
        ? `Running: ${status.current_module}`
        : "Scanning...";
    } else {
      cs.style.display = "none";
    }

    // Complete banner
    document.getElementById("complete-banner").style.display = status.complete ? "block" : "none";

    // Target grid
    const grid = document.getElementById("grid");
    grid.innerHTML = (status.targets || []).map(renderCard).join("");

    // Log
    if (log !== lastLog) {
      lastLog = log;
      const lb = document.getElementById("log-body");
      lb.textContent = log;
      lb.scrollTop = lb.scrollHeight;
    }
    document.getElementById("log-status").textContent = `${log.split("\n").length} lines`;

  } catch(e) {
    document.getElementById("last-tick").textContent = `Connection error — ${e.message}`;
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass  # suppress request logging

    def send_json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text):
        body = text.encode("utf-8", errors="replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        if path == "/install":
            # Stream setup-ubuntu.sh output back to the browser
            import subprocess
            setup = os.path.join(BASE, "setup-ubuntu.sh")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                proc = subprocess.Popen(
                    ["bash", setup], stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, errors="replace")
                import re as _re
                ansi = _re.compile(r'\x1b\[[0-9;]*[mK]|\x0f|\r')
                for line in proc.stdout:
                    chunk = ansi.sub("", line).encode("utf-8", errors="replace")
                    size = f"{len(chunk):X}\r\n".encode()
                    self.wfile.write(size + chunk + b"\r\n")
                    self.wfile.flush()
                proc.wait()
                self.wfile.write(b"0\r\n\r\n")
            except Exception as e:
                pass

        elif path == "/run-batch":
            import subprocess
            script = os.path.join(BASE, "batch-run.sh")
            try:
                subprocess.Popen(
                    ["bash", script],
                    stdout=open("/tmp/batch-master.log","w"),
                    stderr=subprocess.STDOUT,
                    start_new_session=True)
                self.send_json({"ok": True, "message": "Batch scan launched. Switch to the Scan Progress tab."})
            except Exception as e:
                self.send_json({"ok": False, "message": f"Failed to launch: {e}"})

        elif path == "/run-scan":
            import subprocess, json as _json
            try:
                data = _json.loads(body)
                url  = data.get("url","")
                mode = data.get("mode","staging")
                if not url:
                    self.send_json({"ok": False, "message": "No URL provided."}); return
                script = os.path.join(BASE, "pentest_wizard.py")
                proc = subprocess.Popen(
                    ["python3", script, url, f"--{mode}", "--yes"],
                    stdout=open("/tmp/batch-master.log","w"),
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    stdin=subprocess.DEVNULL)
                self.send_json({"ok": True, "message": f"Scanning {url} ({mode} mode). Check the Scan Progress tab."})
            except Exception as e:
                self.send_json({"ok": False, "message": f"Error: {e}"})
        else:
            self.send_response(404); self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path == "/" or path == "/index.html":
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/status":
            self.send_json(get_status())

        elif path == "/log":
            self.send_text(get_log_tail(80))

        elif path == "/tools":
            import shutil
            tools = ["nmap","nikto","hydra","ffuf","testssl.sh","jwt_tool"]
            result = {t: shutil.which(t) or "" for t in tools}
            self.send_json(result)

        elif path == "/report":
            qs = parse_qs(parsed.query)
            rp = qs.get("path", [""])[0]
            # Resolve WSL /mnt/c/ paths to Windows path
            rp = rp.replace("/mnt/c/", "C:/").replace("/", os.sep)
            if os.path.exists(rp):
                body = open(rp, "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", len(body))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404); self.end_headers()
        else:
            self.send_response(404); self.end_headers()

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"\n  Yao Pentest Dashboard")
    print(f"  Open: http://localhost:{PORT}")
    print(f"  Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Dashboard stopped.")
