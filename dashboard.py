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
    """Return the most relevant batch directory.
    Prefers incomplete batches (in-progress) over complete ones.
    Sorts by directory name timestamp (not mtime) to avoid being
    fooled by files written into old batch dirs."""
    import re as _re
    def batch_ts(d):
        m = _re.search(r"batch_(\d{8}_\d{6})", d)
        return m.group(1) if m else ""
    all_dirs = sorted(glob.glob(os.path.join(BASE, "batch_*")), key=batch_ts, reverse=True)
    # Prefer most recent incomplete batch (actively running)
    for d in all_dirs:
        if os.path.exists(os.path.join(d, "checkpoint.json")) and \
           not os.path.exists(os.path.join(d, "batch_complete")):
            return d
    # Fall back to most recent complete batch
    for d in all_dirs:
        if os.path.exists(os.path.join(d, "batch_complete")):
            return d
    return all_dirs[0] if all_dirs else None

def get_all_batches():
    """Return all completed batch runs sorted newest-first, with summary data."""
    import datetime as dt
    batch_dirs = sorted(
        glob.glob(os.path.join(BASE, "batch_*")),
        key=os.path.getmtime, reverse=True
    )
    batches = []
    for bd in batch_dirs:
        complete = os.path.exists(os.path.join(bd, "batch_complete"))
        ts_match = re.search(r"batch_(\d{8}_\d{6})", bd)
        if not ts_match:
            continue
        ts_str = ts_match.group(1)
        try:
            run_dt = dt.datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
            run_label = run_dt.strftime("%d %b %Y, %H:%M")
        except Exception:
            run_label = ts_str

        # Load checkpoint
        cp = {}
        cp_file = os.path.join(bd, "checkpoint.json")
        if os.path.exists(cp_file):
            try:
                data = json.load(open(cp_file))
                completed = data.get("completed", {})
                cp = completed if isinstance(completed, dict) else {u: {"status":"complete"} for u in completed}
            except Exception:
                pass

        # Gather per-target results from scan dirs
        targets_data = []
        try:
            tgts = json.load(open(os.path.join(BASE, "targets.json")))["targets"]
        except Exception:
            tgts = []

        total_c = total_h = total_m = total_l = 0
        for t in tgts:
            url  = t["url"]
            host = url.replace("https://","").replace("http://","")
            safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", host)
            # Find the scan dir created during this batch window
            ts_epoch = os.path.getmtime(bd)
            # Look for scan dirs within ±12h of batch start
            scan_dirs = sorted(
                glob.glob(os.path.join(BASE, f"pentest_{safe}_*")),
                key=os.path.getmtime
            )
            scan_dir = None
            in_cp = url in cp
            # For completed targets: most recent dir WITH a summary.json (skip empty/killed dirs)
            # For running targets: most recent dir within the batch window
            if in_cp:
                for sd in reversed(scan_dirs):  # newest first
                    if os.path.exists(os.path.join(sd, "summary.json")):
                        scan_dir = sd
                        break
                if not scan_dir and scan_dirs:  # fallback to most recent even without summary
                    scan_dir = scan_dirs[-1]
            else:
                for sd in scan_dirs:
                    sd_mtime = os.path.getmtime(sd)
                    if sd_mtime >= ts_epoch - 60 and sd_mtime <= ts_epoch + 43200:
                        scan_dir = sd

            counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
            g = None
            cp_entry = cp.get(url, {})
            cp_status = cp_entry.get("status","") if isinstance(cp_entry,dict) else ""

            if scan_dir and os.path.exists(os.path.join(scan_dir,"summary.json")):
                try:
                    s = json.load(open(os.path.join(scan_dir,"summary.json")))
                    counts = s.get("findings_by_severity", counts)
                    nc,nh,nm = counts.get("CRITICAL",0),counts.get("HIGH",0),counts.get("MEDIUM",0)
                    total_c+=nc; total_h+=nh; total_m+=nm; total_l+=counts.get("LOW",0)
                    g,_ = grade(nc,nh,nm)
                except Exception:
                    pass

            nmap_txt = os.path.join(scan_dir,"nmap.txt") if scan_dir else ""
            st = "complete"
            if cp_status == "OFFLINE" or (nmap_txt and os.path.exists(nmap_txt) and re.search(r"\|_http-title:.*503", open(nmap_txt).read(), re.IGNORECASE)):
                st = "offline"
            elif cp_status == "UNREACHABLE":
                st = "unreachable"
            elif url not in cp:
                st = "not_run"

            targets_data.append({"url":url,"status":st,"grade":g,"counts":counts})

        batches.append({
            "batch_dir":  bd,
            "run_label":  run_label,
            "ts":         ts_str,
            "complete":   complete,
            "targets":    targets_data,
            "totals":     {"CRITICAL":total_c,"HIGH":total_h,"MEDIUM":total_m,"LOW":total_l},
            "scanned":    sum(1 for t in targets_data if t["status"] in ("complete","offline","unreachable")),
        })
    return batches

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

    checkpoint = {}
    cp_file = os.path.join(batch_dir, "checkpoint.json")
    if os.path.exists(cp_file):
        try:
            data = json.load(open(cp_file))
            completed = data.get("completed", {})
            # Support both old list format and new dict format
            if isinstance(completed, list):
                checkpoint = {url: {"status":"complete"} for url in completed}
            else:
                checkpoint = completed
        except Exception:
            pass

    complete = os.path.exists(os.path.join(batch_dir, "batch_complete"))
    target_states = []
    running_idx = None

    for i, t in enumerate(targets):
        url = t["url"]
        host = url.replace("https://","").replace("http://","")
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", host)

        # Find most recent scan dir WITH a summary.json for this target
        # (skip empty dirs from killed scans)
        all_scan_dirs = sorted(glob.glob(os.path.join(BASE, f"pentest_{safe}_*")),
                               key=os.path.getmtime, reverse=True)
        scan_dir = next(
            (d for d in all_scan_dirs if os.path.exists(os.path.join(d, "summary.json"))),
            all_scan_dirs[0] if all_scan_dirs else None
        )

        # Determine status
        if url in checkpoint:
            cp_status = checkpoint[url].get("status","") if isinstance(checkpoint.get(url),dict) else ""
            _nmap_f = os.path.join(scan_dir,"nmap.txt") if scan_dir else ""
            _nmap_503 = bool(re.search(r"\|_http-title:.*503", open(_nmap_f).read(), re.IGNORECASE)) if _nmap_f and os.path.exists(_nmap_f) else False
            if cp_status == "OFFLINE" or _nmap_503:
                status = "offline"
            elif cp_status == "UNREACHABLE":
                status = "unreachable"
            else:
                status = "complete"
        else:
            if complete:
                status = "not_run"
            elif scan_dir:
                import re as _re2, datetime as _dt
                # Use the timestamp in the dir name — not mtime which changes when
                # files are regenerated (e.g. regen-all-reports.py)
                m = _re2.search(r"(\d{8}_\d{6})$", os.path.basename(scan_dir))
                if m:
                    try:
                        scan_start = _dt.datetime.strptime(m.group(1), "%Y%m%d_%H%M%S")
                        age_min = (_dt.datetime.now() - scan_start).total_seconds() / 60
                        status = "running" if age_min < 90 else "queued"
                    except Exception:
                        status = "queued"
                else:
                    status = "queued"
                if status == "running":
                    running_idx = i
            else:
                status = "queued"

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
  <div style="display:flex;flex-direction:column;align-items:flex-end;gap:10px;">
    <div style="text-align:right;">
      <div style="font-size:1.8em;font-weight:800;color:#2ecc71;" id="done-count">—</div>
      <div style="font-size:0.72em;color:#64a6d6;" id="done-label">of — targets</div>
    </div>
    <a href="/export" download
       style="background:#2980b9;color:#fff;padding:9px 18px;border-radius:8px;font-size:0.82em;font-weight:700;text-decoration:none;display:flex;align-items:center;gap:7px;white-space:nowrap;"
       title="Download full HTML report with all findings and parameters">
      &#x2B07; Export Report
    </a>
  </div>
</div>

<div class="tabs">
  <div class="tab active" onclick="showTab('scan')">&#x1F4CA; Scan Progress</div>
  <div class="tab" onclick="showTab('history'); loadHistory()">&#x1F4C5; History</div>
  <div class="tab" onclick="showTab('tools')">&#x1F527; Tools &amp; Parameters</div>
  <div class="tab" onclick="showTab('setup')">&#x2699;&#xFE0F; Setup</div>
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
  <!-- No scan running -->
  <div id="no-scan-banner" style="display:none;background:#1a2a3a;border:2px dashed #2980b9;border-radius:12px;padding:32px;text-align:center;margin-bottom:20px;">
    <div style="font-size:2em;margin-bottom:10px;">&#x1F6E1;</div>
    <div style="font-size:1.2em;font-weight:700;color:#fff;margin-bottom:6px;">No scan running</div>
    <div style="color:#64a6d6;font-size:0.88em;margin-bottom:20px;">Start a new batch scan against all targets in targets.json</div>
    <div style="display:flex;align-items:center;justify-content:center;gap:14px;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:8px;">
        <label style="font-size:0.82em;color:#64a6d6;font-weight:600;">Parallel targets:</label>
        <select id="parallel-count-main" style="background:#0f2030;border:1px solid #2980b9;border-radius:6px;padding:6px 10px;color:#e2e8f0;font-size:0.88em;">
          <option value="1">1 (slow, low load)</option>
          <option value="2">2</option>
          <option value="3">3</option>
          <option value="4" selected>4 (recommended)</option>
          <option value="6">6 (fast, high load)</option>
          <option value="13">All at once</option>
        </select>
      </div>
      <button onclick="startBatchFromProgress()" class="btn btn-success" style="font-size:1em;padding:12px 32px;">
        &#x25B6; Start Batch Scan
      </button>
    </div>
    <div id="start-scan-msg" style="margin-top:12px;font-size:0.82em;color:#64a6d6;"></div>
  </div>

  <!-- Stop button — visible only when running -->
  <div id="stop-banner" style="display:none;background:#2c1515;border:1px solid #c0392b;border-radius:8px;padding:12px 20px;margin-bottom:16px;display:none;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
    <div style="color:#e2e8f0;font-size:0.88em;">&#x1F534; Scan in progress — <span id="stop-running-label"></span></div>
    <button onclick="stopScan()" style="background:#c0392b;color:#fff;border:none;padding:8px 20px;border-radius:7px;font-size:0.85em;font-weight:700;cursor:pointer;">&#x23F9; Stop Scan</button>
  </div>
  <div id="stop-msg" style="display:none;background:#1a2a3a;border:1px solid #e67e22;border-radius:8px;padding:12px 20px;margin-bottom:16px;color:#e67e22;font-size:0.88em;"></div>

  <!-- Complete -->
  <div id="complete-banner" style="display:none;" class="complete-banner">
    &#x2705; Batch scan complete — all targets processed. &nbsp;
    <a href="/export" download style="color:#2ecc71;text-decoration:underline;font-size:0.9em;">&#x2B07; Download Report</a>
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

<div id="tab-history" class="tab-content">
<div style="padding:20px 32px;max-width:1200px;">

  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:12px;">
    <div>
      <div style="font-size:1.1em;font-weight:700;color:#fff;">Scan History</div>
      <div style="font-size:0.82em;color:#64a6d6;margin-top:2px;">All completed batch runs — track security posture over time</div>
    </div>
    <button class="btn btn-primary" onclick="loadHistory()" style="font-size:0.82em;padding:8px 16px;">&#x21BB; Refresh</button>
  </div>

  <div id="history-loading" style="color:#64a6d6;font-size:0.88em;padding:20px 0;">Loading history...</div>

  <!-- Grade trend table (populated by JS) -->
  <div id="grade-trend" style="display:none;margin-bottom:20px;">
    <div class="setup-card">
      <h3>&#x1F4C8; Grade Trend — All Targets</h3>
      <p style="color:#8fb3c8;font-size:0.85em;margin-bottom:14px;">Each column is a scan run. Green = improving, red = regressing.</p>
      <div style="overflow-x:auto;">
        <table id="trend-table" style="border-collapse:collapse;font-size:0.82em;min-width:600px;">
          <thead id="trend-head"></thead>
          <tbody id="trend-body"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Per-run cards -->
  <div id="history-runs"></div>

</div>
</div><!-- end tab-history -->

<div id="tab-tools" class="tab-content">
<div class="setup-con" style="max-width:1060px;">

  <div class="setup-card">
    <h3>&#x1F4CB; All Modules — Tools &amp; Exact Parameters</h3>
    <p style="margin-bottom:16px;">Every command run during a full staging scan, in execution order.
    Parameters shown as passed; <code style="background:#0f2030;padding:1px 5px;border-radius:3px;">&lt;target&gt;</code> is substituted at runtime.</p>
    <table style="width:100%;border-collapse:collapse;font-size:0.82em;">
      <thead>
        <tr style="background:#0f2030;">
          <th style="padding:10px 12px;text-align:left;color:#64a6d6;font-size:0.8em;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap;">#</th>
          <th style="padding:10px 12px;text-align:left;color:#64a6d6;font-size:0.8em;text-transform:uppercase;letter-spacing:.5px;">Tool</th>
          <th style="padding:10px 12px;text-align:left;color:#64a6d6;font-size:0.8em;text-transform:uppercase;letter-spacing:.5px;">Purpose</th>
          <th style="padding:10px 12px;text-align:left;color:#64a6d6;font-size:0.8em;text-transform:uppercase;letter-spacing:.5px;">Command &amp; Parameters</th>
          <th style="padding:10px 12px;text-align:left;color:#64a6d6;font-size:0.8em;text-transform:uppercase;letter-spacing:.5px;">Modes</th>
        </tr>
      </thead>
      <tbody>
        <tr style="border-top:1px solid #1e3a5f;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">1a</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">nmap</td>
          <td style="padding:10px 12px;color:#8fb3c8;">Port scan &amp; service fingerprinting</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">nmap -sV -sC --open \
  -p 21,22,25,80,443,3306,5432,6379,8080,8443,9200,27017 \
  -oN nmap.txt &lt;host&gt;</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>-sV</b> version detection &nbsp;·&nbsp; <b>-sC</b> default scripts &nbsp;·&nbsp;
            <b>--open</b> show open ports only &nbsp;·&nbsp; <b>-p</b> scan these ports only
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;background:#111e2b;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">1b</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">nmap</td>
          <td style="padding:10px 12px;color:#8fb3c8;">Known vulnerability scripts</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">nmap --script vuln \
  -p &lt;port&gt; -oN nmap_vuln.txt &lt;host&gt;</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>--script vuln</b> runs the full vulnerability script library against the target port
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">2</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">nikto</td>
          <td style="padding:10px 12px;color:#8fb3c8;">Web server misconfiguration &amp; missing security headers</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">nikto -h &lt;url&gt; \
  -ssl -port 443 \
  -output nikto.txt -Format txt \
  -maxtime 300</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>-ssl</b> force HTTPS &nbsp;·&nbsp; <b>-maxtime 300</b> 5-minute cap per host
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;background:#111e2b;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">3</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">testssl.sh</td>
          <td style="padding:10px 12px;color:#8fb3c8;">TLS/SSL protocols, ciphers, certificates, BREACH, HSTS</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">testssl.sh \
  --jsonfile testssl.json \
  &lt;host&gt;:&lt;port&gt;</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>--jsonfile</b> structured JSON output for parsing &nbsp;·&nbsp;
            Tests all 4 CloudFront IPs; results are deduplicated by check ID
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">4</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">ffuf</td>
          <td style="padding:10px 12px;color:#8fb3c8;">Hidden endpoint &amp; directory discovery</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">ffuf -u &lt;url&gt;/FUZZ \
  -w yao_ffuf_wordlist.txt \
  -mc 200,201,204,301,302,403,404 \
  -ic -ac -t 40 \
  -fs &lt;baseline_size&gt; \
  -o ffuf.json -of json</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>-ic</b> ignore wordlist comment lines &nbsp;·&nbsp;
            <b>-ac</b> auto-calibrate to filter SPA catch-all responses &nbsp;·&nbsp;
            <b>-fs</b> filter by baseline response size (auto-detected) &nbsp;·&nbsp;
            <b>-t 40</b> 40 concurrent threads
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;background:#111e2b;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">5a</td>
          <td style="padding:10px 12px;font-weight:700;color:#e67e22;white-space:nowrap;">Rate-limit check</td>
          <td style="padding:10px 12px;color:#8fb3c8;">15 rapid login attempts to detect throttling before brute-force</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">POST &lt;url&gt;&lt;login_path&gt;  ×15 rapid requests
  Content-Type: application/x-www-form-urlencoded
  Body: username=ratelimitcheck_dummy&amp;password=wrongpassword123
  Interval: 100ms between requests</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            Checks for: HTTP 429, Retry-After header, progressive slowdown, response body change
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1F4E79;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">FULL SCAN</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;background:#111e2b;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">5b</td>
          <td style="padding:10px 12px;font-weight:700;color:#e67e22;white-space:nowrap;">hydra</td>
          <td style="padding:10px 12px;color:#8fb3c8;">Credential brute-force against login endpoint</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">hydra -L yao_usernames.txt -P passwords.txt \
  -s &lt;port&gt; &lt;host&gt; https-post-form \
  "&lt;login_path&gt;:username=^USER^&amp;password=^PASS^:F=Invalid" \
  -t 4 -o hydra.txt</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>-t 4</b> 4 threads &nbsp;·&nbsp; <b>https-post-form</b> TLS-aware form POST &nbsp;·&nbsp;
            <b>F=Invalid</b> failure string &nbsp;·&nbsp; 27 Yao usernames × wordlist passwords
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1F4E79;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">FULL SCAN</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">6</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">jwt_tool</td>
          <td style="padding:10px 12px;color:#8fb3c8;">JWT token analysis — alg:none, weak secrets, expiry</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">jwt_tool &lt;token&gt; -t</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>-t</b> tamper mode — tests alg:none bypass, HS256 weakness, expiry enforcement.
            Requires a valid JWT from the target (pasted interactively).
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;background:#111e2b;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">7</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">nuclei</td>
          <td style="padding:10px 12px;color:#8fb3c8;">CVE scanner, misconfigurations, exposed files, default credentials (9,000+ templates)</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">nuclei -u &lt;url&gt; \
  -t cves,exposures,misconfiguration,default-logins,technologies \
  -json -o nuclei.jsonl \
  -silent -no-color \
  -timeout 10 \
  -rate-limit 10</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>-t</b> template categories &nbsp;·&nbsp;
            <b>-rate-limit 10</b> 10 req/s — respectful of target &nbsp;·&nbsp;
            <b>-timeout 10</b> per-request timeout
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">8</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">wafw00f</td>
          <td style="padding:10px 12px;color:#8fb3c8;">WAF/CDN detection — identifies protection layer in front of the target</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">wafw00f &lt;url&gt; -a -o wafw00f.txt</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>-a</b> test all WAF fingerprints (not just first match) &nbsp;·&nbsp;
            No active probing — fingerprints via HTTP response headers and behaviour
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;background:#111e2b;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">9</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">checkdmarc</td>
          <td style="padding:10px 12px;color:#8fb3c8;">Email security — SPF, DKIM, DMARC records. Catches email spoofing risk.</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">checkdmarc &lt;base-domain&gt; \
  --format json -o checkdmarc.json</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            <b>&lt;base-domain&gt;</b> extracted from target host (e.g. app.stg.yao.legal → yao.legal) &nbsp;·&nbsp;
            Passive DNS queries only — no traffic to the web server
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
        <tr style="border-top:1px solid #1e3a5f;">
          <td style="padding:10px 12px;color:#64a6d6;font-weight:700;">10</td>
          <td style="padding:10px 12px;font-weight:700;color:#2ecc71;white-space:nowrap;">SecretFinder</td>
          <td style="padding:10px 12px;color:#8fb3c8;">Scans JavaScript bundles for API keys, AWS credentials, tokens, private keys</td>
          <td style="padding:10px 12px;"><code style="background:#0f2030;color:#cdd6f4;padding:4px 8px;border-radius:4px;display:block;white-space:pre-wrap;line-height:1.6;">python3 /opt/SecretFinder/SecretFinder.py \
  -i &lt;url&gt; -o cli</code>
          <div style="margin-top:6px;color:#4a7a9b;font-size:0.85em;">
            Crawls the page, finds all linked <b>.js</b> files, scans each for secret patterns &nbsp;·&nbsp;
            Detects: Google/AWS/Stripe/Slack/GitHub/Twilio API keys, private keys, Firebase config
          </div></td>
          <td style="padding:10px 12px;white-space:nowrap;"><span style="background:#1a7a4a;color:#fff;padding:1px 7px;border-radius:8px;font-size:0.75em;">ALL</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="setup-card">
    <h3>&#x1F512; What is NOT tested</h3>
    <p>For full transparency — areas outside the current scan coverage:</p>
    <table style="width:100%;border-collapse:collapse;font-size:0.82em;margin-top:8px;">
      <tr style="border-top:1px solid #1e3a5f;">
        <td style="padding:8px 12px;color:#e74c3c;font-weight:700;">Authenticated scanning</td>
        <td style="padding:8px 12px;color:#8fb3c8;">All scans are unauthenticated. Vulnerabilities behind login are not tested.</td>
      </tr>
      <tr style="border-top:1px solid #1e3a5f;background:#111e2b;">
        <td style="padding:8px 12px;color:#27ae60;font-weight:700;">CORS misconfiguration</td>
        <td style="padding:8px 12px;color:#8fb3c8;">Tested by <strong>Corsy</strong> (Module 11) — checks wildcard, origin reflection, null origin, subdomain bypass.</td>
      </tr>
      <tr style="border-top:1px solid #1e3a5f;">
        <td style="padding:8px 12px;color:#e67e22;font-weight:700;">Subdomain takeover</td>
        <td style="padding:8px 12px;color:#8fb3c8;">Not tested — would require subjack or similar.</td>
      </tr>
      <tr style="border-top:1px solid #1e3a5f;background:#111e2b;">
        <td style="padding:8px 12px;color:#e67e22;font-weight:700;">Business logic flaws</td>
        <td style="padding:8px 12px;color:#8fb3c8;">Requires manual testing — cannot be automated.</td>
      </tr>
      <tr style="border-top:1px solid #1e3a5f;">
        <td style="padding:8px 12px;color:#d4a017;font-weight:700;">S3 bucket exposure</td>
        <td style="padding:8px 12px;color:#8fb3c8;">CloudFront/S3 backend bucket policy not directly assessed.</td>
      </tr>
    </table>
  </div>

</div>
</div><!-- end tab-tools -->

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

  <div class="setup-card" style="border-left:4px solid #c0392b;">
    <h3>&#x23F9; Stop Running Scan</h3>
    <p>Gracefully stops the current batch scan, marks all in-progress targets as STOPPED, and releases the lock.</p>
    <button class="btn btn-danger" onclick="stopScan()">&#x23F9; Stop Scan</button>
    <div id="stop-msg-setup" style="margin-top:10px;font-size:0.82em;color:#e67e22;"></div>
  </div>

  <div class="setup-card">
    <h3>&#x1F680; Run a New Batch Scan</h3>
    <p>Starts a new full batch scan against all targets in targets.json.
       Discovery runs first to pick up any new subdomains.</p>
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:8px;">
        <label style="font-size:0.82em;color:#8fb3c8;font-weight:600;">Parallel targets:</label>
        <select id="parallel-count-setup" style="background:#0f2030;border:1px solid #1e3a5f;border-radius:6px;padding:6px 10px;color:#e2e8f0;font-size:0.88em;">
          <option value="1">1 (slow, low load)</option>
          <option value="2">2</option>
          <option value="3">3</option>
          <option value="4" selected>4 (recommended)</option>
          <option value="6">6 (fast, high load)</option>
          <option value="13">All at once</option>
        </select>
      </div>
      <button class="btn btn-primary" onclick="runBatch()">&#x25B6; Start Batch Scan</button>
    </div>
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
  const parallel = document.getElementById("parallel-count-setup")?.value || "4";
  msg.textContent = "Launching batch scan...";
  const res = await fetch("/run-batch", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({parallel})});
  const data = await res.json();
  msg.textContent = data.message;
  if(data.ok) showTab("scan");
}

async function loadHistory() {
  document.getElementById("history-loading").style.display = "block";
  document.getElementById("grade-trend").style.display     = "none";
  document.getElementById("history-runs").innerHTML        = "";

  const res     = await fetch("/history");
  const batches = await res.json();
  document.getElementById("history-loading").style.display = "none";

  if (!batches.length) {
    document.getElementById("history-runs").innerHTML =
      "<div style='color:#64a6d6;padding:20px 0;'>No completed scans yet.</div>";
    return;
  }

  // ── Grade trend table ─────────────────────────────────────
  const allUrls = [...new Set(batches.flatMap(b => b.targets.map(t => t.url)))];
  const completed = batches.filter(b => b.complete);

  if (completed.length > 1) {
    document.getElementById("grade-trend").style.display = "block";

    // Header row: target | run1 | run2 | ...
    let headHtml = "<tr><th style='padding:8px 12px;background:#1a2a3a;text-align:left;color:#64a6d6;font-size:0.78em;text-transform:uppercase;position:sticky;left:0;z-index:1;'>Target</th>";
    completed.forEach(b => {
      headHtml += `<th style='padding:8px 12px;background:#1a2a3a;color:#64a6d6;font-size:0.75em;text-align:center;white-space:nowrap;'>${b.run_label}</th>`;
    });
    headHtml += "</tr>";
    document.getElementById("trend-head").innerHTML = headHtml;

    // Body: one row per URL
    let bodyHtml = "";
    allUrls.forEach(url => {
      const host = url.replace(/https?:\/\//,"");
      bodyHtml += `<tr><td style='padding:7px 12px;font-size:0.82em;font-weight:600;white-space:nowrap;position:sticky;left:0;background:#1a2a3a;border-right:1px solid #1e3a5f;'>${host}</td>`;
      let prevGrade = null;
      completed.forEach(b => {
        const t = b.targets.find(t => t.url === url);
        const g = t ? t.grade : null;
        const st= t ? t.status : "not_run";
        let cell = "";
        if (st === "offline")     cell = `<span style='color:#8e44ad;font-size:0.78em;'>OFFLINE</span>`;
        else if (st === "unreachable") cell = `<span style='color:#555;font-size:0.78em;'>—</span>`;
        else if (st === "not_run") cell = `<span style='color:#333;font-size:0.78em;'>—</span>`;
        else if (g) {
          const gc = GRADE_COLORS[g] || "#555";
          // trend arrow
          let arrow = "";
          if (prevGrade && prevGrade !== g) {
            const gradeOrder = {"A":0,"B+":1,"B":2,"C":3,"D":4,"F":5};
            const prev = gradeOrder[prevGrade]||99, cur = gradeOrder[g]||99;
            arrow = cur < prev ? " &#x2191;" : cur > prev ? " &#x2193;" : "";
            const arrowColor = cur < prev ? "#2ecc71" : "#e74c3c";
            arrow = `<span style='color:${arrowColor};font-size:0.9em;'>${arrow}</span>`;
          }
          cell = `<span style='background:${gc};color:#fff;padding:2px 8px;border-radius:8px;font-weight:800;font-size:0.85em;'>${g}</span>${arrow}`;
          prevGrade = g;
        } else {
          cell = `<span style='color:#555;font-size:0.78em;'>—</span>`;
        }
        bodyHtml += `<td style='padding:7px 12px;text-align:center;border-bottom:1px solid #1e3a5f;'>${cell}</td>`;
      });
      bodyHtml += "</tr>";
    });
    document.getElementById("trend-body").innerHTML = bodyHtml;
  }

  // ── Per-run summary cards ─────────────────────────────────
  let runsHtml = "";
  batches.forEach((b,idx) => {
    const statusBadge = b.complete
      ? `<span style='background:#27ae60;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.75em;font-weight:700;'>COMPLETE</span>`
      : `<span style='background:#3498db;color:#fff;padding:2px 8px;border-radius:8px;font-size:0.75em;font-weight:700;'>IN PROGRESS</span>`;

    const t = b.totals;
    const hasCrit = t.CRITICAL > 0, hasHigh = t.HIGH > 0;
    function tot(n,sev) { return n > 0 ? `<span style='color:${SEV_COLORS[sev]};font-weight:700;'>${n}</span>` : n; }

    // Target rows
    let targetRows = "";
    b.targets.forEach(tgt => {
      if (tgt.status === "not_run") return;
      const host = tgt.url.replace(/https?:\/\//,"");
      const g = tgt.grade;
      const gc = g ? (GRADE_COLORS[g]||"#555") : "#555";
      const gradeCell = g
        ? `<span style='background:${gc};color:#fff;padding:1px 7px;border-radius:6px;font-weight:800;font-size:0.8em;'>${g}</span>`
        : (tgt.status==="offline"?"<span style='color:#8e44ad;font-size:0.78em;'>OFFLINE</span>":"<span style='color:#555;font-size:0.78em;'>—</span>");
      const c = tgt.counts;
      targetRows += `<tr style='border-top:1px solid #e8ecf0;'>
        <td style='padding:6px 12px;font-size:0.82em;word-break:break-all;'>${host}</td>
        <td style='padding:6px 12px;text-align:center;'>${gradeCell}</td>
        <td style='padding:6px 12px;font-size:0.82em;text-align:center;color:#c0392b;font-weight:${c.CRITICAL?700:400};'>${c.CRITICAL||0}</td>
        <td style='padding:6px 12px;font-size:0.82em;text-align:center;color:#e67e22;font-weight:${c.HIGH?700:400};'>${c.HIGH||0}</td>
        <td style='padding:6px 12px;font-size:0.82em;text-align:center;color:#d4a017;'>${c.MEDIUM||0}</td>
        <td style='padding:6px 12px;font-size:0.82em;text-align:center;color:#888;'>${c.LOW||0}</td>
      </tr>`;
    });

    runsHtml += `
    <div class="setup-card" style="margin-bottom:16px;${idx===0?'border-color:#3498db;':'' }">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:12px;">
        <div>
          <div style="font-size:1em;font-weight:700;color:#fff;">&#x1F4C5; ${b.run_label} ${idx===0?'<span style="font-size:0.72em;color:#64a6d6;">(most recent)</span>':''}</div>
          <div style="font-size:0.78em;color:#64a6d6;margin-top:2px;">${b.scanned} of ${b.targets.length} targets scanned &nbsp;·&nbsp; ${statusBadge}</div>
        </div>
        <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;">
          <div style="text-align:center;"><div style="font-size:1.4em;font-weight:800;color:#c0392b;">${t.CRITICAL}</div><div style="font-size:0.68em;font-weight:700;color:#c0392b;text-transform:uppercase;">Critical</div></div>
          <div style="text-align:center;"><div style="font-size:1.4em;font-weight:800;color:#e67e22;">${t.HIGH}</div><div style="font-size:0.68em;font-weight:700;color:#e67e22;text-transform:uppercase;">High</div></div>
          <div style="text-align:center;"><div style="font-size:1.4em;font-weight:800;color:#d4a017;">${t.MEDIUM}</div><div style="font-size:0.68em;font-weight:700;color:#d4a017;text-transform:uppercase;">Medium</div></div>
          <div style="text-align:center;"><div style="font-size:1.4em;font-weight:800;color:#27ae60;">${t.LOW}</div><div style="font-size:0.68em;font-weight:700;color:#27ae60;text-transform:uppercase;">Low</div></div>
          ${b.complete ? `<a href="/export?batch=${encodeURIComponent(b.batch_dir)}" download style="background:#2980b9;color:#fff;padding:7px 14px;border-radius:7px;font-size:0.8em;font-weight:700;text-decoration:none;">&#x2B07; Export</a>` : ''}
        </div>
      </div>
      ${targetRows ? `<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;">
        <thead><tr style="background:#0f2030;">
          <th style="padding:7px 12px;text-align:left;color:#64a6d6;font-size:0.75em;text-transform:uppercase;">Target</th>
          <th style="padding:7px 12px;text-align:center;color:#64a6d6;font-size:0.75em;">Grade</th>
          <th style="padding:7px 12px;text-align:center;color:#c0392b;font-size:0.75em;">CRIT</th>
          <th style="padding:7px 12px;text-align:center;color:#e67e22;font-size:0.75em;">HIGH</th>
          <th style="padding:7px 12px;text-align:center;color:#d4a017;font-size:0.75em;">MED</th>
          <th style="padding:7px 12px;text-align:center;color:#888;font-size:0.75em;">LOW</th>
        </tr></thead>
        <tbody>${targetRows}</tbody>
      </table></div>` : '<div style="color:#555;font-size:0.82em;">No scan data yet.</div>'}
    </div>`;
  });

  document.getElementById("history-runs").innerHTML = runsHtml;
}

async function stopScan() {
  const btn = event.target;
  const msg = document.getElementById("stop-msg");
  btn.disabled = true;
  btn.textContent = "Stopping...";
  try {
    const res  = await fetch("/stop-batch", {method:"POST"});
    const data = await res.json();
    msg.style.display = "block";
    msg.textContent = data.message;
    document.getElementById("stop-banner").style.display = "none";
    btn.disabled = false;
    btn.textContent = "⏹ Stop Scan";
  } catch(e) {
    msg.style.display = "block";
    msg.textContent = "Error: " + e.message;
    btn.disabled = false;
    btn.textContent = "⏹ Stop Scan";
  }
}

async function startBatchFromProgress() {
  const msg = document.getElementById("start-scan-msg");
  const btn = event.target;
  const parallel = document.getElementById("parallel-count-main")?.value || "4";
  btn.disabled = true;
  btn.textContent = "Launching...";
  msg.textContent = "Starting scan — this page will update automatically...";
  try {
    const res  = await fetch("/run-batch", {method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({parallel})});
    const data = await res.json();
    if (data.ok) {
      msg.textContent = "Scan launched. Progress will appear below in a few seconds.";
      document.getElementById("no-scan-banner").style.display = "none";
    } else {
      msg.textContent = "Error: " + data.message;
      btn.disabled = false;
      btn.textContent = "▶ Start Batch Scan";
    }
  } catch(e) {
    msg.textContent = "Connection error: " + e.message;
    btn.disabled = false;
    btn.textContent = "▶ Start Batch Scan";
  }
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
  const modeBadge = `<span style="background:#1F4E79;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.72em;font-weight:700;">FULL SCAN</span>`;

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
      document.getElementById("no-scan-banner").style.display = "block";
      document.getElementById("complete-banner").style.display = "none";
      document.getElementById("current-scan").style.display   = "none";
      document.getElementById("prog-fill").style.width = "0%";
      document.getElementById("done-count").textContent = "—";
      document.getElementById("done-label").textContent = "";
      document.getElementById("grid").innerHTML = "";
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

    // Banners
    const hasTargets = (status.targets || []).length > 0;
    const isRunning  = (status.targets || []).some(t => t.status === "running");
    document.getElementById("complete-banner").style.display  = (status.complete && hasTargets) ? "block" : "none";
    document.getElementById("no-scan-banner").style.display   = (!hasTargets || (!isRunning && !status.complete)) ? "block" : "none";
    if (isRunning || status.complete) document.getElementById("no-scan-banner").style.display = "none";
    // Stop button — show when running, hide when idle or complete
    const stopBanner = document.getElementById("stop-banner");
    if (isRunning && !status.complete) {
      stopBanner.style.display = "flex";
      document.getElementById("stop-running-label").textContent =
        status.current_url ? `scanning ${status.current_url}` : `${status.done}/${status.total} targets done`;
    } else {
      stopBanner.style.display = "none";
    }

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

SEV_COLOR = {"CRITICAL":"#c0392b","HIGH":"#e67e22","MEDIUM":"#d4a017","LOW":"#27ae60","INFO":"#2980b9"}
SEV_BG    = {"CRITICAL":"#fdf0ef","HIGH":"#fef6ee","MEDIUM":"#fefde8","LOW":"#edfaf1","INFO":"#eaf4fb"}
SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
PRIORITY  = {"CRITICAL":"P0 — Fix within 24 hours","HIGH":"P1 — Fix within 1 week",
             "MEDIUM":"P2 — Fix within 1 month","LOW":"P3 — Fix in next sprint","INFO":"Informational"}

def _esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')
def _code(c): return f'<pre style="background:#1e1e2e;color:#cdd6f4;padding:12px;border-radius:5px;overflow-x:auto;font-size:0.8em;line-height:1.5;margin:8px 0;">{_esc(c)}</pre>'

def grade(nc, nh, nm):
    risk = nc*10 + nh*5 + nm*2
    if nc>=2: return ("F","#c0392b")
    if nc==1: return ("D","#e74c3c")
    if nh>=3: return ("C","#e67e22")
    if nh>=1: return ("B","#f39c12")
    if risk>0: return ("B+","#2ecc71")
    return ("A","#27ae60")

def generate_export_report(batch_dir_override=None):
    """Build a full HTML report across all batch scan targets."""
    import datetime as dt
    status = get_status() if not batch_dir_override else reconstruct_status(batch_dir_override)
    if "error" in status:
        return f"<html><body>{status['error']}</body></html>"

    ts = dt.datetime.now().strftime("%d %B %Y, %H:%M")
    targets = status.get("targets", [])

    # ── per-target summary rows ──────────────────────────────
    summary_rows = ""
    for t in targets:
        url  = t["url"]; mode = t["mode"]; st = t["status"]
        c    = t.get("counts",{})
        nc   = c.get("CRITICAL",0); nh = c.get("HIGH",0)
        nm   = c.get("MEDIUM",0);   nl = c.get("LOW",0)
        mc   = "#1F4E79"

        if st == "offline":
            grade_cell = "<span style='background:#8e44ad;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.75em;font-weight:700;'>OFFLINE</span>"
            counts_cell = "<span style='color:#aaa;'>Service was down — not scanned</span>"
        elif st == "unreachable":
            grade_cell = "<span style='background:#555;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.75em;font-weight:700;'>UNREACHABLE</span>"
            counts_cell = "<span style='color:#aaa;'>DNS failed — not scanned</span>"
        elif st in ("complete","skipped"):
            g, gc = grade(nc,nh,nm)
            grade_cell = f"<span style='background:{gc};color:#fff;width:30px;height:30px;display:inline-flex;align-items:center;justify-content:center;border-radius:50%;font-weight:800;font-size:0.85em;'>{g}</span>"
            def cv(n,sev): return f"<span style='color:{SEV_COLOR[sev]};font-weight:700;'>{n}</span>" if n else "0"
            counts_cell = f"CRIT:{cv(nc,'CRITICAL')} &nbsp; HIGH:{cv(nh,'HIGH')} &nbsp; MED:{cv(nm,'MEDIUM')} &nbsp; LOW:{cv(nl,'LOW')}"
        elif st in ("running",):
            grade_cell = "<span style='color:#3498db;'>SCANNING...</span>"
            counts_cell = "—"
        else:
            grade_cell = "<span style='color:#888;'>NOT RUN</span>"
            counts_cell = "<span style='color:#555;font-size:0.85em;'>Scan did not complete</span>"

        summary_rows += f"""<tr>
          <td style='padding:10px 14px;font-weight:600;word-break:break-all;'>{_esc(url)}</td>
          <td style='padding:10px 14px;'><span style='background:#1F4E79;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.75em;font-weight:700;'>FULL SCAN</span></td>
          <td style='padding:10px 14px;text-align:center;'>{grade_cell}</td>
          <td style='padding:10px 14px;font-size:0.88em;'>{counts_cell}</td>
        </tr>"""

    # ── all findings across all targets ──────────────────────
    all_findings_html = ""
    for t in targets:
        if t["status"] not in ("complete","skipped"): continue
        scan_dir = t.get("scan_dir","")
        if not scan_dir or not os.path.exists(os.path.join(scan_dir,"summary.json")):
            continue
        try:
            s = json.load(open(os.path.join(scan_dir,"summary.json")))
            findings = sorted(s.get("findings",[]), key=lambda f: SEV_ORDER.get(f.get("severity","INFO"),99))
            if not findings: continue

            cards = ""
            for f in findings:
                sev   = f.get("severity","INFO")
                color = SEV_COLOR.get(sev,"#555")
                bg    = SEV_BG.get(sev,"#fff")
                plabel= PRIORITY.get(sev,"")
                steps_html = ""
                for h_,b_ in f.get("steps",[]):
                    steps_html += f'<div style="margin-top:12px;"><div style="font-size:0.75em;text-transform:uppercase;letter-spacing:0.5px;color:#888;font-weight:700;margin-bottom:4px;">{_esc(h_)}</div>{_code(b_)}</div>'
                refs_html = ""
                if f.get("refs"):
                    refs_html = "<div style='margin-top:8px;font-size:0.82em;'><strong>References:</strong> " + " &nbsp;·&nbsp; ".join(
                        f"<a href='{_esc(href)}' style='color:#2980b9;'>{_esc(label)}</a>" for label,href in f["refs"]
                    ) + "</div>"
                cards += f"""<div style="background:{bg};border-left:4px solid {color};border-radius:6px;padding:14px 18px;margin-bottom:12px;">
                  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
                    <span style="background:{color};color:#fff;padding:2px 8px;border-radius:8px;font-size:0.75em;font-weight:700;">{sev}</span>
                    <span style="background:#f0f3f7;color:#555;padding:2px 8px;border-radius:8px;font-size:0.75em;">{_esc(f.get('tool',''))}</span>
                    <span style="font-size:0.75em;color:{color};font-weight:600;">{_esc(plabel)}</span>
                  </div>
                  <div style="font-weight:700;margin-top:8px;font-size:0.95em;">{_esc(f.get('title',''))}</div>
                  <div style="color:#555;font-size:0.85em;margin-top:4px;line-height:1.6;">{_esc(f.get('detail',''))}</div>
                  {steps_html}{refs_html}
                </div>"""

            g_lbl, gc = grade(t.get("counts",{}).get("CRITICAL",0),t.get("counts",{}).get("HIGH",0),t.get("counts",{}).get("MEDIUM",0))
            all_findings_html += f"""
            <div style="margin-bottom:32px;">
              <div style="display:flex;align-items:center;gap:14px;padding:14px 20px;background:#1a1a2e;border-radius:8px;margin-bottom:14px;">
                <div style="background:{gc};color:#fff;width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:0.9em;flex-shrink:0;">{g_lbl}</div>
                <div>
                  <div style="font-weight:700;color:#fff;font-size:1em;">{_esc(t['url'])}</div>
                  <div style="color:#888;font-size:0.8em;margin-top:2px;">{len(findings)} finding(s)</div>
                </div>
              </div>
              {cards}
            </div>"""
        except Exception:
            continue

    # ── parameters table ─────────────────────────────────────
    params_rows = ""
    modules = [
        ("1a","nmap","Port scan & service fingerprinting","nmap -sV -sC --open -p 21,22,25,80,443,3306,5432,6379,8080,8443,9200,27017 -oN nmap.txt <host>","ALL"),
        ("1b","nmap","Vulnerability scripts","nmap --script vuln -p <port> -oN nmap_vuln.txt <host>","ALL"),
        ("2","nikto","Web server misconfiguration & headers","nikto -h <url> -ssl -port 443 -output nikto.txt -Format txt -maxtime 300","ALL"),
        ("3","testssl.sh","TLS/SSL — protocols, ciphers, BREACH, HSTS","testssl.sh --jsonfile testssl.json <host>:<port>","ALL"),
        ("4","ffuf","Hidden endpoint discovery","ffuf -u <url>/FUZZ -w wordlist.txt -mc 200,201,204,301,302,403,404 -ic -ac -t 40 -fs <baseline>","ALL"),
        ("5a","Rate-limit check","15 rapid POSTs to detect throttling","POST <url><login_path> ×15  body: username=dummy&password=wrong  interval: 100ms","ALL"),
        ("5b","hydra","Credential brute-force","hydra -L usernames.txt -P passwords.txt -s <port> <host> https-post-form \"<path>:user=^USER^&pass=^PASS^:F=Invalid\" -t 4","ALL"),
        ("6","jwt_tool","JWT token analysis","jwt_tool <token> -t","ALL"),
        ("7","nuclei","CVE & misconfiguration scanner","nuclei -u <url> -t cves,exposures,misconfiguration,default-logins,technologies -json -rate-limit 10 -timeout 10","ALL"),
        ("8","wafw00f","WAF/CDN detection","wafw00f <url> -a -o wafw00f.txt","ALL"),
        ("9","checkdmarc","Email security (SPF/DKIM/DMARC)","checkdmarc <base-domain> --format json -o checkdmarc.json","ALL"),
        ("10","SecretFinder","JavaScript bundle secret scanner","python3 SecretFinder.py -i <url> -o cli","ALL"),
        ("11","corsy","CORS misconfiguration scanner","corsy -u <url> -o corsy.json --headers \"User-Agent: PentestWizard/1.0\"","ALL"),
    ]
    for num, tool, purpose, cmd, modes in modules:
        mc2 = "#1a7a4a" if modes=="ALL" else "#b45309"
        params_rows += f"""<tr style="border-top:1px solid #e8ecf0;">
          <td style="padding:9px 12px;color:#2980b9;font-weight:700;white-space:nowrap;">{num}</td>
          <td style="padding:9px 12px;font-weight:700;white-space:nowrap;">{_esc(tool)}</td>
          <td style="padding:9px 12px;color:#555;font-size:0.88em;">{_esc(purpose)}</td>
          <td style="padding:9px 12px;"><code style="background:#f4f6f9;padding:3px 6px;border-radius:4px;font-size:0.8em;word-break:break-all;">{_esc(cmd)}</code></td>
          <td style="padding:9px 12px;"><span style="background:{mc2};color:#fff;padding:2px 8px;border-radius:8px;font-size:0.72em;font-weight:700;">{modes}</span></td>
        </tr>"""

    total_c = sum(t.get("counts",{}).get("CRITICAL",0) for t in targets if t["status"] in ("complete","skipped"))
    total_h = sum(t.get("counts",{}).get("HIGH",0)     for t in targets if t["status"] in ("complete","skipped"))
    total_m = sum(t.get("counts",{}).get("MEDIUM",0)   for t in targets if t["status"] in ("complete","skipped"))
    total_l = sum(t.get("counts",{}).get("LOW",0)      for t in targets if t["status"] in ("complete","skipped"))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Yao Security Assessment — Batch Report {ts}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#f4f6f9;color:#2c3e50;font-size:14px;line-height:1.5}}
  a{{color:#2980b9}}
  .hdr{{background:linear-gradient(135deg,#0f1923 0%,#1a2a3a 60%,#0f3460 100%);color:#fff;padding:32px 44px}}
  .hdr h1{{font-size:1.7em;font-weight:700}}
  .hdr .sub{{color:#a8c6e8;margin-top:4px;font-size:0.88em}}
  .meta{{margin-top:14px;display:flex;gap:24px;flex-wrap:wrap}}
  .mi{{font-size:0.8em;color:#c8ddf0}}.mi strong{{color:#fff;display:block;font-size:1.05em}}
  .con{{max-width:1100px;margin:0 auto;padding:24px 18px}}
  .card{{background:#fff;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.07);padding:22px 26px;margin-bottom:20px}}
  .card h2{{font-size:1.05em;font-weight:700;color:#1a1a2e;border-bottom:2px solid #e8ecf0;padding-bottom:8px;margin-bottom:14px}}
  .totals{{display:flex;gap:28px;flex-wrap:wrap;margin-bottom:4px}}
  .tot .n{{font-size:1.8em;font-weight:800}}.tot .l{{font-size:0.7em;font-weight:700;text-transform:uppercase}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#f0f3f7;text-align:left;padding:9px 12px;font-size:0.76em;text-transform:uppercase;letter-spacing:.5px;color:#666}}
  td{{padding:10px 12px;border-bottom:1px solid #f0f3f7;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  .footer{{text-align:center;color:#aaa;font-size:0.76em;padding:18px}}
  @media print{{body{{background:#fff}}.card{{box-shadow:none;border:1px solid #e0e0e0}}}}
</style>
</head>
<body>
<div class="hdr">
  <h1>&#x1F6E1; Security Assessment — All Targets</h1>
  <div class="sub">Yao Pentest Wizard &nbsp;·&nbsp; Batch export generated {ts}</div>
  <div class="meta">
    <div class="mi"><strong>{len(targets)}</strong>Targets</div>
    <div class="mi"><strong>{sum(1 for t in targets if t['status'] in ('complete','skipped'))}</strong>Scanned</div>
    <div class="mi"><strong>{sum(1 for t in targets if t['status']=='offline')}</strong>Offline</div>
    <div class="mi"><strong>{sum(1 for t in targets if t['status']=='unreachable')}</strong>Unreachable</div>
    <div class="mi"><strong>{ts}</strong>Generated</div>
  </div>
</div>
<div class="con">

  <div class="card">
    <h2>&#x1F4CA; Combined Finding Totals</h2>
    <div class="totals">
      <div class="tot"><div class="n" style="color:#c0392b;">{total_c}</div><div class="l" style="color:#c0392b;">Critical</div></div>
      <div class="tot"><div class="n" style="color:#e67e22;">{total_h}</div><div class="l" style="color:#e67e22;">High</div></div>
      <div class="tot"><div class="n" style="color:#d4a017;">{total_m}</div><div class="l" style="color:#d4a017;">Medium</div></div>
      <div class="tot"><div class="n" style="color:#27ae60;">{total_l}</div><div class="l" style="color:#27ae60;">Low</div></div>
    </div>
    <div style="margin-top:14px;font-size:0.8em;color:#888;">
      Grade scale: &nbsp;
      <span style="background:#27ae60;color:#fff;padding:1px 7px;border-radius:6px;font-weight:700;">A</span> No HIGH/CRIT &nbsp;
      <span style="background:#f39c12;color:#fff;padding:1px 7px;border-radius:6px;font-weight:700;">B</span> 1–2 HIGH &nbsp;
      <span style="background:#e67e22;color:#fff;padding:1px 7px;border-radius:6px;font-weight:700;">C</span> 3+ HIGH &nbsp;
      <span style="background:#e74c3c;color:#fff;padding:1px 7px;border-radius:6px;font-weight:700;">D</span> 1 CRITICAL &nbsp;
      <span style="background:#c0392b;color:#fff;padding:1px 7px;border-radius:6px;font-weight:700;">F</span> 2+ CRITICAL
    </div>
  </div>

  <div class="card">
    <h2>&#x1F50D; Target Summary</h2>
    <table>
      <thead><tr><th>Target URL</th><th>Mode</th><th style="text-align:center;">Grade</th><th>Findings</th></tr></thead>
      <tbody>{summary_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>&#x1F9EA; Tools &amp; Parameters Run</h2>
    <p style="color:#555;font-size:0.85em;margin-bottom:12px;">Every command executed during this assessment, with exact flags.</p>
    <table>
      <thead><tr><th>#</th><th>Tool</th><th>Purpose</th><th>Command &amp; Parameters</th><th>Mode</th></tr></thead>
      <tbody>{params_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>&#x1F50D; Findings by Target — Full Detail</h2>
    <p style="color:#555;font-size:0.85em;margin-bottom:16px;">
      All findings with technical descriptions and DevOps remediation steps.
    </p>
    {all_findings_html if all_findings_html else "<p style='color:#888;'>No findings loaded — scans may still be in progress.</p>"}
  </div>

  <div class="card" style="border-left:4px solid #e67e22;">
    <h2>&#x26A0;&#xFE0F; Disclaimer</h2>
    <p style="color:#555;line-height:1.7;font-size:0.88em;">
      This report was generated automatically. All findings require manual verification before remediation.
      This does not constitute a professional penetration test. For regulated environments, engage a
      qualified security professional (CREST, CHECK, or equivalent accreditation).
    </p>
  </div>

</div>
<div class="footer">Yao Pentest Wizard &nbsp;·&nbsp; {ts} &nbsp;·&nbsp; For authorised use only</div>
</body></html>"""
    return html

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

        elif path == "/stop-batch":
            import subprocess, signal as _sig, json as _json
            stopped = []
            lock_file = os.path.join(BASE, ".batch.lock")
            # Kill batch-run.sh via PID file
            if os.path.exists(lock_file):
                try:
                    pid = int(open(lock_file).read().strip())
                    os.killpg(os.getpgid(pid), _sig.SIGTERM)
                    stopped.append(f"batch-run PID {pid}")
                except Exception:
                    pass
                try: os.remove(lock_file)
                except Exception: pass
            # Kill any remaining scan tools
            for pattern in ["pentest_wizard.py", "testssl.sh", "nmap --script", "hydra", "nuclei", "nikto", "ffuf", "corsy", "wafw00f"]:
                try:
                    subprocess.run(["pkill", "-9", "-f", pattern], capture_output=True)
                except Exception:
                    pass
            # Mark current batch as stopped (so it shows as complete in dashboard)
            batch_dir = find_active_batch()
            if batch_dir and not os.path.exists(os.path.join(batch_dir, "batch_complete")):
                # Write batch_complete with a STOPPED marker
                open(os.path.join(batch_dir, "batch_complete"), "w").write("STOPPED")
                # Update checkpoint: mark any un-checkpointed targets as STOPPED
                cp_file = os.path.join(batch_dir, "checkpoint.json")
                try:
                    cp = _json.load(open(cp_file)) if os.path.exists(cp_file) else {"completed": {}}
                    targets = _json.load(open(os.path.join(BASE, "targets.json")))["targets"]
                    for t in targets:
                        if t["url"] not in cp.get("completed", {}):
                            cp.setdefault("completed", {})[t["url"]] = {"status": "STOPPED", "duration": "0s"}
                    _json.dump(cp, open(cp_file, "w"), indent=2)
                except Exception:
                    pass
                stopped.append(f"batch marked stopped: {os.path.basename(batch_dir)}")
            msg = "Scan stopped. " + (", ".join(stopped) if stopped else "No active scan found.")
            self.send_json({"ok": True, "message": msg})

        elif path == "/run-batch":
            import subprocess, json as _json
            script = os.path.join(BASE, "batch-run.sh")
            try:
                body_data = {}
                cl = int(self.headers.get("Content-Length", 0))
                if cl:
                    try: body_data = _json.loads(self.rfile.read(cl))
                    except Exception: pass
                parallel = str(int(body_data.get("parallel", 4)))
                env = os.environ.copy()
                env["MAX_PARALLEL"] = parallel
                # Clear any stale lock before launching
                lock_file = os.path.join(BASE, ".batch.lock")
                if os.path.exists(lock_file):
                    try:
                        old_pid = int(open(lock_file).read().strip())
                        import signal
                        os.kill(old_pid, 0)  # raises if process doesn't exist
                    except (ValueError, ProcessLookupError, OSError):
                        os.remove(lock_file)  # stale lock — remove it
                subprocess.Popen(
                    ["bash", script],
                    stdout=open("/tmp/batch-master.log","w"),
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    env=env)
                self.send_json({"ok": True, "message": f"Batch scan launched ({parallel} parallel). Switch to the Scan Progress tab."})
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
            tools = ["nmap","nikto","hydra","ffuf","testssl.sh","jwt_tool",
                     "nuclei","wafw00f","checkdmarc","secretfinder","corsy"]
            result = {t: shutil.which(t) or "" for t in tools}
            self.send_json(result)

        elif path == "/history":
            self.send_json(get_all_batches())

        elif path == "/export":
            import datetime as dt
            qs = parse_qs(parsed.query)
            batch_override = qs.get("batch",[""])[0]
            html = generate_export_report(batch_override or None)
            fname = f"yao-pentest-report-{dt.datetime.now().strftime('%Y%m%d-%H%M')}.html"
            body  = html.encode("utf-8", errors="replace")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

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
