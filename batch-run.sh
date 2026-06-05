#!/usr/bin/env bash
# Batch runner — parallel edition.
# Runs up to MAX_PARALLEL targets concurrently.
# Usage: MAX_PARALLEL=4 bash batch-run.sh   (default: 4)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_JSON="$SCRIPT_DIR/targets.json"
MAX_PARALLEL="${MAX_PARALLEL:-4}"

# ── Checkpoint: resume or start fresh ─────────────────────
RESUME_DIR=""
for d in "$SCRIPT_DIR"/batch_*/; do
    if [[ -f "$d/checkpoint.json" && ! -f "$d/batch_complete" ]]; then
        RESUME_DIR="$d"; break
    fi
done

if [[ -n "$RESUME_DIR" ]]; then
    BATCH_DIR="$RESUME_DIR"
else
    BATCH_DIR="$SCRIPT_DIR/batch_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BATCH_DIR"
fi

LOG="$BATCH_DIR/batch.log"
CHECKPOINT="$BATCH_DIR/checkpoint.json"
LOCK="$BATCH_DIR/checkpoint.lock"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# Thread-safe checkpoint helpers (flock serialises concurrent writes)
checkpoint_done() {
    local url="$1" status="$2" dur="$3"
    (flock 9
     python3 - "$CHECKPOINT" "$url" "$status" "$dur" << 'PYEOF'
import json, sys
f, url, status, dur = sys.argv[1:]
try:    data = json.load(open(f))
except: data = {"completed": {}}
data.setdefault("completed", {})[url] = {"status": status, "duration": dur}
json.dump(data, open(f, "w"), indent=2)
PYEOF
    ) 9>"$LOCK"
}

is_done() {
    local url="$1"
    python3 - "$CHECKPOINT" "$url" << 'PYEOF'
import json, sys
f, url = sys.argv[1:]
try:    done = json.load(open(f)).get("completed", {})
except: done = {}
sys.exit(0 if url in done else 1)
PYEOF
}

http_precheck() {
    local url="$1"
    curl -s -o /dev/null -w "%{http_code}" \
        --max-time 10 --connect-timeout 5 \
        -H "User-Agent: PentestWizard/1.0" \
        "$url" 2>/dev/null || echo "000"
}

# ── Worker function (runs in background) ──────────────────
run_target() {
    local URL="$1" MODE="$2" LOGIN_PATH="$3" IDX="$4" TOTAL="$5"
    local HOST; HOST=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$URL').hostname)")
    local SAFE; SAFE=$(echo "$HOST" | sed 's/[^a-zA-Z0-9._-]/_/g')
    local TARGET_LOG="$BATCH_DIR/scan_${SAFE}.log"

    log "  START [$IDX/$TOTAL] $URL"

    # Pre-check
    local CODE; CODE=$(http_precheck "$URL")
    if [[ "$CODE" == "503" ]]; then
        log "  OFFLINE [$IDX/$TOTAL] $URL (503)"
        mkdir -p "$SCRIPT_DIR/pentest_${SAFE}_$(date +%Y%m%d_%H%M%S)"
        local SCAN_DIR; SCAN_DIR=$(ls -dt "$SCRIPT_DIR/pentest_${SAFE}_"*/ 2>/dev/null | head -1)
        echo "503 Service Temporarily Unavailable" > "$SCAN_DIR/nmap.txt"
        echo '{"findings_by_severity":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":1},"findings":[{"tool":"Pre-check","severity":"INFO","title":"Service offline — HTTP 503","detail":"Pre-flight check returned 503. Scan skipped.","recommendation":"Verify service is running.","steps":[],"refs":[]}]}' > "$SCAN_DIR/summary.json"
        checkpoint_done "$URL" "OFFLINE" "0s"
        return
    fi
    if [[ "$CODE" == "000" ]]; then
        local HOST_ONLY; HOST_ONLY=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$URL').hostname)")
        if ! nslookup "$HOST_ONLY" > /dev/null 2>&1; then
            log "  UNREACHABLE [$IDX/$TOTAL] $URL (DNS failed)"
            checkpoint_done "$URL" "UNREACHABLE" "0s"
            return
        fi
    fi

    local START_TS; START_TS=$(date +%s)

    # All interactive prompts are handled via CLI args or batch-mode defaults.
    # Redirect stdin from /dev/null so any remaining input() raises EOF cleanly.
    python3 "$SCRIPT_DIR/pentest_wizard.py" "$URL" "--${MODE}" --yes \
        --login-path "$LOGIN_PATH" \
        < /dev/null \
        > "$TARGET_LOG" 2>&1
    local EXIT=$?

    local DURATION=$(( $(date +%s) - START_TS ))
    local STATUS="OK"
    [[ $EXIT -eq 2 ]] && STATUS="UNREACHABLE"
    [[ $EXIT -ne 0 && $EXIT -ne 2 ]] && STATUS="ERROR($EXIT)"

    # Append target log to master log
    echo "" >> "$LOG"
    echo "=== $URL ===" >> "$LOG"
    cat "$TARGET_LOG" >> "$LOG" 2>/dev/null || true

    # Read finding counts
    local SCAN_DIR; SCAN_DIR=$(ls -dt "$SCRIPT_DIR/pentest_${SAFE}_"*/ 2>/dev/null | head -1)
    local C=0 H=0 M=0 L=0
    if [[ -n "$SCAN_DIR" && -f "$SCAN_DIR/summary.json" ]]; then
        read -r C H M L <<< "$(python3 -c "
import json; s=json.load(open('$SCAN_DIR/summary.json')); b=s['findings_by_severity']
print(b.get('CRITICAL',0),b.get('HIGH',0),b.get('MEDIUM',0),b.get('LOW',0))" 2>/dev/null || echo '0 0 0 0')"
    fi

    checkpoint_done "$URL" "$STATUS" "${DURATION}s"
    log "  DONE [$IDX/$TOTAL] $STATUS ${DURATION}s C:$C H:$H M:$M L:$L — $URL"
}

# ── Main ──────────────────────────────────────────────────
log "======================================================"
log " Yao Pentest Wizard — Parallel Batch (max $MAX_PARALLEL)"
log " Started: $(date)"
log " Batch dir: $BATCH_DIR"
log "======================================================"

# Step 0: discovery (fresh runs only)
if [[ -z "$RESUME_DIR" ]]; then
    log ""
    log "--- Step 0: Subdomain discovery ---"
    python3 "$SCRIPT_DIR/discover-subdomains.py" >> "$LOG" 2>&1
    [[ -f "$SCRIPT_DIR/subdomain_discovery.json" ]] && \
        python3 "$SCRIPT_DIR/update-targets.py" >> "$LOG" 2>&1 && \
        log "Targets updated from discovery"
else
    log "--- Resuming — skipping discovery ---"
fi

# Parse targets
TARGETS=$(python3 -c "
import json
for t in json.load(open('$TARGETS_JSON'))['targets']:
    print(t['url']+'|'+t['mode']+'|'+t['login_path'])
")
TOTAL=$(echo "$TARGETS" | wc -l)
IDX=0

log ""
log "Running $TOTAL targets with MAX_PARALLEL=$MAX_PARALLEL"
log ""

# Launch workers with concurrency cap
while IFS='|' read -r URL MODE LOGIN_PATH; do
    IDX=$((IDX + 1))

    if is_done "$URL"; then
        log "  SKIP [$IDX/$TOTAL] already completed — $URL"
        continue
    fi

    # Wait until a worker slot is free
    while [[ $(jobs -rp | wc -l) -ge $MAX_PARALLEL ]]; do
        sleep 3
    done

    run_target "$URL" "$MODE" "$LOGIN_PATH" "$IDX" "$TOTAL" &

done <<< "$TARGETS"

# Wait for all workers to finish
log ""
log "All targets launched — waiting for workers to complete..."
wait

# Mark complete and save a snapshot report
touch "$BATCH_DIR/batch_complete"
python3 - "$BATCH_DIR" << 'PYEOF' 2>/dev/null || true
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest')
batch_dir = sys.argv[1]
script_dir = os.path.dirname(os.path.abspath(batch_dir))
sys.path.insert(0, script_dir)
# Minimal import to generate report
exec(open(os.path.join(script_dir, 'dashboard.py')).read().split('class Handler')[0])
html = generate_export_report(batch_dir)
open(os.path.join(batch_dir, 'report.html'), 'w').write(html)
print(f'Snapshot report saved: {batch_dir}/report.html')
PYEOF
DONE=$(python3 -c "
import json
try:
    d=json.load(open('$CHECKPOINT')).get('completed',{})
    print(len(d))
except: print(0)" 2>/dev/null || echo 0)

log ""
log "======================================================"
log " Batch complete: $DONE/$TOTAL targets finished"
log " Batch dir: $BATCH_DIR"
log "======================================================"
echo "BATCH_COMPLETE:$BATCH_DIR"
