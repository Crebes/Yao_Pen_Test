#!/usr/bin/env bash
# Batch runner — reads targets.json, runs pentest_wizard.py for each target.
# Features:
#   - Pre-checks each target for 503/DNS before running the full scan
#   - Checkpoint file so the batch resumes after a WSL restart
#   - All output tee'd to batch_TIMESTAMP/batch.log
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_JSON="$SCRIPT_DIR/targets.json"

# ── Checkpoint: resume an existing batch or start fresh ───
# If a batch dir exists with an incomplete checkpoint, resume it.
# Otherwise create a new one.
RESUME_DIR=""
for d in "$SCRIPT_DIR"/batch_*/; do
    if [[ -f "$d/checkpoint.json" && ! -f "$d/batch_complete" ]]; then
        RESUME_DIR="$d"; break
    fi
done

if [[ -n "$RESUME_DIR" ]]; then
    BATCH_DIR="$RESUME_DIR"
    echo "[$(date '+%H:%M:%S')] Resuming interrupted batch: $BATCH_DIR"
else
    TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
    BATCH_DIR="$SCRIPT_DIR/batch_$TIMESTAMP"
    mkdir -p "$BATCH_DIR"
fi

LOG="$BATCH_DIR/batch.log"
CHECKPOINT="$BATCH_DIR/checkpoint.json"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# Checkpoint helpers
checkpoint_done() {
    local url="$1"
    python3 - "$CHECKPOINT" "$url" << 'PYEOF'
import json, sys
cp_file, url = sys.argv[1], sys.argv[2]
try:    done = json.load(open(cp_file)).get("completed", [])
except: done = []
if url not in done:
    done.append(url)
json.dump({"completed": done}, open(cp_file, "w"), indent=2)
PYEOF
}

is_done() {
    local url="$1"
    python3 - "$CHECKPOINT" "$url" << 'PYEOF'
import json, sys
cp_file, url = sys.argv[1], sys.argv[2]
try:    done = json.load(open(cp_file)).get("completed", [])
except: done = []
sys.exit(0 if url in done else 1)
PYEOF
}

# Quick HTTP pre-check — returns status code or "DNS" / "TIMEOUT"
http_precheck() {
    local url="$1"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 10 --connect-timeout 5 \
        -H "User-Agent: PentestWizard/1.0 (authorised security test)" \
        "$url" 2>/dev/null) || true
    if [[ -z "$code" || "$code" == "000" ]]; then
        # Try DNS resolution separately
        local host
        host=$(python3 -c "from urllib.parse import urlparse; print(urlparse('$url').hostname)")
        if ! nslookup "$host" > /dev/null 2>&1; then
            echo "DNS"; return
        fi
        echo "TIMEOUT"; return
    fi
    echo "$code"
}

log "======================================================"
log " Yao Pentest Wizard — Batch Run"
log " Started: $(date)"
log " Batch dir: $BATCH_DIR"
log "======================================================"

# ── Step 0: Subdomain discovery (only on fresh start) ─────
if [[ -z "$RESUME_DIR" ]]; then
    log ""
    log "--- Step 0: Subdomain discovery ---"
    python3 "$SCRIPT_DIR/discover-subdomains.py" >> "$LOG" 2>&1
    if [[ -f "$SCRIPT_DIR/subdomain_discovery.json" ]]; then
        python3 "$SCRIPT_DIR/update-targets.py" >> "$LOG" 2>&1
        log "Targets updated from discovery"
    fi
else
    log "--- Resuming — skipping discovery ---"
fi

# ── Parse targets ──────────────────────────────────────────
TARGETS=$(python3 -c "
import json
data = json.load(open('$TARGETS_JSON'))
for t in data['targets']:
    print(t['url'] + '|' + t['mode'] + '|' + t['login_path'])
")
TOTAL=$(echo "$TARGETS" | wc -l)
IDX=0

while IFS='|' read -r URL MODE LOGIN_PATH; do
    IDX=$((IDX + 1))

    # ── Skip if already completed in a previous run ────────
    if is_done "$URL"; then
        log "[$IDX/$TOTAL] SKIPPED (already completed) — $URL"
        continue
    fi

    log ""
    log "------------------------------------------------------"
    log "[$IDX/$TOTAL] $URL ($MODE)"
    log "------------------------------------------------------"

    # ── Pre-check: 503 / DNS before running full scan ──────
    log "  Pre-check: testing $URL..."
    PRECHECK=$(http_precheck "$URL")
    log "  Pre-check result: HTTP $PRECHECK"

    if [[ "$PRECHECK" == "503" ]]; then
        log "  OFFLINE (503) — service is down. Skipping full scan."
        mkdir -p "$SCRIPT_DIR/pentest_$(echo "$URL" | sed 's|https\?://||' | sed 's|/.*||')_$(date +%Y%m%d_%H%M%S)"
        SCAN_DIR=$(ls -dt "$SCRIPT_DIR"/pentest_*/ 2>/dev/null | head -1)
        # Write a minimal nmap.txt so build-index.py detects OFFLINE
        echo "503 Service Temporarily Unavailable — pre-check confirmed offline" > "$SCAN_DIR/nmap.txt"
        echo '{"findings_by_severity":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":1},"findings":[{"tool":"Pre-check","severity":"INFO","title":"Service offline — HTTP 503","detail":"Pre-flight HTTP check returned 503. No scan performed.","recommendation":"Verify the service is running before re-scanning.","steps":[],"refs":[]}]}' > "$SCAN_DIR/summary.json"
        checkpoint_done "$URL"
        log "[$IDX/$TOTAL] OFFLINE in 0s — $SCAN_DIR"
        continue
    fi

    if [[ "$PRECHECK" == "DNS" ]]; then
        log "  UNREACHABLE (DNS failed) — skipping."
        checkpoint_done "$URL"
        log "[$IDX/$TOTAL] UNREACHABLE — $URL"
        continue
    fi

    if [[ "$PRECHECK" == "TIMEOUT" ]]; then
        log "  TIMEOUT on pre-check — will attempt scan anyway."
    fi

    # ── Run the wizard ─────────────────────────────────────
    START_TS=$(date +%s)
    printf "${LOGIN_PATH}\n1\n/tmp/passwords.txt\n\n\n\n" | \
        python3 "$SCRIPT_DIR/pentest_wizard.py" "$URL" "--$MODE" --yes \
        >> "$LOG" 2>&1
    EXIT=$?
    DURATION=$(( $(date +%s) - START_TS ))

    if [[ $EXIT -eq 2 ]]; then   STATUS="UNREACHABLE"
    elif [[ $EXIT -eq 0 ]]; then STATUS="OK"
    else                          STATUS="ERROR ($EXIT)"
    fi

    SCAN_DIR=$(ls -dt "$SCRIPT_DIR"/pentest_*/ 2>/dev/null | head -1)

    C=0; H=0; M=0; L=0
    if [[ -f "$SCAN_DIR/summary.json" ]]; then
        read -r C H M L <<< "$(python3 -c "
import json; s=json.load(open('$SCAN_DIR/summary.json')); b=s['findings_by_severity']
print(b.get('CRITICAL',0),b.get('HIGH',0),b.get('MEDIUM',0),b.get('LOW',0))")"
    fi

    checkpoint_done "$URL"
    log "[$IDX/$TOTAL] $STATUS in ${DURATION}s — C:$C H:$H M:$M L:$L → $SCAN_DIR"

done <<< "$TARGETS"

# ── Mark batch complete ────────────────────────────────────
touch "$BATCH_DIR/batch_complete"
log ""
log "======================================================"
log " Batch complete: $TOTAL targets processed"
log " Batch dir: $BATCH_DIR"
log "======================================================"
echo "BATCH_COMPLETE:$BATCH_DIR"
