#!/usr/bin/env bash
# Batch runner — called from WSL, reads targets.json, runs pentest_wizard.py
# for each target in sequence. All output goes to batch_<timestamp>/batch.log
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_JSON="$SCRIPT_DIR/targets.json"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BATCH_DIR="$SCRIPT_DIR/batch_$TIMESTAMP"
LOG="$BATCH_DIR/batch.log"

mkdir -p "$BATCH_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

log "======================================================"
log " Yao Pentest Wizard — Batch Run"
log " Started: $(date)"
log " Targets JSON: $TARGETS_JSON"
log " Output dir:   $BATCH_DIR"
log "======================================================"

# Parse targets.json with Python (available in WSL)
TARGETS=$(python3 -c "
import json, sys
data = json.load(open('$TARGETS_JSON'))
for t in data['targets']:
    print(t['url'] + '|' + t['mode'] + '|' + t['login_path'])
")

TOTAL=$(echo "$TARGETS" | wc -l)
IDX=0
RESULTS=()

while IFS='|' read -r URL MODE LOGIN_PATH; do
    IDX=$((IDX + 1))
    log ""
    log "------------------------------------------------------"
    log "[$IDX/$TOTAL] $URL ($MODE)"
    log "------------------------------------------------------"

    START_TS=$(date +%s)
    MODE_FLAG="--$MODE"

    # Run the wizard — stdin provides interactive prompts
    if printf "${LOGIN_PATH}\n1\n/tmp/passwords.txt\n\n\n\n" | \
        python3 "$SCRIPT_DIR/pentest_wizard.py" "$URL" "$MODE_FLAG" --yes \
        >> "$LOG" 2>&1; then
        STATUS="OK"
    else
        STATUS="ERROR"
    fi

    END_TS=$(date +%s)
    DURATION=$((END_TS - START_TS))

    # Find the scan output dir just created (most recent pentest_* dir)
    SCAN_DIR=$(ls -dt "$SCRIPT_DIR"/pentest_*/ 2>/dev/null | head -1)

    # Extract finding counts from summary.json
    if [[ -f "$SCAN_DIR/summary.json" ]]; then
        COUNTS=$(python3 -c "
import json
s = json.load(open('$SCAN_DIR/summary.json'))
b = s['findings_by_severity']
print(b.get('CRITICAL',0), b.get('HIGH',0), b.get('MEDIUM',0), b.get('LOW',0))
")
        read -r C H M L <<< "$COUNTS"
    else
        C=0; H=0; M=0; L=0
    fi

    log "[$IDX/$TOTAL] $STATUS in ${DURATION}s — C:$C H:$H M:$M L:$L → $SCAN_DIR"
    RESULTS+=("$URL|$MODE|$STATUS|${DURATION}s|$C|$H|$M|$L|$SCAN_DIR")

done <<< "$TARGETS"

# Write results summary for the index report generator
RESULTS_FILE="$BATCH_DIR/results.json"
python3 -c "
import json, sys
results = []
for line in '''$(IFS=$'\n'; echo "${RESULTS[*]}")'''.strip().splitlines():
    parts = line.split('|')
    if len(parts) == 9:
        results.append({
            'url': parts[0], 'mode': parts[1], 'status': parts[2],
            'duration': parts[3],
            'critical': int(parts[4]), 'high': int(parts[5]),
            'medium': int(parts[6]), 'low': int(parts[7]),
            'scan_dir': parts[8].strip()
        })
json.dump({'batch_dir': '$BATCH_DIR', 'results': results}, open('$RESULTS_FILE', 'w'), indent=2)
print('Results written to $RESULTS_FILE')
"

log ""
log "======================================================"
log " Batch complete: $IDX targets scanned"
log " Results: $RESULTS_FILE"
log " Log:     $LOG"
log "======================================================"
echo "BATCH_COMPLETE:$RESULTS_FILE"
