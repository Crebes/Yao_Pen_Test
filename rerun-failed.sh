#!/usr/bin/env bash
# Re-runs specific targets — used to fix unreachable targets and
# run Hydra against production targets.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/tmp/rerun-failed.log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# backoffice.staging corrects the previously unreachable backoffice.stg
# Production targets now run with full staging mode (Hydra included)
TARGETS=(
  "https://app.yao.legal|staging|/auth/login"
  "https://backoffice.yao.legal|staging|/auth/login"
  "https://uk.yao.legal|staging|/auth/login"
  "https://aus.yao.legal|staging|/auth/login"
)

log "Re-running ${#TARGETS[@]} targets (incl. production with Hydra)"
log "NOTE: pete@yaotechnology.com is in the username list — lockout accepted"

for entry in "${TARGETS[@]}"; do
  IFS='|' read -r URL MODE LOGIN_PATH <<< "$entry"
  log "--- $URL ($MODE) ---"
  if printf "${LOGIN_PATH}\n1\n/tmp/passwords.txt\n\n\n\n" | \
      python3 "$SCRIPT_DIR/pentest_wizard.py" "$URL" "--$MODE" --yes >> "$LOG" 2>&1; then
    SCAN_DIR=$(ls -dt "$SCRIPT_DIR"/pentest_*/ 2>/dev/null | head -1)
    COUNTS=$(python3 -c "
import json
s = json.load(open('${SCAN_DIR}summary.json'))
b = s['findings_by_severity']
print(b.get('CRITICAL',0), b.get('HIGH',0), b.get('MEDIUM',0), b.get('LOW',0))
" 2>/dev/null || echo "? ? ? ?")
    log "OK — C/H/M/L: $COUNTS → $SCAN_DIR"
  else
    log "ERROR scanning $URL"
  fi
done

log "All done. Log: $LOG"
echo "RERUN_COMPLETE"
