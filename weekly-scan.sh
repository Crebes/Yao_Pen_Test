#!/usr/bin/env bash
# =============================================================
#  Yao Pentest — Weekly Automated Scan
#  1. Updates all pentest tools
#  2. Refreshes password wordlist from SecLists
#  3. Runs full batch scan against all targets
#  4. Emails the combined HTML report
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/tmp/weekly-scan-$(date +%Y%m%d_%H%M%S).log"
EMAIL_CONFIG="$SCRIPT_DIR/email-config.json"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "=============================================="
log " Yao Pentest — Weekly Automated Scan"
log " Started: $(date)"
log "=============================================="

# ── Fix DNS (survives WSL restarts) ────────────────────────
log "Setting DNS..."
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf

# ── Step 1: Update all tools ───────────────────────────────
log ""
log "--- Step 1: Updating pentest tools ---"
if bash "$SCRIPT_DIR/setup-ubuntu.sh" >> "$LOG" 2>&1; then
    log "Tools updated successfully"
else
    log "WARNING: Tool update had errors — continuing with existing versions"
fi

# ── Step 2: Update password wordlist ──────────────────────
log ""
log "--- Step 2: Refreshing password wordlist ---"
PASS_URLS=(
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-passwords-top-10000.txt"
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-passwords-shortlist.txt"
)
PASS_UPDATED=false
for url in "${PASS_URLS[@]}"; do
    if curl -fsSL --max-time 30 "$url" -o /tmp/passwords_new.txt 2>/dev/null; then
        COUNT=$(wc -l < /tmp/passwords_new.txt)
        mv /tmp/passwords_new.txt /tmp/passwords.txt
        log "Password list updated: $COUNT entries from $url"
        PASS_UPDATED=true
        break
    fi
done
if [[ "$PASS_UPDATED" == "false" ]]; then
    log "WARNING: Could not download password list — using existing /tmp/passwords.txt"
fi

# ── Step 3: Run full batch scan ────────────────────────────
log ""
log "--- Step 3: Running batch scan ---"
rm -f "$SCRIPT_DIR/.batch.lock"

# Clean up incomplete batches from previous runs
python3 "$SCRIPT_DIR/cleanup-batches.py" >> "$LOG" 2>&1

# Run batch and wait for it to finish
MAX_PARALLEL="${MAX_PARALLEL:-4}" bash "$SCRIPT_DIR/batch-run.sh" >> "$LOG" 2>&1
SCAN_EXIT=$?

if [[ $SCAN_EXIT -ne 0 ]]; then
    log "WARNING: Batch scan exited with code $SCAN_EXIT"
fi

# ── Step 4: Generate and email report ─────────────────────
log ""
log "--- Step 4: Generating and emailing report ---"

if [[ ! -f "$EMAIL_CONFIG" ]]; then
    log "ERROR: email-config.json not found at $EMAIL_CONFIG"
    log "Run: cp email-config.example.json email-config.json and fill in your details"
    exit 1
fi

python3 "$SCRIPT_DIR/send-report.py" \
    --config "$EMAIL_CONFIG" \
    --log "$LOG" \
    2>&1 | tee -a "$LOG"

log ""
log "=============================================="
log " Weekly scan complete: $(date)"
log " Log: $LOG"
log "=============================================="
