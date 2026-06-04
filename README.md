# Yao Pentest Wizard

Automated SaaS security assessment tool. Runs Nmap, Nikto, testssl.sh, ffuf, Hydra, and JWT_Tool against a target URL and produces an HTML report with DevOps-grade remediation guidance.

---

## Quick start (Windows)

### 1. First-time setup — run once as Administrator

```powershell
# Open PowerShell as Administrator, then:
.\setup.ps1
```

This installs WSL2, Ubuntu 24.04, and all pentest tools automatically. No manual steps needed.

### 2. Run a scan

```powershell
# Staging — full suite including Hydra brute-force
.\pentest.ps1 https://app.stg.yao.legal --staging --yes

# Production — read-only, no Hydra
.\pentest.ps1 https://app.yao.legal --production --yes
```

The report opens automatically in your browser when the scan finishes.

---

## Quick start (Linux / macOS)

```bash
# Install tools
bash setup-ubuntu.sh

# Run a scan
./pentest https://app.stg.yao.legal --staging --yes
```

---

## Updating tools

Tools update automatically every 7 days when you run a scan. To force an update immediately:

```powershell
# Update all pentest tools
.\pentest.ps1 --update

# Refresh password wordlist from SecLists (10,000 common passwords)
.\pentest.ps1 --update-passwords

# Do both
.\pentest.ps1 --update --update-passwords
```

---

## Scan modes

| Mode | Flag | Modules | Hydra | Safe for live? |
|------|------|---------|-------|----------------|
| **Production** | `--production` / `-p` | 1–4, 6 | ✘ Excluded | ✔ Yes |
| **Staging** | `--staging` / `-s` | 1–6 | ✔ Included | ✘ No |
| **Custom** | `--modules 1,2,3` | Your choice | Your choice | Depends |

---

## Modules

| # | Tool | What it checks |
|---|------|---------------|
| 1 | **Nmap** | Open ports, service versions, known vulnerabilities |
| 2 | **Nikto** | Web server misconfigurations, missing headers |
| 3 | **testssl.sh** | TLS/SSL protocols, ciphers, certificates, BREACH, HSTS |
| 4 | **ffuf** | Hidden endpoints and directories |
| 5 | **Hydra** | Credential brute-force on the login endpoint |
| 6 | **JWT_Tool** | JWT token weaknesses (requires a token to be pasted) |

---

## Output

Each scan creates a timestamped folder, e.g. `pentest_app.stg.yao.legal_20260604_161148/`:

```
report.html          ← DevOps report — open in any browser
summary.json         ← Machine-readable findings
nmap.txt
nmap_vuln.txt
nikto.txt
testssl.json / testssl.txt
ffuf.json
hydra.txt            ← Staging only
rate_limit_check.json
yao_usernames.txt
```

---

## Files

| File | Purpose |
|------|---------|
| `pentest.ps1` | **Windows launcher** — run this on Windows |
| `setup.ps1` | **Windows installer** — run once as Administrator |
| `setup-ubuntu.sh` | **Linux/macOS installer** — also used by setup.ps1 |
| `pentest` | Linux/macOS launcher |
| `pentest_wizard.py` | Main wizard |
| `yao_ffuf_wordlist.txt` | Custom wordlist (319 entries, Yao-specific) |

---

## Legal notice

Only run this against targets you own or have **explicit written permission** to test.
Unauthorised use is illegal under the Computer Misuse Act 1990 (UK) and equivalent legislation in other jurisdictions.
