#!/usr/bin/env bash
# =============================================================
#  Yao Pentest Wizard — dependency installer
#  Run once: bash setup.sh
#  Supports: Debian/Ubuntu/Kali, macOS (Homebrew)
# =============================================================

set -e

GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; BOLD="\033[1m"; RESET="\033[0m"
ok()   { echo -e "${GREEN}✔  $*${RESET}"; }
warn() { echo -e "${YELLOW}⚠  $*${RESET}"; }
err()  { echo -e "${RED}✘  $*${RESET}"; }
h()    { echo -e "\n${BOLD}$*${RESET}"; }

h "=== Yao Pentest Wizard — Setup ==="

# ── Detect OS ─────────────────────────────────────────────
if [[ "$OSTYPE" == "darwin"* ]]; then
  OS="mac"
elif command -v apt-get &>/dev/null; then
  OS="debian"
else
  warn "Unknown OS — will attempt installs but some may fail."
  OS="unknown"
fi
ok "Detected OS: $OS"

# ── Python 3 ──────────────────────────────────────────────
h "Checking Python 3..."
if command -v python3 &>/dev/null; then
  ok "python3 found: $(python3 --version)"
else
  err "python3 not found. Install it manually and re-run."
  exit 1
fi

# ── Nmap ──────────────────────────────────────────────────
h "Installing nmap..."
if command -v nmap &>/dev/null; then
  ok "nmap already installed: $(nmap --version | head -1)"
elif [[ "$OS" == "mac" ]]; then
  brew install nmap && ok "nmap installed"
elif [[ "$OS" == "debian" ]]; then
  sudo apt-get install -y nmap && ok "nmap installed"
fi

# ── Nikto ─────────────────────────────────────────────────
h "Installing nikto..."
if command -v nikto &>/dev/null; then
  ok "nikto already installed"
elif [[ "$OS" == "mac" ]]; then
  brew install nikto && ok "nikto installed"
elif [[ "$OS" == "debian" ]]; then
  sudo apt-get install -y nikto && ok "nikto installed"
fi

# ── Hydra ─────────────────────────────────────────────────
h "Installing hydra..."
if command -v hydra &>/dev/null; then
  ok "hydra already installed"
elif [[ "$OS" == "mac" ]]; then
  brew install hydra && ok "hydra installed"
elif [[ "$OS" == "debian" ]]; then
  sudo apt-get install -y hydra && ok "hydra installed"
fi

# ── ffuf ──────────────────────────────────────────────────
h "Installing ffuf..."
if command -v ffuf &>/dev/null; then
  ok "ffuf already installed"
elif [[ "$OS" == "mac" ]]; then
  brew install ffuf && ok "ffuf installed"
elif [[ "$OS" == "debian" ]]; then
  # Try apt first (available in Kali), fall back to Go install
  if apt-cache show ffuf &>/dev/null 2>&1; then
    sudo apt-get install -y ffuf && ok "ffuf installed via apt"
  elif command -v go &>/dev/null; then
    go install github.com/ffuf/ffuf/v2@latest
    export PATH="$PATH:$(go env GOPATH)/bin"
    ok "ffuf installed via go"
  else
    warn "ffuf not installable automatically — install Go first: https://go.dev/dl/"
    warn "Then run: go install github.com/ffuf/ffuf/v2@latest"
  fi
fi

# ── testssl.sh ────────────────────────────────────────────
h "Installing testssl.sh..."
if command -v testssl.sh &>/dev/null; then
  ok "testssl.sh already on PATH"
else
  TESTSSL_DIR="$HOME/testssl.sh"
  if [[ -d "$TESTSSL_DIR" ]]; then
    ok "testssl.sh repo already cloned at $TESTSSL_DIR"
  else
    git clone --depth 1 https://github.com/drwetter/testssl.sh "$TESTSSL_DIR"
    ok "testssl.sh cloned to $TESTSSL_DIR"
  fi
  sudo ln -sf "$TESTSSL_DIR/testssl.sh" /usr/local/bin/testssl.sh
  sudo chmod +x /usr/local/bin/testssl.sh
  ok "testssl.sh linked to /usr/local/bin/testssl.sh"
fi

# ── jwt_tool ──────────────────────────────────────────────
h "Installing jwt_tool..."
if command -v jwt_tool &>/dev/null; then
  ok "jwt_tool already installed"
else
  pip3 install jwt_tool --quiet && ok "jwt_tool installed via pip3" || {
    warn "pip3 install failed — trying pipx..."
    if command -v pipx &>/dev/null; then
      pipx install jwt_tool && ok "jwt_tool installed via pipx"
    else
      warn "jwt_tool could not be installed automatically."
      warn "Run manually: pip3 install jwt_tool"
    fi
  }
fi

# ── Password wordlist ─────────────────────────────────────
h "Checking password wordlist..."
ROCKYOU="/usr/share/wordlists/rockyou.txt"
ROCKYOU_GZ="/usr/share/wordlists/rockyou.txt.gz"
SECLISTS_TOP="$HOME/SecLists/Passwords/Common-Credentials/10-million-passwords-top-10000.txt"

if [[ -f "$ROCKYOU" ]]; then
  ok "rockyou.txt found at $ROCKYOU"
elif [[ -f "$ROCKYOU_GZ" ]]; then
  sudo gzip -d "$ROCKYOU_GZ" && ok "rockyou.txt extracted from .gz"
elif [[ -f "$SECLISTS_TOP" ]]; then
  ok "SecLists top-10k passwords found at $SECLISTS_TOP"
else
  warn "No password list found. Downloading SecLists top 10k..."
  mkdir -p "$HOME/SecLists/Passwords/Common-Credentials"
  curl -sSL -o "$SECLISTS_TOP" \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-passwords-top-10000.txt" \
    && ok "Downloaded to $SECLISTS_TOP" \
    || warn "Download failed — run manually or provide your own password list."
fi

# ── Make launcher executable ──────────────────────────────
h "Setting permissions..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/pentest"
chmod +x "$SCRIPT_DIR/pentest_wizard.py"
ok "pentest launcher is executable"

# ── Done ──────────────────────────────────────────────────
echo -e "\n${BOLD}${GREEN}
 ╔══════════════════════════════════════════════╗
 ║           Setup complete!                   ║
 ╚══════════════════════════════════════════════╝
${RESET}
 Run a scan:
   ${BOLD}./pentest https://app.yaotechnology.com${RESET}

 Run all modules non-interactively (for Claude Code):
   ${BOLD}./pentest https://app.yaotechnology.com --all --yes${RESET}

 Run specific modules:
   ${BOLD}./pentest https://app.yaotechnology.com --modules 1,2,3${RESET}
"
