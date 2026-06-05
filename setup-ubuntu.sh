#!/usr/bin/env bash
# =============================================================
#  Yao Pentest Wizard — Ubuntu tool installer
#  Run inside WSL Ubuntu 24.04 (or any Debian/Ubuntu/Kali).
#  Called automatically by setup.ps1, or run directly on Linux/macOS.
# =============================================================
set -euo pipefail

GREEN="\033[92m"; YELLOW="\033[93m"; RED="\033[91m"; CYAN="\033[96m"; RESET="\033[0m"
ok()   { echo -e "${GREEN}  [OK] $*${RESET}"; }
info() { echo -e "${CYAN}  [..] $*${RESET}"; }
warn() { echo -e "${YELLOW}  [!!] $*${RESET}"; }
fail() { echo -e "${RED}  [XX] $*${RESET}"; exit 1; }

echo -e "\n${CYAN}=== Installing pentest tools ===${RESET}\n"

# ── Detect OS ─────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v brew &>/dev/null; then
    PKG_MGR="brew"
else
    fail "Unsupported OS — requires apt (Debian/Ubuntu/Kali) or Homebrew (macOS)"
fi

# ── apt packages ──────────────────────────────────────────
if [[ "$PKG_MGR" == "apt" ]]; then
    info "Updating apt..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq

    info "Installing core tools..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        nmap nikto hydra \
        python3 python3-pip \
        git curl wget \
        dnsutils \
        golang-go \
        perl openssl 2>&1 | tail -5
    ok "apt packages installed"

elif [[ "$PKG_MGR" == "brew" ]]; then
    info "Installing via Homebrew..."
    brew install nmap nikto hydra go python3 2>&1 | tail -5
    ok "Homebrew packages installed"
fi

# ── ffuf (always get latest) ──────────────────────────────
info "Installing/updating ffuf..."
if [[ "$PKG_MGR" == "apt" ]]; then
    go install github.com/ffuf/ffuf/v2@latest 2>&1 | tail -3
    cp ~/go/bin/ffuf /usr/local/bin/ffuf
else
    brew upgrade ffuf 2>/dev/null || brew install ffuf
fi
ok "ffuf → $(ffuf -V 2>&1 | head -1)"

# ── testssl.sh (git pull to update) ───────────────────────
info "Installing/updating testssl.sh..."
if [[ -d /opt/testssl.sh/.git ]]; then
    git -C /opt/testssl.sh pull --ff-only 2>&1 | tail -2
else
    rm -rf /opt/testssl.sh
    git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh 2>&1 | tail -3
fi
ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
chmod +x /opt/testssl.sh/testssl.sh
ok "testssl.sh → $(testssl.sh --version 2>&1 | grep -m1 version || echo 'installed')"

# ── jwt_tool (git pull to update) ─────────────────────────
info "Installing/updating jwt_tool..."
if [[ -d /opt/jwt_tool/.git ]]; then
    git -C /opt/jwt_tool pull --ff-only 2>&1 | tail -2
else
    rm -rf /opt/jwt_tool
    git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>&1 | tail -3
fi
pip3 install termcolor cprint --break-system-packages -q 2>/dev/null || \
pip3 install termcolor cprint -q 2>/dev/null || true
cat > /usr/local/bin/jwt_tool <<'JWTEOF'
#!/usr/bin/env bash
exec python3 /opt/jwt_tool/jwt_tool.py "$@"
JWTEOF
chmod +x /usr/local/bin/jwt_tool
ok "jwt_tool installed → $(which jwt_tool)"

# ── Nuclei ────────────────────────────────────────────────
info "Installing/updating nuclei..."
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>&1 | tail -3
cp ~/go/bin/nuclei /usr/local/bin/nuclei 2>/dev/null || true
nuclei -update-templates -silent 2>/dev/null || true
ok "nuclei → $(which nuclei 2>/dev/null || echo installed)"

# ── wafw00f ────────────────────────────────────────────────
info "Installing/updating wafw00f..."
pip3 install wafw00f --break-system-packages -q 2>/dev/null || pip3 install wafw00f -q 2>/dev/null || true
ok "wafw00f → $(which wafw00f 2>/dev/null || echo installed)"

# ── checkdmarc ─────────────────────────────────────────────
info "Installing/updating checkdmarc..."
pip3 install checkdmarc --break-system-packages -q 2>/dev/null || pip3 install checkdmarc -q 2>/dev/null || true
ok "checkdmarc → $(which checkdmarc 2>/dev/null || echo installed)"

# ── SecretFinder ───────────────────────────────────────────
info "Installing/updating SecretFinder..."
if [[ -d /opt/SecretFinder/.git ]]; then
    git -C /opt/SecretFinder pull --ff-only 2>&1 | tail -2
else
    git clone --depth 1 https://github.com/m4ll0k/SecretFinder /opt/SecretFinder 2>&1 | tail -2
fi
pip3 install jsbeautifier requests --break-system-packages -q 2>/dev/null || \
    pip3 install jsbeautifier requests -q 2>/dev/null || true
cat > /usr/local/bin/secretfinder << 'SFEOF'
#!/usr/bin/env bash
exec python3 /opt/SecretFinder/SecretFinder.py "$@"
SFEOF
chmod +x /usr/local/bin/secretfinder
ok "secretfinder → $(which secretfinder)"

# ── DNS fix (WSL only) ────────────────────────────────────
if grep -qi microsoft /proc/version 2>/dev/null; then
    info "WSL detected — ensuring DNS is set..."
    if ! grep -q "8.8.8.8" /etc/resolv.conf 2>/dev/null; then
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    fi
    if ! grep -q "generateResolvConf" /etc/wsl.conf 2>/dev/null; then
        printf "\n[network]\ngenerateResolvConf = false\n" >> /etc/wsl.conf
    fi
    ok "WSL DNS configured"
fi

# ── Password wordlist ─────────────────────────────────────
if [[ ! -f /tmp/passwords.txt ]]; then
    info "Creating default password wordlist..."
    cat > /tmp/passwords.txt <<'EOF'
password
Password1
password123
Password123
Password123!
changeme
Welcome1
Welcome123
admin
admin123
letmein
qwerty
123456
111111
monkey
dragon
master
pass123
test123
staging
staging123
Staging123!
yao
yao123
Yao123!
yaolegal
yaolegal123
YaoLegal1!
EOF
    ok "Password wordlist → /tmp/passwords.txt"
fi

# ── Final check ───────────────────────────────────────────
echo ""
echo -e "${CYAN}=== Tool check ===${RESET}"
ALL_OK=true
for tool in nmap nikto hydra ffuf testssl.sh jwt_tool nuclei wafw00f checkdmarc secretfinder; do
    path=$(command -v "$tool" 2>/dev/null || true)
    if [[ -n "$path" ]]; then
        ok "$tool → $path"
    else
        warn "$tool NOT FOUND"
        ALL_OK=false
    fi
done

echo ""
if $ALL_OK; then
    echo -e "${GREEN}  All tools ready.${RESET}"
else
    echo -e "${YELLOW}  Some tools missing — check output above.${RESET}"
    exit 1
fi
