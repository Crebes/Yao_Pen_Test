#!/usr/bin/env bash
set -e
if [[ -d /opt/Corsy/.git ]]; then
    git -C /opt/Corsy pull --ff-only 2>&1 | tail -2
else
    git clone --depth 1 https://github.com/s0md3v/Corsy /opt/Corsy 2>&1 | tail -2
fi
pip3 install requests --break-system-packages -q 2>/dev/null || true
cat > /usr/local/bin/corsy << 'WRAPPER'
#!/usr/bin/env bash
exec python3 /opt/Corsy/corsy.py "$@"
WRAPPER
chmod +x /usr/local/bin/corsy
echo "corsy -> $(which corsy)"
python3 /opt/Corsy/corsy.py --help 2>&1 | head -2
