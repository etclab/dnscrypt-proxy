#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_DIR="${SCRIPT_DIR}/dnscrypt-proxy"
CONFIG_FILE="${PROXY_DIR}/dnscrypt-proxy.toml"

# --- Tear down any existing dnscrypt-proxy ---
if pgrep -x dnscrypt-proxy >/dev/null 2>&1; then
    echo "Stopping existing dnscrypt-proxy..."
    pkill -x dnscrypt-proxy || true
    sleep 2
    # Force kill if still running
    if pgrep -x dnscrypt-proxy >/dev/null 2>&1; then
        pkill -9 -x dnscrypt-proxy || true
    fi
fi

# --- Build ---
echo "Building dnscrypt-proxy..."
cd "$PROXY_DIR"
go build -mod vendor
echo "Build complete."

# --- Run ---
echo "Starting dnscrypt-proxy (ODoH mode) on 127.0.0.1:5300..."
exec ./dnscrypt-proxy -config "$CONFIG_FILE"
