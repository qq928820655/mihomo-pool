#!/bin/bash
cd "$(dirname "$0")" || exit 1
PORT="${MPOOL_PORT:-8006}"
PIDS=$(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oE "pid=[0-9]+" | cut -d= -f2 | sort -u)
for pid in $PIDS; do kill "$pid" 2>/dev/null; done
pkill -f "bin/mihomo -d .*mihomo-pool/runtime" 2>/dev/null
sleep 1
echo "stopped mihomo-pool"
pkill -f "sing-box run -c .*mihomo-pool/runtime" 2>/dev/null
