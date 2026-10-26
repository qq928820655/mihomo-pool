#!/bin/bash
cd "$(dirname "$0")" || exit 1
if ss -tln 2>/dev/null | grep -q ":${MPOOL_PORT:-8006} "; then
  echo "mihomo-pool already listening on ${MPOOL_PORT:-8006}"
  exit 0
fi
mkdir -p configs/history runtime
setsid nohup .venv/bin/python server.py >> runtime/service.log 2>&1 &
echo "started mihomo-pool pid=$!"
