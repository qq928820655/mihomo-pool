#!/bin/bash
# mihomo-pool 一键部署：新服务器上只需要本目录 + python3
# 用法: ./deploy.sh   (可先编辑 .env 改 Token/端口)
set -e
cd "$(dirname "$0")"

echo "[1/3] python venv + pyyaml"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
if ! .venv/bin/python -c "import yaml" 2>/dev/null; then
  .venv/bin/pip install -q pyyaml -i "${PIP_INDEX:-https://pypi.tuna.tsinghua.edu.cn/simple}" \
    || .venv/bin/pip install -q pyyaml
fi

echo "[2/3] mihomo binary"
if [ ! -x bin/mihomo ]; then
  mkdir -p bin
  URL=$(.venv/bin/python - <<'EOF'
import json, urllib.request
d = json.load(urllib.request.urlopen("https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", timeout=30))
print([a["browser_download_url"] for a in d["assets"]
       if a["name"].startswith("mihomo-linux-amd64-compatible-") and a["name"].endswith(".gz")][0])
EOF
)
  curl -sL -m 300 -o bin/mihomo.gz "$URL"
  gunzip -f bin/mihomo.gz
  chmod 755 bin/mihomo
fi
./bin/mihomo -v | head -1

echo "[3/3] start"
if [ ! -f .env ]; then
  printf 'MPOOL_PORT=8006\nMPOOL_TOKEN=changeme\nMPOOL_CONTROLLER=127.0.0.1:9090\nMPOOL_LISTEN_BASE=17901\nMPOOL_LISTEN_MAX=32\n' > .env
  echo "已生成默认 .env，请修改 MPOOL_TOKEN！"
fi
./start.sh
sleep 3

PORT="${MPOOL_PORT:-8006}"
IP=$(curl -s -m 5 http://api.ipify.org || echo "<服务器IP>")
echo
echo "部署完成："
echo "  面板:     http://$IP:$PORT/          (Token 在 .env)"
echo "  节点订阅: http://$IP:$PORT/local-node.yaml   (clash 配置→新建→URL)"
echo "  测试:     curl -x http://$IP:${MPOOL_LOCAL_PORT:-7893} http://api.ipify.org"
