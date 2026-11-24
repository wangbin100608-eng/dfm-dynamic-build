#!/usr/bin/env bash
# 08_capture.sh — mitmdump 抓包（配合 SSL bypass / 系统证书）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/env.example" 2>/dev/null || true
PORT="${MITM_PORT:-8080}"
CAP="$ROOT/reports/capture"
mkdir -p "$CAP"

echo "[*] 启动 mitmdump，端口 $PORT，输出到 $CAP/flow.mitm"
echo "[*] 设备代理需设置为 <主机IP>:$PORT"
echo "[*] 按 Ctrl-C 停止"
mitmdump -p "$PORT" -w "$CAP/flow.mitm"
