#!/usr/bin/env bash
# 02_decompile.sh — apktool decode + jadx 反编译
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/env.example" 2>/dev/null || true
APK="$ROOT/apk/${APK_NAME:-dfm_official_cn.apk}"
TOOLS="$ROOT/tools"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

[ -f "$APK" ] || { echo "[!] APK 不存在"; exit 1; }

echo "[*] apktool decode（smali + 资源）"
java -jar "$TOOLS/apktool.jar" decode -f -o "$BUILD/apktool" "$APK"

echo "[*] jadx 反编译（java 源码）"
if [ -f "$TOOLS/jadx.zip" ] && [ ! -d "$TOOLS/jadx" ]; then
  unzip -q "$TOOLS/jadx.zip" -d "$TOOLS/jadx_extract"
  mv "$TOOLS/jadx_extract"/jadx-* "$TOOLS/jadx" 2>/dev/null || true
fi
JADX_BIN=$(find "$TOOLS" -path "*/bin/jadx" -type f | head -1)
if [ -n "$JADX_BIN" ]; then
  chmod +x "$JADX_BIN"
  "$JADX_BIN" -d "$BUILD/jadx" "$APK"
else
  echo "[!] 未找到 jadx 可执行文件，跳过"
fi

echo "[*] 从 java 源码提取 URL"
grep -rhoE "https?://[a-zA-Z0-9./?=&_%-]+" "$BUILD/jadx"/sources 2>/dev/null \
  | sort -u > "$ROOT/reports/dex_urls.txt" || true
echo "[*] 完成"
