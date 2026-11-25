#!/usr/bin/env bash
# 01_meta.sh — 用 SDK 工具提取 APK 元信息 / 签名证书 / Manifest
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/env.example" 2>/dev/null || true
BT="${ANDROID_BUILD_TOOLS:-/opt/android-sdk/build-tools/34.0.0}"
APK="$ROOT/apk/${APK_NAME:-dfm_official_cn.apk}"
REP="$ROOT/reports"
mkdir -p "$REP"

[ -f "$APK" ] || { echo "[!] APK 不存在，请先运行 00_fetch_apk.sh"; exit 1; }

echo "[*] aapt 读取 badging"
"$BT/aapt" dump badging "$APK" > "$REP/apk_meta.txt" 2>&1 || true

echo "[*] aapt 读取权限"
"$BT/aapt" dump permissions "$APK" > "$REP/permissions.txt" 2>&1 || true

echo "[*] apksigner 校验签名"
"$BT/apksigner" verify --print-certs -v "$APK" > "$REP/signature_cert.txt" 2>&1 || true

echo "[*] Manifest（XML 树）"
"$BT/aapt" dump xmltree "$APK" AndroidManifest.xml > "$REP/manifest.xml" 2>&1 || true

echo "[*] dex / so 清单"
unzip -l "$APK" | grep -E "classes[0-9]*\.dex|\.so$" > "$REP/dex_so_list.txt" || true

echo "[*] 完成，产物在 $REP"
