#!/usr/bin/env bash
# 09_rebuild.sh — zipalign + apksigner 重签名打包（仅本地分析用）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/env.example" 2>/dev/null || true
BT="${ANDROID_BUILD_TOOLS:-/opt/android-sdk/build-tools/34.0.0}"
APK="$ROOT/apk/${APK_NAME:-dfm_official_cn.apk}"
OUT="$ROOT/build/rebuilt"
mkdir -p "$OUT"

[ -f "$APK" ] || { echo "[!] APK 不存在"; exit 1; }

echo "[*] 生成调试签名密钥"
if [ ! -f "$OUT/debug.jks" ]; then
  keytool -genkeypair -v -keystore "$OUT/debug.jks" -alias dfmdebug \
    -keyalg RSA -keysize 2048 -validity 3650 \
    -storepass dfmdebug123 -keypass dfmdebug123 \
    -dname "CN=DFM Research, OU=Research, O=Local, L=NA, S=NA, C=CN" >/dev/null 2>&1
fi

echo "[*] zipalign 对齐"
"$BT/zipalign" -f -p 4 "$APK" "$OUT/aligned.apk"

echo "[*] apksigner 重签名"
"$BT/apksigner" sign --ks "$OUT/debug.jks" \
  --ks-key-alias dfmdebug --ks-pass pass:dfmdebug123 \
  --key-pass pass:dfmdebug123 --v1-signing-enabled true \
  --v2-signing-enabled true "$OUT/aligned.apk"

mv "$OUT/aligned.apk" "$OUT/dfm_rebuilt_signed.apk"
echo "[*] 校验"
"$BT/apksigner" verify --print-certs "$OUT/dfm_rebuilt_signed.apk" || true
echo "[*] 产物: $OUT/dfm_rebuilt_signed.apk"
