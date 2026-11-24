#!/usr/bin/env bash
# 00_fetch_apk.sh — 从官网分发直链下载三角洲行动国服官服 APK（带断点续传 + SHA256）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/env.example" 2>/dev/null || true
APK_URL="${APK_URL:-https://dlied4.myapp.com/myapp/1110543085/cos.release-75799/89900051_com.tencent.tmgp.dfm_h3275935_1.201.1035.13_Rmt4f0.apk}"
APK_NAME="${APK_NAME:-dfm_official_cn.apk}"
OUT="$ROOT/apk/$APK_NAME"
mkdir -p "$(dirname "$OUT")" "$ROOT/reports"

echo "[*] 下载官服 APK: $APK_URL"
echo "[*] 输出: $OUT"
curl -L --retry 5 --retry-delay 3 -C - -A "Mozilla/5.0" -o "$OUT" "$APK_URL"

echo "[*] 计算 SHA256"
SHA=$(sha256sum "$OUT" | awk '{print $1}')
echo "$SHA  $APK_NAME" | tee "$ROOT/reports/apk_sha256.txt"
echo "[*] 大小: $(du -h "$OUT" | cut -f1)"
echo "[*] 完成"
