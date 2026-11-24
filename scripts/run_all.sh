#!/usr/bin/env bash
# run_all.sh — 一键编排「不依赖真机」的静态全流程（下载/元信息/反编译）
# 动态 hook 部分见 README 第 5 节，需手动接设备执行
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=========== [1/3] 下载 APK ==========="
bash scripts/00_fetch_apk.sh
echo "=========== [2/3] 元信息提取 ==========="
bash scripts/01_meta.sh
echo "=========== [3/3] 反编译 ==========="
bash scripts/02_decompile.sh
echo "=========== 静态全流程完成 ==========="
echo "后续动态分析见 README.md 第 5 节"
