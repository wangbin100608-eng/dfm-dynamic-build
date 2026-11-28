#!/usr/bin/env bash
# 任务5：30分钟稳定性测试（独立测试实例 redroid-x86-test）
set -u
C="docker exec redroid-x86-test"
LOG=/root/三角洲/环境专项/stability-30min.csv
RAW=/root/三角洲/环境专项/stability-30min.log
: > "$LOG"; : > "$RAW"
echo "timestamp,elapsed_s,cpu,mem,pid,state,undef,anr,crash,rss_kb" >> "$LOG"
START=$(date +%s)
for i in $(seq 1 60); do
  EL=$(( $(date +%s) - START ))
  CPU=$($C /system/bin/top -n 1 -b 2>/dev/null | grep tmgp | head -1 | awk '{print $9}')
  CPU=${CPU:-NA}
  MEM=$(docker stats redroid-x86-test --no-stream --format '{{.MemUsage}}' 2>/dev/null | awk '{print $1}')
  MEM=${MEM:-NA}
  PID=$($C /system/bin/ps -A 2>/dev/null | grep tmgp | awk '{print $2}' | head -1)
  if [ -n "$PID" ]; then
    STATE=$($C /system/bin/sh -c "awk '{print \$3}' /proc/$PID/stat 2>/dev/null")
    RSS=$($C /system/bin/sh -c "awk '/VmRSS/{print \$2}' /proc/$PID/status 2>/dev/null")
  else
    STATE="DEAD"; RSS="0"
  fi
  STATE=${STATE:-NA}; RSS=${RSS:-0}
  # 单次 logcat 快照，所有计数从同一份快照算，避免多次调用
  SNAP=$(timeout 3 $C /system/bin/logcat -v brief -d 2>/dev/null)
  UNDEF=$(echo "$SNAP" | grep -c 'Undefined instruction' || true)
  ANR=$(echo "$SNAP" | grep -c 'ANR in com.tencent.tmgp.dfm' || true)
  CRASH=$(echo "$SNAP" | grep -c 'FATAL EXCEPTION' || true)
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$EL" "$CPU" "$MEM" "$PID" "$STATE" "$UNDEF" "$ANR" "$CRASH" "$RSS" >> "$LOG"
  echo "[$EL s] cpu=$CPU mem=$MEM pid=$PID state=$STATE undef=$UNDEF anr=$ANR crash=$CRASH rss=$RSS" >> "$RAW"
  sleep 30
done
echo "DONE" >> "$RAW"
