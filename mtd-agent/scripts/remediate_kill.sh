#!/usr/bin/env bash
set -euo pipefail

PID="${1:-}"
LOG_FILE="/var/log/miner_detector_response.log"

if [[ ! "$PID" =~ ^[0-9]+$ ]] || (( PID <= 100 )); then
  echo "拒绝无效或受保护的 PID" >&2
  exit 2
fi
if [[ ! -d "/proc/$PID" ]]; then
  echo "进程不存在: $PID" >&2
  exit 3
fi

PROCESS_NAME="$(cat "/proc/$PID/comm" 2>/dev/null || true)"
case "$PROCESS_NAME" in
  systemd|sshd|kthreadd|ksoftirqd*|migration*)
    echo "拒绝终止受保护进程: $PROCESS_NAME" >&2
    exit 4
    ;;
esac

printf '%s user=%s action=kill pid=%s process=%s\n' "$(date --iso-8601=seconds)" "$(id -un)" "$PID" "$PROCESS_NAME" >> "$LOG_FILE"
kill -TERM "$PID"
sleep 2
if kill -0 "$PID" 2>/dev/null; then kill -KILL "$PID"; fi
echo "已终止进程 $PID ($PROCESS_NAME)"
