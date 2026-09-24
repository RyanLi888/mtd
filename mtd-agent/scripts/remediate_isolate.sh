#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
QUARANTINE="/opt/miner_detector/isolated"
LOG_FILE="/var/log/miner_detector_response.log"

if [[ -z "$TARGET" || ! -f "$TARGET" || -L "$TARGET" ]]; then
  echo "目标不是可隔离的普通文件" >&2
  exit 2
fi
REAL_TARGET="$(realpath -- "$TARGET")"
case "$REAL_TARGET" in
  /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/lib/*|/lib64/*)
    echo "拒绝隔离系统目录文件" >&2
    exit 3
    ;;
esac

mkdir -p "$QUARANTINE"
chmod 700 "$QUARANTINE"
DESTINATION="$QUARANTINE/$(basename -- "$REAL_TARGET")_$(date +%Y%m%d_%H%M%S)"
mv -- "$REAL_TARGET" "$DESTINATION"
chmod 600 "$DESTINATION"
printf '%s user=%s action=isolate source=%s destination=%s\n' "$(date --iso-8601=seconds)" "$(id -un)" "$REAL_TARGET" "$DESTINATION" >> "$LOG_FILE"
echo "文件已隔离到 $DESTINATION"
