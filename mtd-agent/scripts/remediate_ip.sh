#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
LOG_FILE="/var/log/miner_detector_response.log"

python3 - "$TARGET_IP" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
if address.is_loopback or address.is_private or address.is_link_local or address.is_multicast:
    raise SystemExit("拒绝封禁本地、私有或保留地址")
PY

if iptables -C OUTPUT -d "$TARGET_IP" -j DROP 2>/dev/null; then
  echo "IP 已在封禁列表: $TARGET_IP"
  exit 0
fi
iptables -A OUTPUT -d "$TARGET_IP" -j DROP
printf '%s user=%s action=block_ip target=%s\n' "$(date --iso-8601=seconds)" "$(id -un)" "$TARGET_IP" >> "$LOG_FILE"
echo "已封禁 IP $TARGET_IP"
