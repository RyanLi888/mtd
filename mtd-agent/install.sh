#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${MTD_INSTALL_DIR:-/opt/miner_detector}"
MONITOR_USER="${MTD_MONITOR_USER:-monitor}"

if [[ $EUID -ne 0 ]]; then
  echo "请使用 sudo 执行安装脚本" >&2
  exit 1
fi

if ! id "$MONITOR_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$MONITOR_USER"
fi

install -d -m 0750 -o "$MONITOR_USER" -g "$MONITOR_USER" "$INSTALL_DIR"
cp -R "$SOURCE_DIR/detector.py" "$SOURCE_DIR/requirements.txt" "$SOURCE_DIR/config" "$SOURCE_DIR/scripts" "$INSTALL_DIR/"
install -d -m 0750 -o "$MONITOR_USER" -g "$MONITOR_USER" "$INSTALL_DIR/data/logs" "$INSTALL_DIR/data/cache" "$INSTALL_DIR/isolated"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --disable-pip-version-check -r "$INSTALL_DIR/requirements.txt"
chmod 0750 "$INSTALL_DIR/detector.py" "$INSTALL_DIR/scripts"/*.sh
chown -R "$MONITOR_USER:$MONITOR_USER" "$INSTALL_DIR"

echo "MTD 检测代理已安装到 $INSTALL_DIR"
echo "请按仓库根目录 README.md 的 Linux 检测组件说明配置 SSH 公钥和 /etc/sudoers.d/mtd-monitor"
