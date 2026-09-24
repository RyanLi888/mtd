#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/layerminer"
CONFIG_DIR="/etc/layerminer"
LOG_DIR="/var/log/layerminer"
STATE_DIR="/var/lib/layerminer"
SERVICE_FILE="/etc/systemd/system/layerminerguard.service"

echo "=== LayerMinerGuard Server Tool Uninstaller ==="

# Stop service if running
if systemctl is-active --quiet layerminerguard 2>/dev/null; then
    echo "Stopping layerminerguard service..."
    systemctl stop layerminerguard
fi

# Remove service file
if [ -f "$SERVICE_FILE" ]; then
    echo "Removing systemd service..."
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
fi

# Remove install directory
if [ -d "$INSTALL_DIR" ]; then
    echo "Removing $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
fi

# Remove config
if [ -d "$CONFIG_DIR" ]; then
    echo "Removing $CONFIG_DIR..."
    rm -rf "$CONFIG_DIR"
fi

# Ask before removing logs
echo ""
echo "Log directory: $LOG_DIR"
echo "State directory: $STATE_DIR"
read -p "Remove logs and state? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$LOG_DIR" "$STATE_DIR"
    echo "Logs and state removed."
else
    echo "Logs and state preserved."
fi

echo ""
echo "=== Uninstall Complete ==="
