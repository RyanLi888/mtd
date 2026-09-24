#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/layerminer"
CONFIG_DIR="/etc/layerminer"
LOG_DIR="/var/log/layerminer"
STATE_DIR="/var/lib/layerminer"
SERVICE_FILE="/etc/systemd/system/layerminerguard.service"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== LayerMinerGuard Server Tool Installer ==="

# Create directories
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$STATE_DIR"

# Copy project files
cp -r "$PROJECT_ROOT"/* "$INSTALL_DIR/"

# Copy config
cp "$PROJECT_ROOT/server_tool/config/server.yaml" "$CONFIG_DIR/server.yaml"

# Install systemd service
cp "$PROJECT_ROOT/server_tool/packaging/layerminerguard.service" "$SERVICE_FILE"
systemctl daemon-reload

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Installed to: $INSTALL_DIR"
echo "Config at:    $CONFIG_DIR/server.yaml"
echo "Logs at:      $LOG_DIR"
echo ""
echo "Manual run (one-shot):"
echo "  sudo python3 $INSTALL_DIR/server_tool/bin/layerminerd.py --config $CONFIG_DIR/server.yaml --once"
echo ""
echo "Manual run (continuous):"
echo "  sudo python3 $INSTALL_DIR/server_tool/bin/layerminerd.py --config $CONFIG_DIR/server.yaml"
echo ""
echo "Manual systemd start:"
echo "  sudo systemctl start layerminerguard"
echo ""
echo "Manual systemd stop:"
echo "  sudo systemctl stop layerminerguard"
echo ""
echo "NOTE: Service is NOT auto-started. Use 'systemctl start' manually."
