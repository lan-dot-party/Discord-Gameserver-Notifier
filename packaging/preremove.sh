#!/bin/bash
#
# Pre-removal script for Discord Gameserver Notifier
# This script is executed before package removal (.deb/.rpm)
#

set -e

echo "Discord Gameserver Notifier: Pre-removal cleanup..."

# Stop and disable systemd service if systemctl is available
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet discord-gameserver-notifier.service 2>/dev/null; then
        echo "Stopping discord-gameserver-notifier service..."
        systemctl stop discord-gameserver-notifier.service 2>/dev/null || true
    fi
    
    if systemctl is-enabled --quiet discord-gameserver-notifier.service 2>/dev/null; then
        echo "Disabling discord-gameserver-notifier service..."
        systemctl disable discord-gameserver-notifier.service 2>/dev/null || true
    fi
    
    # Reload systemd daemon
    systemctl daemon-reload 2>/dev/null || true
    echo "Service stopped and disabled."
else
    echo "Systemctl not available - skipping service management."
fi

# Remove virtual environment
VENV_DIR="/opt/discord-gameserver-notifier"
if [ -d "$VENV_DIR" ]; then
    echo "Removing virtual environment at $VENV_DIR..."
    rm -rf "$VENV_DIR"
    echo "Virtual environment removed."
else
    echo "Virtual environment not found - nothing to remove."
fi

echo "Pre-removal cleanup completed!"

exit 0 