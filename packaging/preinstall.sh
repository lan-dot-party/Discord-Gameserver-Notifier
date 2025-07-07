#!/bin/bash
#
# Pre-installation script for Discord Gameserver Notifier
# This script is executed before package installation (.deb/.rpm)
#

set -e

echo "Discord Gameserver Notifier: Pre-installation setup..."

# Create system user and group for the service
if ! getent group dgn >/dev/null 2>&1; then
    echo "Creating system group: dgn"
    groupadd --system dgn
else
    echo "System group 'dgn' already exists"
fi

if ! getent passwd dgn >/dev/null 2>&1; then
    echo "Creating system user: dgn"
    useradd --system --gid dgn --home-dir /var/lib/dgn --shell /usr/sbin/nologin \
            --comment "Discord Gameserver Notifier service user" dgn
else
    echo "System user 'dgn' already exists"
fi

# Create necessary directories
echo "Creating service directories..."

# Configuration directory
if [ ! -d "/etc/dgn" ]; then
    mkdir -p /etc/dgn
    chmod 755 /etc/dgn
    echo "Created configuration directory: /etc/dgn"
else
    echo "Configuration directory already exists: /etc/dgn"
fi

# Working directory for the service
if [ ! -d "/var/lib/dgn" ]; then
    mkdir -p /var/lib/dgn
    chown dgn:dgn /var/lib/dgn
    chmod 755 /var/lib/dgn
    echo "Created working directory: /var/lib/dgn"
else
    echo "Working directory already exists: /var/lib/dgn"
    # Ensure correct ownership
    chown dgn:dgn /var/lib/dgn 2>/dev/null || true
fi

# Log directory
if [ ! -d "/var/log/dgn" ]; then
    mkdir -p /var/log/dgn
    chown dgn:dgn /var/log/dgn
    chmod 755 /var/log/dgn
    echo "Created log directory: /var/log/dgn"
else
    echo "Log directory already exists: /var/log/dgn"
    # Ensure correct ownership
    chown dgn:dgn /var/log/dgn 2>/dev/null || true
fi

echo "Pre-installation setup completed!"

exit 0 