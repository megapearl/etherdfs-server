#!/bin/sh

INTERFACE=${INTERFACE:-vlan2}

echo "=== EtherDFS Docker Entrypoint ==="

# Prevent crash if directory is missing
if [ ! -d "/data" ]; then
    echo "Warning: /data directory does not exist. Creating it now..."
    mkdir -p /data
fi

echo "Available network interfaces in the container/host:"
ip link show | grep -E '^[0-9]+:' | awk -F: '{print $2}' | tr -d ' '

echo ""
echo "Attempting to use interface: $INTERFACE"

# Check if interface exists
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "--------------------------------------------------------"
    echo "ERROR: Network interface '$INTERFACE' was not found!"
    echo "Please set the INTERFACE environment variable in your"
    echo "docker-compose.yml or TrueNAS app settings to match"
    echo "one of the available interfaces listed above."
    echo "--------------------------------------------------------"
    echo "Sleeping for 60 seconds to prevent rapid crash loops..."
    sleep 60
    exit 1
fi

echo "Starting ethersrv on interface $INTERFACE..."

# Build up the arguments array dynamically
ARGS="-f"

if [ -n "$VOLUME_LABEL" ]; then
    echo "Using custom volume label: $VOLUME_LABEL"
    ARGS="$ARGS -v \"$VOLUME_LABEL\""
fi

if [ -n "$ALLOWED_MAC" ]; then
    echo "Applying MAC ACL Whitelist (-m): $ALLOWED_MAC"
    ARGS="$ARGS -m \"$ALLOWED_MAC\""
fi

if [ "$ETHERDFS_LOWERCASE" = "1" ] || [ "$ETHERDFS_LOWERCASE" = "true" ]; then
    echo "Enabling Auto-Lowercasing (-l)"
    ARGS="$ARGS -l"
fi

if [ "$ETHERDFS_DEBUG" = "1" ] || [ "$ETHERDFS_DEBUG" = "true" ]; then
    echo "Enabling runtime debug logging (-d)"
    ARGS="$ARGS -d"
fi

if [ "$ETHERDFS_READONLY" = "1" ] || [ "$ETHERDFS_READONLY" = "true" ]; then
    echo "Enabling Museum Mode: Read-Only (-r)"
    ARGS="$ARGS -r"
fi

if [ -n "$ETHERDFS_DELAY" ] && [ "$ETHERDFS_DELAY" -gt 0 ] 2>/dev/null; then
    echo "Applying artificial network delay of ${ETHERDFS_DELAY}ms (-s)"
    ARGS="$ARGS -s $ETHERDFS_DELAY"
fi

# The eval is necessary because ARGS contains quotes around the volume label
eval "exec ethersrv $ARGS \"$INTERFACE\" /data"
