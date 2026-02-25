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

echo "Starting ethersrv-linux on interface $INTERFACE..."

# If user provided a VOLUME_LABEL environment variable, pass it as -v
if [ -n "$VOLUME_LABEL" ]; then
    echo "Using custom volume label: $VOLUME_LABEL"
    # exec replaces the shell process so signals are passed correctly
    exec ethersrv-linux -f "$INTERFACE" -v "$VOLUME_LABEL" /data
else
    exec ethersrv-linux -f "$INTERFACE" /data
fi
