#!/bin/sh
set -e

# Get capture interface from environment variable, default to wlan0
CAPTURE_INTERFACE=${CAPTURE_INTERFACE:-wlan0}

echo "Starting Zeek to capture on $CAPTURE_INTERFACE (hotspot network) for IDS"
echo "Creating log directory..."
mkdir -p /data/zeek/logs/current
cd /data/zeek/logs/current

echo "Running Zeek on interface: $CAPTURE_INTERFACE"
# Run Zeek directly on the interface
exec /usr/local/zeek/bin/zeek -i "$CAPTURE_INTERFACE" local

