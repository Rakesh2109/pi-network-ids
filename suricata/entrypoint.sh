#!/bin/bash
set -e

# Capture only on wlan0 (hotspot) for IDS data collection
echo "Starting Suricata to capture on wlan0 (hotspot network) for IDS"

# Execute suricata on wlan0 only
exec suricata -c /etc/suricata/suricata.yaml -i wlan0 --init-errors-fatal

