#!/bin/bash
echo "=== Available Network Interfaces ==="
echo ""
echo "Active interfaces:"
ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/:$//' | while read iface; do
    status=$(ip link show "$iface" | grep -o "state [A-Z]*" | awk '{print $2}')
    if [ "$status" = "UP" ]; then
        ip=$(ip -4 addr show "$iface" | grep -oP 'inet \K[\d.]+' | head -1)
        echo "  $iface: UP (IP: ${ip:-none})"
    else
        echo "  $iface: DOWN"
    fi
done
echo ""
echo "Set CAPTURE_INTERFACE environment variable:"
echo "  export CAPTURE_INTERFACE=<interface-name>"
echo ""
echo "Example:"
echo "  export CAPTURE_INTERFACE=eth1"

