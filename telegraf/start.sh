#!/bin/sh
# Telegraf startup script - creates dated filename on container start

export TZ=Europe/Oslo
DATE=$(date +%Y-%m-%d_%H-%M-%S)
FILENAME="/data/telegraf/metrics-${DATE}.json"

# Create the directory if it doesn't exist
mkdir -p /data/telegraf

# Update telegraf config with dated filename (create temp config)
sed "s|files = \[\"/data/telegraf/.*\"\]|files = [\"${FILENAME}\"]|" /etc/telegraf/telegraf.conf > /tmp/telegraf.conf

# Run telegraf with updated config
exec /entrypoint.sh telegraf --config /tmp/telegraf.conf

