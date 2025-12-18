#!/bin/bash

# Cleanup script for old pcap files and logs
# Keeps files from last 24 hours, deletes older files

echo "Cleaning up old files..."

# Delete pcap files older than 24 hours
echo "Cleaning pcap files older than 24 hours..."
find /home/rakeshry/Pi_Server/pcap -name "*.pcap*" -type f -mtime +1 -delete
echo "PCAP cleanup complete"

# Delete Suricata logs older than 7 days (keep a week of logs)
echo "Cleaning Suricata logs older than 7 days..."
find /home/rakeshry/Pi_Server/suricata/logs -name "*.json" -type f -mtime +7 -delete
echo "Suricata logs cleanup complete"

# Delete Zeek logs older than 7 days
echo "Cleaning Zeek logs older than 7 days..."
find /home/rakeshry/Pi_Server/zeek/logs -type f -mtime +7 -delete
echo "Zeek logs cleanup complete"

# Delete MQTT collector logs older than 7 days
echo "Cleaning MQTT collector logs older than 7 days..."
find /home/rakeshry/Pi_Server/mqtt-collector/logs -type f -mtime +7 -delete
echo "MQTT collector logs cleanup complete"

# Show current disk usage
echo ""
echo "Current disk usage:"
du -sh /home/rakeshry/Pi_Server/pcap
du -sh /home/rakeshry/Pi_Server/suricata/logs
du -sh /home/rakeshry/Pi_Server/zeek/logs
du -sh /home/rakeshry/Pi_Server/mqtt-collector/logs

echo ""
echo "Cleanup complete!"
