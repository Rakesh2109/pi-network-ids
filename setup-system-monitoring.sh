#!/bin/bash

echo "Setting up system monitoring..."

# Start InfluxDB first
echo "Starting InfluxDB..."
docker compose up -d influxdb

# Wait for InfluxDB to be ready
echo "Waiting for InfluxDB to be ready..."
sleep 10

# Create system_metrics bucket
echo "Creating system_metrics bucket..."
docker exec influxdb influx bucket create \
  --name system_metrics \
  --org pi_server \
  --token my-super-secret-admin-token \
  2>/dev/null || echo "Bucket already exists or error occurred (this is okay if bucket exists)"

# Start Telegraf
echo "Starting Telegraf..."
docker compose up -d telegraf

# Restart Grafana to pick up new dashboard
echo "Restarting Grafana..."
docker compose restart grafana

echo ""
echo "System monitoring setup complete!"
echo ""
echo "Access Grafana at: http://128.39.201.47:3000"
echo "Default credentials: admin / admin123"
echo ""
echo "New dashboard: 'Pi System & Docker Monitoring'"
echo ""
echo "Monitoring:"
echo "  - CPU Usage (per core and total)"
echo "  - RAM Usage"
echo "  - Disk Usage"
echo "  - Docker Container CPU Usage"
echo "  - Docker Container Memory Usage"
echo "  - Network Traffic"
echo "  - Disk I/O"
echo ""
