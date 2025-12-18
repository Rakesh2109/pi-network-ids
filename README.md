# Pi Server - Network Security Monitoring System

Real-time network security monitoring and analysis on Raspberry Pi with IDS/IPS capabilities.

## 🚀 Quick Start

### Access Points
- **Grafana**: http://128.39.201.47:3000 (admin/admin123)
- **Traffic Monitor**: http://128.39.201.47:8080

### System Status
```bash
docker compose ps                    # Check services
docker compose logs -f suricata      # View Suricata logs
docker compose logs -f zeek          # View Zeek logs
```

## 📊 Architecture

Network traffic monitoring from wlan0 hotspot interface:
- **Capture**: Zeek, Suricata, Tcpdump
- **Storage**: Loki (logs), InfluxDB (metrics), PCAP files
- **Analysis**: Promtail, Telegraf
- **Visualization**: Grafana, Traffic Monitor

## 🎯 Dashboards

### System Monitoring
- CPU, RAM, Disk usage
- Docker container resources
- Hotspot traffic and clients
- Network connections

### Security Monitoring
- **Suricata**: IDS alerts and threat detection
- **Zeek**: Network protocol analysis

## 🛠️ Installation

### Prerequisites
- Raspberry Pi (4GB+ RAM)
- Docker & Docker Compose
- WiFi hotspot on wlan0

### Setup
```bash
git clone <repository-url>
cd Pi_Server
docker compose up -d
./setup-system-monitoring.sh
```

## 🔧 Configuration

### Data Retention
- PCAP: 24 hours (hourly rotation)
- Logs: 7 days (auto-cleanup at 2 AM)
- Metrics: 30 days (InfluxDB)

### Refresh Intervals
- Metrics: 10 seconds
- Dashboards: 5 seconds
- Traffic Monitor: 5 minutes

## 💾 Data Storage

### Network Captures (PCAP)
- **Location**: `pcap/trace-YYYYMMDD-HHMMSS.pcap0`
- **Format**: PCAP (Wireshark compatible)
- **Rotation**: Every 1 hour
- **Max Files**: 24 files (24 hours retention)
- **Max Size**: 100MB per file
- **Tool**: tshark (tcpdump)
- **Interface**: wlan0 (WiFi hotspot)
- **Export**: Download directly from web UI at http://128.39.201.47:8080

### Suricata (IDS/IPS Alerts)
- **Location**: `suricata/logs/`
- **Main Log**: `eve.json` (JSON format)
- **Contains**: Security alerts, network flows, HTTP, DNS, TLS, SSH events
- **Format**: JSON Lines (one JSON object per line)
- **Other Files**:
  - `fast.log` - Alert summary (plain text)
  - `stats.log` - Performance statistics
- **Current Size**: ~40MB
- **Retention**: 7 days (auto-cleanup)
- **Export**: CSV/JSON via web UI at http://128.39.201.47:8080

### Zeek (Network Analysis Logs)
- **Location**: `zeek/logs/current/*.log`
- **Format**: TSV (Tab-separated values with header)
- **Log Files**:
  - `conn.log` - All network connections (src/dst IP, ports, bytes, duration)
  - `dhcp.log` - DHCP lease requests and assignments
  - `dns.log` - DNS queries and responses (when present)
  - `http.log` - HTTP requests and responses (when present)
  - `ssl.log` - TLS/SSL handshakes and certificates (when present)
  - `stats.log` - Zeek performance metrics
  - `loaded_scripts.log` - Active Zeek analysis scripts
- **Rotation**: Automatic daily rotation to dated folders (zeek/logs/YYYY-MM-DD/)
- **Current Size**: ~4KB per log file
- **Retention**: 7 days (auto-cleanup)
- **Export**: CSV via web UI at http://128.39.201.47:8080

### InfluxDB Metrics (Time-Series Database)
- **Location**: `influxdb/data/`
- **Format**: Internal InfluxDB storage (columnar)
- **Buckets**:
  - `system_metrics` - System monitoring data:
    - CPU usage (per core and total)
    - RAM usage (used, free, cached)
    - Disk I/O (read/write bytes/sec)
    - Network traffic (bytes/packets per interface)
    - Docker container stats (CPU, memory, network per container)
    - Hotspot stats (connected clients, RX/TX traffic on wlan0)
    - Process counts
  - `sensor_data` - ESP32 IoT sensor data from MQTT:
    - Temperature, humidity, pressure
    - Custom sensor readings
- **Collection Interval**: Every 10 seconds
- **Retention**: 30 days
- **Query**: Grafana dashboards or `docker exec influxdb influx query`
- **Visualize**: http://128.39.201.47:3000

### Loki Logs (Centralized Logging)
- **Location**: `loki/data/`
- **Format**: Internal Loki chunks and index
- **Contains**: Aggregated logs from all Docker services
- **Storage**: 
  - `chunks/` - Compressed log data
  - `boltdb-shipper-active/` - Active index
  - `wal/` - Write-ahead log
- **Retention**: 7 days
- **Query**: Grafana Explore (LogQL) at http://128.39.201.47:3000

### MQTT Data
- **Location**: `mqtt/log/mosquitto.log`
- **Format**: Plain text log
- **Contains**: MQTT broker connection logs, publish/subscribe events
- **Retention**: 7 days

### Traffic Monitor Exports
- **CSV Exports**: Available via web interface
- **JSON Exports**: Full event data with nested structures
- **Access**: http://128.39.201.47:8080
- **Export Types**:
  - Suricata events (last 500) → CSV/JSON
  - Zeek connections (last 500) → CSV
  - Combined traffic data → JSON

## 🗑️ Maintenance

```bash
./cleanup-old-files.sh               # Manual cleanup
docker compose restart               # Restart all
docker compose restart <service>     # Restart specific
```

## 📁 Structure

```
Pi_Server/
├── grafana/              # Dashboards & visualizations
├── influxdb/             # Time-series metrics
├── loki/                 # Log aggregation
├── mqtt/                 # MQTT broker
├── mqtt-collector/       # Sensor data collector
├── pcap/                 # Network captures
├── suricata/             # IDS/IPS engine
├── telegraf/             # Metrics collector
├── traffic-monitor/      # Web UI
└── zeek/                 # Network analyzer
```

## 🐛 Troubleshooting

### No Dashboard Data
```bash
docker logs telegraf
docker exec influxdb influx query "from(bucket: \"system_metrics\") |> range(start: -5m)"
```

### Service Issues
```bash
docker compose ps
docker compose logs <service>
docker compose restart <service>
```

### Disk Space
```bash
du -sh pcap/ suricata/logs/ zeek/logs/
./cleanup-old-files.sh
```

## 📝 License

MIT License - Copyright (c) 2025 Rakesh Reddy Yakakti (yrakesh2109@gmail.com)

See [LICENSE](LICENSE) file for details.

## 👥 Author

**Rakesh Reddy Yakakti** - yrakesh2109@gmail.com

## 🤝 Contributing

Contributions welcome! Open an issue or submit a pull request.
