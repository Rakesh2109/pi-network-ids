# Pi Server - Network Security Monitoring System

Real-time network security monitoring and analysis on Raspberry Pi with IDS/IPS capabilities.

## 🚀 Quick Start

### Access Points
- **Grafana**: http://128.39.201.47:3000 (admin/admin123)
- **Traffic Monitor**: http://128.39.201.47:5000

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
