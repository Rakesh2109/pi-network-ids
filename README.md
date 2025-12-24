# Pi Server - Network Monitoring & Sensor Data Collection

A comprehensive Docker-based monitoring system for Raspberry Pi that collects network traffic data and sensor measurements.

## Services

### Core Services

- **MQTT Broker** - Mosquitto MQTT broker for IoT sensor data communication
  - Port: 1883 (MQTT), 9001 (WebSocket)
  
- **InfluxDB** - Time series database for storing sensor and metrics data
  - Port: 8086
  - Organization: `pi_server`
  - Bucket: `sensor_data`
  - Token: `my-super-secret-admin-token`

- **MQTT Collector** - Python service that subscribes to MQTT topics and stores data to InfluxDB

- **Telegraf** - System and Docker metrics collector, sends data to InfluxDB

- **Grafana** - Data visualization and dashboards
  - Port: 3000 (accessible at 128.39.201.47:3000)
  - Default credentials: admin / admin123

- **Tcpdump** - Network packet capture tool
  - Interface: wlan0 (hotspot network)
  - Output: `./pcap/trace.pcap`
  - Rotation: 100MB files, 10 file rotation

- **ntopng** - Real-time network traffic monitoring and analysis
  - Port: 3001 (Web dashboard accessible at 128.39.201.47:3001)
  - Features: Top talkers (IPs), protocol breakdown, flow analysis
  - Shows: Packets/bytes per IP address, real-time traffic statistics

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Rakesh2109/pi-network-ids.git
   cd pi-network-ids
   ```

2. **Start all services:**
   ```bash
   docker compose up -d
   ```

3. **Check service status:**
   ```bash
   docker compose ps
   ```

4. **View logs:**
   ```bash
   docker compose logs -f [service-name]
   ```

5. **Stop all services:**
   ```bash
   docker compose down
   ```

## Directory Structure

```
.
├── docker-compose.yml          # Main orchestration file
├── grafana/                    # Grafana configuration and dashboards
│   ├── data/                   # Grafana data directory
│   └── provisioning/           # Dashboards and datasources
├── influxdb/                   # InfluxDB data and configuration
├── mqtt/                       # MQTT broker configuration
├── mqtt-collector/             # MQTT to InfluxDB collector service
├── ntopng/                     # ntopng data directory
│   └── data/                   # ntopng database and data
├── pcap/                       # PCAP capture files
├── telegraf/                   # Telegraf configuration
└── README.md                   # This file
```

## Configuration

### InfluxDB

- **URL:** http://localhost:8086
- **Username:** admin
- **Password:** admin123
- **Organization:** pi_server
- **Bucket:** sensor_data

### Grafana

- **URL:** http://128.39.201.47:3000
- **Username:** admin
- **Password:** admin123
- **Datasource:** InfluxDB (pre-configured)

### Network Interface

The system is configured to monitor the `wlan0` interface (WiFi hotspot network).

## Data Flow

1. **Sensor Data:**
   - Sensors → MQTT Broker → MQTT Collector → InfluxDB → Grafana

2. **System Metrics:**
   - Host System → Telegraf → InfluxDB → Grafana

3. **Network Traffic:**
   - Network Interface (wlan0) → Tcpdump → PCAP files
   - Network Interface (wlan0) → ntopng → Real-time flow monitoring

## Access Points

- **Grafana Dashboard:** http://128.39.201.47:3000
- **ntopng Network Monitor:** http://128.39.201.47:3001
- **InfluxDB API:** http://localhost:8086
- **MQTT Broker:** localhost:1883

## Maintenance

### Viewing Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f mqtt-collector
docker compose logs -f grafana
```

### Restarting Services
```bash
# Restart all
docker compose restart

# Restart specific service
docker compose restart grafana
```

### Updating Services
```bash
# Pull latest images and restart
docker compose pull
docker compose up -d
```

## Requirements

- Docker
- Docker Compose
- Raspberry Pi with WiFi interface (wlan0)
- Root/sudo access for network monitoring

## Notes

- The system captures network traffic on the `wlan0` interface
- PCAP files are stored in `./pcap/` directory
- Sensor data is stored in InfluxDB with automatic timestamping
- All services restart automatically unless stopped manually

## License

See LICENSE file for details.

