# Pi_Server - Hotspot Network Security Monitoring System

**Real-time IDS/IPS monitoring with Zeek (normal traffic) & Suricata (threats) on Raspberry Pi**

---

## 🚀 Quick Start

### Access Dashboards
```
🔴 Suricata (Threats):  http://128.39.201.47:3000/d/suricata-enhanced-dashboard
🟢 Zeek (Normal):       http://128.39.201.47:3000/d/zeek-enhanced-dashboard
Grafana:                http://128.39.201.47:3000
Login:                  admin / admin123
```

### System Status
```bash
# Check all services
docker compose ps

# View real-time Zeek logs (normal traffic)
tail -f zeek/logs/current/conn.log

# View real-time Suricata logs (threats)
tail -f suricata/logs/eve.json

# Check PCAP capture
ls -lah pcap/
```

---

## 📊 System Architecture

```
Network Traffic (wlan0)
    ↓
┌──────────────────────────────────────┐
│  DATA CAPTURE LAYER                  │
├──────────────────────────────────────┤
│ • Zeek (Network analysis)            │
│ • Suricata (IDS/IPS engine)          │
│ • Tcpdump (Raw PCAP files)           │
└──────────────────────────────────────┘
    ↓
┌──────────────────────────────────────┐
│  LOG PROCESSING                      │
├──────────────────────────────────────┤
│ • Promtail (ships logs to Loki)      │
└──────────────────────────────────────┘
    ↓
┌──────────────────────────────────────┐
│  LOG AGGREGATION                     │
├──────────────────────────────────────┤
│ • Loki (7-day retention)             │
└──────────────────────────────────────┘
    ↓
┌──────────────────────────────────────┐
│  VISUALIZATION & ANALYSIS            │
├──────────────────────────────────────┤
│ • Grafana (Real-time dashboards)     │
│ • Traffic Monitor (REST APIs)        │
└──────────────────────────────────────┘
```

---

## 🎯 Dashboards Overview

### Suricata Network Security Dashboard (18 Panels)
**Purpose**: Real-time detection and analysis of abnormal/malicious traffic

**Key Metrics**:
- 🚨 Critical Alerts (1h)
- 📊 Network Flows (1h)
- 🌐 HTTP Traffic (1h)
- 🔒 TLS/SSL Traffic (1h)

**Analysis Panels**:
- Alert rate trending (time-series)
- Event type comparison
- Top source IPs (attack origins)
- Top destination IPs (attack targets)
- Protocol distribution
- Port analysis (Top 15)
- Real-time alert feed (last 100)
- Traffic direction analysis
- IPv4 vs IPv6 breakdown
- Threat severity levels
- Flow, HTTP, TLS/SSL, DNS details

**Color Coding**:
- 🟢 Green = Safe (0-4 alerts)
- 🟡 Yellow = Elevated (5-19)
- 🟠 Orange = High (20-99)
- 🔴 Red = Critical (100+)

---

### Zeek Network Analysis Dashboard (19 Panels)
**Purpose**: Deep analysis of normal network behavior and baseline establishment

**Key Metrics**:
- 🔗 Total Connections (1h)
- 📡 DNS Queries (1h)
- 🌐 HTTP Requests (1h)
- 🔒 TLS/SSL Sessions (1h)

**Baseline Panels**:
- Connection rate trending (time-series)
- Activity rate comparison (all types)
- Protocol distribution (TCP vs UDP)
- Top destination ports (services)
- Top visited destinations (remote IPs)
- Local clients (device identification)
- Connection state analysis
- IPv4 vs IPv6 breakdown

**Detailed Log Panels**:
- Connection details (session info)
- DNS resolution activity
- HTTP traffic details
- SSL/TLS certificate analysis
- Security notices & anomalies
- System stats & packet filter health

**Typical Baseline (1 hour)**:
- Connections: 100-500
- DNS Queries: 50-200
- HTTP Requests: 100-400
- TLS/SSL: 30-100

---

## 🔧 System Components

### Docker Services
| Service | Port | Purpose |
|---------|------|---------|
| **Zeek** | - | Network analysis (TCP/UDP, DNS, HTTP, SSL) |
| **Suricata** | - | IDS/IPS engine (threat detection) |
| **Tcpdump** | - | Raw packet capture (PCAP files) |
| **Loki** | 3100 | Log aggregation (7-day retention) |
| **Promtail** | - | Log shipper (Zeek → Loki, Suricata → Loki) |
| **Grafana** | 3000 | Visualization & dashboards |
| **InfluxDB** | 8086 | Time-series metrics |
| **MQTT** | 1883 | Message broker (IoT/sensors) |
| **Traffic Monitor** | 8080 | REST API for traffic analysis |

### Storage Locations
```
/home/rakeshry/Pi_Server/
├── zeek/logs/current/          # Zeek logs (normal traffic)
├── suricata/logs/eve.json      # Suricata events (threats)
├── pcap/                        # PCAP files (rotating)
├── loki/data/                   # Loki log storage
├── influxdb/data/               # InfluxDB time-series
└── grafana/data/                # Grafana config & dashboards
```

---

## 📈 Data Flow Explanation

### Normal Traffic (Zeek) 🟢
1. **Capture**: Zeek listens on wlan0, analyzes all network traffic
2. **Log**: Writes to `zeek/logs/current/` (conn.log, dns.log, http.log, ssl.log, etc.)
3. **Ship**: Promtail reads logs and sends to Loki
4. **Store**: Loki aggregates logs (7-day retention)
5. **Display**: Grafana queries Loki and shows in Zeek dashboard
6. **Use**: Establish baseline, detect anomalies, understand behavior

### Threat Detection (Suricata) 🔴
1. **Capture**: Suricata listens on wlan0, applies IDS/IPS rules
2. **Alert**: Generates events for suspicious traffic to `suricata/logs/eve.json`
3. **Ship**: Promtail ships Suricata logs to Loki
4. **Store**: Loki aggregates events
5. **Display**: Grafana shows threats in Suricata dashboard
6. **Action**: Alert, investigate, block, escalate

### Raw Packets (Tcpdump) 📦
1. **Capture**: Tcpdump captures raw packets on wlan0
2. **Store**: Rotating PCAP files in `pcap/` (5-minute rotation, 6×50MB)
3. **Use**: Deep packet inspection, forensics, ML training data

---

## ⚙️ Configuration Files

### Zeek
- **Config**: `zeek/config/node.cfg` - Node configuration
- **Rules**: `zeek/config/local.zeek` - Custom Zeek scripts
- **Entrypoint**: `zeek/entrypoint.sh` - Startup script (captures on wlan0)

### Suricata
- **Config**: `suricata/config/suricata.yaml` - Engine configuration
- **Rules**: `suricata/rules/suricata.rules` - Detection rules
- **Entrypoint**: `suricata/entrypoint.sh` - Startup script

### Loki
- **Config**: `loki/config/local-config.yaml` - Log retention, storage
- **Retention**: 7 days of logs

### Promtail
- **Config**: `promtail/config/config.yml` - Log scraping rules
- **Targets**: 
  - Zeek logs: `zeek/logs/current/*.log`
  - Suricata: `suricata/logs/eve.json`
  - Docker logs: All containers
- **Push**: `http://172.18.0.3:3100/loki/api/v1/push`

### Grafana
- **Dashboards**: `grafana/provisioning/dashboards/`
  - `suricata-enhanced-dashboard.json` (18 panels)
  - `zeek-enhanced-dashboard.json` (19 panels)
- **Datasources**: `grafana/provisioning/datasources/datasources.yml` (Loki)

---

## 🔍 Understanding the Dashboards

### For Security Teams
**Suricata Dashboard** shows:
- ✅ Real-time security threats
- ✅ Attack sources and targets
- ✅ Threat severity levels
- ✅ Protocol-level attack patterns
- ✅ Actionable threat intelligence

**Use Cases**:
- Monitor active threats
- Investigate security alerts
- Identify attack patterns
- Track threat actors

### For Network Teams
**Zeek Dashboard** shows:
- ✅ Network baseline behavior
- ✅ Device communication patterns
- ✅ DNS resolution activity
- ✅ Service usage (ports, protocols)
- ✅ Network health metrics

**Use Cases**:
- Establish baseline
- Identify new devices
- Monitor service usage
- Detect anomalies

---

## 📊 Interpreting Data

### Green Status = Safe ✅
- Suricata: 0-4 alerts/hour
- Zeek: Normal baseline activity

### Yellow/Orange = Investigate ⚠️
- Suricata: 5-99 alerts/hour
- Zeek: Above normal but not critical

### Red = ALERT 🚨
- Suricata: 100+ alerts/hour
- Zeek: Significant deviation from baseline

### Common Patterns

**Normal Zeek Activity**:
- DNS queries every few minutes (service lookups)
- HTTP/HTTPS traffic (web browsing)
- Constant background connections (NTP, updates)
- Periodic device check-ins

**Suspicious Suricata Alerts**:
- Same source IP repeated alerts = active attack
- High alert rate = scanning/probing
- Unusual ports = potential C2 communication
- Failed authentications = brute force attempt

---

## 🚀 Typical Workflow

### 1. Morning Check
```bash
# Open Suricata dashboard
# Check stat cards for alerts
# Note any overnight incidents
```

### 2. Investigation
```bash
# If high alert count:
#   → Check "Top Source IPs" (who's attacking?)
#   → Check "Top Dest IPs" (what's being targeted?)
#   → Click alert to see details
#   → Cross-reference in Zeek dashboard
```

### 3. Baseline Establishment
```bash
# Watch Zeek dashboard for 24-48 hours
# Note normal stat card values
# Identify regular devices/services
# Set these as baseline for anomaly detection
```

### 4. Ongoing Monitoring
```bash
# 5-second dashboard refresh (automatic)
# Live log streaming (real-time)
# Color-coded alerts (green/yellow/red)
# Drill down into log details as needed
```

---

## 🔧 Maintenance

### Daily
- Check alert status in Suricata dashboard
- Verify Zeek capturing normal traffic
- Monitor disk usage (PCAP files, logs)

### Weekly
- Review log retention and cleanup
- Fine-tune alert thresholds if needed
- Check for new devices in network

### Monthly
- Export data for analysis/ML training
- Review and update detection rules
- Archive PCAP files older than 30 days

### Check Health
```bash
# All containers running?
docker compose ps

# Disk space OK?
df -h

# Loki has data?
curl http://172.18.0.3:3100/loki/api/v1/labels

# Logs being written?
stat zeek/logs/current/conn.log
stat suricata/logs/eve.json
```

---

## 🐛 Troubleshooting

### Dashboard Shows "No Data"
```bash
# 1. Check time range (use "Last 1h" not custom dates)
# 2. Verify containers running
docker compose ps

# 3. Check if logs exist
ls -l zeek/logs/current/
ls -l suricata/logs/

# 4. Verify Loki has data
curl http://172.18.0.3:3100/loki/api/v1/labels

# 5. Check Promtail logs
docker logs promtail
```

### Data Not Updating
```bash
# Check if logs being written
tail -f zeek/logs/current/conn.log
tail -f suricata/logs/eve.json

# Restart services
docker compose restart zeek suricata promtail

# Check Loki connection
curl http://172.18.0.3:3100/loki/api/v1/series
```

### High Disk Usage
```bash
# Check what's taking space
du -sh loki/data/
du -sh pcap/
du -sh zeek/logs/
du -sh suricata/logs/

# PCAP files are rotated automatically (5 min, 6×50MB)
# Loki keeps 7 days of data
# Archive old PCAP files:
tar -czf pcap-backup-$(date +%Y%m%d).tar.gz pcap/
```

### Suricata Not Alerting
```bash
# Check if listening on wlan0
docker exec suricata ss -tulnp | grep -i listen

# Verify rules loaded
docker exec suricata grep "loaded" /var/log/suricata/suricata.log | tail -5

# Restart Suricata
docker compose restart suricata
```

### Zeek Not Capturing
```bash
# Check Zeek logs
docker exec zeek zeekctl status
docker logs zeek

# Verify wlan0 interface
docker exec zeek ip link show wlan0

# Restart Zeek
docker compose restart zeek
```

---

## 📡 REST API (Traffic Monitor)

Base URL: `http://128.39.201.47:8080/api/`

### Available Endpoints
```
GET /api/data-health           # Data source status
GET /api/traffic/baseline      # Normal traffic summary
GET /api/traffic/protocols     # Protocol distribution
GET /api/traffic/top-destinations # Top IPs contacted
```

### Example
```bash
# Check data health
curl http://128.39.201.47:8080/api/data-health | jq

# Get traffic baseline
curl http://128.39.201.47:8080/api/traffic/baseline | jq

# Get top destinations
curl http://128.39.201.47:8080/api/traffic/top-destinations | jq
```

---

## 🎯 Use Cases

### Threat Detection & Response
```
Suricata detects threat → Alert appears in dashboard
→ Check top source IPs → Identify attacker
→ Cross-reference in Zeek → Verify unusual behavior
→ Take action (block, isolate, escalate)
```

### Baseline Establishment
```
Run Zeek for 30 days → Collect normal traffic patterns
→ Note typical connections, DNS queries, services
→ Use as baseline for anomaly detection
→ Train ML model on normal behavior
```

### Compliance & Auditing
```
Export Zeek logs → Review DNS queries, HTTP requests
→ Verify no unauthorized access
→ Document approved services
→ Archive for compliance requirements
```

### Network Troubleshooting
```
User reports issue → Check Zeek dashboard
→ See connections, protocols, errors
→ Correlate with Suricata alerts
→ Identify root cause (blocked, slow, misconfigured)
```

---

## 🔐 Security Notes

- **Credentials**: Change default Grafana password (`admin/admin123`)
- **Network**: Running on hotspot (192.168.4.x) - verify access controls
- **Logs**: Contains network traffic data - protect log files
- **Data**: 7-day retention in Loki - configure per compliance needs
- **PCAP**: Raw packet data - handle with care, archive securely

---

## 📦 Deployment

### Start System
```bash
cd /home/rakeshry/Pi_Server
docker compose up -d
docker compose ps  # Verify all running
```

### Stop System
```bash
docker compose down
```

### View Logs
```bash
docker compose logs -f [service]  # Replace [service] with zeek, suricata, etc.
```

### Update Suricata Rules
```bash
# Edit rules
nano suricata/rules/suricata.rules

# Restart to apply
docker compose restart suricata
```

### Backup Configuration
```bash
tar -czf pi_server_backup.tar.gz \
  zeek/config \
  suricata/config \
  grafana/provisioning
```

---

## 📚 Additional Resources

### Zeek Documentation
- Logs: https://docs.zeek.org/en/master/logs/
- Scripts: https://docs.zeek.org/en/master/script-reference/

### Suricata Documentation
- EVE JSON: https://suricata.readthedocs.io/en/suricata-7.0.0/output/eve/eve-json-output.html
- Rules: https://suricata.readthedocs.io/en/latest/rules/

### Grafana
- Dashboard Creation: https://grafana.com/docs/grafana/latest/dashboards/
- LogQL Queries: https://grafana.com/docs/loki/latest/logql/

---

## 🆘 Support

### Key Metrics to Check
- **Zeek capturing?**: Check `zeek/logs/current/conn.log` modification time
- **Suricata alerting?**: Check `suricata/logs/eve.json` size & modification time
- **Loki receiving?**: `curl http://172.18.0.3:3100/loki/api/v1/labels`
- **Promtail shipping?**: `docker logs promtail` (check for errors)
- **Grafana rendering?**: Try hard refresh (Ctrl+Shift+R) and check browser console

### Debug Commands
```bash
# Full system status
docker compose ps && echo "---" && \
stat zeek/logs/current/conn.log suricata/logs/eve.json

# Loki query test
curl http://172.18.0.3:3100/loki/api/v1/query_range \
  --data-urlencode 'query={job="zeek"}' \
  --data-urlencode 'start=now-1h' \
  --data-urlencode 'end=now'

# Test network capture
docker exec tcpdump tcpdump -i wlan0 -c 5
```

---

## 📝 System Information

- **Location**: `/home/rakeshry/Pi_Server`
- **Network**: Hotspot (wlan0, 192.168.4.x)
- **OS**: Linux (Raspberry Pi / Debian-based)
- **Docker Compose**: Version 2.x
- **Grafana**: 12.3.1
- **Zeek**: Latest
- **Suricata**: 8.0.2
- **Loki**: Latest

---

## ✅ Production Checklist

- ✅ All 10 Docker services running
- ✅ Zeek capturing on wlan0
- ✅ Suricata detecting threats
- ✅ Tcpdump rotating PCAP files
- ✅ Promtail shipping logs to Loki
- ✅ Loki aggregating (7-day retention)
- ✅ Grafana dashboards updating (5-sec refresh)
- ✅ Real-time alerts enabled
- ✅ 18 + 19 = 37 total panels
- ✅ Color-coded metrics active
- ✅ Live log streaming working
- ✅ All panels displaying data

---

**System Status**: ✅ PRODUCTION READY

**Last Updated**: December 18, 2025  
**Ready for**: 24/7 Network Security Monitoring
