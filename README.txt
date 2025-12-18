Pi Server - IoT Monitoring & Network Security Stack
====================================================

Services:
- MQTT Broker (Mosquitto): Port 1883, 9001
- InfluxDB: Port 8086 (admin/admin123)
- Grafana: Port 3000 (admin/admin123)
- Loki: Port 3100
- Suricata: Network IDS/IPS
- Zeek: Network analysis
- Traffic Monitor: Port 8080

Quick Start:
1. docker-compose up -d

2. Access services:
   - Grafana: http://localhost:3000
   - Traffic Monitor: http://localhost:8080
   - InfluxDB: http://localhost:8086

3. MQTT Configuration for ESP32 sensors:
   MQTT Server IP: 192.168.4.1 (hotspot interface wlan0)
   MQTT Port: 1883
   MQTT Topic: sensors/esp32/temperature (or any topic)
   No authentication (anonymous access enabled)

4. Test MQTT from Pi:
   mosquitto_pub -h 192.168.4.1 -t sensors/esp32/temperature -m '{"value": 25.5}'

Important:
- wlan0 = Hotspot network (192.168.4.1) - Used for ESP32 sensors and Kali attacks
- eth0 = LAN/Internet (NOT used for capture)
- Suricata and Zeek capture traffic ONLY on wlan0 (hotspot)
- MQTT is accessible at 192.168.4.1:1883 for ESP32 devices

