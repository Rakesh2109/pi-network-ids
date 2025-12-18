#!/usr/bin/env python3
import os
import json
import time
import logging
from paho.mqtt import client as mqtt_client
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# Configuration
MQTT_BROKER = os.getenv('MQTT_BROKER', 'mqtt')
MQTT_PORT = int(os.getenv('MQTT_PORT', 1883))
INFLUXDB_URL = os.getenv('INFLUXDB_URL', 'http://influxdb:8086')
INFLUXDB_TOKEN = os.getenv('INFLUXDB_TOKEN', 'my-super-secret-admin-token')
INFLUXDB_ORG = os.getenv('INFLUXDB_ORG', 'pi_server')
INFLUXDB_BUCKET = os.getenv('INFLUXDB_BUCKET', 'sensor_data')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MQTT Client
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to MQTT broker")
        client.subscribe("#")  # Subscribe to all topics
    else:
        logger.error(f"Failed to connect to MQTT broker, return code {rc}")

def on_message(client, userdata, msg):
    try:
        topic = msg.topic
        payload = msg.payload.decode()
        
        # Try to parse JSON, if fails treat as string value
        numeric_value = None
        tags = {}
        try:
            data = json.loads(payload)
            # If it's a dict, extract numeric values and tags
            if isinstance(data, dict):
                # Look for common numeric fields: temperature, value, humidity, pressure, etc.
                # Check temperature first for temperature sensors
                if 'temperature' in data and isinstance(data['temperature'], (int, float)):
                    numeric_value = float(data['temperature'])
                else:
                    for field in ['value', 'humidity', 'pressure', 'voltage', 'current']:
                        if field in data and isinstance(data[field], (int, float)):
                            numeric_value = float(data[field])
                            break
                
                # If no numeric field found, use 'value' key or first numeric value
                if numeric_value is None:
                    if 'value' in data:
                        numeric_value = float(data['value']) if isinstance(data['value'], (int, float)) else None
                    else:
                        # Find first numeric value
                        for v in data.values():
                            if isinstance(v, (int, float)):
                                numeric_value = float(v)
                                break
                
                # Store metadata fields as tags (exclude numeric sensor values)
                tags = {k: str(v) for k, v in data.items() if k not in ['temperature', 'value', 'humidity', 'pressure', 'voltage', 'current']}
            else:
                numeric_value = float(data) if isinstance(data, (int, float)) else None
        except (json.JSONDecodeError, ValueError):
            # Try to parse as float directly
            try:
                numeric_value = float(payload)
            except ValueError:
                pass
        
        # Extract sensor name from topic or use sensor tag
        sensor_name = tags.get('sensor', topic.split('/')[-1] if '/' in topic else topic)
        
        # Create InfluxDB point with numeric value - use new measurement to avoid field conflicts
        point = Point("sensors") \
            .tag("sensor", sensor_name) \
            .tag("topic", topic) \
            .time(time.time_ns())
        
        # Add numeric value field (use temperature field name if it's temperature data)
        if numeric_value is not None:
            # Use appropriate field name based on topic or data - NEVER use "value" to avoid type conflicts
            if 'temperature' in data or 'temperature' in topic.lower():
                point = point.field("temperature", numeric_value)
                logger.debug(f"Writing temperature field: {numeric_value}")
            elif 'humidity' in data or 'humidity' in topic.lower():
                point = point.field("humidity", numeric_value)
            elif 'pressure' in data or 'pressure' in topic.lower():
                point = point.field("pressure", numeric_value)
            else:
                point = point.field("value_num", numeric_value)
        else:
            # Fallback to string value - use value_str to avoid conflict
            point = point.field("value_str", payload)
        
        # Add additional tags if present
        for key, val in tags.items():
            if key not in ['value']:  # Don't duplicate 'value' as tag if it exists
                point = point.tag(key, str(val))
        
        # Write to InfluxDB
        write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
        logger.info(f"Stored data: topic={topic}, temperature={numeric_value}")
        
    except Exception as e:
        logger.error(f"Error processing message: {e}")

# Initialize InfluxDB client
logger.info("Connecting to InfluxDB...")
influx_client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
write_api = influx_client.write_api(write_options=SYNCHRONOUS)

# Initialize MQTT client
logger.info("Connecting to MQTT broker...")
mqtt_client_instance = mqtt_client.Client()
mqtt_client_instance.on_connect = on_connect
mqtt_client_instance.on_message = on_message

# Connect with retry logic
while True:
    try:
        mqtt_client_instance.connect(MQTT_BROKER, MQTT_PORT, 60)
        break
    except Exception as e:
        logger.error(f"Failed to connect to MQTT broker: {e}. Retrying in 5 seconds...")
        time.sleep(5)

mqtt_client_instance.loop_forever()

