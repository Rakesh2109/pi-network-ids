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
                # Handle Health/Bio sensor data
                if 'heartRate' in data or 'oxygen' in data:
                    # Create separate point for health sensor data
                    point = Point("health_sensors") \
                        .tag("sensor", "biosensor") \
                        .tag("topic", topic) \
                        .time(time.time_ns())
                    
                    # Heart rate data
                    if 'heartRate' in data:
                        point = point.field("heart_rate", float(data['heartRate']))
                    if 'confidence' in data:
                        point = point.field("heart_confidence", float(data['confidence']))
                    
                    # Oxygen saturation data
                    if 'oxygen' in data:
                        point = point.field("spo2", float(data['oxygen']))
                    if 'oxygenConfidence' in data:
                        point = point.field("spo2_confidence", float(data['oxygenConfidence']))
                    
                    # Store timestamp as field (not tag) to avoid creating multiple series
                    if 'timestamp' in data:
                        point = point.field("sensor_timestamp", float(data['timestamp']))
                    
                    # Write health data to InfluxDB
                    write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
                    logger.info(f"Stored health data: topic={topic}, HR={data.get('heartRate')}, SpO2={data.get('oxygen')}")
                    return
                
                # Handle SGP40 VOC sensor data
                if data.get('sensor') == 'SGP40' or 'voc_index' in data:
                    sensor_name = data.get('sensor', 'SGP40')
                    device_id = data.get('device_id', 'ESP32_SGP40')
                    point = Point("sgp40_voc") \
                        .tag("sensor", sensor_name) \
                        .tag("device_id", device_id) \
                        .tag("topic", topic) \
                        .time(time.time_ns())
                    
                    # VOC Index
                    if 'voc_index' in data:
                        point = point.field("voc_index", float(data['voc_index']))
                    
                    # Raw Gas value
                    if 'raw_gas' in data:
                        point = point.field("raw_gas", float(data['raw_gas']))
                    
                    # Store sensor timestamp if available
                    if 'timestamp' in data:
                        point = point.field("sensor_timestamp", float(data['timestamp']))
                    
                    # Write SGP40 data to InfluxDB
                    write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
                    logger.info(f"Stored SGP40 VOC data: topic={topic}, voc_index={data.get('voc_index')}, raw_gas={data.get('raw_gas')}")
                    return
                
                # Handle ESP32_PIR_IMU sensor data (combined PIR motion + IMU)
                # Check for sensor field first, then check for imu key (motion is optional)
                if data.get('sensor') == 'ESP32_PIR_IMU' or 'imu' in data:
                    sensor_name = data.get('sensor', 'ESP32_PIR_IMU')
                    point = Point("esp32_pir_imu") \
                        .tag("sensor", sensor_name) \
                        .tag("topic", topic) \
                        .time(time.time_ns())
                    
                    # PIR Motion Data
                    if 'motion' in data and isinstance(data['motion'], dict):
                        motion_data = data['motion']
                        if 'motion_count' in motion_data:
                            point = point.field("motion_count", int(motion_data['motion_count']))
                        if 'motion_detected' in motion_data:
                            # Convert boolean to int (0/1) for InfluxDB
                            point = point.field("motion_detected", 1 if motion_data['motion_detected'] in [True, 'true', 'True', 1, '1'] else 0)
                    
                    # IMU Data (nested structure)
                    if 'imu' in data and isinstance(data['imu'], dict):
                        imu_data = data['imu']
                        
                        # Accelerometer data
                        if 'accel' in imu_data and isinstance(imu_data['accel'], dict):
                            point = point.field("accel_x", float(imu_data['accel'].get('x', 0)))
                            point = point.field("accel_y", float(imu_data['accel'].get('y', 0)))
                            point = point.field("accel_z", float(imu_data['accel'].get('z', 0)))
                        
                        # Gyroscope data
                        if 'gyro' in imu_data and isinstance(imu_data['gyro'], dict):
                            point = point.field("gyro_x", float(imu_data['gyro'].get('x', 0)))
                            point = point.field("gyro_y", float(imu_data['gyro'].get('y', 0)))
                            point = point.field("gyro_z", float(imu_data['gyro'].get('z', 0)))
                        
                        # Magnetometer data
                        if 'mag' in imu_data and isinstance(imu_data['mag'], dict):
                            point = point.field("mag_x", float(imu_data['mag'].get('x', 0)))
                            point = point.field("mag_y", float(imu_data['mag'].get('y', 0)))
                            point = point.field("mag_z", float(imu_data['mag'].get('z', 0)))
                        
                        # Temperature
                        if 'temperature' in imu_data:
                            point = point.field("temperature", float(imu_data['temperature']))
                    
                    # Store sensor timestamp if available
                    if 'timestamp' in data:
                        point = point.field("sensor_timestamp", float(data['timestamp']))
                    
                    # Write ESP32_PIR_IMU data to InfluxDB
                    write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
                    logger.info(f"Stored ESP32_PIR_IMU data: topic={topic}, motion_count={data.get('motion', {}).get('motion_count')}, temp={data.get('imu', {}).get('temperature')}")
                    return
                
                # Handle LSM9DS1 IMU sensor data with nested structure (legacy format)
                if 'accel' in data and 'gyro' in data and 'mag' in data:
                    # Create separate point for IMU data with all fields
                    point = Point("imu_sensors") \
                        .tag("sensor", "lsm9ds1") \
                        .tag("topic", topic) \
                        .time(time.time_ns())
                    
                    # Accelerometer data
                    if isinstance(data['accel'], dict):
                        point = point.field("accel_x", float(data['accel'].get('x', 0)))
                        point = point.field("accel_y", float(data['accel'].get('y', 0)))
                        point = point.field("accel_z", float(data['accel'].get('z', 0)))
                    
                    # Gyroscope data
                    if isinstance(data['gyro'], dict):
                        point = point.field("gyro_x", float(data['gyro'].get('x', 0)))
                        point = point.field("gyro_y", float(data['gyro'].get('y', 0)))
                        point = point.field("gyro_z", float(data['gyro'].get('z', 0)))
                    
                    # Magnetometer data
                    if isinstance(data['mag'], dict):
                        point = point.field("mag_x", float(data['mag'].get('x', 0)))
                        point = point.field("mag_y", float(data['mag'].get('y', 0)))
                        point = point.field("mag_z", float(data['mag'].get('z', 0)))
                    
                    # Temperature and heading
                    if 'temp' in data:
                        point = point.field("temperature", float(data['temp']))
                    if 'heading' in data:
                        point = point.field("heading", float(data['heading']))
                    
                    # Write IMU data to InfluxDB
                    write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
                    logger.info(f"Stored IMU data: topic={topic}, temp={data.get('temp')}, heading={data.get('heading')}")
                    return
                
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

