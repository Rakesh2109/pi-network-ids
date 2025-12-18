FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir paho-mqtt influxdb-client

COPY collector.py .
COPY requirements.txt .

CMD ["python", "collector.py"]

