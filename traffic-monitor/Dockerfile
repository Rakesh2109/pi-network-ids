FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y tcpdump && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask flask-cors pandas

COPY app.py .
COPY templates templates/
COPY static static/

EXPOSE 8080

CMD ["python", "app.py"]

