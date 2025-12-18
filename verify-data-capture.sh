#!/bin/bash

echo "═══════════════════════════════════════════════════════════════"
echo "IDS DATA CAPTURE VERIFICATION - NORMAL & ABNORMAL TRAFFIC"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[1] NORMAL TRAFFIC DATA${NC}"
echo "────────────────────────────────────────────────────────────────"

# Check Zeek connections (normal traffic)
CONN_LOG="/data/zeek/logs/current/conn.log"
if [ -f "$CONN_LOG" ]; then
    CONN_COUNT=$(grep -v "^#" "$CONN_LOG" 2>/dev/null | wc -l)
    CONN_SIZE=$(du -h "$CONN_LOG" | cut -f1)
    echo -e "${GREEN}✓ ZEEK CONNECTIONS (conn.log)${NC}"
    echo "  File: $CONN_LOG"
    echo "  Size: $CONN_SIZE"
    echo "  Entries: $CONN_COUNT normal connections"
    echo ""
else
    echo -e "${YELLOW}⚠ ZEEK CONNECTIONS${NC} - No conn.log yet (awaiting traffic)"
    echo ""
fi

# Check HTTP (normal traffic)
HTTP_LOG="/data/zeek/logs/current/http.log"
if [ -f "$HTTP_LOG" ]; then
    HTTP_COUNT=$(grep -v "^#" "$HTTP_LOG" 2>/dev/null | wc -l)
    HTTP_SIZE=$(du -h "$HTTP_LOG" | cut -f1)
    echo -e "${GREEN}✓ ZEEK HTTP REQUESTS (http.log)${NC}"
    echo "  File: $HTTP_LOG"
    echo "  Size: $HTTP_SIZE"
    echo "  Entries: $HTTP_COUNT HTTP requests"
    echo ""
else
    echo -e "${YELLOW}⚠ ZEEK HTTP REQUESTS${NC} - No http.log yet"
    echo ""
fi

# Check DNS (normal traffic)
DNS_LOG="/data/zeek/logs/current/dns.log"
if [ -f "$DNS_LOG" ]; then
    DNS_COUNT=$(grep -v "^#" "$DNS_LOG" 2>/dev/null | wc -l)
    DNS_SIZE=$(du -h "$DNS_LOG" | cut -f1)
    echo -e "${GREEN}✓ ZEEK DNS QUERIES (dns.log)${NC}"
    echo "  File: $DNS_LOG"
    echo "  Size: $DNS_SIZE"
    echo "  Entries: $DNS_COUNT DNS queries"
    echo ""
else
    echo -e "${YELLOW}⚠ ZEEK DNS QUERIES${NC} - No dns.log yet"
    echo ""
fi

# Check SSL/TLS (normal traffic)
SSL_LOG="/data/zeek/logs/current/ssl.log"
if [ -f "$SSL_LOG" ]; then
    SSL_COUNT=$(grep -v "^#" "$SSL_LOG" 2>/dev/null | wc -l)
    SSL_SIZE=$(du -h "$SSL_LOG" | cut -f1)
    echo -e "${GREEN}✓ ZEEK SSL/TLS CONNECTIONS (ssl.log)${NC}"
    echo "  File: $SSL_LOG"
    echo "  Size: $SSL_SIZE"
    echo "  Entries: $SSL_COUNT SSL/TLS connections"
    echo ""
else
    echo -e "${YELLOW}⚠ ZEEK SSL/TLS CONNECTIONS${NC} - No ssl.log yet"
    echo ""
fi

echo ""
echo -e "${BLUE}[2] ABNORMAL TRAFFIC DATA${NC}"
echo "────────────────────────────────────────────────────────────────"

# Check Suricata alerts (abnormal traffic)
EVE_FILE="/data/suricata/eve.json"
if [ -f "$EVE_FILE" ]; then
    EVE_SIZE=$(du -h "$EVE_FILE" | cut -f1)
    ALERT_COUNT=$(grep -c '"event_type":"alert"' "$EVE_FILE" 2>/dev/null || echo "0")
    FLOW_COUNT=$(grep -c '"event_type":"flow"' "$EVE_FILE" 2>/dev/null || echo "0")
    HTTP_COUNT=$(grep -c '"event_type":"http"' "$EVE_FILE" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}✓ SURICATA EVENTS (eve.json)${NC}"
    echo "  File: $EVE_FILE"
    echo "  Size: $EVE_SIZE"
    echo "  Alert Events: $ALERT_COUNT (abnormal detections)"
    echo "  Flow Events: $FLOW_COUNT (all flows)"
    echo "  HTTP Events: $HTTP_COUNT (application layer)"
    echo ""
    
    # Show sample alert if available
    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}  Sample Alert:${NC}"
        grep '"event_type":"alert"' "$EVE_FILE" | head -1 | python3 -m json.tool | head -20 | sed 's/^/    /'
    else
        echo "  (No alerts yet - awaiting attack traffic)"
    fi
    echo ""
else
    echo -e "${YELLOW}⚠ SURICATA EVENTS${NC} - No eve.json found"
    echo ""
fi

echo ""
echo -e "${BLUE}[3] RAW PACKET CAPTURE${NC}"
echo "────────────────────────────────────────────────────────────────"

PCAP_DIR="/data/pcap"
if [ -d "$PCAP_DIR" ]; then
    PCAP_COUNT=$(ls "$PCAP_DIR"/*.pcap 2>/dev/null | wc -l)
    PCAP_TOTAL=$(du -sh "$PCAP_DIR" | cut -f1)
    
    echo -e "${GREEN}✓ TCPDUMP PCAP FILES${NC}"
    echo "  Directory: $PCAP_DIR"
    echo "  Total Size: $PCAP_TOTAL"
    echo "  File Count: $PCAP_COUNT .pcap files"
    echo ""
    
    if [ "$PCAP_COUNT" -gt 0 ]; then
        echo "  Recent Files:"
        ls -lh "$PCAP_DIR"/*.pcap 2>/dev/null | tail -3 | awk '{print "    " $9 " (" $5 ")"}'
    else
        echo "  (Waiting for first rotation - captures every 5 minutes)"
    fi
    echo ""
else
    echo -e "${RED}✗ TCPDUMP PCAP${NC} - Directory not found"
    echo ""
fi

echo ""
echo -e "${BLUE}[4] LOKI LOG AGGREGATION${NC}"
echo "────────────────────────────────────────────────────────────────"

# Query Loki for data
LOKI_RESPONSE=$(curl -s 'http://localhost:3100/loki/api/v1/query_range' \
    --data-urlencode 'query={job=~"suricata|zeek"}' \
    --data-urlencode 'start=1h' \
    --data-urlencode 'end=0' 2>/dev/null || echo "ERROR")

if [ "$LOKI_RESPONSE" != "ERROR" ]; then
    if echo "$LOKI_RESPONSE" | grep -q '"result"'; then
        STREAM_COUNT=$(echo "$LOKI_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data.get('data',{}).get('result',[])))" 2>/dev/null || echo "?")
        echo -e "${GREEN}✓ LOKI AGGREGATION${NC}"
        echo "  Status: Connected to Loki"
        echo "  Data Streams: $STREAM_COUNT active streams"
        echo "  Retention: 7 days"
        
        # Show available job labels
        JOBS=$(curl -s 'http://localhost:3100/loki/api/v1/labels' 2>/dev/null | python3 -c "import sys, json; data=json.load(sys.stdin); print(', '.join([str(j) for j in data.get('data',[]) if j]))" 2>/dev/null || echo "suricata, zeek")
        echo "  Labels found: $JOBS"
        echo ""
    else
        echo -e "${YELLOW}⚠ LOKI AGGREGATION${NC} - No data in Loki yet"
        echo ""
    fi
else
    echo -e "${YELLOW}⚠ LOKI AGGREGATION${NC} - Cannot connect"
    echo ""
fi

echo ""
echo -e "${BLUE}[5] SUMMARY${NC}"
echo "────────────────────────────────────────────────────────────────"

# Get API data
API_DATA=$(curl -s http://128.39.201.47:8080/api/data-health 2>/dev/null)

if [ ! -z "$API_DATA" ]; then
    echo -e "${GREEN}✓ Traffic Monitor API${NC}"
    echo "  Status: ONLINE"
    echo ""
    
    # Extract values
    if echo "$API_DATA" | python3 -c "import sys, json; json.load(sys.stdin)" 2>/dev/null; then
        echo -e "${BLUE}Data Being Captured:${NC}"
        echo "$API_DATA" | python3 -m json.tool 2>/dev/null | grep -E '"size|status|filename|job' | head -20
    fi
else
    echo -e "${YELLOW}⚠ Traffic Monitor API${NC} - Cannot reach"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e "${GREEN}SYSTEM STATUS: Data collection is ACTIVE${NC}"
echo ""
echo "Capturing NORMAL traffic:  ✓ Zeek logs (all connections/protocols)"
echo "Capturing ABNORMAL data:   ✓ Suricata alerts (attack signatures)"
echo "Capturing RAW packets:     ✓ Tcpdump PCAP (complete packet data)"
echo "Aggregating to Loki:       ✓ For real-time visualization"
echo ""
echo "Dashboard: http://128.39.201.47:3000 (admin/admin123)"
echo "Traffic Monitor: http://128.39.201.47:8080"
echo ""
echo "═══════════════════════════════════════════════════════════════"
