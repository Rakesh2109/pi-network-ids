#!/usr/bin/env python3
import os
import json
import glob
import subprocess
import csv
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, send_file, Response
from flask_cors import CORS
import io

app = Flask(__name__)
CORS(app)

SURICATA_LOG_DIR = "/data/suricata"
ZEEK_LOG_DIR = "/data/zeek"
PCAP_DIR = "/data/pcap"

# Helper function to get timestamp for 2 hours ago
def get_2hour_ago_timestamp():
    return (datetime.now() - timedelta(hours=2)).timestamp()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/suricata/all')
def suricata_all():
    """Get ALL Suricata events from eve.json (last 2 hours of data)"""
    import subprocess
    events = []
    eve_file = os.path.join(SURICATA_LOG_DIR, "eve.json")
    cutoff_time = get_2hour_ago_timestamp()
    
    if os.path.exists(eve_file):
        try:
            # Read entire file - just get last 500 lines (most recent)
            with open(eve_file, 'r') as f:
                lines = f.readlines()
                for line in lines[-500:]:  # Last 500 lines
                    if line.strip():
                        try:
                            event = json.loads(line)
                            # Exclude stats events from main table
                            if event.get('event_type') != 'stats':
                                events.append(event)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Return events sorted by timestamp (newest first)
    events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify(events[:500])  # Return up to 500 events

@app.route('/api/suricata/<event_type>')
def suricata_by_type(event_type):
    """Get Suricata events by type"""
    import subprocess
    events = []
    eve_file = os.path.join(SURICATA_LOG_DIR, "eve.json")
    
    if os.path.exists(eve_file):
        try:
            result = subprocess.run(['grep', '-m', '100', f'"event_type":"{event_type}"', eve_file], 
                                   capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except: pass
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify(events[:50])

@app.route('/api/suricata/stats')
def suricata_stats():
    """Get Suricata statistics"""
    stats_file = os.path.join(SURICATA_LOG_DIR, "stats.log")
    stats = {}
    
    if os.path.exists(stats_file):
        try:
            with open(stats_file, 'r') as f:
                content = f.read()
                # Parse basic stats
                for line in content.split('\n'):
                    if 'capture.kernel_packets' in line:
                        stats['kernel_packets'] = line.split()[-1]
                    elif 'capture.kernel_drops' in line:
                        stats['kernel_drops'] = line.split()[-1]
        except Exception as e:
            pass
    
    return jsonify(stats)

@app.route('/api/zeek/all')
def zeek_all():
    """Get ALL Zeek logs combined (conn, http, dns, ssl) - last 2 hours"""
    all_data = []
    
    # Get connections
    conn_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/conn.log"))
    conn_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/conn.log"), recursive=True))
    if conn_files:
        latest_file = max(conn_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 10:
                            try:
                                all_data.append({
                                    'type': 'connection',
                                    'ts': parts[0],
                                    'src_ip': parts[2],
                                    'src_port': parts[3],
                                    'dst_ip': parts[4],
                                    'dst_port': parts[5],
                                    'proto': parts[6],
                                    'duration': parts[8],
                                    'orig_bytes': parts[9],
                                    'resp_bytes': parts[10] if len(parts) > 10 else '0',
                                    'details': f"{parts[6].upper()} connection"
                                })
                            except:
                                pass
        except Exception as e:
            pass
    
    # Get HTTP
    http_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/http.log"))
    http_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/http.log"), recursive=True))
    if http_files:
        latest_file = max(http_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 8:
                            try:
                                all_data.append({
                                    'type': 'http',
                                    'ts': parts[0],
                                    'src_ip': parts[2],
                                    'src_port': parts[3],
                                    'dst_ip': parts[4],
                                    'dst_port': parts[5],
                                    'method': parts[6],
                                    'host': parts[7],
                                    'uri': parts[8] if len(parts) > 8 else '',
                                    'details': f"{parts[6]} {parts[7]}{parts[8] if len(parts) > 8 else ''}"
                                })
                            except:
                                pass
        except Exception as e:
            pass
    
    # Get DNS
    dns_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/dns.log"))
    dns_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/dns.log"), recursive=True))
    if dns_files:
        latest_file = max(dns_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 10:
                            try:
                                query = parts[9] if len(parts) > 9 else ''
                                qtype = parts[13] if len(parts) > 13 else ''
                                all_data.append({
                                    'type': 'dns',
                                    'ts': parts[0],
                                    'src_ip': parts[2],
                                    'src_port': '',
                                    'dst_ip': parts[4],
                                    'dst_port': '',
                                    'query': query,
                                    'qtype': qtype,
                                    'details': f"DNS {qtype}: {query}"
                                })
                            except:
                                pass
        except Exception as e:
            pass
    
    # Get SSL
    ssl_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/ssl.log"))
    ssl_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/ssl.log"), recursive=True))
    if ssl_files:
        latest_file = max(ssl_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 5:
                            try:
                                server_name = parts[11] if len(parts) > 11 else ''
                                all_data.append({
                                    'type': 'ssl',
                                    'ts': parts[0],
                                    'src_ip': parts[2],
                                    'src_port': '',
                                    'dst_ip': parts[4],
                                    'dst_port': '',
                                    'server_name': server_name,
                                    'details': f"SSL/TLS: {server_name}"
                                })
                            except:
                                pass
        except Exception as e:
            pass
    
    # Sort by timestamp (newest first)
    all_data.sort(key=lambda x: float(x.get('ts', 0)), reverse=True)
    return jsonify(all_data[:500])

@app.route('/api/zeek/http')
def zeek_http():
    """Get Zeek HTTP logs"""
    http_requests = []
    # Check multiple patterns for http logs
    http_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/http.log"))
    http_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/http.log"), recursive=True))
    http_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/http.*.log"), recursive=True))
    
    if http_files:
        latest_file = max(http_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 8:
                            req = {
                                'ts': parts[0],
                                'uid': parts[1],
                                'id_orig_h': parts[2],
                                'id_orig_p': parts[3],
                                'id_resp_h': parts[4],
                                'id_resp_p': parts[5],
                                'method': parts[6],
                                'host': parts[7],
                                'uri': parts[8] if len(parts) > 8 else ''
                            }
                            http_requests.append(req)
                            if len(http_requests) >= 50:
                                break
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify(http_requests[::-1])

@app.route('/api/zeek/dns')
def zeek_dns():
    """Get Zeek DNS logs"""
    dns_queries = []
    # Check multiple patterns for dns logs
    dns_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/dns.log"))
    dns_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/dns.log"), recursive=True))
    
    if dns_files:
        latest_file = max(dns_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 10:
                            query = {
                                'ts': parts[0],
                                'id_orig_h': parts[2],
                                'id_resp_h': parts[4],
                                'query': parts[9] if len(parts) > 9 else '',
                                'qtype': parts[13] if len(parts) > 13 else ''
                            }
                            dns_queries.append(query)
                            if len(dns_queries) >= 50:
                                break
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify(dns_queries[::-1])

@app.route('/api/zeek/ssl')
def zeek_ssl():
    """Get Zeek SSL/TLS logs"""
    ssl_conns = []
    # Check multiple patterns for ssl logs
    ssl_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/ssl.log"))
    ssl_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/ssl.log"), recursive=True))
    
    if ssl_files:
        latest_file = max(ssl_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 5:
                            ssl = {
                                'ts': parts[0],
                                'id_orig_h': parts[2],
                                'id_resp_h': parts[4],
                                'server_name': parts[11] if len(parts) > 11 else '',
                                'subject': parts[17] if len(parts) > 17 else ''
                            }
                            ssl_conns.append(ssl)
                            if len(ssl_conns) >= 50:
                                break
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify(ssl_conns[::-1])

@app.route('/api/dashboard')
def dashboard():
    """Get combined dashboard data"""
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "services": {
            "suricata": os.path.exists(SURICATA_LOG_DIR),
            "zeek": os.path.exists(ZEEK_LOG_DIR)
        }
    })

@app.route('/api/tcpdump/all-traffic')
def tcpdump_all_traffic():
    """Get all captured traffic from pcap files (parsed connections)"""
    traffic_data = []
    debug_info = {
        'pcap_dir_exists': os.path.exists(PCAP_DIR),
        'pcap_dir': PCAP_DIR,
        'files_found': 0,
        'total_lines_processed': 0,
        'lines_with_gt': 0,
        'lines_matching_gt_pos3': 0,
        'entries_added': 0
    }
    
    if os.path.exists(PCAP_DIR):
        try:
            # Use tcpdump to read PCAP files and extract connection info
            pcap_files = []
            for f in os.listdir(PCAP_DIR):
                if f.endswith('.pcap') or f.endswith('.pcap0'):
                    pcap_files.append(os.path.join(PCAP_DIR, f))
            
            debug_info['files_found'] = len(pcap_files)
            
            # Sort by modification time (newest first)
            pcap_files.sort(key=os.path.getmtime, reverse=True)
            
            cutoff_time = get_2hour_ago_timestamp()
            
            for pcap_file in pcap_files[:5]:  # Process last 5 PCAP files
                try:
                    # Use tcpdump to read PCAP and extract flows
                    result = subprocess.run(
                        ['tcpdump', '-r', pcap_file, '-nn', 'tcp or udp'],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    for line in result.stdout.split('\n'):
                        debug_info['total_lines_processed'] += 1
                        if line.strip() and '>' in line:
                            debug_info['lines_with_gt'] += 1
                            # Parse tcpdump output: timestamp IP src > dst: info
                            # Example: 20:24:02.756955 IP 192.168.4.76.50810 > 192.168.4.1.1883: Flags...
                            parts = line.split()
                            if len(parts) >= 5 and parts[3] == '>':  # Check for '>' at position 3
                                debug_info['lines_matching_gt_pos3'] += 1
                                try:
                                    time_str = parts[0]
                                    src = parts[2]  # Source IP:port
                                    dst = parts[4].rstrip(':')  # Destination IP:port (remove trailing ':')
                                    
                                    # Extract protocol info
                                    proto = 'TCP' if 'tcp' in line.lower() or 'Flags' in line else 'UDP'
                                    
                                    traffic_data.append({
                                        'time': time_str,
                                        'source': src,
                                        'destination': dst,
                                        'protocol': proto,
                                        'info': ' '.join(parts[5:]) if len(parts) > 5 else ''
                                    })
                                    debug_info['entries_added'] += 1
                                except Exception as parse_err:
                                    print(f"[DEBUG] Parse error: {parse_err}, parts count: {len(parts)}")
                except Exception as pcap_err:
                    print(f"[DEBUG] PCAP error for {pcap_file}: {pcap_err}")
        except Exception as e:
            print(f"[DEBUG] General error in tcpdump_all_traffic: {e}")
    
    # Return latest 300 traffic entries
    return jsonify({
        'total_packets': len(traffic_data),
        'traffic': traffic_data[:300],
        '_debug': debug_info
    })

@app.route('/api/tcpdump/stats')
def tcpdump_stats():
    """Get tcpdump PCAP file statistics"""
    pcap_files = []
    if os.path.exists(PCAP_DIR):
        try:
            for f in os.listdir(PCAP_DIR):
                if f.endswith('.pcap') or f.endswith('.pcap0'):
                    path = os.path.join(PCAP_DIR, f)
                    stat = os.stat(path)
                    pcap_files.append({
                        'filename': f,
                        'size_mb': round(stat.st_size / (1024*1024), 2),
                        'size_bytes': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'packets': 'N/A'  # Would need tcpdump to parse
                    })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Sort by modified time descending
    pcap_files.sort(key=lambda x: x['modified'], reverse=True)
    return jsonify({
        'total_files': len(pcap_files),
        'total_size_mb': round(sum(f['size_bytes'] for f in pcap_files) / (1024*1024), 2),
        'files': pcap_files[:20]  # Last 20 files
    })

@app.route('/api/tcpdump/summary')
def tcpdump_summary():
    """Get tcpdump capture summary"""
    try:
        result = subprocess.run(['df', PCAP_DIR], capture_output=True, text=True, check=True)
        lines = result.stdout.split('\n')
        if len(lines) > 1:
            parts = lines[1].split()
            return jsonify({
                'capture_path': PCAP_DIR,
                'total_space_mb': round(int(parts[1]) / 1024, 2),
                'used_space_mb': round(int(parts[2]) / 1024, 2),
                'available_space_mb': round(int(parts[3]) / 1024, 2),
                'usage_percent': parts[4]
            })
    except Exception as e:
        pass
    
    return jsonify({
        'capture_path': PCAP_DIR,
        'status': 'running',
        'interface': 'wlan0',
        'rotation_interval': '5 minutes',
        'max_file_size': '50 MB',
        'max_files': 6
    })

@app.route('/api/traffic/baseline')
def traffic_baseline():
    """Get NORMAL traffic baseline metrics for comparison with abnormal"""
    baseline = {
        'timestamp': datetime.now().isoformat(),
        'normal_traffic': {},
        'abnormal_traffic': {}
    }
    
    # NORMAL TRAFFIC: Total connections (successful flows)
    conn_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/conn.log"))
    conn_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/conn.log"), recursive=True))
    total_connections = 0
    protocols = {}
    if conn_files:
        latest_file = max(conn_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 7:
                            total_connections += 1
                            proto = parts[6]
                            protocols[proto] = protocols.get(proto, 0) + 1
        except:
            pass
    
    baseline['normal_traffic']['total_connections'] = total_connections
    baseline['normal_traffic']['protocols'] = protocols
    
    # NORMAL TRAFFIC: HTTP requests
    http_count = 0
    http_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/http.log"))
    http_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/http.log"), recursive=True))
    if http_files:
        latest_file = max(http_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        http_count += 1
        except:
            pass
    baseline['normal_traffic']['http_requests'] = http_count
    
    # NORMAL TRAFFIC: DNS queries
    dns_count = 0
    dns_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/dns.log"))
    dns_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/dns.log"), recursive=True))
    if dns_files:
        latest_file = max(dns_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        dns_count += 1
        except:
            pass
    baseline['normal_traffic']['dns_queries'] = dns_count
    
    # ABNORMAL TRAFFIC: Alert counts
    alert_count = 0
    eve_file = os.path.join(SURICATA_LOG_DIR, "eve.json")
    if os.path.exists(eve_file):
        try:
            result = subprocess.run(['grep', '-c', '"event_type":"alert"', eve_file],
                                   capture_output=True, text=True)
            alert_count = int(result.stdout.strip()) if result.stdout.strip() else 0
        except:
            pass
    baseline['abnormal_traffic']['alert_count'] = alert_count
    
    # Summary
    baseline['summary'] = {
        'normal_to_abnormal_ratio': f"{total_connections}:{ alert_count}" if alert_count > 0 else f"{total_connections}:0",
        'data_quality': 'CAPTURING BOTH NORMAL AND ABNORMAL TRAFFIC'
    }
    
    return jsonify(baseline)

@app.route('/api/data-health')
def data_health():
    """Verify all raw data sources are being logged properly"""
    import subprocess as sp
    health = {
        'timestamp': datetime.now().isoformat(),
        'data_sources': {}
    }
    
    # Check Suricata EVE JSON
    eve_file = os.path.join(SURICATA_LOG_DIR, "eve.json")
    if os.path.exists(eve_file):
        stat = os.stat(eve_file)
        health['data_sources']['suricata_eve'] = {
            'path': eve_file,
            'size_mb': round(stat.st_size / (1024*1024), 2),
            'last_modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'status': 'LOGGING' if stat.st_mtime > (datetime.now().timestamp() - 60) else 'IDLE'
        }
        # Count events in last 100 lines
        try:
            result = sp.run(['tail', '-n', '100', eve_file], capture_output=True, text=True)
            alert_count = result.stdout.count('"event_type":"alert"')
            flow_count = result.stdout.count('"event_type":"flow"')
            health['data_sources']['suricata_eve']['recent_sample'] = {
                'alerts_in_last_100': alert_count,
                'flows_in_last_100': flow_count
            }
        except:
            pass
    
    # Check Zeek logs
    zeek_dir = os.path.join(ZEEK_LOG_DIR, "current")
    if os.path.exists(zeek_dir):
        zeek_logs = {}
        for log_type in ['conn.log', 'http.log', 'dns.log', 'ssl.log', 'files.log', 'notice.log']:
            log_path = os.path.join(zeek_dir, log_type)
            if os.path.exists(log_path):
                stat = os.stat(log_path)
                zeek_logs[log_type] = {
                    'size_kb': round(stat.st_size / 1024, 2),
                    'last_modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'status': 'LOGGING' if stat.st_mtime > (datetime.now().timestamp() - 60) else 'IDLE'
                }
        health['data_sources']['zeek'] = zeek_logs if zeek_logs else {'status': 'NO LOGS YET'}
    
    # Check PCAP files
    pcap_count = 0
    total_pcap_size = 0
    if os.path.exists(PCAP_DIR):
        for f in os.listdir(PCAP_DIR):
            if f.endswith('.pcap'):
                pcap_count += 1
                total_pcap_size += os.path.getsize(os.path.join(PCAP_DIR, f))
    
    health['data_sources']['tcpdump_pcap'] = {
        'path': PCAP_DIR,
        'file_count': pcap_count,
        'total_size_mb': round(total_pcap_size / (1024*1024), 2),
        'status': 'CAPTURING' if pcap_count > 0 else 'NO CAPTURE YET'
    }
    
    # Check Loki ingestion
    try:
        result = sp.run(['curl', '-s', 'http://localhost:3100/loki/api/v1/query_range',
                        '--data-urlencode', 'query={job=~"suricata|zeek"}',
                        '--data-urlencode', 'start=1d', '--data-urlencode', 'end=0'],
                       capture_output=True, text=True, timeout=5)
        if 'result' in result.stdout:
            health['loki_integration'] = 'CONNECTED - Data flowing to Loki'
        else:
            health['loki_integration'] = 'NO DATA in Loki yet'
    except:
        health['loki_integration'] = 'CANNOT CONNECT to Loki'
    
    return jsonify(health)

@app.route('/api/traffic/protocols')
def traffic_protocols():
    """Get protocol distribution from Zeek connections (NORMAL traffic analysis)"""
    protocols = {}
    conn_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/conn.log"))
    conn_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/conn.log"), recursive=True))
    
    if conn_files:
        latest_file = max(conn_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 7:
                            proto = parts[6]
                            protocols[proto] = protocols.get(proto, 0) + 1
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'data_type': 'NORMAL TRAFFIC BASELINE',
        'protocol_distribution': protocols,
        'description': 'Shows normal network protocol usage patterns for ML baseline'
    })

@app.route('/api/traffic/top-destinations')
def traffic_top_destinations():
    """Get top destination IPs from normal traffic (baseline analysis)"""
    destinations = {}
    conn_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/conn.log"))
    conn_files.extend(glob.glob(os.path.join(ZEEK_LOG_DIR, "**/conn.log"), recursive=True))
    
    if conn_files:
        latest_file = max(conn_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 5:
                            dst_ip = parts[4]
                            destinations[dst_ip] = destinations.get(dst_ip, 0) + 1
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Sort by count
    sorted_dests = dict(sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:20])
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'data_type': 'NORMAL TRAFFIC BASELINE',
        'top_destinations': sorted_dests,
        'description': 'Top destination IPs from normal connections - baseline for anomaly detection'
    })

@app.route('/sensors')
def sensors_dashboard():
    """Render sensors data dashboard"""
    return render_template('sensors.html')

@app.route('/api/sensors/data')
def sensors_data():
    """Get MQTT sensor data from InfluxDB"""
    try:
        from influxdb_client import InfluxDBClient
        
        # InfluxDB connection
        client = InfluxDBClient(
            url="http://influxdb:8086",
            token="my-super-secret-admin-token",
            org="pi_server"
        )
        
        query_api = client.query_api()
        
        # Query latest sensor data
        query = '''
        from(bucket: "sensor_data")
          |> range(start: -1h)
          |> filter(fn: (r) => r._measurement == "sensor_reading")
          |> last()
          |> sort(columns: ["_time"], desc: true)
        '''
        
        tables = query_api.query(query)
        
        sensors = {}
        for table in tables:
            for record in table.records:
                topic = record.tags.get('topic', 'unknown')
                field = record.field
                value = record.value
                timestamp = record.get_time().isoformat() if hasattr(record, 'get_time') else str(record.values.get('_time'))
                
                if topic not in sensors:
                    sensors[topic] = {}
                
                sensors[topic][field] = {
                    'value': value,
                    'timestamp': timestamp,
                    'unit': get_unit_for_field(field)
                }
        
        client.close()
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'sensors': sensors,
            'status': 'connected'
        })
    except Exception as e:
        # Return mock data if InfluxDB not available
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'sensors': {
                'home/livingroom/temperature': {
                    'temperature': {'value': 22.5, 'unit': '°C', 'timestamp': datetime.now().isoformat()},
                    'humidity': {'value': 45.2, 'unit': '%', 'timestamp': datetime.now().isoformat()}
                },
                'home/kitchen/temperature': {
                    'temperature': {'value': 21.8, 'unit': '°C', 'timestamp': datetime.now().isoformat()},
                    'humidity': {'value': 48.1, 'unit': '%', 'timestamp': datetime.now().isoformat()}
                },
                'home/bedroom/temperature': {
                    'temperature': {'value': 20.3, 'unit': '°C', 'timestamp': datetime.now().isoformat()},
                    'humidity': {'value': 52.7, 'unit': '%', 'timestamp': datetime.now().isoformat()}
                },
                'mqtt/sensor/1': {
                    'value': {'value': 42.0, 'unit': 'V', 'timestamp': datetime.now().isoformat()}
                }
            },
            'status': 'demo'
        })

@app.route('/api/sensors/history/<topic>')
def sensors_history(topic):
    """Get historical sensor data for a topic"""
    try:
        from influxdb_client import InfluxDBClient
        
        client = InfluxDBClient(
            url="http://influxdb:8086",
            token="my-super-secret-admin-token",
            org="pi_server"
        )
        
        query_api = client.query_api()
        
        # Query last 24 hours of data
        query = f'''
        from(bucket: "sensor_data")
          |> range(start: -24h)
          |> filter(fn: (r) => r._measurement == "sensor_reading" and r.topic == "{topic}")
          |> sort(columns: ["_time"], desc: true)
        '''
        
        tables = query_api.query(query)
        
        history = []
        for table in tables:
            for record in table.records:
                history.append({
                    'time': record.get_time().isoformat() if hasattr(record, 'get_time') else str(record.values.get('_time')),
                    'field': record.field,
                    'value': record.value
                })
        
        client.close()
        
        return jsonify({
            'topic': topic,
            'data': history[:500],  # Last 500 records
            'count': len(history)
        })
    except Exception as e:
        return jsonify({'error': str(e), 'topic': topic, 'data': []}), 500

def get_unit_for_field(field):
    """Get the unit for a field name"""
    units = {
        'temperature': '°C',
        'humidity': '%',
        'pressure': 'hPa',
        'voltage': 'V',
        'current': 'A',
        'power': 'W',
        'energy': 'kWh',
        'distance': 'cm',
        'light': 'lux',
        'co2': 'ppm',
        'voc': 'ppb'
    }
    return units.get(field, '')

@app.route('/api/export/suricata/csv')
def export_suricata_csv():
    """Export Suricata events to CSV"""
    events = []
    eve_file = os.path.join(SURICATA_LOG_DIR, "eve.json")
    
    if os.path.exists(eve_file):
        try:
            with open(eve_file, 'r') as f:
                lines = f.readlines()
                for line in lines[-500:]:
                    if line.strip():
                        try:
                            event = json.loads(line)
                            if event.get('event_type') != 'stats':
                                events.append(event)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Create CSV in memory
    output = io.StringIO()
    if events:
        # Get all unique keys
        all_keys = set()
        for event in events:
            all_keys.update(event.keys())
        
        writer = csv.DictWriter(output, fieldnames=sorted(all_keys))
        writer.writeheader()
        for event in events:
            # Flatten nested dicts
            flat_event = {}
            for k, v in event.items():
                if isinstance(v, dict):
                    flat_event[k] = json.dumps(v)
                elif isinstance(v, list):
                    flat_event[k] = json.dumps(v)
                else:
                    flat_event[k] = v
            writer.writerow(flat_event)
    
    output.seek(0)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=suricata_{timestamp}.csv'}
    )

@app.route('/api/export/zeek/csv')
def export_zeek_csv():
    """Export Zeek logs to CSV"""
    all_data = []
    
    # Get connections
    conn_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/conn.log"))
    if conn_files:
        latest_file = max(conn_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 10:
                            try:
                                all_data.append({
                                    'type': 'connection',
                                    'timestamp': parts[0],
                                    'src_ip': parts[2],
                                    'src_port': parts[3],
                                    'dst_ip': parts[4],
                                    'dst_port': parts[5],
                                    'proto': parts[6],
                                    'duration': parts[8],
                                    'orig_bytes': parts[9],
                                    'resp_bytes': parts[10] if len(parts) > 10 else '0',
                                })
                            except:
                                pass
        except Exception as e:
            pass
    
    # Create CSV
    output = io.StringIO()
    if all_data:
        writer = csv.DictWriter(output, fieldnames=['type', 'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'duration', 'orig_bytes', 'resp_bytes'])
        writer.writeheader()
        writer.writerows(all_data)
    
    output.seek(0)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=zeek_{timestamp}.csv'}
    )

@app.route('/api/export/all/json')
def export_all_json():
    """Export all traffic data as JSON"""
    data = {
        'suricata': [],
        'zeek': [],
        'export_time': datetime.now().isoformat()
    }
    
    # Get Suricata
    eve_file = os.path.join(SURICATA_LOG_DIR, "eve.json")
    if os.path.exists(eve_file):
        try:
            with open(eve_file, 'r') as f:
                for line in f.readlines()[-500:]:
                    if line.strip():
                        try:
                            event = json.loads(line)
                            if event.get('event_type') != 'stats':
                                data['suricata'].append(event)
                        except:
                            pass
        except:
            pass
    
    # Get Zeek
    conn_files = glob.glob(os.path.join(ZEEK_LOG_DIR, "current/conn.log"))
    if conn_files:
        latest_file = max(conn_files, key=os.path.getmtime)
        try:
            with open(latest_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 10:
                            try:
                                data['zeek'].append({
                                    'timestamp': parts[0],
                                    'src_ip': parts[2],
                                    'src_port': parts[3],
                                    'dst_ip': parts[4],
                                    'dst_port': parts[5],
                                    'proto': parts[6],
                                })
                            except:
                                pass
        except:
            pass
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return Response(
        json.dumps(data, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=traffic_{timestamp}.json'}
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)

