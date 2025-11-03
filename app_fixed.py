from flask import Flask, render_template, jsonify, request
import threading
import time
import random
from datetime import datetime, timedelta
import os
app = Flask(__name__, 
            template_folder='templates', 
            static_folder='static')



# Simple in-memory storage (no database dependencies)
alerts = []
threats = []
blocked_ips = set()
packet_count = 0
start_time = time.time()
is_simulating = False

# Enhanced simulation data
threat_ip_details = {}
internal_assets = ['192.168.1.1', '192.168.1.10', '192.168.1.20', '192.168.1.30']
packet_rates = []
threat_history = []

class SimpleSimulationManager:
    def __init__(self):
        self.packet_count = 0
        self.start_time = time.time()
        
    def start_simulation(self):
        global is_simulating
        is_simulating = True
        print("🚀 Starting enhanced simulation...")
        
    def stop_simulation(self):
        global is_simulating
        is_simulating = False
        print("🛑 Simulation stopped")
    
    def generate_packet_data(self):
        source_ip = random.choice(['192.168.1.100', '10.0.0.50', '172.16.1.200', '192.168.1.150'])
        destination_ip = random.choice(internal_assets)
        
        return {
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'source_port': random.randint(1000, 65000),
            'destination_port': random.choice([80, 443, 22, 53]),
            'length': random.randint(64, 1500),
            'timestamp': datetime.now().isoformat()
        }
    
    def generate_threat_data(self, packet_data):
        threat_types = ['PORT_SCAN', 'SYN_FLOOD', 'SUSPICIOUS_IP']
        threat_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        threat_type = random.choice(threat_types)
        threat_level = random.choice(threat_levels)
        source_ip = packet_data['source_ip']
        
        # Update threat IP details
        if source_ip not in threat_ip_details:
            threat_ip_details[source_ip] = {
                'first_seen': datetime.now(),
                'threat_count': 0,
                'targeted_assets': set(),
                'threat_types': set()
            }
        
        threat_ip_details[source_ip]['threat_count'] += 1
        threat_ip_details[source_ip]['targeted_assets'].add(packet_data['destination_ip'])
        threat_ip_details[source_ip]['threat_types'].add(threat_type)
        threat_ip_details[source_ip]['last_seen'] = datetime.now()
        
        threat_data = {
            'id': len(threats) + 1,
            'source_ip': source_ip,
            'destination_ip': packet_data['destination_ip'],
            'threat_type': threat_type,
            'threat_level': threat_level,
            'description': f"{threat_type} detected from {source_ip}",
            'timestamp': datetime.now().isoformat(),
            'packet_count': random.randint(5, 50),
            'first_seen': threat_ip_details[source_ip]['first_seen'].isoformat(),
            'last_seen': datetime.now().isoformat(),
            'threat_count': threat_ip_details[source_ip]['threat_count'],
            'targeted_assets': list(threat_ip_details[source_ip]['targeted_assets']),
            'threat_types': list(threat_ip_details[source_ip]['threat_types']),
            'status': 'Blocked' if source_ip in blocked_ips else 'Active'
        }
        
        threats.append(threat_data)
        
        # Generate alert
        alert_data = {
            'id': len(alerts) + 1,
            'threat_id': threat_data['id'],
            'message': f"{threat_type} detected from {source_ip}",
            'recommendation': self.generate_recommendation(threat_type, threat_level),
            'timestamp': datetime.now().isoformat(),
            'is_resolved': False,
            'action_taken': None
        }
        
        alerts.append(alert_data)
        threat_history.append({
            'timestamp': datetime.now(),
            'threat_type': threat_type,
            'severity': threat_level,
            'source_ip': source_ip
        })
        
        return threat_data, alert_data
    
    def generate_recommendation(self, threat_type, threat_level):
        recommendations = {
            'PORT_SCAN': {
                'LOW': 'Monitor IP and review firewall logs',
                'MEDIUM': 'Temporarily block IP for investigation',
                'HIGH': 'Immediately block IP and scan systems',
                'CRITICAL': 'Emergency: Block IP and initiate incident response'
            },
            'SYN_FLOOD': {
                'LOW': 'Enable SYN cookie protection',
                'MEDIUM': 'Configure rate limiting rules',
                'HIGH': 'Block source IP and enable DDoS protection',
                'CRITICAL': 'Emergency: Block IP range and activate DDoS mitigation'
            },
            'SUSPICIOUS_IP': {
                'LOW': 'Log all traffic from this IP',
                'MEDIUM': 'Block IP if not business critical',
                'HIGH': 'Immediately block IP and scan for compromises',
                'CRITICAL': 'Emergency: Block IP and isolate affected systems'
            }
        }
        
        return recommendations.get(threat_type, {}).get(threat_level, 'Investigate this security anomaly')
    
    def get_packet_rate_trend(self):
        # Simple trend calculation
        if len(packet_rates) < 5:
            return [0, 0, 0, 0, 0]
        return [rate for _, rate in packet_rates[-5:]]
    
    def get_threat_trend(self):
        if len(threat_history) < 5:
            return [0, 0, 0, 0, 0]
        
        # Count threats in recent intervals
        now = datetime.now()
        intervals = []
        for i in range(5):
            interval_start = now - timedelta(minutes=(4-i))
            count = len([t for t in threat_history 
                        if t['timestamp'] > interval_start - timedelta(minutes=1) 
                        and t['timestamp'] <= interval_start])
            intervals.append(count)
        return intervals
    
    def get_threat_severity_breakdown(self):
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for threat in threats[-100:]:
            severity_counts[threat['threat_level']] += 1
        return severity_counts
    
    def get_top_threat_types(self):
        type_counts = {}
        for threat in threats[-100:]:
            t_type = threat['threat_type']
            type_counts[t_type] = type_counts.get(t_type, 0) + 1
        return sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    def get_top_targeted_assets(self):
        asset_counts = {}
        for ip, details in threat_ip_details.items():
            for asset in details.get('targeted_assets', []):
                asset_counts[asset] = asset_counts.get(asset, 0) + 1
        return sorted(asset_counts.items(), key=lambda x: x[1], reverse=True)[:5]

simulation_manager = SimpleSimulationManager()

def simulation_loop():
    global packet_count
    print("🎬 Enhanced simulation started")
    
    while is_simulating:
        try:
            # Generate packet
            packet_data = simulation_manager.generate_packet_data()
            packet_count += 1
            packet_rates.append((time.time(), 1))
            
            # Generate threat (25% chance)
            if random.random() < 0.25 and packet_data['source_ip'] not in blocked_ips:
                threat_data, alert_data = simulation_manager.generate_threat_data(packet_data)
                print(f"🚨 New threat: {threat_data['threat_type']} from {threat_data['source_ip']}")
            
            # Variable delay for realistic traffic
            delay = random.uniform(0.1, 0.8)
            time.sleep(delay)
            
        except Exception as e:
            print(f"❌ Simulation error: {e}")
            time.sleep(1)

@app.route('/')
def index():
    return render_template('/templates/index.html')

@app.route('/api/stats')
def get_stats():
    current_time = time.time()
    uptime = current_time - simulation_manager.start_time
    
    # Calculate real packets per second
    recent_packets = [rate for ts, rate in packet_rates if ts > current_time - 10]
    packets_per_second = len(recent_packets) / 10.0 if recent_packets else 0
    
    stats = {
        'capture': {
            'total_packets': packet_count,
            'uptime': uptime,
            'packets_per_second': packets_per_second,
            'is_capturing': is_simulating,
            'packet_trend': simulation_manager.get_packet_rate_trend(),
            'threat_trend': simulation_manager.get_threat_trend()
        },
        'alerts': {
            'total_alerts': len(alerts),
            'resolved_alerts': len([a for a in alerts if a['is_resolved']]),
            'active_alerts': len([a for a in alerts if not a['is_resolved']])
        },
        'threat_analysis': {
            'severity_breakdown': simulation_manager.get_threat_severity_breakdown(),
            'top_threat_types': simulation_manager.get_top_threat_types(),
            'top_targeted_assets': simulation_manager.get_top_targeted_assets()
        }
    }
    return jsonify(stats)

@app.route('/api/alerts')
def get_alerts():
    recent_alerts = sorted(alerts, key=lambda x: x['timestamp'], reverse=True)[:20]
    return jsonify(recent_alerts)

@app.route('/api/threats')
def get_threats():
    recent_threats = sorted(threats, key=lambda x: x['timestamp'], reverse=True)[:50]
    return jsonify(recent_threats)

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    data = request.get_json()
    ip = data.get('ip')
    if ip:
        blocked_ips.add(ip)
        # Update threat status
        for threat in threats:
            if threat['source_ip'] == ip:
                threat['status'] = 'Blocked'
        print(f"🔒 IP {ip} added to blocklist")
        return jsonify({'status': 'success', 'message': f'IP {ip} blocked'})
    return jsonify({'status': 'error', 'message': 'No IP provided'})

@app.route('/api/acknowledge_alert', methods=['POST'])
def acknowledge_alert():
    data = request.get_json()
    alert_id = data.get('alert_id')
    for alert in alerts:
        if alert['id'] == alert_id:
            alert['is_resolved'] = True
            alert['action_taken'] = 'Acknowledged'
            return jsonify({'status': 'success', 'message': 'Alert acknowledged'})
    return jsonify({'status': 'error', 'message': 'Alert not found'})

@app.route('/api/start_capture')
def start_capture():
    global is_simulating
    if not is_simulating:
        simulation_manager.start_simulation()
        thread = threading.Thread(target=simulation_loop, daemon=True)
        thread.start()
        return jsonify({'status': 'started', 'mode': 'enhanced_simulation'})
    return jsonify({'status': 'already_running'})

@app.route('/api/stop_capture')
def stop_capture():
    global is_simulating
    if is_simulating:
        simulation_manager.stop_simulation()
        return jsonify({'status': 'stopped'})
    return jsonify({'status': 'not_running'})

@app.route('/debug-paths')
def debug_paths():
    import os
    template_path = os.path.join(app.root_path, app.template_folder)
    static_path = os.path.join(app.root_path, app.static_folder)
    
    return f"""
    App root path: {app.root_path}<br>
    Template folder: {app.template_folder}<br>
    Static folder: {app.static_folder}<br>
    Absolute template path: {template_path}<br>
    Absolute static path: {static_path}<br>
    Template exists: {os.path.exists(template_path)}<br>
    Index.html exists: {os.path.exists(os.path.join(template_path, 'index.html'))}<br>
    Static folder exists: {os.path.exists(static_path)}
    """

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 LiveGuard Enhanced IDS Starting...")
    print("📊 Mode: ENHANCED SIMULATION (No Database)")
    print("🌐 Dashboard: http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, host='127.0.0.1', port=5000)