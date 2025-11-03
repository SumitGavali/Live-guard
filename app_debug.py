from flask import Flask, render_template, jsonify
import threading
import time
import random
from datetime import datetime

# Create Flask app
# app = Flask(__name__)
app = Flask(__name__, template_folder='.../templates', static_folder='static')

# Global variables
is_simulating = False
packet_count = 0
start_time = time.time()
threat_counter = 0

# Simple in-memory storage for demo
alerts = []
threats = []

class SimpleAlertManager:
    """Simple alert manager without database"""
    
    @staticmethod
    def generate_recommendation(threat_type, threat_level):
        recommendations = {
            'PORT_SCAN': {
                'LOW': 'Monitor the source IP for further activity',
                'MEDIUM': 'Consider temporary blocking and investigation',
                'HIGH': 'Immediately block the IP and review firewall logs',
                'CRITICAL': 'Emergency: Block IP, scan network, alert security team'
            },
            'SYN_FLOOD': {
                'LOW': 'Monitor SYN packet rates',
                'MEDIUM': 'Enable SYN cookie protection', 
                'HIGH': 'Block source IP and enable DDoS protection',
                'CRITICAL': 'Emergency: Block IP, max DDoS protection, incident response'
            },
            'SUSPICIOUS_IP': {
                'LOW': 'Log and monitor traffic',
                'MEDIUM': 'Block IP if not business critical',
                'HIGH': 'Immediately block and scan for compromises', 
                'CRITICAL': 'Block IP, full system scan, incident response'
            }
        }
        
        return recommendations.get(threat_type, {}).get(threat_level, 'Investigate this security anomaly')

def simulation_loop():
    """Simple simulation without database"""
    global packet_count, threat_counter, is_simulating
    
    print("🎬 Starting simulation...")
    
    sample_ips = ['192.168.1.100', '10.0.0.50', '172.16.1.200', '192.168.1.150']
    
    while is_simulating:
        try:
            # Generate packet
            packet_count += 1
            
            # Generate threat occasionally (20% chance)
            if random.random() < 0.2:
                threat_counter += 1
                
                threat_types = ['PORT_SCAN', 'SYN_FLOOD', 'SUSPICIOUS_IP']
                threat_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                
                threat_type = random.choice(threat_types)
                threat_level = random.choice(threat_levels)
                source_ip = random.choice(sample_ips)
                
                threat = {
                    'id': threat_counter,
                    'timestamp': datetime.now().isoformat(),
                    'threat_type': threat_type,
                    'source_ip': source_ip,
                    'description': f"{threat_type} detected from {source_ip}",
                    'threat_level': threat_level
                }
                
                threats.append(threat)
                
                # Create alert
                recommendation = SimpleAlertManager.generate_recommendation(threat_type, threat_level)
                
                alert = {
                    'id': len(alerts) + 1,
                    'threat_id': threat_counter,
                    'timestamp': datetime.now().isoformat(),
                    'message': f"{threat_type} detected from {source_ip}",
                    'recommendation': recommendation,
                    'is_resolved': False
                }
                
                alerts.append(alert)
                print(f"🚨 New {threat_type} alert from {source_ip}")
            
            # Print progress
            if packet_count % 10 == 0:
                print(f"📦 Packets: {packet_count}, Threats: {threat_counter}")
                
            time.sleep(0.5)  # 2 packets per second
            
        except Exception as e:
            print(f"❌ Simulation error: {e}")
            time.sleep(1)

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """API endpoint for current statistics"""
    global packet_count, threat_counter
    
    uptime = time.time() - start_time
    packets_per_second = packet_count / uptime if uptime > 0 else 0
    
    stats = {
        'capture': {
            'total_packets': packet_count,
            'uptime': uptime,
            'packets_per_second': packets_per_second,
            'is_capturing': is_simulating
        },
        'alerts': {
            'total_alerts': len(alerts),
            'resolved_alerts': len([a for a in alerts if a['is_resolved']]),
            'active_alerts': len([a for a in alerts if not a['is_resolved']])
        }
    }
    return jsonify(stats)

@app.route('/api/alerts')
def get_alerts():
    """API endpoint for recent alerts"""
    recent_alerts = sorted(alerts, key=lambda x: x['timestamp'], reverse=True)[:10]
    return jsonify(recent_alerts)

@app.route('/api/threats')
def get_threats():
    """API endpoint for recent threats"""
    recent_threats = sorted(threats, key=lambda x: x['timestamp'], reverse=True)[:10]
    return jsonify(recent_threats)

@app.route('/api/start_capture')
def start_capture():
    """API endpoint to start packet capture"""
    global is_simulating
    
    if not is_simulating:
        is_simulating = True
        # Start simulation in background thread
        thread = threading.Thread(target=simulation_loop, daemon=True)
        thread.start()
        return jsonify({'status': 'started', 'message': 'Capture started successfully'})
    return jsonify({'status': 'already_running', 'message': 'Capture is already running'})

@app.route('/api/stop_capture')
def stop_capture():
    """API endpoint to stop packet capture"""
    global is_simulating
    
    if is_simulating:
        is_simulating = False
        return jsonify({'status': 'stopped', 'message': 'Capture stopped successfully'})
    return jsonify({'status': 'not_running', 'message': 'Capture is not running'})

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 LiveGuard IDS - DEBUG MODE")
    print("📊 No database required")
    print("🌐 Dashboard: http://localhost:5000")
    print("🎯 Click 'Start Capture' to begin simulation")
    print("=" * 50)
    
    app.run(debug=True, host='127.0.0.1', port=5000)