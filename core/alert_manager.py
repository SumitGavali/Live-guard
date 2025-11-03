from services.websocket import WebSocketService
from services.database import db
from models.alert import Alert
from models.threat import ThreatLevel
import time

class EnhancedAlertManager:
    """Enhanced alert manager with actionable recommendations"""
    
    def __init__(self, websocket_service):
        self.websocket_service = websocket_service
        self.active_alerts = {}
        self.recommendations_queue = []
    
    def process_threat(self, threat):
        """Process threat and create enhanced alert"""
        try:
            # Enhanced recommendations with specific actions
            recommendations = {
                'PORT_SCAN': {
                    'LOW': 'Monitor IP and review firewall logs for suspicious patterns',
                    'MEDIUM': 'Temporarily block IP for 1 hour and investigate source',
                    'HIGH': 'Immediately block IP and scan targeted systems for vulnerabilities',
                    'CRITICAL': 'Emergency: Block IP, initiate incident response, review all systems'
                },
                'SYN_FLOOD': {
                    'LOW': 'Enable SYN cookie protection and monitor traffic patterns',
                    'MEDIUM': 'Configure rate limiting and DDoS protection rules',
                    'HIGH': 'Block source IP and enable emergency DDoS mitigation',
                    'CRITICAL': 'Emergency: Block IP range, activate full DDoS protection, alert ISP'
                },
                'SUSPICIOUS_IP': {
                    'LOW': 'Log all traffic from this IP for further analysis',
                    'MEDIUM': 'Block IP if not required for business operations',
                    'HIGH': 'Immediately block IP and scan internal systems for compromise',
                    'CRITICAL': 'Emergency: Block IP, isolate affected systems, forensic analysis'
                }
            }
            
            threat_type = threat.threat_type
            threat_level = threat.threat_level
            
            recommendation = recommendations.get(threat_type, {}).get(
                threat_level, 
                'Investigate this security anomaly and take appropriate action'
            )
            
            # Add specific actionable steps
            actionable_steps = self.generate_actionable_steps(threat, recommendation)
            
            message = f"{threat_type} detected from {threat.source_ip}"
            
            alert = Alert(
                threat_id=threat.id,
                message=message,
                recommendation=recommendation
            )
            
            db.session.add(alert)
            db.session.commit()
            
            # Prepare enhanced alert data
            alert_data = {
                'alert': alert.to_dict(),
                'threat': threat.to_dict(),
                'actionable_steps': actionable_steps,
                'timestamp': alert.timestamp.isoformat()
            }
            
            print(f"📢 Broadcasting enhanced alert: {threat_type} from {threat.source_ip}")
            
            # Broadcast via WebSocket
            if self.websocket_service:
                self.websocket_service.broadcast_alert(alert_data)
            
            # Add to recommendations queue
            self.recommendations_queue.append({
                'alert_id': alert.id,
                'threat_ip': threat.source_ip,
                'steps': actionable_steps,
                'status': 'pending',
                'timestamp': time.time()
            })
            
            # Store in active alerts
            self.active_alerts[alert.id] = alert
            
            return alert
            
        except Exception as e:
            print(f"❌ Error processing threat: {e}")
            return None
    
    def generate_actionable_steps(self, threat, base_recommendation):
        """Generate specific actionable steps"""
        steps = []
        
        if threat.threat_type == 'PORT_SCAN':
            steps = [
                f"1. Block IP {threat.source_ip} in perimeter firewall [Block IP]",
                f"2. Review firewall logs for pattern analysis [Investigate]",
                f"3. Scan internal systems {threat.destination_ip} for vulnerabilities [Scan]",
                "4. Update intrusion detection rules [Update Rules]"
            ]
        elif threat.threat_type == 'SYN_FLOOD':
            steps = [
                f"1. Emergency block of IP {threat.source_ip} [Block IP]",
                "2. Enable SYN cookie protection globally [Enable Protection]",
                "3. Configure rate limiting rules [Configure Rules]",
                "4. Notify network security team [Notify Team]"
            ]
        elif threat.threat_type == 'SUSPICIOUS_IP':
            steps = [
                f"1. Block suspicious IP {threat.source_ip} [Block IP]",
                f"2. Investigate traffic to {threat.destination_ip} [Investigate]",
                "3. Check threat intelligence feeds [Check Intel]",
                "4. Review access logs for compromise indicators [Review Logs]"
            ]
        else:
            steps = [f"1. {base_recommendation} [Investigate]"]
        
        return steps
    
    def execute_recommendation(self, alert_id, action):
        """Execute a specific recommendation action"""
        try:
            alert = Alert.query.get(alert_id)
            if alert:
                alert.action_taken = action
                alert.is_resolved = True
                db.session.commit()
                
                # Update recommendations queue
                for rec in self.recommendations_queue:
                    if rec['alert_id'] == alert_id:
                        rec['status'] = 'completed'
                        rec['completed_at'] = time.time()
                        break
                
                return True
            return False
        except Exception as e:
            print(f"❌ Error executing recommendation: {e}")
            return False
    
    def get_pending_recommendations(self):
        """Get pending recommendations"""
        return [rec for rec in self.recommendations_queue if rec['status'] == 'pending']
    
    def resolve_alert(self, alert_id, action_taken):
        """Mark an alert as resolved"""
        alert = Alert.query.get(alert_id)
        if alert:
            alert.is_resolved = True
            alert.action_taken = action_taken
            db.session.commit()
            
            # Remove from active alerts
            self.active_alerts.pop(alert_id, None)
            
            return alert
        return None
    
    def get_active_alerts(self):
        """Get all active alerts"""
        return list(self.active_alerts.values())
    
    def get_alert_stats(self):
        """Get alert statistics"""
        total_alerts = Alert.query.count()
        resolved_alerts = Alert.query.filter_by(is_resolved=True).count()
        active_alerts = Alert.query.filter_by(is_resolved=False).count()
        
        return {
            'total_alerts': total_alerts,
            'resolved_alerts': resolved_alerts,
            'active_alerts': active_alerts
        }