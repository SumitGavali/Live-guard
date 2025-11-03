from models.alert import Alert
from models.threat import ThreatType, ThreatLevel
from services.database import db

class ThreatRecommender:
    """Provide actionable recommendations for detected threats"""
    
    def __init__(self):
        self.recommendation_templates = {
            ThreatType.PORT_SCAN: {
                ThreatLevel.LOW: "Monitor the source IP for further suspicious activity",
                ThreatLevel.MEDIUM: "Consider blocking the source IP temporarily",
                ThreatLevel.HIGH: "Immediately block the source IP and investigate further",
                ThreatLevel.CRITICAL: "Block the source IP and review firewall rules"
            },
            ThreatType.SYN_FLOOD: {
                ThreatLevel.LOW: "Monitor SYN packet rates",
                ThreatLevel.MEDIUM: "Implement SYN cookie protection",
                ThreatLevel.HIGH: "Block the source IP and enable DDoS protection",
                ThreatLevel.CRITICAL: "Emergency: Block source IP, enable maximum DDoS protection, and alert security team"
            },
            ThreatType.SUSPICIOUS_IP: {
                ThreatLevel.LOW: "Log and monitor traffic from this IP",
                ThreatLevel.MEDIUM: "Block the IP if not required for business operations",
                ThreatLevel.HIGH: "Immediately block the IP and scan for compromises",
                ThreatLevel.CRITICAL: "Block IP, scan systems, and initiate incident response"
            }
        }
    
    def generate_recommendation(self, threat):
        """Generate recommendation based on threat type and level"""
        threat_type = ThreatType(threat.threat_type)
        threat_level = ThreatLevel(threat.threat_level)
        
        template = self.recommendation_templates.get(threat_type, {}).get(
            threat_level, "Investigate the anomaly and take appropriate action"
        )
        
        # Customize recommendation based on specific threat details
        if threat_type == ThreatType.PORT_SCAN:
            template += f". Scanned {threat.packet_count} ports."
        elif threat_type == ThreatType.SYN_FLOOD:
            template += f". Detected {threat.packet_count} SYN packets."
        
        return template
    
    def create_alert(self, threat):
        """Create an alert with recommendation for a threat"""
        recommendation = self.generate_recommendation(threat)
        message = f"{threat.threat_type} detected from {threat.source_ip}"
        
        alert = Alert(
            threat_id=threat.id,
            message=message,
            recommendation=recommendation
        )
        
        db.session.add(alert)
        db.session.commit()
        
        return alert