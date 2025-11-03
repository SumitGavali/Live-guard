from services.database import db
from datetime import datetime
from enum import Enum

class ThreatLevel(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'

class ThreatType(Enum):
    PORT_SCAN = 'PORT_SCAN'
    SYN_FLOOD = 'SYN_FLOOD'
    SUSPICIOUS_IP = 'SUSPICIOUS_IP'
    MALICIOUS_PAYLOAD = 'MALICIOUS_PAYLOAD'

class Threat(db.Model):
    __tablename__ = 'threats'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    threat_type = db.Column(db.String(20), nullable=False)
    source_ip = db.Column(db.String(15), nullable=False)
    destination_ip = db.Column(db.String(15))
    description = db.Column(db.Text, nullable=False)
    threat_level = db.Column(db.String(10), nullable=False)
    packet_count = db.Column(db.Integer, default=1)
    is_active = db.Column(db.Boolean, default=True)
    
    def __init__(self, threat_type, source_ip, description, threat_level, **kwargs):
        self.threat_type = threat_type.value if isinstance(threat_type, ThreatType) else threat_type
        self.source_ip = source_ip
        self.description = description
        self.threat_level = threat_level.value if isinstance(threat_level, ThreatLevel) else threat_level
        
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'threat_type': self.threat_type,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'description': self.description,
            'threat_level': self.threat_level,
            'packet_count': self.packet_count,
            'is_active': self.is_active
        }
    
    def __repr__(self):
        return f'<Threat {self.threat_type} from {self.source_ip} [{self.threat_level}]>'