from services.database import db
from datetime import datetime
from enum import Enum

class Protocol(Enum):
    TCP = 'TCP'
    UDP = 'UDP'
    ICMP = 'ICMP'
    OTHER = 'OTHER'

class Packet(db.Model):
    __tablename__ = 'packets'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(15), nullable=False)
    destination_ip = db.Column(db.String(15), nullable=False)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10), nullable=False)
    length = db.Column(db.Integer)
    flags = db.Column(db.String(20))
    payload = db.Column(db.Text)
    
    def __init__(self, source_ip, destination_ip, protocol, **kwargs):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol.value if isinstance(protocol, Protocol) else protocol
        
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'length': self.length,
            'flags': self.flags
        }
    
    def __repr__(self):
        return f'<Packet {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} [{self.protocol}]>'