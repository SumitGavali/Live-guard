from services.database import db
from datetime import datetime

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats.id'))
    message = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    action_taken = db.Column(db.String(50))
    is_resolved = db.Column(db.Boolean, default=False)
    
    # Relationship
    threat = db.relationship('Threat', backref=db.backref('alerts', lazy=True))
    
    def __init__(self, threat_id, message, recommendation):
        self.threat_id = threat_id
        self.message = message
        self.recommendation = recommendation
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'threat_id': self.threat_id,
            'message': self.message,
            'recommendation': self.recommendation,
            'action_taken': self.action_taken,
            'is_resolved': self.is_resolved
        }
    
    def __repr__(self):
        return f'<Alert for Threat {self.threat_id}: {self.message}>'