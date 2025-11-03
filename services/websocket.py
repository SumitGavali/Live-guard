from flask_socketio import SocketIO
import eventlet

socketio = SocketIO(async_mode='eventlet')

class WebSocketService:
    def __init__(self, app=None):
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        socketio.init_app(app, cors_allowed_origins="*")
    
    def broadcast_alert(self, alert_data):
        """Broadcast alert to all connected clients"""
        socketio.emit('new_alert', alert_data)
    
    def broadcast_packet(self, packet_data):
        """Broadcast packet to all connected clients"""
        socketio.emit('new_packet', packet_data)
    
    def broadcast_threat(self, threat_data):
        """Broadcast threat to all connected clients"""
        socketio.emit('new_threat', threat_data)
    
    def broadcast_stats(self, stats_data):
        """Broadcast statistics to all connected clients"""
        socketio.emit('stats_update', stats_data)