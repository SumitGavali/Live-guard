from collections import defaultdict, deque
import time
from models.threat import Threat, ThreatType, ThreatLevel
from services.database import db

class ThreatAnalyzer:
    """Analyze packets and detect various threats"""
    
    def __init__(self, config):
        self.config = config
        
        # Data structures for threat detection
        self.port_scan_tracker = defaultdict(set)  # src_ip -> set of dst_ports
        self.syn_flood_tracker = defaultdict(lambda: deque(maxlen=1000))
        self.ip_connection_count = defaultdict(int)
        
        # Thresholds
        self.port_scan_threshold = config.PORT_SCAN_THRESHOLD
        self.syn_flood_threshold = config.SYN_FLOOD_THRESHOLD
        self.suspicious_ips = set(config.SUSPICIOUS_IPS)
        
        self.detected_threats = {}
    
    def analyze_packet(self, packet_data):
        """Analyze a single packet for threats"""
        threats = []
        
        # Check for port scanning
        port_scan_threat = self._detect_port_scan(packet_data)
        if port_scan_threat:
            threats.append(port_scan_threat)
        
        # Check for SYN flood
        syn_flood_threat = self._detect_syn_flood(packet_data)
        if syn_flood_threat:
            threats.append(syn_flood_threat)
        
        # Check for suspicious IPs
        suspicious_ip_threat = self._detect_suspicious_ip(packet_data)
        if suspicious_ip_threat:
            threats.append(suspicious_ip_threat)
        
        return threats
    
    def _detect_port_scan(self, packet_data):
        """Detect port scanning activity"""
        if not packet_data.get('destination_port'):
            return None
        
        src_ip = packet_data['source_ip']
        dst_port = packet_data['destination_port']
        
        # Add port to tracker
        self.port_scan_tracker[src_ip].add(dst_port)
        
        # Check if threshold exceeded
        if len(self.port_scan_tracker[src_ip]) >= self.port_scan_threshold:
            threat = Threat(
                threat_type=ThreatType.PORT_SCAN,
                source_ip=src_ip,
                description=f"Port scan detected from {src_ip}. Scanned {len(self.port_scan_tracker[src_ip])} ports",
                threat_level=ThreatLevel.HIGH,
                destination_ip=packet_data.get('destination_ip'),
                packet_count=len(self.port_scan_tracker[src_ip])
            )
            
            # Clear tracker after detection
            self.port_scan_tracker[src_ip].clear()
            
            return threat
        
        return None
    
    def _detect_syn_flood(self, packet_data):
        """Detect SYN flood attacks"""
        if (packet_data.get('protocol') == 'TCP' and 
            packet_data.get('flags') and 'SYN' in packet_data['flags'] and
            'ACK' not in packet_data['flags']):
            
            src_ip = packet_data['source_ip']
            current_time = time.time()
            
            # Add SYN packet to tracker
            self.syn_flood_tracker[src_ip].append(current_time)
            
            # Remove old entries (older than 1 second)
            window_start = current_time - 1.0
            while (self.syn_flood_tracker[src_ip] and 
                   self.syn_flood_tracker[src_ip][0] < window_start):
                self.syn_flood_tracker[src_ip].popleft()
            
            # Check if threshold exceeded
            if len(self.syn_flood_tracker[src_ip]) >= self.syn_flood_threshold:
                threat = Threat(
                    threat_type=ThreatType.SYN_FLOOD,
                    source_ip=src_ip,
                    description=f"SYN flood detected from {src_ip}. {len(self.syn_flood_tracker[src_ip])} SYN packets in 1 second",
                    threat_level=ThreatLevel.CRITICAL,
                    destination_ip=packet_data.get('destination_ip'),
                    packet_count=len(self.syn_flood_tracker[src_ip])
                )
                
                return threat
        
        return None
    
    def _detect_suspicious_ip(self, packet_data):
        """Detect traffic from known suspicious IPs"""
        src_ip = packet_data['source_ip']
        
        if src_ip in self.suspicious_ips:
            threat = Threat(
                threat_type=ThreatType.SUSPICIOUS_IP,
                source_ip=src_ip,
                description=f"Traffic from known suspicious IP: {src_ip}",
                threat_level=ThreatLevel.MEDIUM,
                destination_ip=packet_data.get('destination_ip')
            )
            
            return threat
        
        return None
    
    def save_threat(self, threat):
        """Save threat to database"""
        db.session.add(threat)
        db.session.commit()
        return threat