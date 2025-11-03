import threading
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from models.packet import Packet, Protocol
from services.database import db
from services.websocket import WebSocketService

class PacketCapture:
    """Real-time network packet capture using Scapy"""
    
    def __init__(self, interface='eth0', websocket_service=None):
        self.interface = interface
        self.is_capturing = False
        self.capture_thread = None
        self.websocket_service = websocket_service
        self.packet_count = 0
        self.start_time = None
        
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.is_capturing:
            return
        
        self.is_capturing = True
        self.start_time = time.time()
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        print(f"Packet capture started on interface {self.interface}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        print("Packet capture stopped")
    
    def _capture_loop(self):
        """Main capture loop using Scapy"""
        try:
            sniff(iface=self.interface, prn=self._process_packet, 
                  stop_filter=lambda x: not self.is_capturing)
        except Exception as e:
            print(f"Packet capture error: {e}")
    
    def _process_packet(self, packet):
        """Process individual packets"""
        if not self.is_capturing:
            return
        
        try:
            # Extract basic packet information
            if IP in packet:
                ip_layer = packet[IP]
                source_ip = ip_layer.src
                destination_ip = ip_layer.dst
                protocol = self._get_protocol(packet)
                length = len(packet)
                
                # Create packet model
                packet_data = {
                    'source_ip': source_ip,
                    'destination_ip': destination_ip,
                    'protocol': protocol,
                    'length': length
                }
                
                # Extract protocol-specific information
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_data.update({
                        'source_port': tcp_layer.sport,
                        'destination_port': tcp_layer.dport,
                        'flags': self._get_tcp_flags(tcp_layer.flags)
                    })
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_data.update({
                        'source_port': udp_layer.sport,
                        'destination_port': udp_layer.dport
                    })
                
                # Save to database
                packet_model = Packet(**packet_data)
                db.session.add(packet_model)
                db.session.commit()
                
                self.packet_count += 1
                
                # Broadcast via WebSocket
                if self.websocket_service:
                    self.websocket_service.broadcast_packet(packet_model.to_dict())
                    
        except Exception as e:
            print(f"Error processing packet: {e}")
            db.session.rollback()
    
    def _get_protocol(self, packet):
        """Determine protocol from packet"""
        if TCP in packet:
            return Protocol.TCP
        elif UDP in packet:
            return Protocol.UDP
        elif ICMP in packet:
            return Protocol.ICMP
        else:
            return Protocol.OTHER
    
    def _get_tcp_flags(self, flags):
        """Convert TCP flags to readable string"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        return ", ".join(flag_names)
    
    def get_stats(self):
        """Get capture statistics"""
        if not self.start_time:
            return {}
        
        uptime = time.time() - self.start_time
        packets_per_second = self.packet_count / uptime if uptime > 0 else 0
        
        return {
            'total_packets': self.packet_count,
            'uptime': uptime,
            'packets_per_second': packets_per_second,
            'is_capturing': self.is_capturing
        }