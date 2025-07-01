#!/usr/bin/env python3
"""
NetSpy PCAP-over-IP Client

Simple client to receive PCAP stream from NetSpy and process packets.
Requires scapy: pip install scapy

Usage:
    python3 pcap_stream_client.py [host] [port]
    
Examples:
    python3 pcap_stream_client.py                    # Connect to localhost:57012
    python3 pcap_stream_client.py 192.168.1.100     # Connect to remote host
    python3 pcap_stream_client.py localhost 57013   # Custom port
"""

import socket
import struct
import sys
import signal
import time
from datetime import datetime

try:
    from scapy.all import *
    from scapy.utils import PcapReader
    from scapy.packet import Packet
    HAS_SCAPY = True
except ImportError:
    print("Warning: scapy not available. Install with: pip install scapy")
    HAS_SCAPY = False

class PcapOverIPClient:
    def __init__(self, host='localhost', port=57012):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
    def connect(self):
        """Connect to PCAP-over-IP server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"Connected to NetSpy PCAP-over-IP server at {self.host}:{self.port}")
            
            # Read PCAP file header
            header = self.socket.recv(24)
            if len(header) != 24:
                raise Exception("Failed to read PCAP header")
                
            # Parse PCAP header
            magic, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack('<LHHLLLL', header)
            
            if magic != 0xa1b2c3d4:
                raise Exception(f"Invalid PCAP magic number: 0x{magic:x}")
                
            print(f"PCAP format: version {version_major}.{version_minor}, snaplen={snaplen}, linktype={network}")
            return True
            
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def read_packet(self):
        """Read a single packet from stream"""
        try:
            # Read packet header (16 bytes)
            header_data = self.socket.recv(16)
            if len(header_data) != 16:
                return None
                
            # Parse packet header
            ts_sec, ts_usec, caplen, len_orig = struct.unpack('<LLLL', header_data)
            
            # Read packet data
            packet_data = b''
            while len(packet_data) < caplen:
                chunk = self.socket.recv(caplen - len(packet_data))
                if not chunk:
                    return None
                packet_data += chunk
                
            timestamp = datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000)
            
            return {
                'timestamp': timestamp,
                'caplen': caplen,
                'len': len_orig,
                'data': packet_data
            }
            
        except Exception as e:
            print(f"Error reading packet: {e}")
            return None
    
    def process_packet(self, packet_info):
        """Process a received packet"""
        timestamp = packet_info['timestamp']
        data = packet_info['data']
        
        if HAS_SCAPY:
            try:
                # Parse with scapy
                packet = IP(data)
                
                # Extract basic info
                proto = packet.proto
                src_ip = packet.src
                dst_ip = packet.dst
                
                proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f'Proto-{proto}')
                
                # Get port info for TCP/UDP
                ports = ""
                if proto == 6 and packet.payload:  # TCP
                    tcp = packet.payload
                    ports = f":{tcp.sport} -> :{tcp.dport}"
                elif proto == 17 and packet.payload:  # UDP
                    udp = packet.payload
                    ports = f":{udp.sport} -> :{udp.dport}"
                
                print(f"{timestamp.strftime('%H:%M:%S.%f')[:-3]} {proto_name:4} {src_ip:15} -> {dst_ip:15}{ports} ({len(data)} bytes)")
                
                # Show packet summary
                if hasattr(packet, 'summary'):
                    print(f"  └─ {packet.summary()}")
                
            except Exception as e:
                print(f"{timestamp.strftime('%H:%M:%S.%f')[:-3]} RAW  Raw packet ({len(data)} bytes) - Parse error: {e}")
        else:
            # Basic parsing without scapy
            if len(data) >= 20:  # Minimum IP header
                # Simple IP header parsing
                version_ihl = data[0]
                version = (version_ihl >> 4) & 0xF
                if version == 4:
                    proto = data[9]
                    src_ip = '.'.join(str(x) for x in data[12:16])
                    dst_ip = '.'.join(str(x) for x in data[16:20])
                    proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f'Proto-{proto}')
                    print(f"{timestamp.strftime('%H:%M:%S.%f')[:-3]} {proto_name:4} {src_ip:15} -> {dst_ip:15} ({len(data)} bytes)")
                else:
                    print(f"{timestamp.strftime('%H:%M:%S.%f')[:-3]} RAW  Raw packet ({len(data)} bytes)")
            else:
                print(f"{timestamp.strftime('%H:%M:%S.%f')[:-3]} RAW  Short packet ({len(data)} bytes)")
    
    def run(self):
        """Main packet processing loop"""
        if not self.connect():
            return False
            
        self.running = True
        packet_count = 0
        
        print("\nPacket stream (Ctrl+C to stop):")
        print("-" * 80)
        
        try:
            while self.running:
                packet_info = self.read_packet()
                if packet_info is None:
                    break
                    
                packet_count += 1
                self.process_packet(packet_info)
                
        except KeyboardInterrupt:
            print(f"\n\nStopped by user. Processed {packet_count} packets.")
        except Exception as e:
            print(f"\nError in packet processing: {e}")
        finally:
            self.cleanup()
            
        return True
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        if self.socket:
            self.socket.close()

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print("\nShutting down...")
    sys.exit(0)

def main():
    # Parse command line arguments
    host = 'localhost'
    port = 57012
    
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    print("NetSpy PCAP-over-IP Client")
    print("=" * 40)
    
    if not HAS_SCAPY:
        print("Note: Running without scapy - limited packet parsing")
        print("Install scapy for full packet analysis: pip install scapy")
        print()
    
    client = PcapOverIPClient(host, port)
    
    if not client.run():
        sys.exit(1)

if __name__ == '__main__':
    main()