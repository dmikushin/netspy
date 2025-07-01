#!/usr/bin/env python3
"""
NetSpy Traffic Filter Example

Advanced PCAP-over-IP client with filtering capabilities.
Demonstrates how to implement custom traffic filtering and analysis.

Usage:
    python3 traffic_filter.py [options]
    
Options:
    --host HOST         Server host (default: localhost)
    --port PORT         Server port (default: 57012)
    --filter FILTER     BPF-like filter expression
    --save FILE         Save filtered packets to PCAP file
    --stats             Show traffic statistics
    
Examples:
    python3 traffic_filter.py --filter "tcp and port 80"
    python3 traffic_filter.py --filter "udp" --save udp_traffic.pcap
    python3 traffic_filter.py --stats
"""

import socket
import struct
import sys
import argparse
import signal
import time
import re
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import *
    from scapy.utils import PcapWriter
    HAS_SCAPY = True
except ImportError:
    print("Error: This example requires scapy. Install with: pip install scapy")
    sys.exit(1)

class TrafficFilter:
    def __init__(self, filter_expr=None):
        self.filter_expr = filter_expr
        self.stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.host_stats = defaultdict(int)
        
    def matches_filter(self, packet):
        """Check if packet matches filter expression"""
        if not self.filter_expr:
            return True
            
        try:
            # Simple filter implementation
            filter_lower = self.filter_expr.lower()
            
            # Protocol filters
            if packet.haslayer(TCP) and 'tcp' in filter_lower:
                return True
            elif packet.haslayer(UDP) and 'udp' in filter_lower:
                return True
            elif packet.haslayer(ICMP) and 'icmp' in filter_lower:
                return True
                
            # Port filters
            port_match = re.search(r'port (\d+)', filter_lower)
            if port_match:
                target_port = int(port_match.group(1))
                if packet.haslayer(TCP):
                    if packet[TCP].sport == target_port or packet[TCP].dport == target_port:
                        return True
                elif packet.haslayer(UDP):
                    if packet[UDP].sport == target_port or packet[UDP].dport == target_port:
                        return True
                        
            # Host filters
            host_match = re.search(r'host ([0-9.]+)', filter_lower)
            if host_match:
                target_host = host_match.group(1)
                if packet.haslayer(IP):
                    if packet[IP].src == target_host or packet[IP].dst == target_host:
                        return True
                        
            # HTTP traffic detection
            if 'http' in filter_lower:
                if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                    return True
                    
            # HTTPS traffic detection
            if 'https' in filter_lower:
                if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                    return True
                    
            return False
            
        except Exception as e:
            print(f"Filter evaluation error: {e}")
            return True
    
    def update_stats(self, packet):
        """Update traffic statistics"""
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += len(packet)
        
        if packet.haslayer(IP):
            self.host_stats[packet[IP].src] += 1
            self.host_stats[packet[IP].dst] += 1
            
            if packet.haslayer(TCP):
                self.protocol_stats['TCP'] += 1
            elif packet.haslayer(UDP):
                self.protocol_stats['UDP'] += 1
            elif packet.haslayer(ICMP):
                self.protocol_stats['ICMP'] += 1
            else:
                self.protocol_stats['Other'] += 1
    
    def print_stats(self):
        """Print traffic statistics"""
        print("\n" + "="*60)
        print("TRAFFIC STATISTICS")
        print("="*60)
        
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"Total Bytes:   {self.stats['total_bytes']:,}")
        
        if self.protocol_stats:
            print("\nProtocol Distribution:")
            for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / self.stats['total_packets']) * 100
                print(f"  {proto:8}: {count:6} ({percentage:5.1f}%)")
        
        if self.host_stats:
            print("\nTop Hosts (by packet count):")
            top_hosts = sorted(self.host_stats.items(), key=lambda x: x[1], reverse=True)[:10]
            for host, count in top_hosts:
                print(f"  {host:15}: {count:6} packets")

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
            self.socket.settimeout(5.0)  # 5 second timeout
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
            if "timed out" not in str(e):
                print(f"Error reading packet: {e}")
            return None
    
    def run_with_filter(self, traffic_filter, save_file=None, show_stats=False):
        """Main packet processing loop with filtering"""
        if not self.connect():
            return False
            
        self.running = True
        packet_count = 0
        filtered_count = 0
        
        # Setup PCAP writer if saving
        pcap_writer = None
        if save_file:
            pcap_writer = PcapWriter(save_file, append=False, sync=True)
            print(f"Saving filtered packets to: {save_file}")
        
        if traffic_filter.filter_expr:
            print(f"Applying filter: {traffic_filter.filter_expr}")
        else:
            print("No filter applied - showing all packets")
            
        print("\nPacket stream (Ctrl+C to stop):")
        print("-" * 80)
        
        try:
            last_stats_time = time.time()
            
            while self.running:
                packet_info = self.read_packet()
                if packet_info is None:
                    continue
                    
                packet_count += 1
                
                try:
                    # Parse with scapy
                    packet = IP(packet_info['data'])
                    
                    # Update statistics
                    if show_stats:
                        traffic_filter.update_stats(packet)
                    
                    # Apply filter
                    if traffic_filter.matches_filter(packet):
                        filtered_count += 1
                        
                        # Display packet
                        timestamp = packet_info['timestamp']
                        self.display_packet(packet, timestamp)
                        
                        # Save to file if requested
                        if pcap_writer:
                            pcap_writer.write(packet)
                            
                except Exception as e:
                    print(f"Error processing packet: {e}")
                
                # Show periodic stats
                if show_stats and time.time() - last_stats_time > 10:
                    print(f"\n--- Stats: {packet_count} total, {filtered_count} matched filter ---")
                    last_stats_time = time.time()
                
        except KeyboardInterrupt:
            print(f"\n\nStopped by user.")
        except Exception as e:
            print(f"\nError in packet processing: {e}")
        finally:
            self.cleanup()
            if pcap_writer:
                pcap_writer.close()
                
        print(f"Processed {packet_count} packets, {filtered_count} matched filter")
        
        if show_stats:
            traffic_filter.print_stats()
            
        return True
    
    def display_packet(self, packet, timestamp):
        """Display packet information"""
        try:
            # Basic info
            src_ip = packet.src if hasattr(packet, 'src') else 'unknown'
            dst_ip = packet.dst if hasattr(packet, 'dst') else 'unknown'
            proto_name = 'Unknown'
            ports = ""
            
            # Protocol-specific info
            if packet.haslayer(TCP):
                proto_name = 'TCP'
                tcp = packet[TCP]
                ports = f":{tcp.sport} -> :{tcp.dport}"
                flags = []
                if tcp.flags.S: flags.append('SYN')
                if tcp.flags.A: flags.append('ACK')
                if tcp.flags.F: flags.append('FIN')
                if tcp.flags.R: flags.append('RST')
                if tcp.flags.P: flags.append('PSH')
                if flags:
                    ports += f" [{','.join(flags)}]"
                    
            elif packet.haslayer(UDP):
                proto_name = 'UDP'
                udp = packet[UDP]
                ports = f":{udp.sport} -> :{udp.dport}"
                
            elif packet.haslayer(ICMP):
                proto_name = 'ICMP'
                icmp = packet[ICMP]
                ports = f" type={icmp.type} code={icmp.code}"
            
            print(f"{timestamp.strftime('%H:%M:%S.%f')[:-3]} {proto_name:4} {src_ip:15} -> {dst_ip:15}{ports} ({len(packet)} bytes)")
            
            # Show additional info for interesting packets
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if len(payload) > 0:
                    # Look for interesting strings
                    payload_str = payload.decode('ascii', errors='ignore')
                    if any(keyword in payload_str.lower() for keyword in ['http', 'get ', 'post ', 'user-agent']):
                        lines = payload_str.split('\n')
                        for line in lines[:3]:  # Show first 3 lines
                            if line.strip():
                                print(f"  └─ {line.strip()[:60]}")
                                
        except Exception as e:
            print(f"Error displaying packet: {e}")
    
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
    parser = argparse.ArgumentParser(description='NetSpy PCAP-over-IP Traffic Filter')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=57012, help='Server port (default: 57012)')
    parser.add_argument('--filter', help='Filter expression (e.g., "tcp and port 80")')
    parser.add_argument('--save', help='Save filtered packets to PCAP file')
    parser.add_argument('--stats', action='store_true', help='Show traffic statistics')
    
    args = parser.parse_args()
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    print("NetSpy Traffic Filter")
    print("=" * 40)
    
    traffic_filter = TrafficFilter(args.filter)
    client = PcapOverIPClient(args.host, args.port)
    
    if not client.run_with_filter(traffic_filter, args.save, args.stats):
        sys.exit(1)

if __name__ == '__main__':
    main()