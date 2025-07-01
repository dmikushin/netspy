#!/usr/bin/env python3
import sys
import os
import subprocess
import glob
import re

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <command> [args...]")
    sys.exit(1)

command = sys.argv[1:]

# Set LD_PRELOAD to use netspy
libnetspy = os.path.abspath(os.path.join(os.getcwd(), 'libnetspy.so'))
env = os.environ.copy()
env['LD_PRELOAD'] = libnetspy

# Run the command
try:
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        print(f"FAIL: Command {' '.join(command)} failed with exit code {result.returncode}")
        sys.exit(20)
except Exception as e:
    print(f"FAIL: Exception running command: {e}")
    sys.exit(21)

# Extract .pcap filename from output
pcap_file = None
for line in (result.stdout.splitlines() + result.stderr.splitlines()):
    match = re.search(r'([^\s]+_[0-9]+\.pcap)', line)
    if match:
        pcap_file = match.group(1)
        break
if not pcap_file:
    print("FAIL: Could not determine .pcap file name from command output.")
    sys.exit(22)

# 1. File existence
if not os.path.isfile(pcap_file):
    print(f"FAIL: {pcap_file} does not exist.")
    sys.exit(2)

# 2. File is not empty
if os.path.getsize(pcap_file) == 0:
    print(f"FAIL: {pcap_file} is empty.")
    sys.exit(3)

# 3. File is a valid PCAP (using capinfos)
try:
    result = subprocess.run(["capinfos", pcap_file], capture_output=True, text=True)
    if result.returncode != 0 or not re.search(r"File type:\s+Wireshark/tcpdump/", result.stdout):
        print(f"FAIL: {pcap_file} is not a valid PCAP file.")
        sys.exit(4)
except FileNotFoundError:
    print("capinfos not found. Please install Wireshark/tshark tools.")
    sys.exit(10)

# 4. At least one packet (using tshark)
try:
    result = subprocess.run(["tshark", "-r", pcap_file, "-c", "1"], capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        print(f"FAIL: {pcap_file} contains no packets.")
        sys.exit(5)
except FileNotFoundError:
    print("tshark not found. Please install Wireshark/tshark tools.")
    sys.exit(11)

# 5. At least one outgoing TCP or UDP packet (generic check)
result = subprocess.run([
    "tshark", "-r", pcap_file, "-Y", "tcp || udp", "-c", "1"
], capture_output=True, text=True)
if result.returncode != 0 or not result.stdout.strip():
    print(f"FAIL: {pcap_file} contains no TCP or UDP packets.")
    sys.exit(6)

print(f"PASS: {pcap_file} passed all checks.")
sys.exit(0)
