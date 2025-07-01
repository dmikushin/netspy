#!/bin/bash

# NetSpy Wireshark Integration Example
# 
# This script demonstrates how to connect Wireshark to NetSpy's PCAP-over-IP stream.
# 
# Prerequisites:
# - Wireshark installed
# - NetSpy library available
# - Target application to monitor
#
# Usage:
#   ./wireshark_example.sh [command_to_monitor]
#
# Examples:
#   ./wireshark_example.sh curl google.com
#   ./wireshark_example.sh wget https://example.com
#   ./wireshark_example.sh python3 -c "import requests; requests.get('https://httpbin.org/json')"

set -e

# Configuration
NETSPY_LIB="./libnetspy.so"
PCAP_OVER_IP_PORT=57012
WIRESHARK_BIN="wireshark"

# Check if Wireshark is available
if ! command -v $WIRESHARK_BIN &> /dev/null; then
    echo "Error: Wireshark not found. Please install wireshark."
    echo "Ubuntu/Debian: sudo apt install wireshark"
    echo "CentOS/RHEL: sudo yum install wireshark-gtk"
    exit 1
fi

# Check if NetSpy library exists
if [ ! -f "$NETSPY_LIB" ]; then
    echo "Error: NetSpy library not found at $NETSPY_LIB"
    echo "Please build NetSpy first: cd build && make"
    exit 1
fi

# Function to cleanup background processes
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$TARGET_PID" ]; then
        kill $TARGET_PID 2>/dev/null || true
    fi
    if [ ! -z "$WIRESHARK_PID" ]; then
        kill $WIRESHARK_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

echo "NetSpy + Wireshark Integration Example"
echo "======================================"

# Get the command to monitor
if [ $# -eq 0 ]; then
    echo "Usage: $0 <command_to_monitor>"
    echo ""
    echo "Examples:"
    echo "  $0 curl google.com"
    echo "  $0 wget https://example.com"
    echo "  $0 python3 -c \"import requests; requests.get('https://httpbin.org/json')\""
    exit 1
fi

COMMAND_TO_MONITOR="$*"

echo "Starting Wireshark to capture from NetSpy PCAP-over-IP stream..."
echo "Command to monitor: $COMMAND_TO_MONITOR"
echo ""

# Start Wireshark with TCP capture interface
echo "Starting Wireshark (this may take a moment)..."
$WIRESHARK_BIN -k -i TCP@127.0.0.1:$PCAP_OVER_IP_PORT &
WIRESHARK_PID=$!

# Give Wireshark time to start and connect
echo "Waiting for Wireshark to initialize..."
sleep 3

# Run the target command with NetSpy
echo "Starting target command with NetSpy..."
echo "Command: NETSPY_PCAP_OVER_IP_PORT=$PCAP_OVER_IP_PORT LD_PRELOAD=$NETSPY_LIB $COMMAND_TO_MONITOR"
echo ""

NETSPY_PCAP_OVER_IP_PORT=$PCAP_OVER_IP_PORT LD_PRELOAD=$NETSPY_LIB $COMMAND_TO_MONITOR &
TARGET_PID=$!

# Wait for the target command to complete
wait $TARGET_PID
TARGET_EXIT_CODE=$?

echo ""
echo "Target command completed with exit code: $TARGET_EXIT_CODE"
echo "Wireshark should now be displaying the captured network traffic."
echo ""
echo "Tips for using Wireshark with NetSpy:"
echo "- Use display filters like 'tcp.port == 80' to filter HTTP traffic"
echo "- Use 'tcp.port == 443' for HTTPS traffic"
echo "- Use 'udp' to see UDP traffic"
echo "- Right-click packets and select 'Follow TCP Stream' to see conversations"
echo ""
echo "Press Enter to close Wireshark and exit..."
read

# Cleanup will be handled by the trap