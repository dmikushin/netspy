#!/bin/bash

# NetSpy Demo Generation Script
# This script regenerates all demo files including logs, recordings, and SVG output

set -e

echo "🎬 NetSpy Demo Generation Script"
echo "================================="

# Check dependencies
echo "📋 Checking dependencies..."
command -v netspy >/dev/null 2>&1 || { echo "❌ netspy is not installed. Please install it first."; exit 1; }
command -v tcpdump >/dev/null 2>&1 || { echo "❌ tcpdump is not installed. Please install it first."; exit 1; }
command -v tshark >/dev/null 2>&1 || { echo "❌ tshark is not installed. Please install it first."; exit 1; }
command -v go >/dev/null 2>&1 || { echo "❌ go is not installed. Please install it first."; exit 1; }
command -v agg >/dev/null 2>&1 || { echo "❌ agg is not installed. Please install it first (pip install asciinema-agg)."; exit 1; }
command -v ffmpeg >/dev/null 2>&1 || { echo "❌ ffmpeg is not installed. Please install it first."; exit 1; }

echo "✅ All dependencies found"

# Clean up old files
echo "🧹 Cleaning up old demo files..."
rm -f *.cast *.gif *.mp4 *.pcap

# Record demo
echo "🎥 Recording demo session..."
go mod tidy
asciinema rec netspy_demo.cast -c "go run netspy_demo.go --auto --auto-timeout 4s --basic"

echo "🎨 Converting to GIF with custom theme..."
agg --theme "ffffff,24292f,24292f,d73a49,22863a,b08800,0366d6,6f42c1,0969da,24292f,6a737d,cb2431,28a745,d9b100,2188ff,8b5fbf,0969da,586069" netspy_demo.cast netspy_demo.gif

echo "🎬 Converting GIF to high-quality MP4..."
ffmpeg -i netspy_demo.gif -vf "scale=1280:720:flags=lanczos" -c:v libx264 -preset slow -crf 18 -pix_fmt yuv420p -r 30 -movflags +faststart netspy_demo.mp4

echo "📊 Demo generation complete!"
echo ""
echo "Generated files:"
echo "  🎬 netspy_demo.cast - Terminal recording"
echo "  🖼️  netspy_demo.gif - GIF animation"
echo "  🎥 netspy_demo.mp4 - High-quality MP4 video"
echo ""
echo "✨ Demo is ready for use!"