# NetSpy Demo Generation

This directory contains all files and scripts needed to generate NetSpy demonstration materials.

## Files

- `netspy_demo.go` - Main demo script using saschagrunert/demo framework
- `generate_demo.sh` - Shell script to regenerate all demo materials
- `netspy_demo.cast` - Asciinema terminal recording
- `netspy_demo.svg` - Final SVG animation for web display

## Prerequisites

Before running the demo generation, ensure these tools are installed:

- `netspy` - The NetSpy network traffic logger
- `tcpdump` - For PCAP analysis
- `tshark` - For detailed packet inspection
- `go` - Go runtime for demo framework
- `termtosvg` - For converting terminal recordings to SVG

## Quick Start

1. **Generate all demo materials:**
   ```bash
   ./generate_demo.sh
   ```

2. **Manual demo recording (alternative):**
   ```bash
   go run netspy_demo.go --auto --auto-timeout 4s rec basic
   termtosvg render netspy_demo.cast netspy_demo.svg
   ```

3. **Interactive demo mode:**
   ```bash
   go run netspy_demo.go
   ```

## Demo Content

The demo showcases:

1. **NetSpy Help** - Display available command options
2. **Basic Usage** - Monitor curl request with quiet logging
3. **PCAP Analysis** - Examine captured traffic with tcpdump
4. **Detailed Analysis** - Use tshark for packet inspection
5. **Streaming Mode** - Real-time PCAP streaming capabilities
6. **Wireshark Integration** - Connect Wireshark for live analysis

## Customization

To modify the demo content:

1. Edit `netspy_demo.go` to change demo steps
2. Run `./generate_demo.sh` to regenerate materials

## Output

The script generates:

- **Terminal recording** as `netspy_demo.cast`
- **SVG animation** as `netspy_demo.svg` (ready for web embedding)

The SVG file can be embedded directly in documentation or web pages to show NetSpy capabilities.
