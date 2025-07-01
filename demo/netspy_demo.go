package main

import (
	. "github.com/saschagrunert/demo"
)

func main() {
	// Create a new demo CLI application
	demo := New()

	// Set demo properties
	demo.Name = "NetSpy Network Traffic Logger Demonstration"
	demo.Usage = "Learn how to use NetSpy to monitor network traffic"
	demo.HideVersion = true

	// Register demo runs
	demo.Add(basicUsage(), "basic", "Basic NetSpy usage examples")
	demo.Add(streamingDemo(), "streaming", "PCAP-over-IP streaming features")
	demo.Add(wiresharkDemo(), "wireshark", "Real-time Wireshark integration")

	// Run the application
	demo.Run()
}

// basicUsage demonstrates the core NetSpy functionality
func basicUsage() *Run {
	r := NewRun(
		"NetSpy Network Traffic Logger Demo",
		"NetSpy uses LD_PRELOAD to intercept network calls",
		"and logs them to PCAP files compatible with Wireshark.",
	)

	r.Step(S(
		"Let's start with the help to see available options",
	), S(
		"netspy --help | head -15",
	))

	r.Step(S(
		"Monitor a simple curl request to httpbin.org",
		"This creates a PCAP file with captured network traffic",
	), S(
		"netspy --quiet --filename demo_curl curl -s https://httpbin.org/get",
	))

	r.Step(S(
		"Check what PCAP file was created",
		"We used --filename to create demo_curl.pcap",
	), S(
		"ls -lh demo_curl.pcap",
	))

	r.Step(S(
		"Let's examine the captured network traffic",
		"We can analyze the PCAP file with tcpdump or Wireshark",
	), S(
		"tcpdump -r demo_curl.pcap -n -c 15",
	))

	r.Step(S(
		"For detailed analysis, use tshark for command-line inspection",
		"Let's see the same packets with tshark's detailed output",
	), S(
		"tshark -r demo_curl.pcap -T fields -e frame.number -e ip.src -e ip.dst -e tcp.port -c 15",
	))

	r.Step(S(
		"NetSpy can also stream PCAP data in real-time",
		"Use --stream for live analysis without file I/O",
	), S(
		"echo 'Example: netspy --stream 57012 your_app'",
	))

	r.Step(S(
		"For real-time analysis, connect Wireshark to the stream",
		"This enables live packet capture without disk I/O",
	), S(
		"echo 'Then: wireshark -k -i TCP@127.0.0.1:57012'",
	))

	return r
}

// streamingDemo shows PCAP-over-IP streaming capabilities
func streamingDemo() *Run {
	r := NewRun(
		"NetSpy PCAP-over-IP Streaming",
		"NetSpy can stream PCAP data in real-time over TCP",
		"This allows for live analysis without writing to disk",
	)

	r.Step(S(
		"Start a streaming session in the background",
		"This will stream to port 57012 (default)",
	), S(
		"netspy --stream curl -s https://httpbin.org/ip &",
		"sleep 1",
	))

	r.Step(S(
		"Let's use the built-in Python client to view the stream",
		"This will show packets as they're captured",
	), S(
		"timeout 3 python3 ../examples/pcap_stream_client.py localhost 57012 || true",
	))

	r.Step(S(
		"We can also stream to a custom port",
		"Let's demonstrate with port 8080",
	), S(
		"netspy --stream 8080 curl -s https://httpbin.org/user-agent &",
		"sleep 1",
		"timeout 3 python3 ../examples/pcap_stream_client.py localhost 8080 || true",
	))

	return r
}

// wiresharkDemo shows Wireshark integration
func wiresharkDemo() *Run {
	r := NewRun(
		"NetSpy Wireshark Integration",
		"NetSpy can automatically launch Wireshark for real-time analysis",
		"Perfect for interactive traffic investigation",
	)

	r.Step(S(
		"The --wireshark flag automatically starts Wireshark",
		"Note: This would normally open Wireshark GUI, but we'll use dry-run",
	), S(
		"netspy --dry-run --wireshark curl https://httpbin.org/anything",
	))

	r.Step(S(
		"For manual Wireshark connection, use TCP@ syntax",
		"This connects to our streaming port directly",
	), S(
		"echo 'wireshark -k -i TCP@127.0.0.1:57012'",
		"echo '# This would open Wireshark in capture mode'",
	))

	r.Step(S(
		"NetSpy also includes a Wireshark helper script",
		"Let's examine what it does",
	), S(
		"cat ../examples/wireshark_example.sh",
	))

	r.Step(S(
		"The stream-client option provides a Python-based packet viewer",
		"Great for headless environments or scripted analysis",
	), S(
		"netspy --dry-run --stream-client curl https://httpbin.org/headers",
	))

	return r
}
