# NetSpy Makefile
# Convenience wrapper around CMake and packaging

.PHONY: all build install clean test package package-deps help

# Default target
all: build

# Build the project
build:
	@echo "Building NetSpy..."
	mkdir -p build
	cd build && cmake .. && make

# Install build dependencies for packaging
package-deps:
	@echo "Installing package build dependencies..."
	./build-deb.sh build-deps

# Build Debian packages
package:
	@echo "Building Debian packages..."
	./build-deb.sh all

# Build source package only
package-source:
	@echo "Building source package..."
	./build-deb.sh source

# Build binary package only
package-binary:
	@echo "Building binary package..."
	./build-deb.sh binary

# Clean package build artifacts
package-clean:
	@echo "Cleaning package build artifacts..."
	./build-deb.sh clean

# Install the project system-wide
install: build
	@echo "Installing NetSpy system-wide..."
	cd build && sudo make install

# Run tests
test: build
	@echo "Running tests..."
	cd build && ctest -V

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build
	rm -rf build-deb
	rm -rf dist
	rm -f *.pcap

# Show help
help:
	@echo "NetSpy Build System"
	@echo "=================="
	@echo ""
	@echo "Available targets:"
	@echo "  all             - Build the project (default)"
	@echo "  build           - Build NetSpy with CMake"
	@echo "  install         - Install NetSpy system-wide"
	@echo "  test            - Run unit tests"
	@echo "  clean           - Clean build artifacts"
	@echo ""
	@echo "Packaging targets:"
	@echo "  package-deps    - Install packaging dependencies"
	@echo "  package         - Build Debian packages"
	@echo "  package-source  - Build source package only"
	@echo "  package-binary  - Build binary package only"
	@echo "  package-clean   - Clean packaging artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make build      # Build the project"
	@echo "  make test       # Run tests"
	@echo "  make package    # Build .deb packages"
	@echo "  make install    # Install system-wide"