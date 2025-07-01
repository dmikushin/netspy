# NetSpy Packaging Guide

This document describes how to build and distribute NetSpy packages for Debian and Ubuntu.

## Quick Start

### Build Dependencies
```bash
# Install build dependencies
make package-deps
# OR
./build-deb.sh build-deps
```

### Build Packages
```bash
# Build all packages (recommended)
make package

# Build specific package types
make package-binary    # Binary .deb only
make package-source    # Source package only
```

### Test Package
```bash
# Install and test the built package
sudo dpkg -i dist/netspy_*.deb
netspy --version
netspy --help
```

## Package Structure

The NetSpy package includes:

- **Binary**: `/usr/bin/netspy` - CLI frontend
- **Library**: `/usr/lib/libnetspy.so` - Core library
- **Examples**: `/usr/share/netspy/examples/` - Python clients and utilities
- **Documentation**: `/usr/share/doc/netspy/` - README and docs
- **Man page**: `/usr/share/man/man1/netspy.1` - Manual page
- **Headers**: `/usr/include/netspy/` - Development headers

## Build Script Usage

The `build-deb.sh` script provides comprehensive package building:

```bash
# Show all options
./build-deb.sh --help

# Install build dependencies
./build-deb.sh build-deps

# Build all packages with testing
./build-deb.sh all

# Build without testing (faster)
./build-deb.sh --no-test all

# Build and skip quality checks
./build-deb.sh --no-check all

# Clean build artifacts
./build-deb.sh clean

# Test package installation
./build-deb.sh test
```

## Supported Distributions

### Officially Tested
- Ubuntu 20.04 LTS (Focal)
- Ubuntu 22.04 LTS (Jammy)
- Ubuntu 24.04 LTS (Noble)
- Debian 11 (Bullseye)
- Debian 12 (Bookworm)

### Architecture Support
- amd64 (x86_64) - Primary
- arm64 - Should work
- armhf - Should work
- i386 - Legacy support

## Dependencies

### Build Dependencies
- `build-essential` - Compilation tools
- `debhelper` (>= 10) - Debian packaging helpers
- `cmake` (>= 3.10) - Build system
- `libpcap-dev` - PCAP library development files
- `python3` - Python runtime
- `libgtest-dev` - Google Test framework
- `pkg-config` - Package configuration
- `lintian` - Package quality checker

### Runtime Dependencies
- `libpcap0.8` - PCAP library
- `python3` - Python runtime for CLI frontend

### Recommended Packages
- `wireshark` - For `--wireshark` option
- `python3-scapy` - For advanced Python examples

## GitHub Actions

The repository includes automated package building via GitHub Actions:

### On Push to Tags
```bash
git tag v1.1.0
git push origin v1.1.0
```

This will:
1. Build packages for all supported Ubuntu versions
2. Run installation tests
3. Create a GitHub release
4. Upload packages as release assets

### Manual Trigger
Visit Actions tab in GitHub and trigger "Build Debian Packages" workflow manually.

## Package Versioning

Package versions follow Debian conventions:

- `1.1.0-1` - Release version 1.1.0, Debian revision 1
- `1.1.0-1ubuntu1` - Ubuntu-specific revision
- `1.1.0+git20241230-1` - Development snapshot

Version is automatically derived from:
1. Git tags (for releases)
2. Git commit hash (for development)

## Quality Assurance

### Automated Checks
- `lintian` - Debian policy compliance
- Package installation test
- Basic functionality test
- Man page verification
- File permissions check

### Manual Testing
```bash
# Install package
sudo dpkg -i dist/netspy_*.deb

# Test CLI
netspy --version
netspy --dry-run echo test

# Test streaming
netspy --stream 57012 --dry-run curl google.com

# Test man page
man netspy

# Test library
ldd /usr/lib/libnetspy.so

# Cleanup
sudo dpkg -r netspy
```

## Distribution

### GitHub Releases
1. Tag a release: `git tag v1.1.0 && git push origin v1.1.0`
2. GitHub Actions will build and upload packages
3. Download from releases page

### PPA (Ubuntu)
For PPA distribution:
1. Build source package: `./build-deb.sh source`
2. Upload to Launchpad with `dput`

### Package Repositories
For APT repository:
1. Build packages for target distributions
2. Sign with GPG key
3. Add to repository with `reprepro` or similar

## Troubleshooting

### Build Failures
```bash
# Check build logs
./build-deb.sh --no-test binary 2>&1 | tee build.log

# Debug in build environment
cd build-deb/netspy-1.1.0
dpkg-buildpackage -us -uc
```

### Installation Issues
```bash
# Check package contents
dpkg-deb -c dist/netspy_*.deb

# Check dependencies
dpkg-deb -I dist/netspy_*.deb

# Force install dependencies
sudo apt-get install -f
```

### Testing Problems
```bash
# Run tests manually
cd build && ctest -V

# Check library linking
ldd /usr/lib/libnetspy.so

# Verify Python CLI
python3 -c "import sys; sys.path.append('/usr/bin'); import netspy"
```

## Contributing

To modify packaging:

1. Edit files in `debian/` directory
2. Update version in `debian/changelog`
3. Test with `./build-deb.sh all`
4. Ensure GitHub Actions pass

For new features affecting packaging:
1. Update `debian/control` for new dependencies
2. Update `debian/netspy.install` for new files
3. Update documentation in README and man page