#!/bin/bash

# NetSpy Debian Package Build Script
#
# This script builds .deb packages for Ubuntu/Debian distributions.
# It supports both local building and GitHub Actions automation.

set -e

# Configuration
PACKAGE_NAME="netspy"
VERSION="1.0.0"
BUILD_DIR="build-deb"
DIST_DIR="dist"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[BUILD]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install build dependencies
install_build_deps() {
    log "Installing build dependencies..."
    
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            debhelper \
            devscripts \
            cmake \
            libpcap-dev \
            python3 \
            python3-dev \
            libgtest-dev \
            pkg-config \
            lintian \
            fakeroot
    else
        error "apt-get not found. This script requires Debian/Ubuntu."
    fi
}

# Function to clean previous builds
clean_build() {
    log "Cleaning previous builds..."
    rm -rf "${BUILD_DIR}"
    rm -rf "${DIST_DIR}"
    rm -f ../${PACKAGE_NAME}_${VERSION}*
    rm -f ../${PACKAGE_NAME}-${VERSION}*
}

# Function to prepare source package
prepare_source() {
    log "Preparing source package..."
    
    # Create build directory
    mkdir -p "${BUILD_DIR}"
    mkdir -p "${DIST_DIR}"
    
    # Copy source files (excluding build artifacts)
    rsync -av \
        --exclude="${BUILD_DIR}" \
        --exclude="${DIST_DIR}" \
        --exclude="build" \
        --exclude=".git" \
        --exclude="*.pcap" \
        --exclude="0001-*.patch" \
        --exclude="0002-*.patch" \
        --exclude="third_party" \
        . "${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}/"
    
    # Copy submodules if they exist
    if [[ -d "ThirdParty/googletest" ]]; then
        log "Copying GoogleTest submodule..."
        mkdir -p "${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}/ThirdParty"
        cp -r ThirdParty/googletest "${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}/ThirdParty/"
    else
        warning "GoogleTest submodule not found, build may fail"
    fi
    
    # Create orig tarball
    cd "${BUILD_DIR}"
    tar czf "${PACKAGE_NAME}_${VERSION}.orig.tar.gz" "${PACKAGE_NAME}-${VERSION}"
    cd ..
}

# Function to build binary package
build_binary() {
    log "Building binary package..."
    
    cd "${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}"
    
    # Build the package
    debuild -us -uc -b
    
    cd ../..
}

# Function to build source package
build_source() {
    log "Building source package..."
    
    cd "${BUILD_DIR}/${PACKAGE_NAME}-${VERSION}"
    
    # Build source package
    debuild -S -us -uc
    
    cd ../..
}

# Function to run package checks
check_package() {
    log "Running package checks..."
    
    cd "${BUILD_DIR}"
    
    # Check with lintian
    if command_exists lintian; then
        lintian "${PACKAGE_NAME}_${VERSION}-1_"*.deb || warning "Lintian found some issues"
    else
        warning "lintian not available, skipping package checks"
    fi
    
    cd ..
}

# Function to collect build artifacts
collect_artifacts() {
    log "Collecting build artifacts..."
    
    # Move packages to dist directory
    mv "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}-1_"*.deb "${DIST_DIR}/" 2>/dev/null || true
    mv "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}-1_"*.ddeb "${DIST_DIR}/" 2>/dev/null || true
    mv "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}-1.dsc" "${DIST_DIR}/" 2>/dev/null || true
    mv "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}-1.tar.xz" "${DIST_DIR}/" 2>/dev/null || true
    mv "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}-1_"*.build "${DIST_DIR}/" 2>/dev/null || true
    mv "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}-1_"*.buildinfo "${DIST_DIR}/" 2>/dev/null || true
    mv "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}-1_"*.changes "${DIST_DIR}/" 2>/dev/null || true
    mv "${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}.orig.tar.gz" "${DIST_DIR}/" 2>/dev/null || true
    
    # List created packages
    success "Build completed! Created packages:"
    ls -la "${DIST_DIR}/"
}

# Function to test installation
test_installation() {
    log "Testing package installation..."
    
    local deb_file
    deb_file=$(find "${DIST_DIR}" -name "${PACKAGE_NAME}_${VERSION}-1_*.deb" | head -1)
    
    if [[ -n "$deb_file" ]]; then
        log "Testing installation of $deb_file"
        
        # Install package
        sudo dpkg -i "$deb_file" || true
        sudo apt-get install -f -y  # Fix dependencies if needed
        
        # Test basic functionality
        if command_exists netspy; then
            success "netspy CLI installed successfully"
            netspy --version
            netspy --help | head -10
        else
            error "netspy CLI not found after installation"
        fi
        
        # Test library
        if [[ -f "/usr/lib/libnetspy.so" ]]; then
            success "libnetspy.so installed successfully"
        else
            error "libnetspy.so not found after installation"
        fi
        
        # Test man page
        if man netspy >/dev/null 2>&1; then
            success "Man page installed successfully"
        else
            warning "Man page not accessible"
        fi
        
        # Cleanup test installation
        sudo dpkg -r netspy || true
        
    else
        error "No .deb package found for testing"
    fi
}

# Function to show usage
show_usage() {
    cat << EOF
NetSpy Debian Package Build Script

Usage: $0 [OPTIONS] [COMMAND]

Commands:
  build-deps    Install build dependencies
  clean         Clean previous builds
  source        Build source package only
  binary        Build binary package only
  all           Build both source and binary packages (default)
  test          Test package installation
  check         Run package quality checks

Options:
  --no-test     Skip installation testing
  --no-check    Skip package quality checks
  --help        Show this help message

Examples:
  $0                    # Build packages with testing
  $0 build-deps         # Install build dependencies
  $0 --no-test all      # Build without testing
  $0 clean              # Clean build artifacts

EOF
}

# Main function
main() {
    local cmd="all"
    local run_test=true
    local run_check=true
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help)
                show_usage
                exit 0
                ;;
            --no-test)
                run_test=false
                shift
                ;;
            --no-check)
                run_check=false
                shift
                ;;
            build-deps|clean|source|binary|all|test|check)
                cmd="$1"
                shift
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    log "Starting NetSpy package build (command: $cmd)"
    
    case $cmd in
        build-deps)
            install_build_deps
            ;;
        clean)
            clean_build
            ;;
        source)
            prepare_source
            build_source
            collect_artifacts
            ;;
        binary)
            prepare_source
            build_binary
            if [[ "$run_check" == true ]]; then
                check_package
            fi
            collect_artifacts
            if [[ "$run_test" == true ]]; then
                test_installation
            fi
            ;;
        all)
            clean_build
            prepare_source
            build_binary
            build_source
            if [[ "$run_check" == true ]]; then
                check_package
            fi
            collect_artifacts
            if [[ "$run_test" == true ]]; then
                test_installation
            fi
            ;;
        test)
            test_installation
            ;;
        check)
            check_package
            ;;
        *)
            error "Unknown command: $cmd"
            ;;
    esac
    
    success "Build script completed successfully!"
}

# Run main function
main "$@"