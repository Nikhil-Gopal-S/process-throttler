#!/bin/bash

# Installation script for process-throttler
# Supports multiple installation methods

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/yourusername/process-throttler"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/process-throttler"
LOG_DIR="/var/log/process-throttler"
SYSTEMD_DIR="/etc/systemd/system"

# Detect OS and architecture
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
            OS_VERSION=$VERSION_ID
        else
            OS="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        i686) ARCH="386" ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${YELLOW}Warning: Not running as root. Some features may require sudo.${NC}"
    fi
    
    # Check for required tools
    for tool in curl tar systemctl; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}Error: $tool is not installed${NC}"
            exit 1
        fi
    done
    
    # Check cgroups support
    if [ ! -d "/sys/fs/cgroup" ]; then
        echo -e "${YELLOW}Warning: Cgroups not detected. Some features may not work.${NC}"
    fi
    
    echo -e "${GREEN}Prerequisites check passed${NC}"
}

# Download and install binary
install_binary() {
    local version=${1:-"latest"}
    
    echo -e "${BLUE}Installing process-throttler ${version}...${NC}"
    
    # Determine download URL
    if [ "$version" == "latest" ]; then
        DOWNLOAD_URL="${REPO_URL}/releases/latest/download/process-throttler-linux-${ARCH}.tar.gz"
    else
        DOWNLOAD_URL="${REPO_URL}/releases/download/${version}/process-throttler-${version}-linux-${ARCH}.tar.gz"
    fi
    
    # Download binary
    echo "Downloading from: $DOWNLOAD_URL"
    TEMP_DIR=$(mktemp -d)
    curl -L -o "${TEMP_DIR}/process-throttler.tar.gz" "$DOWNLOAD_URL" || {
        echo -e "${RED}Failed to download binary${NC}"
        rm -rf "$TEMP_DIR"
        exit 1
    }
    
    # Extract and install
    tar -xzf "${TEMP_DIR}/process-throttler.tar.gz" -C "$TEMP_DIR"
    sudo mv "${TEMP_DIR}/process-throttler"* "$INSTALL_DIR/process-throttler"
    sudo chmod +x "$INSTALL_DIR/process-throttler"
    
    # Cleanup
    rm -rf "$TEMP_DIR"
    
    echo -e "${GREEN}Binary installed to $INSTALL_DIR/process-throttler${NC}"
}

# Install from source
install_from_source() {
    echo -e "${BLUE}Installing from source...${NC}"
    
    # Check for Go
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Error: Go is not installed${NC}"
        echo "Please install Go 1.21 or later from https://golang.org/dl/"
        exit 1
    fi
    
    # Clone repository
    TEMP_DIR=$(mktemp -d)
    git clone "$REPO_URL" "$TEMP_DIR/process-throttler" || {
        echo -e "${RED}Failed to clone repository${NC}"
        rm -rf "$TEMP_DIR"
        exit 1
    }
    
    # Build
    cd "$TEMP_DIR/process-throttler"
    make build || {
        echo -e "${RED}Build failed${NC}"
        rm -rf "$TEMP_DIR"
        exit 1
    }
    
    # Install
    sudo mv build/process-throttler "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/process-throttler"
    
    # Copy configs
    sudo mkdir -p "$CONFIG_DIR/profiles"
    sudo cp configs/*.yaml "$CONFIG_DIR/"
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
    
    echo -e "${GREEN}Built and installed from source${NC}"
}

# Setup configuration
setup_configuration() {
    echo -e "${BLUE}Setting up configuration...${NC}"
    
    # Create directories
    sudo mkdir -p "$CONFIG_DIR/profiles"
    sudo mkdir -p "$LOG_DIR/audit"
    sudo mkdir -p "/var/run/process-throttler"
    
    # Set permissions
    sudo chmod 755 "$CONFIG_DIR"
    sudo chmod 750 "$LOG_DIR"
    
    # Download example configs if not present
    if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
        echo "Downloading example configuration..."
        sudo curl -L -o "$CONFIG_DIR/config.yaml" \
            "${REPO_URL}/raw/main/configs/example.yaml"
        sudo curl -L -o "$CONFIG_DIR/profiles/production.yaml" \
            "${REPO_URL}/raw/main/configs/production-profile.yaml"
    fi
    
    echo -e "${GREEN}Configuration setup complete${NC}"
}

# Setup systemd service
setup_systemd() {
    echo -e "${BLUE}Setting up systemd service...${NC}"
    
    # Create service file
    sudo tee "$SYSTEMD_DIR/process-throttler.service" > /dev/null << 'EOF'
[Unit]
Description=Process Throttler Service
Documentation=https://github.com/yourusername/process-throttler
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/process-throttler daemon
ExecStop=/usr/local/bin/process-throttler emergency stop "Service shutdown"
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    sudo systemctl daemon-reload
    
    echo -e "${GREEN}Systemd service created${NC}"
    echo ""
    echo "To start the service:"
    echo "  sudo systemctl start process-throttler"
    echo ""
    echo "To enable at boot:"
    echo "  sudo systemctl enable process-throttler"
}

# Uninstall
uninstall() {
    echo -e "${YELLOW}Uninstalling process-throttler...${NC}"
    
    # Stop service if running
    if systemctl is-active --quiet process-throttler; then
        sudo systemctl stop process-throttler
    fi
    
    # Disable service
    if systemctl is-enabled --quiet process-throttler; then
        sudo systemctl disable process-throttler
    fi
    
    # Remove files
    sudo rm -f "$INSTALL_DIR/process-throttler"
    sudo rm -f "$SYSTEMD_DIR/process-throttler.service"
    
    # Ask about config and logs
    read -p "Remove configuration and logs? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm -rf "$CONFIG_DIR"
        sudo rm -rf "$LOG_DIR"
    fi
    
    echo -e "${GREEN}Uninstallation complete${NC}"
}

# Main menu
show_menu() {
    echo ""
    echo -e "${BLUE}Process Throttler Installation Script${NC}"
    echo "======================================"
    echo ""
    echo "1) Quick install (download latest binary)"
    echo "2) Install from source"
    echo "3) Install specific version"
    echo "4) Setup systemd service only"
    echo "5) Uninstall"
    echo "6) Exit"
    echo ""
    read -p "Select option [1-6]: " choice
}

# Main script
main() {
    detect_os
    
    echo -e "${BLUE}Detected OS: $OS ($ARCH)${NC}"
    
    if [ "$1" == "--uninstall" ]; then
        uninstall
        exit 0
    fi
    
    if [ "$1" == "--quick" ]; then
        check_prerequisites
        install_binary "latest"
        setup_configuration
        setup_systemd
        echo -e "${GREEN}Installation complete!${NC}"
        exit 0
    fi
    
    show_menu
    
    case $choice in
        1)
            check_prerequisites
            install_binary "latest"
            setup_configuration
            setup_systemd
            ;;
        2)
            check_prerequisites
            install_from_source
            setup_configuration
            setup_systemd
            ;;
        3)
            check_prerequisites
            read -p "Enter version (e.g., v1.0.0): " version
            install_binary "$version"
            setup_configuration
            setup_systemd
            ;;
        4)
            setup_systemd
            ;;
        5)
            uninstall
            ;;
        6)
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            exit 1
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Review configuration: $CONFIG_DIR/config.yaml"
    echo "2. Import profiles: process-throttler profile import <file>"
    echo "3. Start service: sudo systemctl start process-throttler"
    echo "4. Check status: process-throttler status"
}

# Run main function
main "$@"
