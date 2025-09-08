#!/bin/bash

# Create Debian package for process-throttler

set -e

PROJECT_NAME="process-throttler"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
ARCH="amd64"
PKG_DIR="pkg/debian"
DEB_NAME="${PROJECT_NAME}_${VERSION}_${ARCH}"

echo "Creating Debian package: ${DEB_NAME}.deb"

# Clean and create package directory structure
rm -rf ${PKG_DIR}
mkdir -p ${PKG_DIR}/${DEB_NAME}/{DEBIAN,usr/local/bin,etc/process-throttler,usr/share/doc/process-throttler,etc/systemd/system}

# Build binary
echo "Building binary..."
go build -ldflags "-X main.Version=${VERSION}" -o ${PKG_DIR}/${DEB_NAME}/usr/local/bin/${PROJECT_NAME} ./cmd/process-throttler

# Copy configuration files
cp configs/example.yaml ${PKG_DIR}/${DEB_NAME}/etc/process-throttler/config.yaml.example
cp configs/production-profile.yaml ${PKG_DIR}/${DEB_NAME}/etc/process-throttler/

# Copy documentation
cp README.md ${PKG_DIR}/${DEB_NAME}/usr/share/doc/process-throttler/
cp LICENSE ${PKG_DIR}/${DEB_NAME}/usr/share/doc/process-throttler/ 2>/dev/null || echo "No LICENSE file"

# Create systemd service file
cat > ${PKG_DIR}/${DEB_NAME}/etc/systemd/system/process-throttler.service << EOF
[Unit]
Description=Process Throttler Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/process-throttler daemon
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create control file
cat > ${PKG_DIR}/${DEB_NAME}/DEBIAN/control << EOF
Package: ${PROJECT_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: Your Name <your.email@example.com>
Description: Universal process management and resource throttling tool
 Process Throttler is a production-ready tool for Linux/Unix servers
 that provides intelligent process monitoring, critical process protection,
 and configurable resource throttling using cgroups.
 .
 Features:
  - Process discovery and monitoring
  - Resource throttling (CPU, memory, I/O)
  - Critical process protection
  - Profile management
  - Audit logging and backup
  - Emergency stop mechanism
Depends: systemd
EOF

# Create postinst script
cat > ${PKG_DIR}/${DEB_NAME}/DEBIAN/postinst << 'EOF'
#!/bin/bash
set -e

# Create necessary directories
mkdir -p /var/log/process-throttler/audit
mkdir -p /var/run/process-throttler
mkdir -p /etc/process-throttler/profiles

# Set permissions
chmod 750 /var/log/process-throttler
chmod 755 /etc/process-throttler

# Reload systemd
systemctl daemon-reload

echo "Process Throttler installed successfully!"
echo "To start the service: systemctl start process-throttler"
echo "To enable at boot: systemctl enable process-throttler"

exit 0
EOF

chmod 755 ${PKG_DIR}/${DEB_NAME}/DEBIAN/postinst

# Create prerm script
cat > ${PKG_DIR}/${DEB_NAME}/DEBIAN/prerm << 'EOF'
#!/bin/bash
set -e

# Stop service if running
if systemctl is-active --quiet process-throttler; then
    systemctl stop process-throttler
fi

exit 0
EOF

chmod 755 ${PKG_DIR}/${DEB_NAME}/DEBIAN/prerm

# Set correct permissions
chmod 755 ${PKG_DIR}/${DEB_NAME}/usr/local/bin/${PROJECT_NAME}

# Build the package
dpkg-deb --build ${PKG_DIR}/${DEB_NAME}

# Move to dist directory
mkdir -p dist
mv ${PKG_DIR}/${DEB_NAME}.deb dist/

echo "Debian package created: dist/${DEB_NAME}.deb"
echo ""
echo "To install:"
echo "  sudo dpkg -i dist/${DEB_NAME}.deb"
echo ""
echo "To remove:"
echo "  sudo dpkg -r ${PROJECT_NAME}"
