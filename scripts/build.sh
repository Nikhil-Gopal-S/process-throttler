#!/bin/bash

# Build script for process-throttler
# Creates binaries for multiple platforms

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Project information
PROJECT_NAME="process-throttler"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_DIR="dist"

# Go build flags
LDFLAGS="-X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE}"

echo -e "${GREEN}Building ${PROJECT_NAME} v${VERSION}${NC}"
echo "Build date: ${BUILD_DATE}"
echo ""

# Create build directory
mkdir -p ${BUILD_DIR}

# Platform configurations
declare -a PLATFORMS=(
    "linux/amd64"
    "linux/386"
    "linux/arm64"
    "linux/arm"
)

# Build for each platform
for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM#*/}
    
    OUTPUT_NAME="${PROJECT_NAME}-${VERSION}-${GOOS}-${GOARCH}"
    OUTPUT_PATH="${BUILD_DIR}/${OUTPUT_NAME}"
    
    echo -e "${YELLOW}Building for ${GOOS}/${GOARCH}...${NC}"
    
    # Build binary
    GOOS=${GOOS} GOARCH=${GOARCH} go build \
        -ldflags "${LDFLAGS}" \
        -o "${OUTPUT_PATH}" \
        ./cmd/process-throttler
    
    if [ $? -eq 0 ]; then
        # Create tar.gz archive
        tar -czf "${OUTPUT_PATH}.tar.gz" -C "${BUILD_DIR}" "${OUTPUT_NAME}"
        rm "${OUTPUT_PATH}"
        
        # Calculate checksum
        if command -v sha256sum &> /dev/null; then
            sha256sum "${OUTPUT_PATH}.tar.gz" | cut -d' ' -f1 > "${OUTPUT_PATH}.tar.gz.sha256"
        fi
        
        echo -e "${GREEN}✓ Built ${OUTPUT_NAME}.tar.gz${NC}"
    else
        echo -e "${RED}✗ Failed to build for ${GOOS}/${GOARCH}${NC}"
    fi
done

# Create source archive
echo -e "${YELLOW}Creating source archive...${NC}"
git archive --format=tar.gz --prefix="${PROJECT_NAME}-${VERSION}/" HEAD > "${BUILD_DIR}/${PROJECT_NAME}-${VERSION}-source.tar.gz"

# Generate checksums file
echo -e "${YELLOW}Generating checksums...${NC}"
cd ${BUILD_DIR}
if command -v sha256sum &> /dev/null; then
    sha256sum *.tar.gz > checksums.txt
fi
cd ..

# Create release notes template
cat > "${BUILD_DIR}/RELEASE_NOTES.md" << EOF
# Release Notes - ${PROJECT_NAME} ${VERSION}

## Date: ${BUILD_DATE}

### Features
- Profile Management System
- Critical Process Protection
- Validation and Testing Framework
- Security Hardening (Audit Logging, Backup, Emergency Stop)

### Improvements
- Enhanced error handling
- Better cross-platform support
- Comprehensive documentation

### Installation

\`\`\`bash
# Download the appropriate binary for your platform
wget https://github.com/yourusername/process-throttler/releases/download/${VERSION}/${PROJECT_NAME}-${VERSION}-linux-amd64.tar.gz

# Extract the archive
tar -xzf ${PROJECT_NAME}-${VERSION}-linux-amd64.tar.gz

# Move to system path
sudo mv ${PROJECT_NAME}-${VERSION}-linux-amd64 /usr/local/bin/${PROJECT_NAME}

# Make executable
sudo chmod +x /usr/local/bin/${PROJECT_NAME}

# Verify installation
${PROJECT_NAME} --version
\`\`\`

### Checksums
See checksums.txt for SHA256 checksums of all release files.

EOF

echo ""
echo -e "${GREEN}Build complete!${NC}"
echo "Artifacts created in ${BUILD_DIR}/"
echo ""
echo "Files created:"
ls -lh ${BUILD_DIR}/*.tar.gz 2>/dev/null | awk '{print "  - " $9 " (" $5 ")"}'
echo ""
echo "To create a GitHub release:"
echo "  1. git tag -a v${VERSION} -m 'Release v${VERSION}'"
echo "  2. git push origin v${VERSION}"
echo "  3. Upload files from ${BUILD_DIR}/ to the release"
