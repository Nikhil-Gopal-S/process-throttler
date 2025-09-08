# Process Throttler

A universal, production-ready process management and resource throttling tool for Linux/Unix servers with intelligent process monitoring, critical process protection, and configurable resource throttling.

## Features

### Phase 1 (Complete) ✅
- **Process Discovery**: Find processes by name, command line, PID, or user
- **Resource Throttling**: Limit CPU, memory, and process count using cgroups
- **Configuration Management**: YAML-based configuration with rule definitions
- **Safety Features**: Dry-run mode and safety checks to prevent system issues
- **Cross-Platform**: Supports both cgroup v1 and v2

### Phase 2 (Complete) ✅
- **Profile Management System**: Create, manage, and activate configuration profiles
- **Critical Process Protection**: OOM protection, priority boosting, health monitoring
- **Validation Framework**: Comprehensive validation and dry-run simulation
- **Advanced Health Checks**: Port, HTTP, command, and file-based health monitoring

## Quick Start

### Installation

```bash
# Build from source
make build

# Install to system (requires sudo)
make install

# Or run directly
./build/process-throttler --help
```

### Basic Usage

#### Process Discovery
```bash
# Find all processes
./process-throttler list

# Discover processes by pattern
./process-throttler discover "nginx.*"

# Find processes by user
./process-throttler discover --match-type user www-data
```

#### Profile Management
```bash
# Import a profile
./process-throttler profile import configs/production-profile.yaml

# List all profiles
./process-throttler profile list

# Show profile details
./process-throttler profile show production-web

# Activate a profile
sudo ./process-throttler profile activate production-web

# Clone a profile
./process-throttler profile clone production-web staging-web

# Export profile
./process-throttler profile export production-web my-profile.yaml
```

#### Validation and Testing
```bash
# Validate system compatibility
./process-throttler validate system

# Validate a profile
./process-throttler validate profile production-web

# Dry-run simulation (see what would happen)
./process-throttler validate dry-run production-web

# Validate configuration file
./process-throttler validate config configs/example.yaml
```

#### Resource Throttling
```bash
# Throttle a process by pattern
sudo ./process-throttler throttle --pattern "backup.*" --cpu 30% --memory 1GB

# Throttle specific PID
sudo ./process-throttler throttle --pid 1234 --cpu 50% --memory 512MB

# Check throttling status
./process-throttler status
```

### Configuration Examples

#### Production Profile (configs/production-profile.yaml)
```yaml
name: production-web
version: "1.0"
description: Production web server configuration

critical_processes:
  - pattern: "nginx.*"
    protection_level: "maximum"
    restart_policy: "always"
    oom_score_adj: -1000
    health_check:
      type: "port"
      target: "80,443"
      interval: 30s

throttling_rules:
  - name: "limit-backup"
    matcher:
      pattern: "backup.*"
      match_type: "name"
    limits:
      cpu_quota: 30000    # 30% CPU
      cpu_period: 100000
      memory_limit: 1073741824  # 1GB
    enabled: true
```

## Phase 2 Implementation Status

### ✅ Completed Features

1. **Profile Management System**
   - Create, list, show, edit, delete profiles
   - Clone profiles for different environments
   - Import/export profiles (YAML/JSON)
   - Profile activation and scheduling
   - Profile validation and diff comparison

2. **Critical Process Protection**
   - OOM killer protection (adjustable scores)
   - Process priority boosting
   - Resource reservation for critical processes
   - Automatic restart on failure
   - Health monitoring with multiple check types
   - Dependency chain protection

3. **Validation & Testing Framework**
   - System compatibility checks
   - Configuration validation
   - Resource limit sanity checks
   - Conflict detection
   - Dry-run mode with detailed simulation
   - Performance impact assessment

### Phase 3 (Complete) ✅
- **Security Hardening**: Comprehensive audit logging with rotation
- **Configuration Backup**: Automatic and manual backup/restore
- **Emergency Stop**: Immediate throttling removal for critical situations
- **Package Distribution**: Multi-platform builds (DEB, RPM, Docker)
- **Installation Scripts**: Automated installation and setup

## Installation

### Quick Install (Linux)
```bash
curl -sSL https://raw.githubusercontent.com/yourusername/process-throttler/main/install.sh | bash -s -- --quick
```

### Manual Installation
```bash
# Download the latest release
wget https://github.com/yourusername/process-throttler/releases/latest/download/process-throttler-linux-amd64.tar.gz

# Extract and install
tar -xzf process-throttler-linux-amd64.tar.gz
sudo mv process-throttler /usr/local/bin/
sudo chmod +x /usr/local/bin/process-throttler

# Setup configuration
sudo mkdir -p /etc/process-throttler
sudo cp configs/*.yaml /etc/process-throttler/
```

### Docker Installation
```bash
# Using Docker Compose
docker-compose up -d

# Or using Docker directly
docker build -t process-throttler .
docker run --privileged --pid=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw process-throttler
```

### Package Managers
```bash
# Debian/Ubuntu
sudo dpkg -i process-throttler_1.0.0_amd64.deb

# RHEL/CentOS/Fedora
sudo rpm -ivh process-throttler-1.0.0-1.x86_64.rpm
```

## Security Features

### Audit Logging
```bash
# Search audit logs
./process-throttler audit search --hours 24 --type THROTTLE_APPLIED

# View audit statistics
./process-throttler audit stats
```

### Configuration Backup
```bash
# Create backup
./process-throttler backup create "Before major changes"

# List backups
./process-throttler backup list

# Restore backup
./process-throttler backup restore <backup-id>
```

### Emergency Stop
```bash
# Initiate emergency stop (removes all throttling)
./process-throttler emergency stop "System overload"

# Check status
./process-throttler emergency status

# Resume normal operation
./process-throttler emergency resume
```

## Development Roadmap

### Phase 4: Advanced Features (Next)
- [ ] Dynamic throttling algorithms
- [ ] Gradual enforcement
- [ ] Time-based rules
- [ ] External system integration (Prometheus, webhooks)
- [ ] Web-based management interface

## Requirements

- Linux operating system (primary support)
- Go 1.21 or higher (for building)
- Root/sudo privileges (for cgroup operations)
- Cgroups v1 or v2 support

## License

MIT License - See LICENSE file for details
