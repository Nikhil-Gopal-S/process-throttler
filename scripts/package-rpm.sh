#!/bin/bash

# Create RPM package for process-throttler

set -e

PROJECT_NAME="process-throttler"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
RELEASE="1"
ARCH="x86_64"

echo "Creating RPM package: ${PROJECT_NAME}-${VERSION}-${RELEASE}.${ARCH}.rpm"

# Create RPM build directory structure
RPM_BUILD_ROOT="${HOME}/rpmbuild"
mkdir -p ${RPM_BUILD_ROOT}/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball
echo "Creating source tarball..."
git archive --format=tar.gz --prefix="${PROJECT_NAME}-${VERSION}/" HEAD > ${RPM_BUILD_ROOT}/SOURCES/${PROJECT_NAME}-${VERSION}.tar.gz

# Create spec file
cat > ${RPM_BUILD_ROOT}/SPECS/${PROJECT_NAME}.spec << EOF
Name:           ${PROJECT_NAME}
Version:        ${VERSION}
Release:        ${RELEASE}%{?dist}
Summary:        Universal process management and resource throttling tool

License:        MIT
URL:            https://github.com/yourusername/process-throttler
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.21
Requires:       systemd

%description
Process Throttler is a production-ready tool for Linux/Unix servers
that provides intelligent process monitoring, critical process protection,
and configurable resource throttling using cgroups.

Features:
- Process discovery and monitoring
- Resource throttling (CPU, memory, I/O)
- Critical process protection
- Profile management
- Audit logging and backup
- Emergency stop mechanism

%prep
%setup -q

%build
go build -ldflags "-X main.Version=%{version}" -o %{name} ./cmd/process-throttler

%install
rm -rf \$RPM_BUILD_ROOT

# Install binary
mkdir -p \$RPM_BUILD_ROOT%{_bindir}
install -m 755 %{name} \$RPM_BUILD_ROOT%{_bindir}/%{name}

# Install config files
mkdir -p \$RPM_BUILD_ROOT%{_sysconfdir}/%{name}
install -m 644 configs/example.yaml \$RPM_BUILD_ROOT%{_sysconfdir}/%{name}/config.yaml.example
install -m 644 configs/production-profile.yaml \$RPM_BUILD_ROOT%{_sysconfdir}/%{name}/

# Install systemd service
mkdir -p \$RPM_BUILD_ROOT%{_unitdir}
cat > \$RPM_BUILD_ROOT%{_unitdir}/%{name}.service << 'EEOF'
[Unit]
Description=Process Throttler Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=%{_bindir}/%{name} daemon
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EEOF

# Install documentation
mkdir -p \$RPM_BUILD_ROOT%{_docdir}/%{name}
install -m 644 README.md \$RPM_BUILD_ROOT%{_docdir}/%{name}/
install -m 644 LICENSE \$RPM_BUILD_ROOT%{_docdir}/%{name}/ 2>/dev/null || :

%files
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/config.yaml.example
%config(noreplace) %{_sysconfdir}/%{name}/production-profile.yaml
%doc %{_docdir}/%{name}/README.md
%license %{_docdir}/%{name}/LICENSE

%post
# Create necessary directories
mkdir -p /var/log/process-throttler/audit
mkdir -p /var/run/process-throttler
mkdir -p /etc/process-throttler/profiles

# Set permissions
chmod 750 /var/log/process-throttler
chmod 755 /etc/process-throttler

# Reload systemd
systemctl daemon-reload

%preun
# Stop service if running
if [ \$1 -eq 0 ]; then
    systemctl stop %{name} >/dev/null 2>&1 || :
fi

%postun
if [ \$1 -eq 0 ]; then
    systemctl daemon-reload
fi

%changelog
* $(date +"%a %b %d %Y") Your Name <your.email@example.com> - ${VERSION}-${RELEASE}
- Initial package release
EOF

# Build the RPM
echo "Building RPM package..."
rpmbuild -ba ${RPM_BUILD_ROOT}/SPECS/${PROJECT_NAME}.spec

# Copy to dist directory
mkdir -p dist
cp ${RPM_BUILD_ROOT}/RPMS/${ARCH}/${PROJECT_NAME}-${VERSION}-${RELEASE}.${ARCH}.rpm dist/ 2>/dev/null || \
cp ${RPM_BUILD_ROOT}/RPMS/${ARCH}/${PROJECT_NAME}-${VERSION}-${RELEASE}.*.${ARCH}.rpm dist/

echo "RPM package created: dist/${PROJECT_NAME}-${VERSION}-${RELEASE}.${ARCH}.rpm"
echo ""
echo "To install:"
echo "  sudo rpm -ivh dist/${PROJECT_NAME}-${VERSION}-${RELEASE}.${ARCH}.rpm"
echo "  # or"
echo "  sudo yum install dist/${PROJECT_NAME}-${VERSION}-${RELEASE}.${ARCH}.rpm"
echo ""
echo "To remove:"
echo "  sudo rpm -e ${PROJECT_NAME}"
