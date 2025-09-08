# Multi-stage build for process-throttler
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN go build -ldflags="-w -s" -o process-throttler ./cmd/process-throttler

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libcap \
    bash

# Create necessary directories
RUN mkdir -p /etc/process-throttler/profiles \
    /var/log/process-throttler/audit \
    /var/run/process-throttler \
    /data/backups

# Copy binary from builder
COPY --from=builder /build/process-throttler /usr/local/bin/

# Copy configuration files
COPY configs/example.yaml /etc/process-throttler/config.yaml
COPY configs/production-profile.yaml /etc/process-throttler/profiles/

# Set permissions
RUN chmod +x /usr/local/bin/process-throttler && \
    chmod 750 /var/log/process-throttler && \
    chmod 755 /etc/process-throttler

# Environment variables
ENV PROCESS_THROTTLER_CONFIG=/etc/process-throttler/config.yaml \
    PROCESS_THROTTLER_PROFILES=/etc/process-throttler/profiles \
    PROCESS_THROTTLER_LOGS=/var/log/process-throttler

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD process-throttler validate system || exit 1

# Volume mounts for persistent data
VOLUME ["/etc/process-throttler", "/var/log/process-throttler", "/data/backups"]

# Default command
ENTRYPOINT ["process-throttler"]
CMD ["--help"]
