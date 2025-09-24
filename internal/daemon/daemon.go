package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yourusername/process-throttler/internal/audit"
	"github.com/yourusername/process-throttler/internal/metrics"
	"github.com/yourusername/process-throttler/internal/protection"
	"github.com/yourusername/process-throttler/internal/throttle"
	"github.com/yourusername/process-throttler/pkg/errors"
)

// Manager manages the daemon process
type Manager struct {
	mu              sync.RWMutex
	pidFile         string
	statusFile      string
	isRunning       bool
	startTime       time.Time
	
	// Components that require daemon
	protectionMgr   *protection.ProtectionManager
	dynamicThrottler *throttle.DynamicThrottler
	metricsCollector *metrics.Collector
	auditLogger     *audit.Logger
	
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// Status represents the daemon status
type Status struct {
	Running         bool      `json:"running"`
	PID             int       `json:"pid"`
	StartTime       time.Time `json:"start_time"`
	Uptime          string    `json:"uptime"`
	Version         string    `json:"version"`
	Features        []string  `json:"features"`
	LastHealthCheck time.Time `json:"last_health_check"`
}

// NewManager creates a new daemon manager
func NewManager() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	
	pidFile := "/var/run/process-throttler.pid"
	statusFile := "/var/run/process-throttler.status"
	
	// Use user directory if system directory is not writable
	if err := os.MkdirAll("/var/run", 0755); err != nil {
		if homeDir, err := os.UserHomeDir(); err == nil {
			runDir := filepath.Join(homeDir, ".local", "run")
			os.MkdirAll(runDir, 0755)
			pidFile = filepath.Join(runDir, "process-throttler.pid")
			statusFile = filepath.Join(runDir, "process-throttler.status")
		}
	}
	
	return &Manager{
		pidFile:    pidFile,
		statusFile: statusFile,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the daemon
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Check if already running
	if m.isRunning {
		return errors.New(errors.ErrInvalidOperation, "daemon is already running")
	}
	
	// Check for existing daemon
	if pid := m.checkExistingDaemon(); pid > 0 {
		return errors.New(errors.ErrAlreadyExists, fmt.Sprintf("daemon already running with PID %d", pid))
	}
	
	// Write PID file
	if err := m.writePIDFile(); err != nil {
		return errors.Wrap(err, "failed to write PID file")
	}
	
	m.isRunning = true
	m.startTime = time.Now()
	
	// Start monitoring goroutines
	m.wg.Add(2)
	go m.healthMonitor()
	go m.signalHandler()
	
	// Log daemon start
	if m.auditLogger != nil {
		m.auditLogger.LogEvent(
			audit.EventTypeSystemStart,
			audit.SeverityInfo,
			"Daemon started",
			"",
			map[string]interface{}{
				"pid":     os.Getpid(),
				"version": m.getVersion(),
			},
		)
	}
	
	fmt.Printf("✅ Daemon started with PID %d\n", os.Getpid())
	fmt.Println("Features enabled:")
	for _, feature := range m.getEnabledFeatures() {
		fmt.Printf("  - %s\n", feature)
	}
	
	return nil
}

// Stop stops the daemon
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.isRunning {
		return errors.New(errors.ErrInvalidOperation, "daemon is not running")
	}
	
	// Cancel context to stop all goroutines
	m.cancel()
	
	// Wait for goroutines to finish
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// Clean shutdown
	case <-time.After(10 * time.Second):
		fmt.Println("Warning: Timeout waiting for daemon to stop")
	}
	
	// Remove PID file
	os.Remove(m.pidFile)
	os.Remove(m.statusFile)
	
	m.isRunning = false
	
	// Log daemon stop
	if m.auditLogger != nil {
		m.auditLogger.LogEvent(
			audit.EventTypeSystemStop,
			audit.SeverityInfo,
			"Daemon stopped",
			"",
			map[string]interface{}{
				"uptime": time.Since(m.startTime).String(),
			},
		)
	}
	
	fmt.Println("✅ Daemon stopped")
	
	return nil
}

// GetStatus returns the daemon status
func (m *Manager) GetStatus() (*Status, error) {
	// Check if daemon is running
	pid := m.checkExistingDaemon()
	if pid == 0 {
		return &Status{
			Running: false,
		}, nil
	}
	
	// Read status file if it exists
	if data, err := os.ReadFile(m.statusFile); err == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) >= 2 {
			startTimeStr := lines[1]
			if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
				return &Status{
					Running:   true,
					PID:       pid,
					StartTime: startTime,
					Uptime:    time.Since(startTime).Round(time.Second).String(),
					Version:   m.getVersion(),
					Features:  m.getEnabledFeatures(),
				}, nil
			}
		}
	}
	
	return &Status{
		Running: true,
		PID:     pid,
		Version: m.getVersion(),
		Features: m.getEnabledFeatures(),
	}, nil
}

// RequiresDaemon checks if a feature requires the daemon
func RequiresDaemon(feature string) bool {
	daemonFeatures := map[string]bool{
		"critical-process-monitoring": true,
		"health-checks":               true,
		"dynamic-throttling":          true,
		"metrics-export":              true,
		"scheduled-profiles":          true,
		"auto-restart":                true,
		"continuous-monitoring":       true,
	}
	
	return daemonFeatures[feature]
}

// CheckDaemonRequired returns an error if daemon is required but not running
func (m *Manager) CheckDaemonRequired(feature string) error {
	if !RequiresDaemon(feature) {
		return nil
	}
	
	status, _ := m.GetStatus()
	if !status.Running {
		return errors.New(
			errors.ErrInvalidOperation,
			fmt.Sprintf(
				"This feature (%s) requires the process-throttler daemon to be running.\n"+
				"Start it with: process-throttler daemon start\n"+
				"Or enable it as a service: systemctl enable --now process-throttler",
				feature,
			),
		)
	}
	
	return nil
}

// healthMonitor monitors daemon health
func (m *Manager) healthMonitor() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.updateStatus()
		}
	}
}

// signalHandler handles system signals
func (m *Manager) signalHandler() {
	defer m.wg.Done()
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				fmt.Println("\nReceived shutdown signal")
				m.Stop()
				return
			case syscall.SIGHUP:
				fmt.Println("Received reload signal")
				// TODO: Implement configuration reload
			}
		}
	}
}

// writePIDFile writes the PID file
func (m *Manager) writePIDFile() error {
	pid := os.Getpid()
	data := fmt.Sprintf("%d\n", pid)
	
	if err := os.WriteFile(m.pidFile, []byte(data), 0644); err != nil {
		return err
	}
	
	// Also write status file
	statusData := fmt.Sprintf("%d\n%s\n", pid, time.Now().Format(time.RFC3339))
	return os.WriteFile(m.statusFile, []byte(statusData), 0644)
}

// checkExistingDaemon checks if a daemon is already running
func (m *Manager) checkExistingDaemon() int {
	data, err := os.ReadFile(m.pidFile)
	if err != nil {
		return 0
	}
	
	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0
	}
	
	// Check if process is still running
	if err := syscall.Kill(pid, 0); err != nil {
		// Process doesn't exist, clean up stale PID file
		os.Remove(m.pidFile)
		os.Remove(m.statusFile)
		return 0
	}
	
	return pid
}

// updateStatus updates the status file
func (m *Manager) updateStatus() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if !m.isRunning {
		return
	}
	
	statusData := fmt.Sprintf("%d\n%s\n%s\n",
		os.Getpid(),
		m.startTime.Format(time.RFC3339),
		time.Now().Format(time.RFC3339),
	)
	
	os.WriteFile(m.statusFile, []byte(statusData), 0644)
}

// getVersion returns the daemon version
func (m *Manager) getVersion() string {
	// This would ideally be set during build
	return "1.0.0"
}

// getEnabledFeatures returns the list of enabled features
func (m *Manager) getEnabledFeatures() []string {
	features := []string{}
	
	if m.protectionMgr != nil {
		features = append(features, "critical-process-protection")
		features = append(features, "health-monitoring")
		features = append(features, "auto-restart")
	}
	
	if m.dynamicThrottler != nil {
		features = append(features, "dynamic-throttling")
		features = append(features, "adaptive-limits")
	}
	
	if m.metricsCollector != nil {
		features = append(features, "prometheus-metrics")
	}
	
	if m.auditLogger != nil {
		features = append(features, "audit-logging")
	}
	
	return features
}

// SetComponents sets the daemon components
func (m *Manager) SetComponents(
	protectionMgr *protection.ProtectionManager,
	dynamicThrottler *throttle.DynamicThrottler,
	metricsCollector *metrics.Collector,
	auditLogger *audit.Logger,
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.protectionMgr = protectionMgr
	m.dynamicThrottler = dynamicThrottler
	m.metricsCollector = metricsCollector
	m.auditLogger = auditLogger
}
