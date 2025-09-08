package protection

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yourusername/process-throttler/internal/discovery"
	"github.com/yourusername/process-throttler/internal/profile"
	"github.com/yourusername/process-throttler/internal/types"
	"github.com/yourusername/process-throttler/pkg/errors"
)

// ProtectionManager manages critical process protection
type ProtectionManager struct {
	mu               sync.RWMutex
	discovery        *discovery.ProcessDiscoveryEngine
	protectedProcs   map[int32]*ProtectedProcess
	healthCheckers   map[int32]*HealthChecker
	restartAttempts  map[int32]int
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

// ProtectedProcess represents a process under protection
type ProtectedProcess struct {
	ProcessInfo     *types.ProcessInfo
	CriticalConfig  *profile.CriticalProcess
	LastHealthCheck time.Time
	HealthStatus    HealthStatus
	RestartCount    int
	ProtectedAt     time.Time
}

// HealthStatus represents the health status of a process
type HealthStatus struct {
	Healthy       bool
	LastError     error
	LastCheckTime time.Time
	FailureCount  int
}

// HealthChecker performs health checks on a process
type HealthChecker struct {
	process    *ProtectedProcess
	config     *profile.HealthCheck
	ctx        context.Context
	cancel     context.CancelFunc
	lastCheck  time.Time
	httpClient *http.Client
}

// NewProtectionManager creates a new protection manager
func NewProtectionManager(discovery *discovery.ProcessDiscoveryEngine) *ProtectionManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &ProtectionManager{
		discovery:       discovery,
		protectedProcs:  make(map[int32]*ProtectedProcess),
		healthCheckers:  make(map[int32]*HealthChecker),
		restartAttempts: make(map[int32]int),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// ProtectProcesses applies protection to critical processes based on the profile
func (pm *ProtectionManager) ProtectProcesses(criticalProcesses []profile.CriticalProcess) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	for _, cp := range criticalProcesses {
		// Find matching processes
		processes, err := pm.discovery.FindByPattern(cp.Pattern, "name")
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to find processes matching pattern '%s'", cp.Pattern))
		}
		
		for _, proc := range processes {
			if err := pm.protectProcess(proc, &cp); err != nil {
				// Log error but continue with other processes
				fmt.Printf("Warning: Failed to protect process %d (%s): %v\n", proc.PID, proc.Name, err)
				continue
			}
		}
	}
	
	return nil
}

// protectProcess applies protection to a single process
func (pm *ProtectionManager) protectProcess(proc *types.ProcessInfo, config *profile.CriticalProcess) error {
	// Apply OOM protection
	if err := pm.setOOMScore(proc.PID, config.OOMScoreAdj); err != nil {
		return errors.Wrap(err, "failed to set OOM score")
	}
	
	// Apply priority boost
	if err := pm.setPriority(proc.PID, config.Priority); err != nil {
		return errors.Wrap(err, "failed to set priority")
	}
	
	// Apply CPU affinity if needed
	if config.ResourceReserve.CPUPercent > 0 {
		if err := pm.reserveCPU(proc.PID, config.ResourceReserve.CPUPercent); err != nil {
			return errors.Wrap(err, "failed to reserve CPU")
		}
	}
	
	// Create protected process entry
	protected := &ProtectedProcess{
		ProcessInfo:    proc,
		CriticalConfig: config,
		ProtectedAt:    time.Now(),
		HealthStatus: HealthStatus{
			Healthy:       true,
			LastCheckTime: time.Now(),
		},
	}
	
	pm.protectedProcs[proc.PID] = protected
	
	// Start health monitoring if configured
	if config.HealthCheck.Type != "" {
		pm.startHealthMonitoring(protected)
	}
	
	return nil
}

// setOOMScore sets the OOM score adjustment for a process
func (pm *ProtectionManager) setOOMScore(pid int32, score int32) error {
	// Protect critical processes from OOM killer
	// -1000 = never kill, 0 = default, 1000 = kill first
	oomPath := fmt.Sprintf("/proc/%d/oom_score_adj", pid)
	
	// For maximum protection, use -1000
	if score < -1000 {
		score = -1000
	} else if score > 1000 {
		score = 1000
	}
	
	data := []byte(fmt.Sprintf("%d", score))
	if err := os.WriteFile(oomPath, data, 0644); err != nil {
		if os.IsNotExist(err) {
			return errors.New(errors.ErrProcessNotFound, fmt.Sprintf("process %d not found", pid))
		}
		return err
	}
	
	return nil
}

// setPriority sets the scheduling priority for a process
func (pm *ProtectionManager) setPriority(pid int32, priority int32) error {
	// Set nice value (priority)
	// -20 = highest priority, 19 = lowest priority
	if priority < -20 {
		priority = -20
	} else if priority > 19 {
		priority = 19
	}
	
	if err := syscall.Setpriority(syscall.PRIO_PROCESS, int(pid), int(priority)); err != nil {
		return err
	}
	
	return nil
}

// reserveCPU reserves CPU resources for a process
func (pm *ProtectionManager) reserveCPU(pid int32, cpuPercent float64) error {
	// This is a simplified implementation
	// In production, you would use CPU affinity and cgroup CPU reservation
	
	// Get number of CPUs
	numCPUs := getCPUCount()
	
	// Calculate number of CPUs to reserve
	reservedCPUs := int(float64(numCPUs) * (cpuPercent / 100.0))
	if reservedCPUs < 1 {
		reservedCPUs = 1
	}
	
	// Set CPU affinity (simplified - just use first N CPUs)
	// In production, you'd want more sophisticated CPU selection
	mask := 0
	for i := 0; i < reservedCPUs && i < numCPUs; i++ {
		mask |= (1 << i)
	}
	
	// Note: This would require platform-specific implementation
	// Here's a placeholder that would need actual syscall implementation
	return nil
}

// startHealthMonitoring starts health monitoring for a protected process
func (pm *ProtectionManager) startHealthMonitoring(protected *ProtectedProcess) {
	if protected.CriticalConfig.HealthCheck.Type == "" {
		return
	}
	
	ctx, cancel := context.WithCancel(pm.ctx)
	
	checker := &HealthChecker{
		process: protected,
		config:  &protected.CriticalConfig.HealthCheck,
		ctx:     ctx,
		cancel:  cancel,
		httpClient: &http.Client{
			Timeout: protected.CriticalConfig.HealthCheck.Timeout,
		},
	}
	
	pm.healthCheckers[protected.ProcessInfo.PID] = checker
	
	pm.wg.Add(1)
	go pm.runHealthCheck(checker)
}

// runHealthCheck runs periodic health checks for a process
func (pm *ProtectionManager) runHealthCheck(checker *HealthChecker) {
	defer pm.wg.Done()
	
	ticker := time.NewTicker(checker.config.Interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-checker.ctx.Done():
			return
		case <-ticker.C:
			pm.performHealthCheck(checker)
		}
	}
}

// performHealthCheck performs a single health check
func (pm *ProtectionManager) performHealthCheck(checker *HealthChecker) {
	var err error
	
	switch checker.config.Type {
	case "port":
		err = pm.checkPort(checker.config.Target)
	case "http":
		err = pm.checkHTTP(checker.config.Target, checker.httpClient)
	case "command":
		err = pm.checkCommand(checker.config.Target)
	case "file":
		err = pm.checkFile(checker.config.Target)
	default:
		err = fmt.Errorf("unknown health check type: %s", checker.config.Type)
	}
	
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	checker.lastCheck = time.Now()
	
	if err != nil {
		checker.process.HealthStatus.Healthy = false
		checker.process.HealthStatus.LastError = err
		checker.process.HealthStatus.FailureCount++
		
		// Check if we need to restart the process
		if checker.process.HealthStatus.FailureCount >= checker.config.Retries {
			pm.handleUnhealthyProcess(checker.process)
		}
	} else {
		checker.process.HealthStatus.Healthy = true
		checker.process.HealthStatus.LastError = nil
		checker.process.HealthStatus.FailureCount = 0
	}
	
	checker.process.HealthStatus.LastCheckTime = time.Now()
}

// checkPort checks if a port is open
func (pm *ProtectionManager) checkPort(target string) error {
	// Parse port(s) from target
	ports := strings.Split(target, ",")
	
	for _, portStr := range ports {
		portStr = strings.TrimSpace(portStr)
		if strings.Contains(portStr, ":") {
			// Format is "host:port"
			conn, err := net.DialTimeout("tcp", portStr, 5*time.Second)
			if err != nil {
				return fmt.Errorf("port %s is not accessible: %v", portStr, err)
			}
			conn.Close()
		} else {
			// Just port number, check on localhost
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%s", portStr), 5*time.Second)
			if err != nil {
				return fmt.Errorf("port %s is not accessible: %v", portStr, err)
			}
			conn.Close()
		}
	}
	
	return nil
}

// checkHTTP performs an HTTP health check
func (pm *ProtectionManager) checkHTTP(target string, client *http.Client) error {
	resp, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("HTTP check failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP check returned status %d", resp.StatusCode)
	}
	
	return nil
}

// checkCommand runs a command and checks its exit status
func (pm *ProtectionManager) checkCommand(target string) error {
	parts := strings.Fields(target)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}
	
	cmd := exec.Command(parts[0], parts[1:]...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command check failed: %v", err)
	}
	
	return nil
}

// checkFile checks if a file exists
func (pm *ProtectionManager) checkFile(target string) error {
	if _, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", target)
		}
		return fmt.Errorf("failed to check file %s: %v", target, err)
	}
	
	return nil
}

// handleUnhealthyProcess handles an unhealthy process based on restart policy
func (pm *ProtectionManager) handleUnhealthyProcess(protected *ProtectedProcess) {
	switch protected.CriticalConfig.RestartPolicy {
	case "always":
		pm.restartProcess(protected)
	case "on-failure":
		// Check if process is actually dead
		if !pm.isProcessRunning(protected.ProcessInfo.PID) {
			pm.restartProcess(protected)
		}
	case "never":
		// Just log the issue
		fmt.Printf("Critical process %d (%s) is unhealthy but restart policy is 'never'\n",
			protected.ProcessInfo.PID, protected.ProcessInfo.Name)
	}
}

// isProcessRunning checks if a process is still running
func (pm *ProtectionManager) isProcessRunning(pid int32) bool {
	process, err := pm.discovery.GetProcessInfo(pid)
	return err == nil && process != nil
}

// restartProcess attempts to restart a process
func (pm *ProtectionManager) restartProcess(protected *ProtectedProcess) error {
	pid := protected.ProcessInfo.PID
	
	// Track restart attempts
	pm.restartAttempts[pid]++
	
	// Check if we've exceeded max restart attempts
	maxAttempts := 5
	if pm.restartAttempts[pid] > maxAttempts {
		return errors.New(errors.ErrMaxRetriesExceeded, 
			fmt.Sprintf("exceeded maximum restart attempts for process %d", pid))
	}
	
	fmt.Printf("Attempting to restart critical process %d (%s), attempt %d/%d\n",
		pid, protected.ProcessInfo.Name, pm.restartAttempts[pid], maxAttempts)
	
	// Get the command line to restart the process
	cmdLine := protected.ProcessInfo.CommandLine
	if cmdLine == "" {
		return errors.New(errors.ErrInvalidInput, "cannot restart process: command line is empty")
	}
	
	// Parse command line
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return errors.New(errors.ErrInvalidInput, "cannot restart process: invalid command line")
	}
	
	// Start the process
	cmd := exec.Command(parts[0], parts[1:]...)
	
	// Set working directory if available
	if protected.ProcessInfo.Executable != "" {
		cmd.Dir = getProcessWorkingDir(protected.ProcessInfo.PID)
	}
	
	// Start the process
	if err := cmd.Start(); err != nil {
		return errors.Wrap(err, "failed to restart process")
	}
	
	// Update process info with new PID
	protected.ProcessInfo.PID = int32(cmd.Process.Pid)
	protected.RestartCount++
	
	// Re-apply protection to the new process
	if err := pm.protectProcess(protected.ProcessInfo, protected.CriticalConfig); err != nil {
		return errors.Wrap(err, "failed to re-apply protection to restarted process")
	}
	
	// Reset restart attempts on successful restart
	delete(pm.restartAttempts, pid)
	pm.restartAttempts[int32(cmd.Process.Pid)] = 0
	
	fmt.Printf("Successfully restarted critical process with new PID %d\n", cmd.Process.Pid)
	
	return nil
}

// MonitorCriticalProcesses monitors all critical processes
func (pm *ProtectionManager) MonitorCriticalProcesses() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.checkCriticalProcesses()
		}
	}
}

// checkCriticalProcesses checks the status of all critical processes
func (pm *ProtectionManager) checkCriticalProcesses() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	for pid, protected := range pm.protectedProcs {
		// Check if process is still running
		if !pm.isProcessRunning(pid) {
			fmt.Printf("Critical process %d (%s) is no longer running\n", pid, protected.ProcessInfo.Name)
			
			// Handle based on restart policy
			pm.handleUnhealthyProcess(protected)
		}
	}
}

// GetProtectedProcesses returns all protected processes
func (pm *ProtectionManager) GetProtectedProcesses() map[int32]*ProtectedProcess {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	processes := make(map[int32]*ProtectedProcess)
	for k, v := range pm.protectedProcs {
		processes[k] = v
	}
	
	return processes
}

// Stop stops the protection manager
func (pm *ProtectionManager) Stop() {
	pm.cancel()
	pm.wg.Wait()
	
	// Stop all health checkers
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	for _, checker := range pm.healthCheckers {
		checker.cancel()
	}
}

// Helper functions

func getCPUCount() int {
	// Read from /proc/cpuinfo or use runtime.NumCPU()
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 1
	}
	
	count := 0
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "processor") {
			count++
		}
	}
	
	if count == 0 {
		count = 1
	}
	
	return count
}

func getProcessWorkingDir(pid int32) string {
	cwdPath := fmt.Sprintf("/proc/%d/cwd", pid)
	if target, err := os.Readlink(cwdPath); err == nil {
		return target
	}
	return ""
}

// ProtectionLevel constants
const (
	ProtectionLevelMaximum = "maximum"
	ProtectionLevelHigh    = "high"
	ProtectionLevelMedium  = "medium"
	ProtectionLevelLow     = "low"
)

// GetOOMScoreForProtectionLevel returns the OOM score adjustment for a protection level
func GetOOMScoreForProtectionLevel(level string) int32 {
	switch level {
	case ProtectionLevelMaximum:
		return -1000 // Never kill
	case ProtectionLevelHigh:
		return -800
	case ProtectionLevelMedium:
		return -500
	case ProtectionLevelLow:
		return -200
	default:
		return 0
	}
}

// GetPriorityForProtectionLevel returns the process priority for a protection level
func GetPriorityForProtectionLevel(level string) int32 {
	switch level {
	case ProtectionLevelMaximum:
		return -20 // Highest priority
	case ProtectionLevelHigh:
		return -15
	case ProtectionLevelMedium:
		return -10
	case ProtectionLevelLow:
		return -5
	default:
		return 0
	}
}
