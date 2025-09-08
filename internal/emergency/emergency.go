package emergency

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/yourusername/process-throttler/internal/audit"
	"github.com/yourusername/process-throttler/internal/backup"
	"github.com/yourusername/process-throttler/internal/cgroup"
	"github.com/yourusername/process-throttler/internal/protection"
	"github.com/yourusername/process-throttler/pkg/errors"
)

// StopManager handles emergency stop operations
type StopManager struct {
	mu            sync.RWMutex
	cgroupManager *cgroup.CgroupManager
	protectionMgr *protection.ProtectionManager
	backupMgr     *backup.BackupManager
	auditLogger   *audit.Logger
	
	stopFile      string
	isEmergency   bool
	stopReason    string
	stopTime      time.Time
	
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// StopState represents the state of an emergency stop
type StopState struct {
	Active    bool      `json:"active"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	PID       int       `json:"pid"`
}

// NewStopManager creates a new emergency stop manager
func NewStopManager(
	cgroupManager *cgroup.CgroupManager,
	protectionMgr *protection.ProtectionManager,
	backupMgr *backup.BackupManager,
	auditLogger *audit.Logger,
) *StopManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	sm := &StopManager{
		cgroupManager: cgroupManager,
		protectionMgr: protectionMgr,
		backupMgr:     backupMgr,
		auditLogger:   auditLogger,
		stopFile:      "/var/run/process-throttler.emergency",
		ctx:           ctx,
		cancel:        cancel,
	}
	
	// Start monitoring for emergency signals
	sm.wg.Add(1)
	go sm.monitorSignals()
	
	// Check for existing emergency stop file
	sm.checkExistingStop()
	
	return sm
}

// EmergencyStop performs an emergency stop of all throttling
func (sm *StopManager) EmergencyStop(reason string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	if sm.isEmergency {
		return errors.New(errors.ErrInvalidOperation, "emergency stop already active")
	}
	
	sm.isEmergency = true
	sm.stopReason = reason
	sm.stopTime = time.Now()
	
	// Log emergency stop
	if sm.auditLogger != nil {
		sm.auditLogger.LogEvent(
			audit.EventTypeEmergencyStop,
			audit.SeverityCritical,
			"Emergency stop initiated",
			"",
			map[string]interface{}{
				"reason": reason,
				"user":   getCurrentUser(),
				"pid":    os.Getpid(),
			},
		)
	}
	
	// Create emergency stop file
	if err := sm.createStopFile(reason); err != nil {
		return errors.Wrap(err, "failed to create stop file")
	}
	
	// Perform emergency actions
	var stopErrors []error
	
	// 1. Remove all throttling
	if err := sm.removeAllThrottling(); err != nil {
		stopErrors = append(stopErrors, fmt.Errorf("throttling removal: %v", err))
	}
	
	// 2. Stop protection monitoring
	if err := sm.stopProtection(); err != nil {
		stopErrors = append(stopErrors, fmt.Errorf("protection stop: %v", err))
	}
	
	// 3. Create emergency backup
	if err := sm.createEmergencyBackup(); err != nil {
		stopErrors = append(stopErrors, fmt.Errorf("backup creation: %v", err))
	}
	
	// Report any errors
	if len(stopErrors) > 0 {
		return errors.New(errors.ErrInvalidOperation, fmt.Sprintf("emergency stop completed with errors: %v", stopErrors))
	}
	
	fmt.Println("🛑 EMERGENCY STOP COMPLETED")
	fmt.Printf("Reason: %s\n", reason)
	fmt.Println("All throttling has been removed")
	fmt.Println("To resume normal operation, use: process-throttler emergency resume")
	
	return nil
}

// Resume resumes normal operation after emergency stop
func (sm *StopManager) Resume(force bool) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	if !sm.isEmergency && !sm.checkStopFile() {
		return errors.New(errors.ErrInvalidOperation, "no emergency stop active")
	}
	
	// Verify user wants to resume
	if !force {
		fmt.Print("Are you sure you want to resume normal operation? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			return errors.New(errors.ErrInvalidOperation, "resume cancelled by user")
		}
	}
	
	// Remove stop file
	if err := os.Remove(sm.stopFile); err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, "failed to remove stop file")
	}
	
	sm.isEmergency = false
	sm.stopReason = ""
	
	// Log resume
	if sm.auditLogger != nil {
		sm.auditLogger.LogEvent(
			audit.EventTypeSystemStart,
			audit.SeverityWarning,
			"System resumed after emergency stop",
			"",
			map[string]interface{}{
				"force":         force,
				"stop_duration": time.Since(sm.stopTime).String(),
			},
		)
	}
	
	fmt.Println("✅ Normal operation resumed")
	fmt.Println("You may need to reactivate profiles and reapply throttling rules")
	
	return nil
}

// GetStatus returns the current emergency stop status
func (sm *StopManager) GetStatus() *StopState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	if !sm.isEmergency && !sm.checkStopFile() {
		return &StopState{
			Active: false,
		}
	}
	
	return &StopState{
		Active:    true,
		Reason:    sm.stopReason,
		Timestamp: sm.stopTime,
		User:      getCurrentUser(),
		PID:       os.Getpid(),
	}
}

// IsEmergencyStopped checks if emergency stop is active
func (sm *StopManager) IsEmergencyStopped() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	return sm.isEmergency || sm.checkStopFile()
}

// monitorSignals monitors for emergency signals
func (sm *StopManager) monitorSignals() {
	defer sm.wg.Done()
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTERM)
	
	for {
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGUSR1:
				// Emergency stop signal
				sm.EmergencyStop("Signal SIGUSR1 received")
			case syscall.SIGUSR2:
				// Resume signal
				sm.Resume(true)
			case syscall.SIGTERM:
				// Graceful shutdown
				sm.shutdown()
				return
			}
		case <-sm.ctx.Done():
			return
		}
	}
}

// removeAllThrottling removes all active throttling
func (sm *StopManager) removeAllThrottling() error {
	if sm.cgroupManager == nil {
		return nil
	}
	
	// Get all cgroups
	groups, err := sm.cgroupManager.ListGroups()
	if err != nil {
		return errors.Wrap(err, "failed to list cgroups")
	}
	
	var removeErrors []error
	for _, group := range groups {
		// Skip system cgroups
		if isSystemCgroup(group) {
			continue
		}
		
		// Get processes in group
		pids, _ := sm.cgroupManager.GetProcesses(group)
		
		// Move processes back to root cgroup
		for _, pid := range pids {
			if err := sm.cgroupManager.MoveProcess(pid, ""); err != nil {
				removeErrors = append(removeErrors, fmt.Errorf("failed to move PID %d: %v", pid, err))
			}
		}
		
		// Delete the cgroup
		if err := sm.cgroupManager.DeleteGroup(group); err != nil {
			removeErrors = append(removeErrors, fmt.Errorf("failed to delete group %s: %v", group, err))
		}
	}
	
	if len(removeErrors) > 0 {
		return fmt.Errorf("failed to remove some throttling: %v", removeErrors)
	}
	
	return nil
}

// stopProtection stops all protection monitoring
func (sm *StopManager) stopProtection() error {
	if sm.protectionMgr == nil {
		return nil
	}
	
	sm.protectionMgr.Stop()
	return nil
}

// createEmergencyBackup creates an emergency backup
func (sm *StopManager) createEmergencyBackup() error {
	if sm.backupMgr == nil {
		return nil
	}
	
	_, err := sm.backupMgr.CreateBackup(fmt.Sprintf("Emergency backup: %s", sm.stopReason))
	return err
}

// createStopFile creates the emergency stop file
func (sm *StopManager) createStopFile(reason string) error {
	state := StopState{
		Active:    true,
		Reason:    reason,
		Timestamp: time.Now(),
		User:      getCurrentUser(),
		PID:       os.Getpid(),
	}
	
	data := fmt.Sprintf("%s|%d|%s|%s\n", 
		state.Timestamp.Format(time.RFC3339),
		state.PID,
		state.User,
		state.Reason,
	)
	
	return os.WriteFile(sm.stopFile, []byte(data), 0644)
}

// checkStopFile checks if stop file exists
func (sm *StopManager) checkStopFile() bool {
	_, err := os.Stat(sm.stopFile)
	return err == nil
}

// checkExistingStop checks for existing emergency stop
func (sm *StopManager) checkExistingStop() {
	if sm.checkStopFile() {
		data, err := os.ReadFile(sm.stopFile)
		if err == nil {
			// Parse stop file
			// Format: timestamp|pid|user|reason
			fmt.Println("⚠️  WARNING: Emergency stop file detected")
			fmt.Printf("Details: %s", string(data))
			fmt.Println("System is in emergency stop mode")
			
			sm.isEmergency = true
		}
	}
}

// shutdown performs graceful shutdown
func (sm *StopManager) shutdown() {
	sm.cancel()
	sm.wg.Wait()
	
	// Log shutdown
	if sm.auditLogger != nil {
		sm.auditLogger.LogEvent(
			audit.EventTypeSystemStop,
			audit.SeverityInfo,
			"System shutdown",
			"",
			nil,
		)
	}
}

// Close closes the stop manager
func (sm *StopManager) Close() error {
	sm.cancel()
	sm.wg.Wait()
	return nil
}

// SafetyCheck performs a safety check before operations
type SafetyCheck struct {
	manager *StopManager
}

// NewSafetyCheck creates a new safety check
func NewSafetyCheck(manager *StopManager) *SafetyCheck {
	return &SafetyCheck{
		manager: manager,
	}
}

// Check performs the safety check
func (sc *SafetyCheck) Check() error {
	if sc.manager.IsEmergencyStopped() {
		return errors.New(
			errors.ErrInvalidOperation,
			"operation blocked: system is in emergency stop mode",
		)
	}
	return nil
}

// PreOperationCheck checks before critical operations
func (sc *SafetyCheck) PreOperationCheck(operation string) error {
	if err := sc.Check(); err != nil {
		return err
	}
	
	// Log the operation attempt
	if sc.manager.auditLogger != nil {
		sc.manager.auditLogger.LogEvent(
			audit.EventTypeConfigChanged,
			audit.SeverityInfo,
			fmt.Sprintf("Pre-operation check: %s", operation),
			"",
			nil,
		)
	}
	
	return nil
}

// Helper functions

func getCurrentUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	return fmt.Sprintf("uid-%d", os.Getuid())
}

func isSystemCgroup(name string) bool {
	systemGroups := []string{
		"systemd",
		"user.slice",
		"system.slice",
		"init.scope",
	}
	
	for _, sg := range systemGroups {
		if name == sg || name == "/"+sg {
			return true
		}
	}
	
	return false
}
