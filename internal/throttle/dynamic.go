package throttle

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/yourusername/process-throttler/internal/audit"
	"github.com/yourusername/process-throttler/internal/cgroup"
	"github.com/yourusername/process-throttler/internal/discovery"
	"github.com/yourusername/process-throttler/internal/types"
	"github.com/yourusername/process-throttler/pkg/errors"
)

// DynamicThrottler implements advanced throttling algorithms
type DynamicThrottler struct {
	mu              sync.RWMutex
	cgroupManager   *cgroup.CgroupManager
	discovery       *discovery.ProcessDiscoveryEngine
	auditLogger     *audit.Logger
	
	activeThrottles map[int32]*ActiveThrottle
	systemMetrics   *SystemMetrics
	policies        map[string]*ThrottlePolicy
	
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// ActiveThrottle represents an active throttling session
type ActiveThrottle struct {
	ProcessID       int32
	ProcessName     string
	Policy          *ThrottlePolicy
	CurrentLimits   types.ResourceLimits
	TargetLimits    types.ResourceLimits
	StartTime       time.Time
	LastAdjustment  time.Time
	AdjustmentCount int
	Metrics         ProcessMetrics
}

// ThrottlePolicy defines how throttling should be applied
type ThrottlePolicy struct {
	Name             string
	Description      string
	Algorithm        string // "gradual", "adaptive", "predictive"
	EnforcementMode  string // "soft", "hard", "elastic"
	
	// Gradual enforcement settings
	RampUpDuration   time.Duration
	RampDownDuration time.Duration
	StepSize         float64 // Percentage change per step
	StepInterval     time.Duration
	
	// Adaptive settings
	TargetCPUUsage   float64
	TargetMemUsage   float64
	AdaptInterval    time.Duration
	Aggressiveness   float64 // 0.0 to 1.0
	
	// Time-based rules
	TimeRules        []TimeRule
	
	// Thresholds
	MinCPULimit      float64
	MaxCPULimit      float64
	MinMemLimit      int64
	MaxMemLimit      int64
}

// TimeRule defines time-based throttling rules
type TimeRule struct {
	StartTime    string // "09:00"
	EndTime      string // "17:00"
	Days         []string // ["Mon", "Tue", "Wed", "Thu", "Fri"]
	Limits       types.ResourceLimits
	Description  string
}

// SystemMetrics tracks system-wide metrics
type SystemMetrics struct {
	CPUUsage        float64
	MemoryUsage     float64
	LoadAverage     []float64
	IOWait          float64
	LastUpdate      time.Time
}

// ProcessMetrics tracks per-process metrics
type ProcessMetrics struct {
	CPUHistory      []float64
	MemoryHistory   []uint64
	ResponseTime    time.Duration
	ThrottleImpact  float64 // 0.0 to 1.0
}

// NewDynamicThrottler creates a new dynamic throttler
func NewDynamicThrottler(
	cgroupManager *cgroup.CgroupManager,
	discovery *discovery.ProcessDiscoveryEngine,
	auditLogger *audit.Logger,
) *DynamicThrottler {
	ctx, cancel := context.WithCancel(context.Background())
	
	dt := &DynamicThrottler{
		cgroupManager:   cgroupManager,
		discovery:       discovery,
		auditLogger:     auditLogger,
		activeThrottles: make(map[int32]*ActiveThrottle),
		policies:        make(map[string]*ThrottlePolicy),
		systemMetrics:   &SystemMetrics{},
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// Initialize default policies
	dt.initializeDefaultPolicies()
	
	// Start monitoring goroutines
	dt.wg.Add(2)
	go dt.systemMetricsMonitor()
	go dt.throttleAdjuster()
	
	return dt
}

// ApplyDynamicThrottle applies throttling with a specific policy
func (dt *DynamicThrottler) ApplyDynamicThrottle(
	processID int32,
	policyName string,
	targetLimits types.ResourceLimits,
) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	
	// Get policy
	policy, exists := dt.policies[policyName]
	if !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("policy '%s' not found", policyName))
	}
	
	// Get process info
	procInfo, err := dt.discovery.GetProcessInfo(processID)
	if err != nil {
		return errors.Wrap(err, "failed to get process info")
	}
	
	// Create throttle session
	throttle := &ActiveThrottle{
		ProcessID:     processID,
		ProcessName:   procInfo.Name,
		Policy:        policy,
		TargetLimits:  targetLimits,
		StartTime:     time.Now(),
		CurrentLimits: dt.calculateInitialLimits(policy, targetLimits),
		Metrics:       ProcessMetrics{},
	}
	
	// Apply initial limits
	groupName := fmt.Sprintf("dynamic_%d", processID)
	if err := dt.applyLimits(processID, groupName, throttle.CurrentLimits); err != nil {
		return errors.Wrap(err, "failed to apply initial limits")
	}
	
	dt.activeThrottles[processID] = throttle
	
	// Log event
	if dt.auditLogger != nil {
		dt.auditLogger.LogEvent(
			audit.EventTypeThrottleApplied,
			audit.SeverityInfo,
			fmt.Sprintf("Dynamic throttle applied with policy '%s'", policyName),
			fmt.Sprintf("PID %d (%s)", processID, procInfo.Name),
			map[string]interface{}{
				"policy":         policyName,
				"algorithm":      policy.Algorithm,
				"target_cpu":     targetLimits.CPUQuota,
				"target_memory":  targetLimits.MemoryLimit,
			},
		)
	}
	
	return nil
}

// calculateInitialLimits calculates starting limits based on policy
func (dt *DynamicThrottler) calculateInitialLimits(
	policy *ThrottlePolicy,
	targetLimits types.ResourceLimits,
) types.ResourceLimits {
	switch policy.Algorithm {
	case "gradual":
		// Start with no throttling for gradual enforcement
		return types.ResourceLimits{
			CPUQuota:    100000, // 100%
			CPUPeriod:   100000,
			MemoryLimit: 0, // No limit initially
		}
		
	case "adaptive":
		// Start with moderate limits for adaptive
		return types.ResourceLimits{
			CPUQuota:    (targetLimits.CPUQuota + 100000) / 2,
			CPUPeriod:   targetLimits.CPUPeriod,
			MemoryLimit: targetLimits.MemoryLimit,
		}
		
	default:
		// Direct application
		return targetLimits
	}
}

// applyLimits applies resource limits to a process
func (dt *DynamicThrottler) applyLimits(
	processID int32,
	groupName string,
	limits types.ResourceLimits,
) error {
	// Create cgroup if needed
	if !dt.cgroupManager.GroupExists(groupName) {
		if err := dt.cgroupManager.CreateGroup(groupName); err != nil {
			return errors.Wrap(err, "failed to create cgroup")
		}
	}
	
	// Apply CPU limits
	if limits.CPUQuota > 0 && limits.CPUPeriod > 0 {
		if err := dt.cgroupManager.SetCPULimit(groupName, limits.CPUQuota, limits.CPUPeriod); err != nil {
			return errors.Wrap(err, "failed to set CPU limit")
		}
	}
	
	// Apply memory limits
	if limits.MemoryLimit > 0 {
		if err := dt.cgroupManager.SetMemoryLimit(groupName, limits.MemoryLimit); err != nil {
			return errors.Wrap(err, "failed to set memory limit")
		}
	}
	
	// Move process to cgroup
	if err := dt.cgroupManager.MoveProcess(processID, groupName); err != nil {
		return errors.Wrap(err, "failed to move process to cgroup")
	}
	
	return nil
}

// systemMetricsMonitor monitors system-wide metrics
func (dt *DynamicThrottler) systemMetricsMonitor() {
	defer dt.wg.Done()
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-dt.ctx.Done():
			return
		case <-ticker.C:
			dt.updateSystemMetrics()
		}
	}
}

// updateSystemMetrics updates system metrics
func (dt *DynamicThrottler) updateSystemMetrics() {
	// This is a simplified version - in production, you'd use proper system metrics
	dt.mu.Lock()
	defer dt.mu.Unlock()
	
	// Update metrics (placeholder implementation)
	dt.systemMetrics.LastUpdate = time.Now()
	// In real implementation, read from /proc/stat, /proc/meminfo, etc.
}

// throttleAdjuster periodically adjusts active throttles
func (dt *DynamicThrottler) throttleAdjuster() {
	defer dt.wg.Done()
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-dt.ctx.Done():
			return
		case <-ticker.C:
			dt.adjustActiveThrottles()
		}
	}
}

// adjustActiveThrottles adjusts all active throttles based on their policies
func (dt *DynamicThrottler) adjustActiveThrottles() {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	
	for pid, throttle := range dt.activeThrottles {
		// Check if process still exists
		if _, err := dt.discovery.GetProcessInfo(pid); err != nil {
			delete(dt.activeThrottles, pid)
			continue
		}
		
		// Check time-based rules
		if newLimits := dt.checkTimeRules(throttle); newLimits != nil {
			throttle.TargetLimits = *newLimits
		}
		
		// Adjust based on algorithm
		switch throttle.Policy.Algorithm {
		case "gradual":
			dt.adjustGradual(throttle)
		case "adaptive":
			dt.adjustAdaptive(throttle)
		case "predictive":
			dt.adjustPredictive(throttle)
		}
	}
}

// adjustGradual implements gradual throttling adjustment
func (dt *DynamicThrottler) adjustGradual(throttle *ActiveThrottle) {
	// Check if it's time to adjust
	if time.Since(throttle.LastAdjustment) < throttle.Policy.StepInterval {
		return
	}
	
	// Calculate progress
	elapsed := time.Since(throttle.StartTime)
	progress := float64(elapsed) / float64(throttle.Policy.RampUpDuration)
	if progress > 1.0 {
		progress = 1.0
	}
	
	// Calculate new limits using easing function
	newCPUQuota := dt.easeInOut(
		100000, // Start at 100%
		float64(throttle.TargetLimits.CPUQuota),
		progress,
	)
	
	// Apply new limits if changed significantly
	if math.Abs(newCPUQuota-float64(throttle.CurrentLimits.CPUQuota)) > 1000 {
		throttle.CurrentLimits.CPUQuota = int64(newCPUQuota)
		
		groupName := fmt.Sprintf("dynamic_%d", throttle.ProcessID)
		if err := dt.applyLimits(throttle.ProcessID, groupName, throttle.CurrentLimits); err != nil {
			fmt.Printf("Failed to adjust limits for PID %d: %v\n", throttle.ProcessID, err)
		} else {
			throttle.LastAdjustment = time.Now()
			throttle.AdjustmentCount++
		}
	}
}

// adjustAdaptive implements adaptive throttling based on system load
func (dt *DynamicThrottler) adjustAdaptive(throttle *ActiveThrottle) {
	// Check if it's time to adapt
	if time.Since(throttle.LastAdjustment) < throttle.Policy.AdaptInterval {
		return
	}
	
	// Get process metrics
	procInfo, err := dt.discovery.GetProcessInfo(throttle.ProcessID)
	if err != nil {
		return
	}
	
	// Update metrics history
	throttle.Metrics.CPUHistory = append(throttle.Metrics.CPUHistory, procInfo.CPUPercent)
	if len(throttle.Metrics.CPUHistory) > 10 {
		throttle.Metrics.CPUHistory = throttle.Metrics.CPUHistory[1:]
	}
	
	// Calculate average CPU usage
	avgCPU := dt.calculateAverage(throttle.Metrics.CPUHistory)
	
	// Adjust limits based on target vs actual
	adjustment := (throttle.Policy.TargetCPUUsage - avgCPU) * throttle.Policy.Aggressiveness
	
	newCPUQuota := float64(throttle.CurrentLimits.CPUQuota) + (adjustment * 1000)
	
	// Apply bounds
	if newCPUQuota < throttle.Policy.MinCPULimit*1000 {
		newCPUQuota = throttle.Policy.MinCPULimit * 1000
	} else if newCPUQuota > throttle.Policy.MaxCPULimit*1000 {
		newCPUQuota = throttle.Policy.MaxCPULimit * 1000
	}
	
	// Apply if changed significantly
	if math.Abs(newCPUQuota-float64(throttle.CurrentLimits.CPUQuota)) > 1000 {
		throttle.CurrentLimits.CPUQuota = int64(newCPUQuota)
		
		groupName := fmt.Sprintf("dynamic_%d", throttle.ProcessID)
		if err := dt.applyLimits(throttle.ProcessID, groupName, throttle.CurrentLimits); err != nil {
			fmt.Printf("Failed to adapt limits for PID %d: %v\n", throttle.ProcessID, err)
		} else {
			throttle.LastAdjustment = time.Now()
			throttle.AdjustmentCount++
			
			// Log significant adjustments
			if dt.auditLogger != nil && throttle.AdjustmentCount%10 == 0 {
				dt.auditLogger.LogEvent(
					audit.EventTypeThrottleApplied,
					audit.SeverityInfo,
					"Adaptive throttle adjusted",
					fmt.Sprintf("PID %d", throttle.ProcessID),
					map[string]interface{}{
						"cpu_quota":     newCPUQuota,
						"avg_cpu_usage": avgCPU,
						"adjustments":   throttle.AdjustmentCount,
					},
				)
			}
		}
	}
}

// adjustPredictive implements predictive throttling (placeholder)
func (dt *DynamicThrottler) adjustPredictive(throttle *ActiveThrottle) {
	// TODO: Implement predictive algorithm using historical data
	// For now, fall back to adaptive
	dt.adjustAdaptive(throttle)
}

// checkTimeRules checks if time-based rules should apply
func (dt *DynamicThrottler) checkTimeRules(throttle *ActiveThrottle) *types.ResourceLimits {
	now := time.Now()
	currentDay := now.Format("Mon")
	currentTime := now.Format("15:04")
	
	for _, rule := range throttle.Policy.TimeRules {
		// Check if day matches
		dayMatch := false
		for _, day := range rule.Days {
			if day == currentDay {
				dayMatch = true
				break
			}
		}
		
		if !dayMatch {
			continue
		}
		
		// Check if time matches
		if currentTime >= rule.StartTime && currentTime <= rule.EndTime {
			return &rule.Limits
		}
	}
	
	return nil
}

// Helper functions

// easeInOut provides smooth transitions
func (dt *DynamicThrottler) easeInOut(start, end, progress float64) float64 {
	if progress < 0.5 {
		return start + (end-start)*2*progress*progress
	}
	progress = progress*2 - 1
	return start + (end-start)*(1-progress*progress)/2
}

// calculateAverage calculates the average of a slice
func (dt *DynamicThrottler) calculateAverage(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	
	return sum / float64(len(values))
}

// GetActiveThrottles returns all active throttles
func (dt *DynamicThrottler) GetActiveThrottles() map[int32]*ActiveThrottle {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	
	throttles := make(map[int32]*ActiveThrottle)
	for k, v := range dt.activeThrottles {
		throttles[k] = v
	}
	
	return throttles
}

// RemoveThrottle removes a dynamic throttle
func (dt *DynamicThrottler) RemoveThrottle(processID int32) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	
	throttle, exists := dt.activeThrottles[processID]
	if !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("no active throttle for PID %d", processID))
	}
	
	// Remove from cgroup
	groupName := fmt.Sprintf("dynamic_%d", processID)
	if err := dt.cgroupManager.MoveProcess(processID, ""); err != nil {
		return errors.Wrap(err, "failed to remove process from cgroup")
	}
	
	// Delete cgroup
	if err := dt.cgroupManager.DeleteGroup(groupName); err != nil {
		// Log but don't fail
		fmt.Printf("Warning: failed to delete cgroup %s: %v\n", groupName, err)
	}
	
	delete(dt.activeThrottles, processID)
	
	// Log event
	if dt.auditLogger != nil {
		dt.auditLogger.LogEvent(
			audit.EventTypeThrottleRemoved,
			audit.SeverityInfo,
			"Dynamic throttle removed",
			fmt.Sprintf("PID %d (%s)", processID, throttle.ProcessName),
			map[string]interface{}{
				"duration":    time.Since(throttle.StartTime).String(),
				"adjustments": throttle.AdjustmentCount,
			},
		)
	}
	
	return nil
}

// AddPolicy adds a custom throttle policy
func (dt *DynamicThrottler) AddPolicy(name string, policy *ThrottlePolicy) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	
	if _, exists := dt.policies[name]; exists {
		return errors.New(errors.ErrAlreadyExists, fmt.Sprintf("policy '%s' already exists", name))
	}
	
	policy.Name = name
	dt.policies[name] = policy
	
	return nil
}

// initializeDefaultPolicies sets up default throttling policies
func (dt *DynamicThrottler) initializeDefaultPolicies() {
	// Gradual enforcement policy
	dt.policies["gradual"] = &ThrottlePolicy{
		Name:             "gradual",
		Description:      "Gradually apply throttling over time",
		Algorithm:        "gradual",
		EnforcementMode:  "soft",
		RampUpDuration:   5 * time.Minute,
		RampDownDuration: 1 * time.Minute,
		StepSize:         5.0,
		StepInterval:     10 * time.Second,
		MinCPULimit:      10.0,
		MaxCPULimit:      100.0,
	}
	
	// Adaptive policy
	dt.policies["adaptive"] = &ThrottlePolicy{
		Name:            "adaptive",
		Description:     "Adapt throttling based on actual usage",
		Algorithm:       "adaptive",
		EnforcementMode: "elastic",
		TargetCPUUsage:  50.0,
		TargetMemUsage:  70.0,
		AdaptInterval:   30 * time.Second,
		Aggressiveness:  0.5,
		MinCPULimit:     20.0,
		MaxCPULimit:     90.0,
	}
	
	// Business hours policy
	dt.policies["business-hours"] = &ThrottlePolicy{
		Name:            "business-hours",
		Description:     "Different limits for business hours",
		Algorithm:       "adaptive",
		EnforcementMode: "hard",
		TimeRules: []TimeRule{
			{
				StartTime:   "09:00",
				EndTime:     "17:00",
				Days:        []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
				Description: "Business hours - strict limits",
				Limits: types.ResourceLimits{
					CPUQuota:    30000,
					CPUPeriod:   100000,
					MemoryLimit: 1073741824, // 1GB
				},
			},
			{
				StartTime:   "17:01",
				EndTime:     "08:59",
				Days:        []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
				Description: "After hours - relaxed limits",
				Limits: types.ResourceLimits{
					CPUQuota:    80000,
					CPUPeriod:   100000,
					MemoryLimit: 4294967296, // 4GB
				},
			},
		},
		AdaptInterval:  1 * time.Minute,
		Aggressiveness: 0.3,
		MinCPULimit:    10.0,
		MaxCPULimit:    100.0,
	}
}

// Stop stops the dynamic throttler
func (dt *DynamicThrottler) Stop() {
	dt.cancel()
	dt.wg.Wait()
	
	// Remove all active throttles
	dt.mu.Lock()
	defer dt.mu.Unlock()
	
	for pid := range dt.activeThrottles {
		dt.RemoveThrottle(pid)
	}
}
