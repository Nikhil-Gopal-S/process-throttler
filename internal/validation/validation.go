package validation

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/yourusername/process-throttler/internal/cgroup"
	"github.com/yourusername/process-throttler/internal/discovery"
	"github.com/yourusername/process-throttler/internal/profile"
	"github.com/yourusername/process-throttler/internal/types"
	"github.com/yourusername/process-throttler/pkg/errors"
)

// Validator performs validation checks on configurations and system state
type Validator struct {
	discovery     *discovery.ProcessDiscoveryEngine
	cgroupManager *cgroup.CgroupManager
}

// ValidationResult represents the result of a validation check
type ValidationResult struct {
	Valid    bool
	Errors   []ValidationError
	Warnings []ValidationWarning
	Info     map[string]interface{}
}

// ValidationError represents a validation error
type ValidationError struct {
	Type    string
	Message string
	Context map[string]interface{}
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Type    string
	Message string
	Context map[string]interface{}
}

// NewValidator creates a new validator
func NewValidator(discovery *discovery.ProcessDiscoveryEngine, cgroupManager *cgroup.CgroupManager) *Validator {
	return &Validator{
		discovery:     discovery,
		cgroupManager: cgroupManager,
	}
}

// ValidateProfile validates a profile configuration
func (v *Validator) ValidateProfile(p *profile.Profile) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Info:     make(map[string]interface{}),
	}

	// Check system compatibility
	v.checkSystemCompatibility(result)

	// Validate critical processes
	v.validateCriticalProcesses(p.CriticalProcesses, result)

	// Validate throttling rules
	v.validateThrottlingRules(p.ThrottlingRules, result)

	// Check for conflicts
	v.checkForConflicts(p, result)

	// Validate resource limits
	v.validateResourceLimits(p, result)

	// Set overall validity
	result.Valid = len(result.Errors) == 0

	return result
}

// checkSystemCompatibility checks if the system is compatible
func (v *Validator) checkSystemCompatibility(result *ValidationResult) {
	// Check OS
	if runtime.GOOS != "linux" {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "SYSTEM_INCOMPATIBLE",
			Message: fmt.Sprintf("This tool requires Linux, current OS: %s", runtime.GOOS),
		})
		return
	}

	// Check cgroups availability
	if v.cgroupManager == nil {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:    "CGROUP_UNAVAILABLE",
			Message: "Cgroup manager is not initialized, throttling features may not work",
		})
		return
	}

	// Check cgroup version
	cgroupVersion := v.detectCgroupVersion()
	result.Info["cgroup_version"] = cgroupVersion

	if cgroupVersion == 0 {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "CGROUP_NOT_FOUND",
			Message: "Cgroups are not available on this system",
		})
	}

	// Check permissions
	if !v.hasRequiredPermissions() {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:    "INSUFFICIENT_PERMISSIONS",
			Message: "Running without root privileges, some features may not work",
		})
	}

	// Check kernel version
	kernelVersion := v.getKernelVersion()
	result.Info["kernel_version"] = kernelVersion

	// Check available resources
	v.checkSystemResources(result)
}

// validateCriticalProcesses validates critical process configurations
func (v *Validator) validateCriticalProcesses(processes []profile.CriticalProcess, result *ValidationResult) {
	for i, cp := range processes {
		// Check if pattern is valid regex
		if cp.Pattern == "" {
			result.Errors = append(result.Errors, ValidationError{
				Type:    "INVALID_PATTERN",
				Message: fmt.Sprintf("Critical process %d: empty pattern", i),
				Context: map[string]interface{}{"index": i},
			})
			continue
		}

		// Check if any processes match the pattern
		matches, err := v.discovery.FindByPattern(cp.Pattern, "name")
		if err != nil {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Type:    "PATTERN_CHECK_FAILED",
				Message: fmt.Sprintf("Critical process %d: failed to check pattern '%s': %v", i, cp.Pattern, err),
				Context: map[string]interface{}{"index": i, "pattern": cp.Pattern},
			})
		} else if len(matches) == 0 {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Type:    "NO_MATCHING_PROCESSES",
				Message: fmt.Sprintf("Critical process %d: no processes match pattern '%s'", i, cp.Pattern),
				Context: map[string]interface{}{"index": i, "pattern": cp.Pattern},
			})
		}

		// Validate OOM score
		if cp.OOMScoreAdj < -1000 || cp.OOMScoreAdj > 1000 {
			result.Errors = append(result.Errors, ValidationError{
				Type:    "INVALID_OOM_SCORE",
				Message: fmt.Sprintf("Critical process %d: OOM score adjustment must be between -1000 and 1000", i),
				Context: map[string]interface{}{"index": i, "oom_score": cp.OOMScoreAdj},
			})
		}

		// Validate priority
		if cp.Priority < -20 || cp.Priority > 19 {
			result.Errors = append(result.Errors, ValidationError{
				Type:    "INVALID_PRIORITY",
				Message: fmt.Sprintf("Critical process %d: priority must be between -20 and 19", i),
				Context: map[string]interface{}{"index": i, "priority": cp.Priority},
			})
		}

		// Validate health check
		if cp.HealthCheck.Type != "" {
			v.validateHealthCheck(&cp.HealthCheck, i, result)
		}

		// Validate resource reserve
		if cp.ResourceReserve.CPUPercent > 100 {
			result.Errors = append(result.Errors, ValidationError{
				Type:    "INVALID_CPU_RESERVE",
				Message: fmt.Sprintf("Critical process %d: CPU reserve cannot exceed 100%%", i),
				Context: map[string]interface{}{"index": i, "cpu_percent": cp.ResourceReserve.CPUPercent},
			})
		}
	}
}

// validateHealthCheck validates health check configuration
func (v *Validator) validateHealthCheck(hc *profile.HealthCheck, processIndex int, result *ValidationResult) {
	validTypes := map[string]bool{"port": true, "http": true, "command": true, "file": true}
	if !validTypes[hc.Type] {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "INVALID_HEALTH_CHECK_TYPE",
			Message: fmt.Sprintf("Critical process %d: invalid health check type '%s'", processIndex, hc.Type),
			Context: map[string]interface{}{"index": processIndex, "type": hc.Type},
		})
	}

	if hc.Target == "" {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "MISSING_HEALTH_CHECK_TARGET",
			Message: fmt.Sprintf("Critical process %d: health check target is required", processIndex),
			Context: map[string]interface{}{"index": processIndex},
		})
	}

	if hc.Interval <= 0 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:    "INVALID_HEALTH_CHECK_INTERVAL",
			Message: fmt.Sprintf("Critical process %d: health check interval should be positive", processIndex),
			Context: map[string]interface{}{"index": processIndex, "interval": hc.Interval},
		})
	}

	if hc.Retries < 0 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:    "INVALID_HEALTH_CHECK_RETRIES",
			Message: fmt.Sprintf("Critical process %d: health check retries should be non-negative", processIndex),
			Context: map[string]interface{}{"index": processIndex, "retries": hc.Retries},
		})
	}
}

// validateThrottlingRules validates throttling rules
func (v *Validator) validateThrottlingRules(rules []types.ThrottleRule, result *ValidationResult) {
	for i, rule := range rules {
		if rule.Name == "" {
			result.Errors = append(result.Errors, ValidationError{
				Type:    "MISSING_RULE_NAME",
				Message: fmt.Sprintf("Throttling rule %d: name is required", i),
				Context: map[string]interface{}{"index": i},
			})
		}

		if rule.Matcher.Pattern == "" {
			result.Errors = append(result.Errors, ValidationError{
				Type:    "MISSING_RULE_PATTERN",
				Message: fmt.Sprintf("Throttling rule %d: pattern is required", i),
				Context: map[string]interface{}{"index": i, "name": rule.Name},
			})
		}

		// Validate match type
		validMatchTypes := map[string]bool{"name": true, "cmdline": true, "pid": true, "user": true}
		if !validMatchTypes[rule.Matcher.MatchType] {
			result.Errors = append(result.Errors, ValidationError{
				Type:    "INVALID_MATCH_TYPE",
				Message: fmt.Sprintf("Throttling rule %d: invalid match type '%s'", i, rule.Matcher.MatchType),
				Context: map[string]interface{}{"index": i, "name": rule.Name, "match_type": rule.Matcher.MatchType},
			})
		}

		// Validate resource limits
		v.validateResourceLimit(&rule.Limits, i, rule.Name, result)
	}
}

// validateResourceLimit validates resource limits
func (v *Validator) validateResourceLimit(limits *types.ResourceLimits, ruleIndex int, ruleName string, result *ValidationResult) {
	// Validate CPU limits
	if limits.CPUQuota < 0 {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "INVALID_CPU_QUOTA",
			Message: fmt.Sprintf("Rule %d (%s): CPU quota cannot be negative", ruleIndex, ruleName),
			Context: map[string]interface{}{"index": ruleIndex, "name": ruleName, "cpu_quota": limits.CPUQuota},
		})
	}

	if limits.CPUPeriod < 0 {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "INVALID_CPU_PERIOD",
			Message: fmt.Sprintf("Rule %d (%s): CPU period cannot be negative", ruleIndex, ruleName),
			Context: map[string]interface{}{"index": ruleIndex, "name": ruleName, "cpu_period": limits.CPUPeriod},
		})
	}

	if limits.CPUQuota > 0 && limits.CPUPeriod > 0 {
		cpuPercent := float64(limits.CPUQuota) / float64(limits.CPUPeriod) * 100
		if cpuPercent > 100 {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Type:    "CPU_LIMIT_EXCEEDS_100",
				Message: fmt.Sprintf("Rule %d (%s): CPU limit exceeds 100%% (%.1f%%)", ruleIndex, ruleName, cpuPercent),
				Context: map[string]interface{}{"index": ruleIndex, "name": ruleName, "cpu_percent": cpuPercent},
			})
		}
	}

	// Validate memory limits
	if limits.MemoryLimit < 0 {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "INVALID_MEMORY_LIMIT",
			Message: fmt.Sprintf("Rule %d (%s): memory limit cannot be negative", ruleIndex, ruleName),
			Context: map[string]interface{}{"index": ruleIndex, "name": ruleName, "memory_limit": limits.MemoryLimit},
		})
	}

	// Validate PIDs limit
	if limits.PidsLimit < 0 {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "INVALID_PIDS_LIMIT",
			Message: fmt.Sprintf("Rule %d (%s): PIDs limit cannot be negative", ruleIndex, ruleName),
			Context: map[string]interface{}{"index": ruleIndex, "name": ruleName, "pids_limit": limits.PidsLimit},
		})
	}
}

// checkForConflicts checks for conflicts in the configuration
func (v *Validator) checkForConflicts(p *profile.Profile, result *ValidationResult) {
	// Check for overlapping patterns in critical processes
	for i := 0; i < len(p.CriticalProcesses); i++ {
		for j := i + 1; j < len(p.CriticalProcesses); j++ {
			if p.CriticalProcesses[i].Pattern == p.CriticalProcesses[j].Pattern {
				result.Warnings = append(result.Warnings, ValidationWarning{
					Type:    "DUPLICATE_CRITICAL_PATTERN",
					Message: fmt.Sprintf("Duplicate pattern '%s' in critical processes %d and %d", p.CriticalProcesses[i].Pattern, i, j),
					Context: map[string]interface{}{"pattern": p.CriticalProcesses[i].Pattern, "indices": []int{i, j}},
				})
			}
		}
	}

	// Check for overlapping patterns in throttling rules
	for i := 0; i < len(p.ThrottlingRules); i++ {
		for j := i + 1; j < len(p.ThrottlingRules); j++ {
			if p.ThrottlingRules[i].Matcher.Pattern == p.ThrottlingRules[j].Matcher.Pattern &&
				p.ThrottlingRules[i].Matcher.MatchType == p.ThrottlingRules[j].Matcher.MatchType {
				result.Warnings = append(result.Warnings, ValidationWarning{
					Type:    "DUPLICATE_THROTTLE_PATTERN",
					Message: fmt.Sprintf("Duplicate pattern '%s' in throttling rules '%s' and '%s'",
						p.ThrottlingRules[i].Matcher.Pattern,
						p.ThrottlingRules[i].Name,
						p.ThrottlingRules[j].Name),
					Context: map[string]interface{}{
						"pattern": p.ThrottlingRules[i].Matcher.Pattern,
						"rules":   []string{p.ThrottlingRules[i].Name, p.ThrottlingRules[j].Name},
					},
				})
			}
		}
	}

	// Check for conflicts between critical processes and throttling rules
	for _, cp := range p.CriticalProcesses {
		for _, rule := range p.ThrottlingRules {
			if cp.Pattern == rule.Matcher.Pattern && rule.Enabled {
				result.Warnings = append(result.Warnings, ValidationWarning{
					Type:    "CRITICAL_THROTTLE_CONFLICT",
					Message: fmt.Sprintf("Pattern '%s' is both critical and throttled", cp.Pattern),
					Context: map[string]interface{}{
						"pattern":       cp.Pattern,
						"throttle_rule": rule.Name,
					},
				})
			}
		}
	}
}

// validateResourceLimits validates that resource limits don't exceed system capacity
func (v *Validator) validateResourceLimits(p *profile.Profile, result *ValidationResult) {
	// Get system resources
	totalMemory := v.getTotalMemory()
	totalCPUs := runtime.NumCPU()

	result.Info["total_memory"] = totalMemory
	result.Info["total_cpus"] = totalCPUs

	// Calculate total reserved resources
	var totalCPUReserve float64
	var totalMemoryReserve int64

	for _, cp := range p.CriticalProcesses {
		totalCPUReserve += cp.ResourceReserve.CPUPercent
		totalMemoryReserve += cp.ResourceReserve.MemoryMB * 1024 * 1024
	}

	// Check if CPU reservation exceeds capacity
	if totalCPUReserve > 100 {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "CPU_OVERCOMMIT",
			Message: fmt.Sprintf("Total CPU reservation (%.1f%%) exceeds 100%%", totalCPUReserve),
			Context: map[string]interface{}{"total_cpu_reserve": totalCPUReserve},
		})
	}

	// Check if memory reservation exceeds capacity
	if totalMemoryReserve > totalMemory {
		result.Errors = append(result.Errors, ValidationError{
			Type:    "MEMORY_OVERCOMMIT",
			Message: fmt.Sprintf("Total memory reservation exceeds system memory"),
			Context: map[string]interface{}{
				"total_memory_reserve": totalMemoryReserve,
				"system_memory":        totalMemory,
			},
		})
	}

	// Calculate total throttle limits
	var totalThrottleMemory int64
	for _, rule := range p.ThrottlingRules {
		if rule.Enabled && rule.Limits.MemoryLimit > 0 {
			totalThrottleMemory += rule.Limits.MemoryLimit
		}
	}

	// Warning if total limits approach system capacity
	if totalThrottleMemory+totalMemoryReserve > totalMemory*90/100 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:    "HIGH_MEMORY_COMMIT",
			Message: "Total memory limits and reservations exceed 90% of system memory",
			Context: map[string]interface{}{
				"total_commit":  totalThrottleMemory + totalMemoryReserve,
				"system_memory": totalMemory,
			},
		})
	}
}

// Helper methods

func (v *Validator) detectCgroupVersion() int {
	// Check for cgroup v2
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return 2
	}

	// Check for cgroup v1
	if _, err := os.Stat("/sys/fs/cgroup/memory"); err == nil {
		return 1
	}

	return 0
}

func (v *Validator) hasRequiredPermissions() bool {
	return os.Geteuid() == 0
}

func (v *Validator) getKernelVersion() string {
	// For now, return a placeholder on non-Linux systems
	// On Linux, we could read from /proc/version
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/version")
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 3 {
				return fields[2]
			}
		}
	}
	return runtime.GOOS + "-" + runtime.GOARCH
}

func (v *Validator) getTotalMemory() int64 {
	// Read from /proc/meminfo
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var memKB int64
				fmt.Sscanf(fields[1], "%d", &memKB)
				return memKB * 1024
			}
		}
	}

	return 0
}

func (v *Validator) checkSystemResources(result *ValidationResult) {
	// Get system load
	loadAvg := v.getLoadAverage()
	result.Info["load_average"] = loadAvg

	// Get available memory
	availMemory := v.getAvailableMemory()
	result.Info["available_memory"] = availMemory

	// Warning if system is under high load
	numCPUs := runtime.NumCPU()
	if len(loadAvg) > 0 && loadAvg[0] > float64(numCPUs)*0.8 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:    "HIGH_SYSTEM_LOAD",
			Message: fmt.Sprintf("System is under high load (%.2f with %d CPUs)", loadAvg[0], numCPUs),
			Context: map[string]interface{}{"load": loadAvg[0], "cpus": numCPUs},
		})
	}

	// Warning if available memory is low
	totalMemory := v.getTotalMemory()
	if availMemory > 0 && totalMemory > 0 {
		memUsagePercent := float64(totalMemory-availMemory) / float64(totalMemory) * 100
		if memUsagePercent > 90 {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Type:    "LOW_AVAILABLE_MEMORY",
				Message: fmt.Sprintf("Available memory is low (%.1f%% used)", memUsagePercent),
				Context: map[string]interface{}{
					"available_memory": availMemory,
					"total_memory":     totalMemory,
					"usage_percent":    memUsagePercent,
				},
			})
		}
	}
}

func (v *Validator) getLoadAverage() []float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return []float64{}
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return []float64{}
	}

	loads := make([]float64, 3)
	for i := 0; i < 3; i++ {
		fmt.Sscanf(fields[i], "%f", &loads[i])
	}

	return loads
}

func (v *Validator) getAvailableMemory() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var memKB int64
				fmt.Sscanf(fields[1], "%d", &memKB)
				return memKB * 1024
			}
		}
	}

	return 0
}

// ValidateConfiguration validates a configuration
func (v *Validator) ValidateConfiguration(config *types.Configuration) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Info:     make(map[string]interface{}),
	}

	// Check system compatibility
	v.checkSystemCompatibility(result)

	// Validate throttling rules
	v.validateThrottlingRules(config.Rules, result)

	// Validate default limits
	v.validateResourceLimit(&config.DefaultLimits, -1, "default", result)

	// Validate settings
	if config.Settings.UpdateInterval <= 0 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:    "INVALID_UPDATE_INTERVAL",
			Message: "Update interval should be positive",
			Context: map[string]interface{}{"interval": config.Settings.UpdateInterval},
		})
	}

	// Set overall validity
	result.Valid = len(result.Errors) == 0

	return result
}

// DryRunResult represents the result of a dry-run operation
type DryRunResult struct {
	Operations []DryRunOperation
	Errors     []error
	Warnings   []string
}

// DryRunOperation represents a single operation in dry-run mode
type DryRunOperation struct {
	Type        string // "throttle", "protect", "create_cgroup", etc.
	Target      string // Process name or PID
	Action      string // Description of what would be done
	Parameters  map[string]interface{}
	WouldSucceed bool
	Reason      string // Reason for failure if WouldSucceed is false
}

// SimulateProfileActivation simulates activating a profile
func (v *Validator) SimulateProfileActivation(p *profile.Profile) *DryRunResult {
	result := &DryRunResult{
		Operations: []DryRunOperation{},
		Errors:     []error{},
		Warnings:   []string{},
	}

	// Simulate critical process protection
	for _, cp := range p.CriticalProcesses {
		processes, err := v.discovery.FindByPattern(cp.Pattern, "name")
		if err != nil {
			result.Errors = append(result.Errors, errors.Wrap(err, fmt.Sprintf("failed to find processes for pattern '%s'", cp.Pattern)))
			continue
		}

		for _, proc := range processes {
			op := DryRunOperation{
				Type:   "protect",
				Target: fmt.Sprintf("%s (PID: %d)", proc.Name, proc.PID),
				Action: fmt.Sprintf("Apply protection level '%s', OOM score %d, priority %d",
					cp.ProtectionLevel, cp.OOMScoreAdj, cp.Priority),
				Parameters: map[string]interface{}{
					"protection_level": cp.ProtectionLevel,
					"oom_score_adj":    cp.OOMScoreAdj,
					"priority":         cp.Priority,
				},
				WouldSucceed: true,
			}

			// Check if we have permission to protect this process
			if !v.hasRequiredPermissions() {
				op.WouldSucceed = false
				op.Reason = "Insufficient permissions (requires root)"
			}

			result.Operations = append(result.Operations, op)
		}
	}

	// Simulate throttling rules
	for _, rule := range p.ThrottlingRules {
		if !rule.Enabled {
			continue
		}

		processes, err := v.discovery.FindByPattern(rule.Matcher.Pattern, rule.Matcher.MatchType)
		if err != nil {
			result.Errors = append(result.Errors, errors.Wrap(err, fmt.Sprintf("failed to find processes for rule '%s'", rule.Name)))
			continue
		}

		for _, proc := range processes {
			// Create cgroup operation
			cgroupName := fmt.Sprintf("throttle_%s_%d", rule.Name, proc.PID)
			createOp := DryRunOperation{
				Type:   "create_cgroup",
				Target: cgroupName,
				Action: "Create cgroup for throttling",
				Parameters: map[string]interface{}{
					"cgroup_name": cgroupName,
				},
				WouldSucceed: true,
			}

			if v.cgroupManager == nil {
				createOp.WouldSucceed = false
				createOp.Reason = "Cgroup manager not available"
			}

			result.Operations = append(result.Operations, createOp)

			// Throttle operation
			throttleOp := DryRunOperation{
				Type:   "throttle",
				Target: fmt.Sprintf("%s (PID: %d)", proc.Name, proc.PID),
				Action: fmt.Sprintf("Apply throttling rule '%s'", rule.Name),
				Parameters: map[string]interface{}{
					"rule_name":     rule.Name,
					"cpu_quota":     rule.Limits.CPUQuota,
					"cpu_period":    rule.Limits.CPUPeriod,
					"memory_limit":  rule.Limits.MemoryLimit,
					"pids_limit":    rule.Limits.PidsLimit,
				},
				WouldSucceed: createOp.WouldSucceed,
				Reason:       createOp.Reason,
			}

			result.Operations = append(result.Operations, throttleOp)
		}
	}

	// Add summary
	protectCount := 0
	throttleCount := 0
	for _, op := range result.Operations {
		if op.Type == "protect" && op.WouldSucceed {
			protectCount++
		} else if op.Type == "throttle" && op.WouldSucceed {
			throttleCount++
		}
	}

	if protectCount > 0 || throttleCount > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Would protect %d processes and throttle %d processes", protectCount, throttleCount))
	}

	return result
}
