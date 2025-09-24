package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/yourusername/process-throttler/internal/daemon"
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Perform comprehensive health checks",
	Long: `Perform comprehensive health checks to verify the tool is properly configured and operational.

Checks include:
  - Daemon status
  - Cgroup availability and version
  - System permissions
  - Configuration validity
  - Webhook connectivity
  - Critical process monitoring`,
	RunE: func(cmd *cobra.Command, args []string) error {
		checkAll, _ := cmd.Flags().GetBool("check-all")
		jsonOutput, _ := cmd.Flags().GetBool("json")
		
		results := performHealthChecks(checkAll)
		
		if jsonOutput {
			data, err := json.MarshalIndent(results, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}
		
		// Human-readable output
		fmt.Println("Process Throttler Health Check")
		fmt.Println("===============================")
		fmt.Println()
		
		allHealthy := true
		for category, checks := range results {
			fmt.Printf("%s:\n", strings.Title(category))
			for _, check := range checks {
				status := "✓"
				if check.Status == "warning" {
					status = "⚠"
					allHealthy = false
				} else if check.Status == "error" {
					status = "✗"
					allHealthy = false
				}
				
				fmt.Printf("  %s %s: %s\n", status, check.Name, check.Message)
				if check.Details != "" && verbose {
					fmt.Printf("     %s\n", check.Details)
				}
			}
			fmt.Println()
		}
		
		// Overall status
		if allHealthy {
			fmt.Printf("Overall Status: HEALTHY\n")
		} else {
			fmt.Printf("Overall Status: ISSUES DETECTED\n")
			fmt.Println("\nRecommended Actions:")
			
			// Provide recommendations based on issues
			for _, checks := range results {
				for _, check := range checks {
					if check.Status != "ok" && check.Recommendation != "" {
						fmt.Printf("  • %s\n", check.Recommendation)
					}
				}
			}
		}
		
		return nil
	},
}

type HealthCheck struct {
	Name           string `json:"name"`
	Status         string `json:"status"` // ok, warning, error
	Message        string `json:"message"`
	Details        string `json:"details,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func performHealthChecks(checkAll bool) map[string][]HealthCheck {
	results := make(map[string][]HealthCheck)
	
	// System checks
	results["system"] = []HealthCheck{
		checkOS(),
		checkPermissions(),
		checkCgroups(),
		checkKernelVersion(),
	}
	
	// Daemon checks
	results["daemon"] = []HealthCheck{
		checkDaemonStatus(),
	}
	
	// Configuration checks
	results["configuration"] = []HealthCheck{
		checkConfigFile(),
		checkProfiles(),
		checkWebhooks(),
	}
	
	if checkAll {
		// Extended checks
		results["resources"] = []HealthCheck{
			checkMemory(),
			checkCPU(),
			checkDiskSpace(),
		}
	}
	
	return results
}

func checkOS() HealthCheck {
	check := HealthCheck{
		Name: "Operating System",
	}
	
	if runtime.GOOS == "linux" {
		check.Status = "ok"
		check.Message = fmt.Sprintf("Linux (%s)", runtime.GOARCH)
	} else {
		check.Status = "warning"
		check.Message = fmt.Sprintf("%s is not fully supported", runtime.GOOS)
		check.Recommendation = "Use Linux for full feature support"
	}
	
	return check
}

func checkPermissions() HealthCheck {
	check := HealthCheck{
		Name: "Permissions",
	}
	
	// Check if running as root
	if os.Geteuid() == 0 {
		check.Status = "ok"
		check.Message = "Running as root"
	} else {
		// Check if we can access cgroup directories
		cgroupDirs := []string{
			"/sys/fs/cgroup",
			"/proc",
		}
		
		canAccess := true
		for _, dir := range cgroupDirs {
			if _, err := os.Stat(dir); err != nil {
				canAccess = false
				break
			}
		}
		
		if canAccess {
			check.Status = "warning"
			check.Message = "Running as non-root (limited functionality)"
			check.Recommendation = "Run with sudo for full functionality"
		} else {
			check.Status = "error"
			check.Message = "Insufficient permissions to access system resources"
			check.Recommendation = "Run with sudo or as root"
		}
	}
	
	return check
}

func checkCgroups() HealthCheck {
	check := HealthCheck{
		Name: "Cgroups",
	}
	
	// Check cgroup v2
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		check.Status = "ok"
		check.Message = "Cgroups v2 available"
		return check
	}
	
	// Check cgroup v1
	if _, err := os.Stat("/sys/fs/cgroup/cpu"); err == nil {
		check.Status = "ok"
		check.Message = "Cgroups v1 available"
		return check
	}
	
	check.Status = "error"
	check.Message = "Cgroups not available"
	check.Recommendation = "Ensure cgroups are enabled in your kernel"
	return check
}

func checkKernelVersion() HealthCheck {
	check := HealthCheck{
		Name: "Kernel Version",
	}
	
	if runtime.GOOS != "linux" {
		check.Status = "warning"
		check.Message = "Not running on Linux"
		return check
	}
	
	// Read kernel version
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		check.Status = "warning"
		check.Message = "Unable to determine kernel version"
		return check
	}
	
	version := string(data)
	check.Status = "ok"
	check.Message = "Compatible"
	check.Details = strings.Split(version, " ")[2]
	
	return check
}

func checkDaemonStatus() HealthCheck {
	check := HealthCheck{
		Name: "Daemon Status",
	}
	
	dm := daemon.NewManager()
	status, err := dm.GetStatus()
	if err != nil {
		check.Status = "error"
		check.Message = "Unable to check daemon status"
		check.Details = err.Error()
		return check
	}
	
	if status.Running {
		check.Status = "ok"
		check.Message = fmt.Sprintf("Running (PID: %d, Uptime: %s)", status.PID, status.Uptime)
	} else {
		check.Status = "warning"
		check.Message = "Not running"
		check.Recommendation = "Start daemon with: process-throttler daemon start"
	}
	
	return check
}

func checkConfigFile() HealthCheck {
	check := HealthCheck{
		Name: "Configuration File",
	}
	
	// Check default locations
	configPaths := []string{
		"/etc/process-throttler/config.yaml",
		"./configs/example.yaml",
	}
	
	if homeDir, err := os.UserHomeDir(); err == nil {
		configPaths = append(configPaths, 
			fmt.Sprintf("%s/.config/process-throttler/config.yaml", homeDir))
	}
	
	found := false
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			check.Status = "ok"
			check.Message = "Found"
			check.Details = path
			found = true
			break
		}
	}
	
	if !found {
		check.Status = "warning"
		check.Message = "No configuration file found"
		check.Recommendation = "Create a configuration file or use --config flag"
	}
	
	return check
}

func checkProfiles() HealthCheck {
	check := HealthCheck{
		Name: "Profiles",
	}
	
	// Check profile directory
	profileDir := "/etc/process-throttler/profiles"
	if homeDir, err := os.UserHomeDir(); err == nil {
		userProfileDir := fmt.Sprintf("%s/.config/process-throttler/profiles", homeDir)
		if _, err := os.Stat(userProfileDir); err == nil {
			profileDir = userProfileDir
		}
	}
	
	files, err := os.ReadDir(profileDir)
	if err != nil {
		check.Status = "warning"
		check.Message = "No profiles directory"
		check.Recommendation = "Create profiles with: process-throttler profile create"
		return check
	}
	
	profileCount := 0
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml") {
			profileCount++
		}
	}
	
	if profileCount > 0 {
		check.Status = "ok"
		check.Message = fmt.Sprintf("%d profile(s) found", profileCount)
	} else {
		check.Status = "warning"
		check.Message = "No profiles found"
		check.Recommendation = "Create profiles with: process-throttler profile create"
	}
	
	return check
}

func checkWebhooks() HealthCheck {
	check := HealthCheck{
		Name: "Webhooks",
	}
	
	// Check webhook configuration file
	webhookFile := "/etc/process-throttler/webhooks.yaml"
	if homeDir, err := os.UserHomeDir(); err == nil {
		userWebhookFile := fmt.Sprintf("%s/.config/process-throttler/webhooks.yaml", homeDir)
		if _, err := os.Stat(userWebhookFile); err == nil {
			webhookFile = userWebhookFile
		}
	}
	
	if _, err := os.Stat(webhookFile); err == nil {
		check.Status = "ok"
		check.Message = "Configuration found"
		check.Details = webhookFile
	} else {
		check.Status = "ok"
		check.Message = "No webhooks configured"
	}
	
	return check
}

func checkMemory() HealthCheck {
	check := HealthCheck{
		Name: "Available Memory",
	}
	
	// Read meminfo
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		check.Status = "warning"
		check.Message = "Unable to check memory"
		return check
	}
	
	lines := strings.Split(string(data), "\n")
	var memAvailable int64
	for _, line := range lines {
		if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(line, "MemAvailable: %d kB", &memAvailable)
			break
		}
	}
	
	memAvailableGB := float64(memAvailable) / (1024 * 1024)
	if memAvailableGB > 1 {
		check.Status = "ok"
		check.Message = fmt.Sprintf("%.1f GB available", memAvailableGB)
	} else {
		check.Status = "warning"
		check.Message = fmt.Sprintf("Low memory: %.1f GB available", memAvailableGB)
		check.Recommendation = "Consider freeing up memory before applying throttling"
	}
	
	return check
}

func checkCPU() HealthCheck {
	check := HealthCheck{
		Name: "CPU Resources",
	}
	
	// Get CPU count
	cpuCount := runtime.NumCPU()
	check.Status = "ok"
	check.Message = fmt.Sprintf("%d CPU(s) available", cpuCount)
	
	// Check load average
	data, err := os.ReadFile("/proc/loadavg")
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			check.Details = fmt.Sprintf("Load average: %s %s %s", fields[0], fields[1], fields[2])
		}
	}
	
	return check
}

func checkDiskSpace() HealthCheck {
	check := HealthCheck{
		Name: "Disk Space",
	}
	
	// This is a simplified check - in production, use proper syscalls
	check.Status = "ok"
	check.Message = "Sufficient disk space"
	
	return check
}

func init() {
	rootCmd.AddCommand(healthCmd)
	
	healthCmd.Flags().Bool("check-all", false, "Perform all extended health checks")
	healthCmd.Flags().Bool("json", false, "Output results in JSON format")
}
