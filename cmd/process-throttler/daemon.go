package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/yourusername/process-throttler/internal/daemon"
)

var daemonManager *daemon.Manager

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the process-throttler daemon",
	Long: `The daemon provides continuous monitoring and management features:
  - Critical process health monitoring
  - Auto-restart of failed processes  
  - Dynamic throttling adjustments
  - Scheduled profile activation
  - Prometheus metrics export
  - Real-time webhook notifications

Many features require the daemon to be running in the background.`,
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the daemon process",
	Long: `Start the process-throttler daemon in the background.

The daemon enables:
  - Continuous monitoring of critical processes
  - Health checks and auto-restart
  - Dynamic resource adjustments
  - Scheduled profile changes
  - Real-time metrics and alerts`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize daemon manager if not already done
		if daemonManager == nil {
			daemonManager = daemon.NewManager()
		}
		
		// Set components
		daemonManager.SetComponents(
			protectionMgr,
			dynamicThrottler,
			metricsCollector,
			auditLogger,
		)
		
		// Start daemon
		if err := daemonManager.Start(); err != nil {
			return fmt.Errorf("failed to start daemon: %w", err)
		}
		
		// Keep the process running
		select {}
	},
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the daemon process",
	RunE: func(cmd *cobra.Command, args []string) error {
		if daemonManager == nil {
			daemonManager = daemon.NewManager()
		}
		
		status, err := daemonManager.GetStatus()
		if err != nil {
			return fmt.Errorf("failed to get daemon status: %w", err)
		}
		
		if !status.Running {
			fmt.Println("❌ Daemon is not running")
			return nil
		}
		
		fmt.Printf("Stopping daemon (PID: %d)...\n", status.PID)
		
		// Send stop signal to running daemon
		if err := sendSignalToDaemon(status.PID, "TERM"); err != nil {
			return fmt.Errorf("failed to stop daemon: %w", err)
		}
		
		// Wait for daemon to stop
		for i := 0; i < 10; i++ {
			time.Sleep(1 * time.Second)
			status, _ = daemonManager.GetStatus()
			if !status.Running {
				fmt.Println("✅ Daemon stopped successfully")
				return nil
			}
		}
		
		return fmt.Errorf("timeout waiting for daemon to stop")
	},
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check daemon status",
	RunE: func(cmd *cobra.Command, args []string) error {
		if daemonManager == nil {
			daemonManager = daemon.NewManager()
		}
		
		status, err := daemonManager.GetStatus()
		if err != nil {
			return fmt.Errorf("failed to get daemon status: %w", err)
		}
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		
		if jsonOutput {
			data, err := json.MarshalIndent(status, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}
		
		// Human-readable output
		fmt.Println("Process Throttler Daemon Status")
		fmt.Println("================================")
		
		if status.Running {
			fmt.Printf("Status:     ● Running\n")
			fmt.Printf("PID:        %d\n", status.PID)
			if !status.StartTime.IsZero() {
				fmt.Printf("Started:    %s\n", status.StartTime.Format("2006-01-02 15:04:05"))
				fmt.Printf("Uptime:     %s\n", status.Uptime)
			}
			fmt.Printf("Version:    %s\n", status.Version)
			
			if len(status.Features) > 0 {
				fmt.Println("\nEnabled Features:")
				for _, feature := range status.Features {
					fmt.Printf("  ✓ %s\n", feature)
				}
			}
		} else {
			fmt.Printf("Status:     ● Stopped\n")
			fmt.Println("\nTo start the daemon, run:")
			fmt.Println("  process-throttler daemon start")
			fmt.Println("\nOr enable as a systemd service:")
			fmt.Println("  sudo systemctl enable --now process-throttler")
		}
		
		// Show which features require daemon
		fmt.Println("\nFeatures requiring daemon:")
		daemonFeatures := []string{
			"critical-process-monitoring",
			"health-checks",
			"auto-restart",
			"dynamic-throttling",
			"scheduled-profiles",
			"metrics-export",
		}
		
		for _, feature := range daemonFeatures {
			if status.Running {
				fmt.Printf("  ✓ %s\n", feature)
			} else {
				fmt.Printf("  ✗ %s (daemon not running)\n", feature)
			}
		}
		
		return nil
	},
}

var daemonRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the daemon process",
	RunE: func(cmd *cobra.Command, args []string) error {
		if daemonManager == nil {
			daemonManager = daemon.NewManager()
		}
		
		// Check if running
		status, _ := daemonManager.GetStatus()
		if status.Running {
			fmt.Printf("Stopping daemon (PID: %d)...\n", status.PID)
			if err := sendSignalToDaemon(status.PID, "TERM"); err != nil {
				return fmt.Errorf("failed to stop daemon: %w", err)
			}
			
			// Wait for stop
			for i := 0; i < 10; i++ {
				time.Sleep(1 * time.Second)
				status, _ = daemonManager.GetStatus()
				if !status.Running {
					break
				}
			}
		}
		
		fmt.Println("Starting daemon...")
		
		// Set components
		daemonManager.SetComponents(
			protectionMgr,
			dynamicThrottler,
			metricsCollector,
			auditLogger,
		)
		
		if err := daemonManager.Start(); err != nil {
			return fmt.Errorf("failed to start daemon: %w", err)
		}
		
		// Keep running
		select {}
	},
}

// sendSignalToDaemon sends a signal to the running daemon
func sendSignalToDaemon(pid int, signal string) error {
	// Use kill command to send signal
	// This is a simplified version - in production, use proper signal handling
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	
	return process.Signal(os.Interrupt)
}

func init() {
	// Add subcommands
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonRestartCmd)
	
	// Add flags
	daemonStatusCmd.Flags().Bool("json", false, "Output status in JSON format")
}
