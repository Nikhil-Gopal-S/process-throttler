package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourusername/process-throttler/internal/metrics"
	"github.com/yourusername/process-throttler/internal/throttle"
	"github.com/yourusername/process-throttler/internal/types"
	"github.com/yourusername/process-throttler/internal/webhook"
)

var (
	dynamicThrottler *throttle.DynamicThrottler
	metricsCollector *metrics.Collector
	webhookNotifier  *webhook.Notifier
)

// Dynamic throttling commands
var dynamicCmd = &cobra.Command{
	Use:   "dynamic",
	Short: "Dynamic throttling management",
	Long:  `Apply and manage dynamic throttling with advanced algorithms.`,
}

var dynamicApplyCmd = &cobra.Command{
	Use:   "apply [pid/pattern]",
	Short: "Apply dynamic throttling",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if dynamicThrottler == nil {
			return fmt.Errorf("dynamic throttler not initialized")
		}

		target := args[0]
		policy, _ := cmd.Flags().GetString("policy")
		cpuLimit, _ := cmd.Flags().GetString("cpu")
		memLimit, _ := cmd.Flags().GetString("memory")
		
		// Parse target (PID or pattern)
		var pid int32
		if p, err := strconv.ParseInt(target, 10, 32); err == nil {
			pid = int32(p)
		} else {
			// Find process by pattern
			processes, err := processDiscovery.FindByPattern(target, "name")
			if err != nil {
				return fmt.Errorf("failed to find processes: %v", err)
			}
			if len(processes) == 0 {
				return fmt.Errorf("no processes found matching pattern '%s'", target)
			}
			if len(processes) > 1 {
				fmt.Printf("Multiple processes found. Select one:\n")
				for i, proc := range processes {
					fmt.Printf("%d. PID %d: %s\n", i+1, proc.PID, proc.Name)
				}
				return fmt.Errorf("multiple processes matched, please specify PID")
			}
			pid = processes[0].PID
		}
		
		// Parse limits
		limits := types.ResourceLimits{}
		if cpuLimit != "" {
			quota, period, err := parseCPULimit(cpuLimit)
			if err != nil {
				return fmt.Errorf("invalid CPU limit: %v", err)
			}
			limits.CPUQuota = quota
			limits.CPUPeriod = period
		}
		
		if memLimit != "" {
			memBytes, err := parseMemoryLimit(memLimit)
			if err != nil {
				return fmt.Errorf("invalid memory limit: %v", err)
			}
			limits.MemoryLimit = memBytes
		}
		
		// Apply dynamic throttling
		if err := dynamicThrottler.ApplyDynamicThrottle(pid, policy, limits); err != nil {
			return fmt.Errorf("failed to apply dynamic throttling: %v", err)
		}
		
		fmt.Printf("✅ Dynamic throttling applied to PID %d with policy '%s'\n", pid, policy)
		return nil
	},
}

var dynamicListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active dynamic throttles",
	Aliases: []string{"ls"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if dynamicThrottler == nil {
			return fmt.Errorf("dynamic throttler not initialized")
		}

		throttles := dynamicThrottler.GetActiveThrottles()
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			data, err := json.MarshalIndent(throttles, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal throttles: %v", err)
			}
			fmt.Println(string(data))
		} else {
			printDynamicThrottles(throttles)
		}
		
		return nil
	},
}

var dynamicRemoveCmd = &cobra.Command{
	Use:   "remove [pid]",
	Short: "Remove dynamic throttling",
	Aliases: []string{"rm"},
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if dynamicThrottler == nil {
			return fmt.Errorf("dynamic throttler not initialized")
		}

		pid, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid PID: %v", err)
		}
		
		if err := dynamicThrottler.RemoveThrottle(int32(pid)); err != nil {
			return fmt.Errorf("failed to remove throttle: %v", err)
		}
		
		fmt.Printf("✅ Dynamic throttling removed from PID %d\n", pid)
		return nil
	},
}

var dynamicPoliciesCmd = &cobra.Command{
	Use:   "policies",
	Short: "List available throttling policies",
	RunE: func(cmd *cobra.Command, args []string) error {
		// This would list available policies
		fmt.Println("Available Throttling Policies:")
		fmt.Println("==============================")
		fmt.Println()
		fmt.Println("1. gradual")
		fmt.Println("   - Gradually applies throttling over time")
		fmt.Println("   - Smooth transitions to avoid system shock")
		fmt.Println("   - Default ramp-up: 5 minutes")
		fmt.Println()
		fmt.Println("2. adaptive")
		fmt.Println("   - Adapts based on actual resource usage")
		fmt.Println("   - Maintains target CPU/memory usage")
		fmt.Println("   - Self-adjusting based on load")
		fmt.Println()
		fmt.Println("3. business-hours")
		fmt.Println("   - Time-based throttling rules")
		fmt.Println("   - Different limits for business/off hours")
		fmt.Println("   - Automatic schedule enforcement")
		
		return nil
	},
}

// Metrics commands
var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Metrics and monitoring",
	Long:  `Prometheus metrics integration and monitoring.`,
}

var metricsStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start metrics server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if metricsCollector == nil {
			return fmt.Errorf("metrics collector not initialized")
		}

		address, _ := cmd.Flags().GetString("address")
		
		if err := metricsCollector.StartServer(address); err != nil {
			return fmt.Errorf("failed to start metrics server: %v", err)
		}
		
		fmt.Printf("✅ Metrics server started on %s\n", address)
		fmt.Println("Prometheus endpoint: http://" + address + "/metrics")
		
		return nil
	},
}

var metricsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show metrics status",
	RunE: func(cmd *cobra.Command, args []string) error {
		// This would show current metrics status
		fmt.Println("Metrics Status")
		fmt.Println("==============")
		fmt.Println()
		fmt.Println("Server: Running on :9090")
		fmt.Println("Endpoint: http://localhost:9090/metrics")
		fmt.Println()
		fmt.Println("Available Metrics:")
		fmt.Println("- process_throttler_processes_total")
		fmt.Println("- process_throttler_processes_throttled")
		fmt.Println("- process_throttler_resources_cpu_usage_percent")
		fmt.Println("- process_throttler_resources_memory_usage_bytes")
		fmt.Println("- process_throttler_system_cpu_usage_percent")
		fmt.Println("- process_throttler_critical_process_health")
		fmt.Println("- process_throttler_audit_events_total")
		
		return nil
	},
}

// Webhook commands
var webhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Webhook notification management",
	Long:  `Configure and manage webhook notifications.`,
}

var webhookAddCmd = &cobra.Command{
	Use:   "add [name] [url]",
	Short: "Add a webhook",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if webhookNotifier == nil {
			return fmt.Errorf("webhook notifier not initialized")
		}

		name := args[0]
		url := args[1]
		
		events, _ := cmd.Flags().GetStringSlice("events")
		secret, _ := cmd.Flags().GetString("secret")
		
		config := &webhook.WebhookConfig{
			Name:    name,
			URL:     url,
			Method:  "POST",
			Events:  events,
			Secret:  secret,
			Enabled: true,
			Timeout: 10 * time.Second,
		}
		
		if err := webhookNotifier.AddWebhook(config); err != nil {
			return fmt.Errorf("failed to add webhook: %v", err)
		}
		
		fmt.Printf("✅ Webhook '%s' added successfully\n", name)
		return nil
	},
}

var webhookListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured webhooks",
	Aliases: []string{"ls"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if webhookNotifier == nil {
			return fmt.Errorf("webhook notifier not initialized")
		}

		webhooks := webhookNotifier.GetWebhooks()
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			data, err := json.MarshalIndent(webhooks, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal webhooks: %v", err)
			}
			fmt.Println(string(data))
		} else {
			printWebhooks(webhooks)
		}
		
		return nil
	},
}

var webhookTestCmd = &cobra.Command{
	Use:   "test [name]",
	Short: "Test a webhook",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if webhookNotifier == nil {
			return fmt.Errorf("webhook notifier not initialized")
		}

		name := args[0]
		
		fmt.Printf("Testing webhook '%s'...\n", name)
		
		if err := webhookNotifier.TestWebhook(name); err != nil {
			return fmt.Errorf("webhook test failed: %v", err)
		}
		
		fmt.Printf("✅ Webhook test successful\n")
		return nil
	},
}

var webhookRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a webhook",
	Aliases: []string{"rm"},
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if webhookNotifier == nil {
			return fmt.Errorf("webhook notifier not initialized")
		}

		name := args[0]
		
		if err := webhookNotifier.RemoveWebhook(name); err != nil {
			return fmt.Errorf("failed to remove webhook: %v", err)
		}
		
		fmt.Printf("✅ Webhook '%s' removed successfully\n", name)
		return nil
	},
}

// Helper functions

func printDynamicThrottles(throttles map[int32]*throttle.ActiveThrottle) {
	if len(throttles) == 0 {
		fmt.Println("No active dynamic throttles")
		return
	}
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tPROCESS\tPOLICY\tCPU_LIMIT\tDURATION\tADJUSTMENTS")
	fmt.Fprintln(w, "---\t-------\t------\t---------\t--------\t-----------")
	
	for pid, t := range throttles {
		cpuPercent := float64(t.CurrentLimits.CPUQuota) / float64(t.CurrentLimits.CPUPeriod) * 100
		duration := time.Since(t.StartTime).Round(time.Second)
		
		fmt.Fprintf(w, "%d\t%s\t%s\t%.1f%%\t%s\t%d\n",
			pid,
			t.ProcessName,
			t.Policy.Name,
			cpuPercent,
			duration,
			t.AdjustmentCount,
		)
	}
	w.Flush()
}

func printWebhooks(webhooks map[string]*webhook.WebhookConfig) {
	if len(webhooks) == 0 {
		fmt.Println("No webhooks configured")
		return
	}
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tURL\tEVENTS\tENABLED")
	fmt.Fprintln(w, "----\t---\t------\t-------")
	
	for _, wh := range webhooks {
		events := strings.Join(wh.Events, ",")
		if events == "" {
			events = "*"
		}
		
		enabled := "Yes"
		if !wh.Enabled {
			enabled = "No"
		}
		
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			wh.Name,
			truncateString(wh.URL, 40),
			truncateString(events, 20),
			enabled,
		)
	}
	w.Flush()
}

func init() {
	// Dynamic apply flags
	dynamicApplyCmd.Flags().String("policy", "gradual", "throttling policy to use")
	dynamicApplyCmd.Flags().String("cpu", "", "CPU limit (e.g., 50%)")
	dynamicApplyCmd.Flags().String("memory", "", "memory limit (e.g., 1GB)")
	
	// Dynamic list flags
	dynamicListCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Metrics start flags
	metricsStartCmd.Flags().String("address", ":9090", "metrics server address")
	
	// Webhook add flags
	webhookAddCmd.Flags().StringSlice("events", []string{}, "events to notify (empty for all)")
	webhookAddCmd.Flags().String("secret", "", "webhook secret/token")
	
	// Webhook list flags
	webhookListCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Add subcommands
	dynamicCmd.AddCommand(
		dynamicApplyCmd,
		dynamicListCmd,
		dynamicRemoveCmd,
		dynamicPoliciesCmd,
	)
	
	metricsCmd.AddCommand(
		metricsStartCmd,
		metricsStatusCmd,
	)
	
	webhookCmd.AddCommand(
		webhookAddCmd,
		webhookListCmd,
		webhookTestCmd,
		webhookRemoveCmd,
	)
}
