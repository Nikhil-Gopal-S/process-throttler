package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourusername/process-throttler/internal/audit"
	"github.com/yourusername/process-throttler/internal/backup"
	"github.com/yourusername/process-throttler/internal/emergency"
)

var (
	auditLogger   *audit.Logger
	backupManager *backup.BackupManager
	stopManager   *emergency.StopManager
)

// Audit commands
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log management",
	Long:  `View and manage audit logs for security and compliance.`,
}

var auditSearchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search audit logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		if auditLogger == nil {
			return fmt.Errorf("audit logger not initialized")
		}

		// Parse search criteria
		criteria := audit.SearchCriteria{}
		
		if hours, _ := cmd.Flags().GetInt("hours"); hours > 0 {
			criteria.StartTime = time.Now().Add(-time.Duration(hours) * time.Hour)
			criteria.EndTime = time.Now()
		}
		
		if eventType, _ := cmd.Flags().GetString("type"); eventType != "" {
			criteria.EventType = audit.EventType(eventType)
		}
		
		if severity, _ := cmd.Flags().GetString("severity"); severity != "" {
			criteria.Severity = audit.Severity(severity)
		}
		
		if user, _ := cmd.Flags().GetString("user"); user != "" {
			criteria.User = user
		}
		
		// Search logs
		events, err := auditLogger.Search(criteria)
		if err != nil {
			return fmt.Errorf("failed to search audit logs: %v", err)
		}
		
		// Output results
		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			data, err := json.MarshalIndent(events, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal events: %v", err)
			}
			fmt.Println(string(data))
		} else {
			printAuditEvents(events)
		}
		
		return nil
	},
}

var auditStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show audit statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		if auditLogger == nil {
			return fmt.Errorf("audit logger not initialized")
		}

		stats, err := auditLogger.GetStats()
		if err != nil {
			return fmt.Errorf("failed to get audit stats: %v", err)
		}
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			data, err := json.MarshalIndent(stats, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal stats: %v", err)
			}
			fmt.Println(string(data))
		} else {
			printAuditStats(stats)
		}
		
		return nil
	},
}

// Backup commands
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Configuration backup management",
	Long:  `Create, restore, and manage configuration backups.`,
}

var backupCreateCmd = &cobra.Command{
	Use:   "create [description]",
	Short: "Create a configuration backup",
	RunE: func(cmd *cobra.Command, args []string) error {
		if backupManager == nil {
			return fmt.Errorf("backup manager not initialized")
		}

		description := "Manual backup"
		if len(args) > 0 {
			description = strings.Join(args, " ")
		}
		
		metadata, err := backupManager.CreateBackup(description)
		if err != nil {
			return fmt.Errorf("failed to create backup: %v", err)
		}
		
		fmt.Printf("✅ Backup created successfully\n")
		fmt.Printf("ID: %s\n", metadata.ID)
		fmt.Printf("Timestamp: %s\n", metadata.Timestamp.Format(time.RFC3339))
		fmt.Printf("Profiles: %d\n", len(metadata.Profiles))
		fmt.Printf("Size: %d bytes\n", metadata.Size)
		
		return nil
	},
}

var backupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available backups",
	Aliases: []string{"ls"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if backupManager == nil {
			return fmt.Errorf("backup manager not initialized")
		}

		backups, err := backupManager.ListBackups()
		if err != nil {
			return fmt.Errorf("failed to list backups: %v", err)
		}
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			data, err := json.MarshalIndent(backups, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal backups: %v", err)
			}
			fmt.Println(string(data))
		} else {
			printBackups(backups)
		}
		
		return nil
	},
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore [backup-id]",
	Short: "Restore a configuration backup",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if backupManager == nil {
			return fmt.Errorf("backup manager not initialized")
		}

		backupID := args[0]
		force, _ := cmd.Flags().GetBool("force")
		
		// Confirm restoration
		if !force {
			fmt.Printf("⚠️  WARNING: This will replace current configuration\n")
			fmt.Print("Are you sure you want to restore backup %s? (y/N): ", backupID)
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Restore cancelled")
				return nil
			}
		}
		
		if err := backupManager.RestoreBackup(backupID, force); err != nil {
			return fmt.Errorf("failed to restore backup: %v", err)
		}
		
		fmt.Printf("✅ Backup %s restored successfully\n", backupID)
		fmt.Println("Please restart the application for changes to take effect")
		
		return nil
	},
}

var backupDeleteCmd = &cobra.Command{
	Use:   "delete [backup-id]",
	Short: "Delete a backup",
	Aliases: []string{"rm", "remove"},
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if backupManager == nil {
			return fmt.Errorf("backup manager not initialized")
		}

		backupID := args[0]
		force, _ := cmd.Flags().GetBool("force")
		
		if !force {
			fmt.Printf("Are you sure you want to delete backup %s? (y/N): ", backupID)
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Deletion cancelled")
				return nil
			}
		}
		
		if err := backupManager.DeleteBackup(backupID); err != nil {
			return fmt.Errorf("failed to delete backup: %v", err)
		}
		
		fmt.Printf("✅ Backup %s deleted successfully\n", backupID)
		
		return nil
	},
}

// Emergency commands
var emergencyCmd = &cobra.Command{
	Use:   "emergency",
	Short: "Emergency stop management",
	Long:  `Emergency stop commands for critical situations.`,
}

var emergencyStopCmd = &cobra.Command{
	Use:   "stop [reason]",
	Short: "Initiate emergency stop",
	RunE: func(cmd *cobra.Command, args []string) error {
		if stopManager == nil {
			return fmt.Errorf("emergency stop manager not initialized")
		}

		reason := "Manual emergency stop"
		if len(args) > 0 {
			reason = strings.Join(args, " ")
		}
		
		fmt.Println("🚨 INITIATING EMERGENCY STOP")
		fmt.Printf("Reason: %s\n", reason)
		
		if err := stopManager.EmergencyStop(reason); err != nil {
			return fmt.Errorf("emergency stop failed: %v", err)
		}
		
		return nil
	},
}

var emergencyResumeCmd = &cobra.Command{
	Use:   "resume",
	Short: "Resume after emergency stop",
	RunE: func(cmd *cobra.Command, args []string) error {
		if stopManager == nil {
			return fmt.Errorf("emergency stop manager not initialized")
		}

		force, _ := cmd.Flags().GetBool("force")
		
		if err := stopManager.Resume(force); err != nil {
			return fmt.Errorf("failed to resume: %v", err)
		}
		
		return nil
	},
}

var emergencyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show emergency stop status",
	RunE: func(cmd *cobra.Command, args []string) error {
		if stopManager == nil {
			return fmt.Errorf("emergency stop manager not initialized")
		}

		status := stopManager.GetStatus()
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			data, err := json.MarshalIndent(status, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal status: %v", err)
			}
			fmt.Println(string(data))
		} else {
			if status.Active {
				fmt.Println("🛑 EMERGENCY STOP ACTIVE")
				fmt.Printf("Reason: %s\n", status.Reason)
				fmt.Printf("Timestamp: %s\n", status.Timestamp.Format(time.RFC3339))
				fmt.Printf("User: %s\n", status.User)
				fmt.Printf("Duration: %s\n", time.Since(status.Timestamp))
			} else {
				fmt.Println("✅ System operating normally")
				fmt.Println("No emergency stop active")
			}
		}
		
		return nil
	},
}

// Helper functions

func printAuditEvents(events []*audit.AuditEvent) {
	if len(events) == 0 {
		fmt.Println("No audit events found")
		return
	}
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tTYPE\tSEVERITY\tUSER\tACTION\tRESULT")
	fmt.Fprintln(w, "---------\t----\t--------\t----\t------\t------")
	
	for _, event := range events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			event.Timestamp.Format("15:04:05"),
			event.Type,
			event.Severity,
			event.User,
			truncateString(event.Action, 30),
			event.Result,
		)
	}
	w.Flush()
}

func printAuditStats(stats *audit.AuditStats) {
	fmt.Printf("Audit Statistics (Last 24 Hours)\n")
	fmt.Printf("================================\n")
	fmt.Printf("Total Events: %d\n\n", stats.TotalEvents)
	
	fmt.Println("Events by Type:")
	for eventType, count := range stats.EventsByType {
		fmt.Printf("  %s: %d\n", eventType, count)
	}
	
	fmt.Println("\nEvents by Severity:")
	for severity, count := range stats.EventsBySeverity {
		fmt.Printf("  %s: %d\n", severity, count)
	}
	
	if len(stats.RecentEvents) > 0 {
		fmt.Println("\nRecent Events:")
		for _, event := range stats.RecentEvents {
			fmt.Printf("  [%s] %s - %s\n",
				event.Timestamp.Format("15:04:05"),
				event.Type,
				event.Action,
			)
		}
	}
}

func printBackups(backups []*backup.BackupMetadata) {
	if len(backups) == 0 {
		fmt.Println("No backups found")
		return
	}
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTIMESTAMP\tDESCRIPTION\tPROFILES\tSIZE")
	fmt.Fprintln(w, "--\t---------\t-----------\t--------\t----")
	
	for _, b := range backups {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			b.ID,
			b.Timestamp.Format("2006-01-02 15:04"),
			truncateString(b.Description, 30),
			len(b.Profiles),
			formatBytes(b.Size),
		)
	}
	w.Flush()
}

// formatBytes is defined in root.go

func init() {
	// Audit search flags
	auditSearchCmd.Flags().Int("hours", 24, "search last N hours")
	auditSearchCmd.Flags().String("type", "", "filter by event type")
	auditSearchCmd.Flags().String("severity", "", "filter by severity")
	auditSearchCmd.Flags().String("user", "", "filter by user")
	auditSearchCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Audit stats flags
	auditStatsCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Backup list flags
	backupListCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Backup restore flags
	backupRestoreCmd.Flags().BoolP("force", "f", false, "force restore without confirmation")
	
	// Backup delete flags
	backupDeleteCmd.Flags().BoolP("force", "f", false, "force delete without confirmation")
	
	// Emergency resume flags
	emergencyResumeCmd.Flags().BoolP("force", "f", false, "force resume without confirmation")
	
	// Emergency status flags
	emergencyStatusCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Add subcommands
	auditCmd.AddCommand(auditSearchCmd, auditStatsCmd)
	backupCmd.AddCommand(backupCreateCmd, backupListCmd, backupRestoreCmd, backupDeleteCmd)
	emergencyCmd.AddCommand(emergencyStopCmd, emergencyResumeCmd, emergencyStatusCmd)
}
