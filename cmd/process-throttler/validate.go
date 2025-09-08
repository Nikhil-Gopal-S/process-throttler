package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/yourusername/process-throttler/internal/config"
	"github.com/yourusername/process-throttler/internal/profile"
	"github.com/yourusername/process-throttler/internal/validation"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configurations and system state",
	Long:  `Validate configurations, profiles, and system state for compatibility and correctness.`,
}

var validateSystemCmd = &cobra.Command{
	Use:   "system",
	Short: "Validate system compatibility",
	RunE: func(cmd *cobra.Command, args []string) error {
		validator := validation.NewValidator(processDiscovery, cgroupManager)
		
		// Create a dummy profile to trigger system validation
		result := validator.ValidateProfile(&profile.Profile{})
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		
		if jsonOutput {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal result: %v", err)
			}
			fmt.Println(string(data))
		} else {
			printValidationResult(result)
		}
		
		if !result.Valid {
			os.Exit(1)
		}
		
		return nil
	},
}

var validateProfileCmd = &cobra.Command{
	Use:   "profile [name]",
	Short: "Validate a profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		profileName := args[0]
		
		p, err := profileManager.Get(profileName)
		if err != nil {
			return fmt.Errorf("failed to get profile: %v", err)
		}
		
		validator := validation.NewValidator(processDiscovery, cgroupManager)
		result := validator.ValidateProfile(p)
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		
		if jsonOutput {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal result: %v", err)
			}
			fmt.Println(string(data))
		} else {
			fmt.Printf("Validating profile: %s\n\n", profileName)
			printValidationResult(result)
		}
		
		if !result.Valid {
			os.Exit(1)
		}
		
		return nil
	},
}

var validateConfigCmd = &cobra.Command{
	Use:   "config [file]",
	Short: "Validate a configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		configFile := cfgFile
		if len(args) > 0 {
			configFile = args[0]
		}
		
		if configFile == "" {
			return fmt.Errorf("no configuration file specified")
		}
		
		// Load the configuration
		cfg := config.NewConfigManager(configFile)
		configuration, err := cfg.LoadConfig()
		if err != nil {
			return fmt.Errorf("failed to load configuration: %v", err)
		}
		
		validator := validation.NewValidator(processDiscovery, cgroupManager)
		result := validator.ValidateConfiguration(configuration)
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		
		if jsonOutput {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal result: %v", err)
			}
			fmt.Println(string(data))
		} else {
			fmt.Printf("Validating configuration: %s\n\n", configFile)
			printValidationResult(result)
		}
		
		if !result.Valid {
			os.Exit(1)
		}
		
		return nil
	},
}

var dryRunCmd = &cobra.Command{
	Use:   "dry-run [profile]",
	Short: "Simulate profile activation without applying changes",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		profileName := args[0]
		
		p, err := profileManager.Get(profileName)
		if err != nil {
			return fmt.Errorf("failed to get profile: %v", err)
		}
		
		validator := validation.NewValidator(processDiscovery, cgroupManager)
		result := validator.SimulateProfileActivation(p)
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		
		if jsonOutput {
			data, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal result: %v", err)
			}
			fmt.Println(string(data))
		} else {
			printDryRunResult(result, profileName)
		}
		
		if len(result.Errors) > 0 {
			os.Exit(1)
		}
		
		return nil
	},
}

func printValidationResult(result *validation.ValidationResult) {
	// Print system info
	if len(result.Info) > 0 {
		fmt.Println("System Information:")
		fmt.Println("==================")
		for key, value := range result.Info {
			fmt.Printf("  %s: %v\n", key, value)
		}
		fmt.Println()
	}
	
	// Print errors
	if len(result.Errors) > 0 {
		fmt.Printf("❌ Validation FAILED with %d error(s):\n", len(result.Errors))
		fmt.Println("=====================================")
		for i, err := range result.Errors {
			fmt.Printf("%d. [%s] %s\n", i+1, err.Type, err.Message)
			if len(err.Context) > 0 {
				fmt.Println("   Context:")
				for k, v := range err.Context {
					fmt.Printf("     %s: %v\n", k, v)
				}
			}
		}
		fmt.Println()
	}
	
	// Print warnings
	if len(result.Warnings) > 0 {
		fmt.Printf("⚠️  %d warning(s):\n", len(result.Warnings))
		fmt.Println("================")
		for i, warn := range result.Warnings {
			fmt.Printf("%d. [%s] %s\n", i+1, warn.Type, warn.Message)
			if len(warn.Context) > 0 {
				fmt.Println("   Context:")
				for k, v := range warn.Context {
					fmt.Printf("     %s: %v\n", k, v)
				}
			}
		}
		fmt.Println()
	}
	
	// Print summary
	if result.Valid {
		fmt.Println("✅ Validation PASSED")
	} else {
		fmt.Println("❌ Validation FAILED")
		fmt.Println("\nPlease fix the errors above before proceeding.")
	}
}

func printDryRunResult(result *validation.DryRunResult, profileName string) {
	fmt.Printf("Dry-run simulation for profile: %s\n", profileName)
	fmt.Println("=" + strings.Repeat("=", len(profileName)+31))
	fmt.Println()
	
	if len(result.Errors) > 0 {
		fmt.Printf("❌ Encountered %d error(s):\n", len(result.Errors))
		for i, err := range result.Errors {
			fmt.Printf("%d. %v\n", i+1, err)
		}
		fmt.Println()
	}
	
	if len(result.Warnings) > 0 {
		fmt.Printf("⚠️  %d warning(s):\n", len(result.Warnings))
		for i, warn := range result.Warnings {
			fmt.Printf("%d. %s\n", i+1, warn)
		}
		fmt.Println()
	}
	
	if len(result.Operations) > 0 {
		fmt.Printf("Operations that would be performed:\n")
		fmt.Println("===================================")
		
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tTARGET\tACTION\tSTATUS")
		fmt.Fprintln(w, "----\t------\t------\t------")
		
		for _, op := range result.Operations {
			status := "✅ Would succeed"
			if !op.WouldSucceed {
				status = fmt.Sprintf("❌ Would fail: %s", op.Reason)
			}
			
			// Truncate long targets
			target := op.Target
			if len(target) > 30 {
				target = target[:27] + "..."
			}
			
			// Truncate long actions
			action := op.Action
			if len(action) > 40 {
				action = action[:37] + "..."
			}
			
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", op.Type, target, action, status)
		}
		w.Flush()
		fmt.Println()
		
		// Print summary
		successCount := 0
		failCount := 0
		for _, op := range result.Operations {
			if op.WouldSucceed {
				successCount++
			} else {
				failCount++
			}
		}
		
		fmt.Printf("Summary: %d operations would succeed, %d would fail\n", successCount, failCount)
	} else {
		fmt.Println("No operations would be performed.")
	}
}

func init() {
	// System validation flags
	validateSystemCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Profile validation flags
	validateProfileCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Config validation flags
	validateConfigCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Dry-run flags
	dryRunCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Add subcommands
	validateCmd.AddCommand(
		validateSystemCmd,
		validateProfileCmd,
		validateConfigCmd,
		dryRunCmd,
	)
}
