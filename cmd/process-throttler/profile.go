package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/yourusername/process-throttler/internal/profile"
	"github.com/yourusername/process-throttler/internal/types"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage configuration profiles",
	Long:  `Manage configuration profiles for different scenarios and environments.`,
}

var profileCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		
		description, _ := cmd.Flags().GetString("description")
		author, _ := cmd.Flags().GetString("author")
		fromFile, _ := cmd.Flags().GetString("from-file")
		
		var p *profile.Profile
		
		if fromFile != "" {
			// Load profile from file
			data, err := os.ReadFile(fromFile)
			if err != nil {
				return fmt.Errorf("failed to read file: %v", err)
			}
			
			p = &profile.Profile{}
			if err := yaml.Unmarshal(data, p); err != nil {
				// Try JSON
				if err := json.Unmarshal(data, p); err != nil {
					return fmt.Errorf("failed to parse profile file: %v", err)
				}
			}
			p.Name = name // Override name
		} else {
			// Create new profile interactively or with defaults
			p = &profile.Profile{
				Name:        name,
				Version:     "1.0",
				Description: description,
				Author:      author,
				Created:     time.Now(),
				Modified:    time.Now(),
				Settings: types.Settings{
					UpdateInterval:   5 * time.Second,
					LogLevel:        "info",
					CgroupRoot:      "/sys/fs/cgroup",
					EnableSafetyMode: true,
				},
			}
		}
		
		if err := profileManager.Create(p); err != nil {
			return fmt.Errorf("failed to create profile: %v", err)
		}
		
		fmt.Printf("Profile '%s' created successfully\n", name)
		return nil
	},
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all profiles",
	Aliases: []string{"ls"},
	RunE: func(cmd *cobra.Command, args []string) error {
		profiles, err := profileManager.List()
		if err != nil {
			return fmt.Errorf("failed to list profiles: %v", err)
		}
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		
		if jsonOutput {
			data, err := json.MarshalIndent(profiles, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal profiles: %v", err)
			}
			fmt.Println(string(data))
		} else {
			if len(profiles) == 0 {
				fmt.Println("No profiles found")
				return nil
			}
			
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tVERSION\tDESCRIPTION\tCREATED\tACTIVE")
			
			for _, p := range profiles {
				active := ""
				if p.Active {
					active = "✓"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					p.Name,
					p.Version,
					truncateString(p.Description, 40),
					p.Created.Format("2006-01-02"),
					active,
				)
			}
			w.Flush()
		}
		
		return nil
	},
}

var profileShowCmd = &cobra.Command{
	Use:   "show [name]",
	Short: "Show profile details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		
		p, err := profileManager.Get(name)
		if err != nil {
			return fmt.Errorf("failed to get profile: %v", err)
		}
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		
		if jsonOutput {
			data, err := json.MarshalIndent(p, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal profile: %v", err)
			}
			fmt.Println(string(data))
		} else {
			data, err := yaml.Marshal(p)
			if err != nil {
				return fmt.Errorf("failed to marshal profile: %v", err)
			}
			fmt.Println(string(data))
		}
		
		return nil
	},
}

var profileEditCmd = &cobra.Command{
	Use:   "edit [name]",
	Short: "Edit an existing profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		
		// Get existing profile
		p, err := profileManager.Get(name)
		if err != nil {
			return fmt.Errorf("failed to get profile: %v", err)
		}
		
		// Update fields if provided
		if desc, _ := cmd.Flags().GetString("description"); desc != "" {
			p.Description = desc
		}
		
		if author, _ := cmd.Flags().GetString("author"); author != "" {
			p.Author = author
		}
		
		// TODO: Add interactive editing or file-based editing
		
		if err := profileManager.Update(name, p); err != nil {
			return fmt.Errorf("failed to update profile: %v", err)
		}
		
		fmt.Printf("Profile '%s' updated successfully\n", name)
		return nil
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:   "delete [name]",
	Short: "Delete a profile",
	Aliases: []string{"rm", "remove"},
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		
		force, _ := cmd.Flags().GetBool("force")
		
		if !force {
			fmt.Printf("Are you sure you want to delete profile '%s'? (y/N): ", name)
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				fmt.Println("Deletion cancelled")
				return nil
			}
		}
		
		if err := profileManager.Delete(name); err != nil {
			return fmt.Errorf("failed to delete profile: %v", err)
		}
		
		fmt.Printf("Profile '%s' deleted successfully\n", name)
		return nil
	},
}

var profileCloneCmd = &cobra.Command{
	Use:   "clone [source] [target]",
	Short: "Clone an existing profile",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := args[0]
		target := args[1]
		
		if err := profileManager.Clone(source, target); err != nil {
			return fmt.Errorf("failed to clone profile: %v", err)
		}
		
		fmt.Printf("Profile '%s' cloned to '%s' successfully\n", source, target)
		return nil
	},
}

var profileActivateCmd = &cobra.Command{
	Use:   "activate [name]",
	Short: "Activate a profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		
		if err := profileManager.Activate(name); err != nil {
			return fmt.Errorf("failed to activate profile: %v", err)
		}
		
		// Get the profile to apply its settings
		p, err := profileManager.Get(name)
		if err != nil {
			return fmt.Errorf("failed to get activated profile: %v", err)
		}
		
		// Apply critical process protection if configured
		if len(p.CriticalProcesses) > 0 && protectionMgr != nil {
			if err := protectionMgr.ProtectProcesses(p.CriticalProcesses); err != nil {
				fmt.Printf("Warning: Failed to apply critical process protection: %v\n", err)
			} else {
				fmt.Printf("Applied protection to %d critical process patterns\n", len(p.CriticalProcesses))
			}
		}
		
		// Apply throttling rules if configured
		if len(p.ThrottlingRules) > 0 {
			appliedCount := 0
			for _, rule := range p.ThrottlingRules {
				if !rule.Enabled {
					continue
				}
				
				// Find matching processes
				processes, err := processDiscovery.FindByPattern(rule.Matcher.Pattern, rule.Matcher.MatchType)
				if err != nil {
					fmt.Printf("Warning: Failed to find processes for rule '%s': %v\n", rule.Name, err)
					continue
				}
				
				// Apply throttling to each process
				for _, proc := range processes {
					groupName := fmt.Sprintf("throttle_%s_%d", rule.Name, proc.PID)
					
					if dryRun {
						fmt.Printf("[DRY RUN] Would throttle process %d (%s) with rule '%s'\n", 
							proc.PID, proc.Name, rule.Name)
					} else {
						// Create cgroup and apply limits
						if err := cgroupManager.CreateGroup(groupName); err != nil {
							fmt.Printf("Warning: Failed to create cgroup for process %d: %v\n", proc.PID, err)
							continue
						}
						
						// Apply CPU limits
						if rule.Limits.CPUQuota > 0 && rule.Limits.CPUPeriod > 0 {
							if err := cgroupManager.SetCPULimit(groupName, rule.Limits.CPUQuota, rule.Limits.CPUPeriod); err != nil {
								fmt.Printf("Warning: Failed to set CPU limit for process %d: %v\n", proc.PID, err)
							}
						}
						
						// Apply memory limits
						if rule.Limits.MemoryLimit > 0 {
							if err := cgroupManager.SetMemoryLimit(groupName, rule.Limits.MemoryLimit); err != nil {
								fmt.Printf("Warning: Failed to set memory limit for process %d: %v\n", proc.PID, err)
							}
						}
						
						// Move process to cgroup
						if err := cgroupManager.MoveProcess(proc.PID, groupName); err != nil {
							fmt.Printf("Warning: Failed to move process %d to cgroup: %v\n", proc.PID, err)
						} else {
							appliedCount++
						}
					}
				}
			}
			
			if !dryRun {
				fmt.Printf("Applied %d throttling rules to processes\n", appliedCount)
			}
		}
		
		fmt.Printf("Profile '%s' activated successfully\n", name)
		return nil
	},
}

var profileExportCmd = &cobra.Command{
	Use:   "export [name] [file]",
	Short: "Export a profile to a file",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		outputPath := args[1]
		
		format, _ := cmd.Flags().GetString("format")
		if format == "" {
			// Determine format from file extension
			if len(outputPath) > 5 && outputPath[len(outputPath)-5:] == ".json" {
				format = "json"
			} else {
				format = "yaml"
			}
		}
		
		if err := profileManager.Export(name, outputPath, format); err != nil {
			return fmt.Errorf("failed to export profile: %v", err)
		}
		
		fmt.Printf("Profile '%s' exported to %s\n", name, outputPath)
		return nil
	},
}

var profileImportCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import a profile from a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]
		
		if err := profileManager.Import(inputPath); err != nil {
			return fmt.Errorf("failed to import profile: %v", err)
		}
		
		fmt.Println("Profile imported successfully")
		return nil
	},
}

var profileDiffCmd = &cobra.Command{
	Use:   "diff [profile1] [profile2]",
	Short: "Compare two profiles",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		profile1 := args[0]
		profile2 := args[1]
		
		diff, err := profileManager.Diff(profile1, profile2)
		if err != nil {
			return fmt.Errorf("failed to compare profiles: %v", err)
		}
		
		jsonOutput, _ := cmd.Flags().GetBool("json")
		
		if jsonOutput {
			data, err := json.MarshalIndent(diff, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal diff: %v", err)
			}
			fmt.Println(string(data))
		} else {
			if len(diff) == 0 {
				fmt.Println("Profiles are identical")
			} else {
				fmt.Printf("Differences between '%s' and '%s':\n", profile1, profile2)
				for key, value := range diff {
					fmt.Printf("  %s: %v\n", key, value)
				}
			}
		}
		
		return nil
	},
}

var profileValidateCmd = &cobra.Command{
	Use:   "validate [name]",
	Short: "Validate a profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		
		if err := profileManager.Validate(name); err != nil {
			return fmt.Errorf("profile validation failed: %v", err)
		}
		
		fmt.Printf("Profile '%s' is valid\n", name)
		return nil
	},
}

func init() {
	// Profile create flags
	profileCreateCmd.Flags().String("description", "", "profile description")
	profileCreateCmd.Flags().String("author", "", "profile author")
	profileCreateCmd.Flags().String("from-file", "", "create profile from file")
	
	// Profile list flags
	profileListCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Profile show flags
	profileShowCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Profile edit flags
	profileEditCmd.Flags().String("description", "", "new description")
	profileEditCmd.Flags().String("author", "", "new author")
	
	// Profile delete flags
	profileDeleteCmd.Flags().BoolP("force", "f", false, "force deletion without confirmation")
	
	// Profile export flags
	profileExportCmd.Flags().String("format", "", "export format (yaml or json)")
	
	// Profile diff flags
	profileDiffCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	
	// Add subcommands
	profileCmd.AddCommand(
		profileCreateCmd,
		profileListCmd,
		profileShowCmd,
		profileEditCmd,
		profileDeleteCmd,
		profileCloneCmd,
		profileActivateCmd,
		profileExportCmd,
		profileImportCmd,
		profileDiffCmd,
		profileValidateCmd,
	)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
