package main

import (
    "fmt"
    "os"
    "strconv"
    "strings"
    "time"
    
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
    
    "github.com/yourusername/process-throttler/internal/audit"
    "github.com/yourusername/process-throttler/internal/backup"
    "github.com/yourusername/process-throttler/internal/cgroup"
    "github.com/yourusername/process-throttler/internal/config"
    "github.com/yourusername/process-throttler/internal/discovery"
    "github.com/yourusername/process-throttler/internal/emergency"
    "github.com/yourusername/process-throttler/internal/metrics"
    "github.com/yourusername/process-throttler/internal/profile"
    "github.com/yourusername/process-throttler/internal/protection"
    "github.com/yourusername/process-throttler/internal/throttle"
    "github.com/yourusername/process-throttler/internal/types"
    "github.com/yourusername/process-throttler/internal/webhook"
)

var (
    cfgFile    string
    cgroupRoot string
    dryRun     bool
    verbose    bool
    
    // Global instances
    processDiscovery *discovery.ProcessDiscoveryEngine
    cgroupManager    *cgroup.CgroupManager
    configManager    *config.ConfigManager
    profileManager   *profile.Manager
    protectionMgr    *protection.ProtectionManager
)

var rootCmd = &cobra.Command{
    Use:   "process-throttler",
    Short: "A tool to discover and throttle system processes",
    Long: `Process Throttler is a command-line tool for discovering, monitoring,
and controlling system processes using Linux cgroups.

It provides fine-grained resource control over CPU, memory, and I/O usage
of running processes while maintaining system stability.`,
    
    PersistentPreRun: func(cmd *cobra.Command, args []string) {
        initializeComponents()
    },
}

var discoverCmd = &cobra.Command{
    Use:   "discover [pattern]",
    Short: "Discover processes by pattern",
    Long: `Discover running processes that match a given pattern.
    
The pattern can match against:
- Process name (default)
- Command line arguments
- Process ID
- Username

Examples:
  process-throttler discover nginx
  process-throttler discover "backup.*" --match-type name
  process-throttler discover --match-type user john`,
    
    Args: cobra.MaximumNArgs(1),
    Run:  runDiscoverCmd,
}

var listCmd = &cobra.Command{
    Use:   "list",
    Short: "List all running processes",
    Long:  `List all running processes with detailed information.`,
    Run:   runListCmd,
}

var throttleCmd = &cobra.Command{
    Use:   "throttle",
    Short: "Apply resource throttling to processes",
    Long: `Apply CPU, memory, and I/O limits to processes matching specified criteria.

Examples:
  process-throttler throttle --pattern "backup.*" --cpu 30% --memory 1GB
  process-throttler throttle --pid 1234 --memory 512MB`,
    
    Run: runThrottleCmd,
}

var statusCmd = &cobra.Command{
    Use:   "status",
    Short: "Show throttling status",
    Long:  `Display current throttling status and cgroup information.`,
    Run:   runStatusCmd,
}

var configCmd = &cobra.Command{
    Use:   "config",
    Short: "Configuration management",
    Long:  `Manage configuration files and settings.`,
}

var configShowCmd = &cobra.Command{
    Use:   "show",
    Short: "Show current configuration",
    Long:  `Display the current configuration.`,
    Run:   runConfigShowCmd,
}

var configExampleCmd = &cobra.Command{
    Use:   "example [path]",
    Short: "Generate example configuration",
    Long:  `Generate an example configuration file.`,
    Args:  cobra.MaximumNArgs(1),
    Run:   runConfigExampleCmd,
}

func init() {
    // Global flags
    rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/process-throttler/config.yaml)")
    rootCmd.PersistentFlags().StringVar(&cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "cgroup root directory")
    rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "show what would be done without applying changes")
    rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
    
    // Discover command flags
    discoverCmd.Flags().String("match-type", "", "match type: name, cmdline, pid, user")
    discoverCmd.Flags().BoolP("exact", "e", false, "exact match")
    discoverCmd.Flags().BoolP("json", "j", false, "output in JSON format")
    
    // List command flags
    listCmd.Flags().BoolP("json", "j", false, "output in JSON format")
    listCmd.Flags().StringP("sort", "s", "pid", "sort by: pid, name, cpu, memory")
    listCmd.Flags().IntP("limit", "l", 0, "limit number of results")
    
    // Throttle command flags
    throttleCmd.Flags().String("pattern", "", "process pattern to match")
    throttleCmd.Flags().String("match-type", "name", "match type: name, cmdline, pid, user")
    throttleCmd.Flags().String("pid", "", "specific process ID")
    throttleCmd.Flags().String("cpu", "", "CPU limit (e.g., 50%, 0.5)")
    throttleCmd.Flags().String("memory", "", "memory limit (e.g., 1GB, 512MB)")
    throttleCmd.Flags().String("pids", "", "process limit (e.g., 100)")
    throttleCmd.Flags().String("group", "", "cgroup name (auto-generated if not specified)")
    
    // Status command flags
    statusCmd.Flags().BoolP("json", "j", false, "output in JSON format")
    statusCmd.Flags().StringP("group", "g", "", "show specific cgroup")
    
    // Add subcommands
    configCmd.AddCommand(configShowCmd, configExampleCmd)
    rootCmd.AddCommand(discoverCmd, listCmd, throttleCmd, statusCmd, configCmd, profileCmd, validateCmd, auditCmd, backupCmd, emergencyCmd, dynamicCmd, metricsCmd, webhookCmd)
    
    // Bind flags to viper
    viper.BindPFlag("cgroup_root", rootCmd.PersistentFlags().Lookup("cgroup-root"))
    viper.BindPFlag("dry_run", rootCmd.PersistentFlags().Lookup("dry-run"))
    viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

func initializeComponents() {
    // Initialize process discovery
    processDiscovery = discovery.NewProcessDiscoveryEngine()
    
    // Initialize cgroup manager
    var err error
    cgroupManager, err = cgroup.NewCgroupManager(cgroupRoot)
    if err != nil {
        fmt.Printf("Warning: Failed to initialize cgroup manager: %v\n", err)
    }
    
    // Initialize config manager
    if cfgFile == "" {
        cfgFile = "/etc/process-throttler/config.yaml"
        // Try user config directory as fallback
        if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
            if homeDir, err := os.UserHomeDir(); err == nil {
                cfgFile = homeDir + "/.config/process-throttler/config.yaml"
            }
        }
    }
    
    configManager = config.NewConfigManager(cfgFile)
    
    // Initialize profile manager
    var err2 error
    profileManager, err2 = profile.NewManager("")
    if err2 != nil {
        fmt.Printf("Warning: Failed to initialize profile manager: %v\n", err2)
    }
    
    // Initialize protection manager
    if processDiscovery != nil {
        protectionMgr = protection.NewProtectionManager(processDiscovery)
    }
    
    // Initialize audit logger
    var err3 error
    auditLogger, err3 = audit.NewLogger("")
    if err3 != nil {
        fmt.Printf("Warning: Failed to initialize audit logger: %v\n", err3)
    }
    
    // Initialize backup manager
    if auditLogger != nil {
        backupManager, err3 = backup.NewBackupManager("", auditLogger)
        if err3 != nil {
            fmt.Printf("Warning: Failed to initialize backup manager: %v\n", err3)
        }
    }
    
    // Initialize emergency stop manager
    if cgroupManager != nil && protectionMgr != nil {
        stopManager = emergency.NewStopManager(cgroupManager, protectionMgr, backupManager, auditLogger)
    }
    
    // Initialize dynamic throttler
    if cgroupManager != nil && processDiscovery != nil && auditLogger != nil {
        dynamicThrottler = throttle.NewDynamicThrottler(cgroupManager, processDiscovery, auditLogger)
    }
    
    // Initialize metrics collector
    metricsCollector = metrics.NewCollector()
    
    // Initialize webhook notifier
    webhookNotifier = webhook.NewNotifier(5)
}

func runDiscoverCmd(cmd *cobra.Command, args []string) {
    pattern := ""
    if len(args) > 0 {
        pattern = args[0]
    }
    
    if pattern == "" {
        fmt.Println("Error: pattern is required")
        os.Exit(1)
    }
    
    matchType, _ := cmd.Flags().GetString("match-type")
    exact, _ := cmd.Flags().GetBool("exact")
    jsonOutput, _ := cmd.Flags().GetBool("json")
    
    // If exact match is requested, modify pattern
    if exact {
        pattern = "^" + pattern + "$"
    }
    
    processes, err := processDiscovery.FindByPattern(pattern, matchType)
    if err != nil {
        fmt.Printf("Error discovering processes: %v\n", err)
        os.Exit(1)
    }
    
    if len(processes) == 0 {
        fmt.Println("No processes found matching pattern:", pattern)
        return
    }
    
    if jsonOutput {
        // TODO: Implement JSON output
        fmt.Println("JSON output not yet implemented")
        return
    }
    
    // Print results in table format
    fmt.Printf("Found %d processes matching pattern '%s':\n\n", len(processes), pattern)
    fmt.Printf("%-8s %-8s %-20s %-8s %-8s %s\n", "PID", "PPID", "NAME", "CPU%", "MEM%", "COMMAND")
    fmt.Println(strings.Repeat("-", 80))
    
    for _, proc := range processes {
        fmt.Printf("%-8d %-8d %-20s %-8.1f %-8.1f %s\n",
            proc.PID,
            proc.PPID,
            truncateString(proc.Name, 20),
            proc.CPUPercent,
            proc.MemoryPercent,
            truncateString(proc.CommandLine, 40),
        )
    }
}

func runListCmd(cmd *cobra.Command, args []string) {
    jsonOutput, _ := cmd.Flags().GetBool("json")
    sortBy, _ := cmd.Flags().GetString("sort")
    limit, _ := cmd.Flags().GetInt("limit")
    
    processes, err := processDiscovery.GetAllProcesses()
    if err != nil {
        fmt.Printf("Error getting process list: %v\n", err)
        os.Exit(1)
    }
    
    // TODO: Implement sorting
    _ = sortBy
    
    // Apply limit if specified
    if limit > 0 && len(processes) > limit {
        processes = processes[:limit]
    }
    
    if jsonOutput {
        // TODO: Implement JSON output
        fmt.Println("JSON output not yet implemented")
        return
    }
    
    // Print results
    fmt.Printf("Total processes: %d\n\n", len(processes))
    fmt.Printf("%-8s %-20s %-10s %-8s %-8s %s\n", "PID", "NAME", "USER", "CPU%", "MEM%", "COMMAND")
    fmt.Println(strings.Repeat("-", 90))
    
    for _, proc := range processes {
        fmt.Printf("%-8d %-20s %-10s %-8.1f %-8.1f %s\n",
            proc.PID,
            truncateString(proc.Name, 20),
            truncateString(proc.Username, 10),
            proc.CPUPercent,
            proc.MemoryPercent,
            truncateString(proc.CommandLine, 30),
        )
    }
}

func runThrottleCmd(cmd *cobra.Command, args []string) {
    pattern, _ := cmd.Flags().GetString("pattern")
    matchType, _ := cmd.Flags().GetString("match-type")
    pidStr, _ := cmd.Flags().GetString("pid")
    cpuLimit, _ := cmd.Flags().GetString("cpu")
    memoryLimit, _ := cmd.Flags().GetString("memory")
    pidsLimit, _ := cmd.Flags().GetString("pids")
    groupName, _ := cmd.Flags().GetString("group")
    
    if pattern == "" && pidStr == "" {
        fmt.Println("Error: either --pattern or --pid must be specified")
        os.Exit(1)
    }
    
    if cpuLimit == "" && memoryLimit == "" && pidsLimit == "" {
        fmt.Println("Error: at least one resource limit must be specified")
        os.Exit(1)
    }
    
    var processes []*types.ProcessInfo
    var err error
    
    if pidStr != "" {
        // Handle specific PID
        pid, err := strconv.ParseInt(pidStr, 10, 32)
        if err != nil {
            fmt.Printf("Error: invalid PID '%s': %v\n", pidStr, err)
            os.Exit(1)
        }
        
        proc, err := processDiscovery.FindByPID(int32(pid))
        if err != nil {
            fmt.Printf("Error: process with PID %d not found: %v\n", pid, err)
            os.Exit(1)
        }
        
        processes = []*types.ProcessInfo{proc}
    } else {
        // Handle pattern matching
        processes, err = processDiscovery.FindByPattern(pattern, matchType)
        if err != nil {
            fmt.Printf("Error discovering processes: %v\n", err)
            os.Exit(1)
        }
        
        if len(processes) == 0 {
            fmt.Printf("No processes found matching pattern: %s\n", pattern)
            return
        }
    }
    
    // Parse resource limits
    limits := types.ResourceLimits{}
    
    if cpuLimit != "" {
        quota, period, err := parseCPULimit(cpuLimit)
        if err != nil {
            fmt.Printf("Error parsing CPU limit '%s': %v\n", cpuLimit, err)
            os.Exit(1)
        }
        limits.CPUQuota = quota
        limits.CPUPeriod = period
    }
    
    if memoryLimit != "" {
        limit, err := parseMemoryLimit(memoryLimit)
        if err != nil {
            fmt.Printf("Error parsing memory limit '%s': %v\n", memoryLimit, err)
            os.Exit(1)
        }
        limits.MemoryLimit = limit
    }
    
    if pidsLimit != "" {
        limit, err := strconv.ParseInt(pidsLimit, 10, 64)
        if err != nil {
            fmt.Printf("Error parsing pids limit '%s': %v\n", pidsLimit, err)
            os.Exit(1)
        }
        limits.PidsLimit = limit
    }
    
    // Generate group name if not specified
    if groupName == "" {
        if pidStr != "" {
            groupName = fmt.Sprintf("throttle-pid-%s", pidStr)
        } else {
            groupName = fmt.Sprintf("throttle-pattern-%d", time.Now().Unix())
        }
    }
    
    fmt.Printf("Applying throttling to %d processes...\n", len(processes))
    
    if dryRun {
        fmt.Println("[DRY RUN] Would create cgroup:", groupName)
        if limits.CPUQuota > 0 {
            fmt.Printf("[DRY RUN] Would set CPU limit: %d/%d\n", limits.CPUQuota, limits.CPUPeriod)
        }
        if limits.MemoryLimit > 0 {
            fmt.Printf("[DRY RUN] Would set memory limit: %d bytes\n", limits.MemoryLimit)
        }
        if limits.PidsLimit > 0 {
            fmt.Printf("[DRY RUN] Would set pids limit: %d\n", limits.PidsLimit)
        }
        
        for _, proc := range processes {
            fmt.Printf("[DRY RUN] Would move process %d (%s) to cgroup\n", proc.PID, proc.Name)
        }
        return
    }
    
    // Create cgroup
    fmt.Printf("Creating cgroup: %s\n", groupName)
    if err := cgroupManager.CreateGroup(groupName); err != nil {
        fmt.Printf("Error creating cgroup: %v\n", err)
        os.Exit(1)
    }
    
    // Apply limits
    if limits.CPUQuota > 0 {
        fmt.Printf("Setting CPU limit: %.1f%%\n", float64(limits.CPUQuota)/float64(limits.CPUPeriod)*100)
        if err := cgroupManager.SetCPULimit(groupName, limits.CPUQuota, limits.CPUPeriod); err != nil {
            fmt.Printf("Error setting CPU limit: %v\n", err)
        }
    }
    
    if limits.MemoryLimit > 0 {
        fmt.Printf("Setting memory limit: %s\n", formatBytes(limits.MemoryLimit))
        if err := cgroupManager.SetMemoryLimit(groupName, limits.MemoryLimit); err != nil {
            fmt.Printf("Error setting memory limit: %v\n", err)
        }
    }
    
    if limits.PidsLimit > 0 {
        fmt.Printf("Setting pids limit: %d\n", limits.PidsLimit)
        if err := cgroupManager.SetPidsLimit(groupName, limits.PidsLimit); err != nil {
            fmt.Printf("Error setting pids limit: %v\n", err)
        }
    }
    
    // Move processes to cgroup
    fmt.Printf("Moving %d processes to cgroup...\n", len(processes))
    for _, proc := range processes {
        fmt.Printf("  Moving PID %d (%s)...", proc.PID, proc.Name)
        if err := cgroupManager.MoveProcess(proc.PID, groupName); err != nil {
            fmt.Printf(" failed: %v\n", err)
        } else {
            fmt.Printf(" done\n")
        }
    }
    
    fmt.Printf("Throttling applied successfully to group: %s\n", groupName)
}

func runStatusCmd(cmd *cobra.Command, args []string) {
    jsonOutput, _ := cmd.Flags().GetBool("json")
    specificGroup, _ := cmd.Flags().GetString("group")
    
    if jsonOutput {
        fmt.Println("JSON output not yet implemented")
        return
    }
    
    if specificGroup != "" {
        // Show specific cgroup status
        if !cgroupManager.GroupExists(specificGroup) {
            fmt.Printf("Cgroup '%s' does not exist\n", specificGroup)
            os.Exit(1)
        }
        
        pids, err := cgroupManager.GetProcesses(specificGroup)
        if err != nil {
            fmt.Printf("Error getting processes for group '%s': %v\n", specificGroup, err)
            os.Exit(1)
        }
        
        fmt.Printf("Cgroup: %s\n", specificGroup)
        fmt.Printf("Processes: %d\n\n", len(pids))
        
        if len(pids) > 0 {
            fmt.Printf("%-8s %-20s %-8s %-8s %s\n", "PID", "NAME", "CPU%", "MEM%", "COMMAND")
            fmt.Println(strings.Repeat("-", 70))
            
            for _, pid := range pids {
                proc, err := processDiscovery.GetProcessInfo(pid)
                if err != nil {
                    continue
                }
                
                fmt.Printf("%-8d %-20s %-8.1f %-8.1f %s\n",
                    proc.PID,
                    truncateString(proc.Name, 20),
                    proc.CPUPercent,
                    proc.MemoryPercent,
                    truncateString(proc.CommandLine, 30),
                )
            }
        }
        
        return
    }
    
    // Show all cgroups
    groups, err := cgroupManager.ListGroups()
    if err != nil {
        fmt.Printf("Error listing cgroups: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Printf("Total cgroups: %d\n\n", len(groups))
    
    if len(groups) == 0 {
        fmt.Println("No custom cgroups found")
        return
    }
    
    fmt.Printf("%-30s %-10s\n", "CGROUP", "PROCESSES")
    fmt.Println(strings.Repeat("-", 45))
    
    for _, group := range groups {
        pids, err := cgroupManager.GetProcesses(group)
        if err != nil {
            continue
        }
        
        fmt.Printf("%-30s %-10d\n", truncateString(group, 30), len(pids))
    }
}

func runConfigShowCmd(cmd *cobra.Command, args []string) {
    config, err := configManager.LoadConfig()
    if err != nil {
        fmt.Printf("Error loading configuration: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Printf("Configuration file: %s\n\n", cfgFile)
    fmt.Printf("Version: %s\n", config.Version)
    fmt.Printf("Update interval: %s\n", config.Settings.UpdateInterval)
    fmt.Printf("Log level: %s\n", config.Settings.LogLevel)
    fmt.Printf("Cgroup root: %s\n", config.Settings.CgroupRoot)
    fmt.Printf("Safety mode: %t\n", config.Settings.EnableSafetyMode)
    fmt.Printf("Dry run: %t\n", config.Settings.DryRun)
    
    fmt.Printf("\nDefault limits:\n")
    fmt.Printf("  CPU quota: %d (%.1f%%)\n", config.DefaultLimits.CPUQuota, 
              float64(config.DefaultLimits.CPUQuota)/float64(config.DefaultLimits.CPUPeriod)*100)
    fmt.Printf("  Memory limit: %s\n", formatBytes(config.DefaultLimits.MemoryLimit))
    fmt.Printf("  Pids limit: %d\n", config.DefaultLimits.PidsLimit)
    
    fmt.Printf("\nRules: %d\n", len(config.Rules))
    for i, rule := range config.Rules {
        status := "disabled"
        if rule.Enabled {
            status = "enabled"
        }
        fmt.Printf("  %d. %s (%s) - Pattern: %s\n", i+1, rule.Name, status, rule.Matcher.Pattern)
    }
}

func runConfigExampleCmd(cmd *cobra.Command, args []string) {
    path := "example-config.yaml"
    if len(args) > 0 {
        path = args[0]
    }
    
    if err := config.CreateExampleConfig(path); err != nil {
        fmt.Printf("Error creating example config: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Printf("Example configuration created: %s\n", path)
}

// Helper functions

func parseCPULimit(limit string) (quota, period int64, err error) {
    period = 100000 // Default 100ms period
    
    if strings.HasSuffix(limit, "%") {
        // Parse percentage
        percentStr := strings.TrimSuffix(limit, "%")
        percent, err := strconv.ParseFloat(percentStr, 64)
        if err != nil {
            return 0, 0, fmt.Errorf("invalid percentage: %s", limit)
        }
        
        if percent <= 0 || percent > 100 {
            return 0, 0, fmt.Errorf("percentage must be between 0 and 100")
        }
        
        quota = int64(float64(period) * percent / 100.0)
        return quota, period, nil
    }
    
    // Parse decimal (e.g., 0.5 for 50%)
    decimal, err := strconv.ParseFloat(limit, 64)
    if err != nil {
        return 0, 0, fmt.Errorf("invalid CPU limit format: %s", limit)
    }
    
    if decimal <= 0 || decimal > 1 {
        return 0, 0, fmt.Errorf("decimal CPU limit must be between 0 and 1")
    }
    
    quota = int64(float64(period) * decimal)
    return quota, period, nil
}

func parseMemoryLimit(limit string) (int64, error) {
    // Parse memory limit with units (GB, MB, KB, B)
    limit = strings.ToUpper(limit)
    
    var multiplier int64 = 1
    var numStr string
    
    if strings.HasSuffix(limit, "GB") {
        multiplier = 1024 * 1024 * 1024
        numStr = strings.TrimSuffix(limit, "GB")
    } else if strings.HasSuffix(limit, "MB") {
        multiplier = 1024 * 1024
        numStr = strings.TrimSuffix(limit, "MB")
    } else if strings.HasSuffix(limit, "KB") {
        multiplier = 1024
        numStr = strings.TrimSuffix(limit, "KB")
    } else if strings.HasSuffix(limit, "B") {
        multiplier = 1
        numStr = strings.TrimSuffix(limit, "B")
    } else {
        // No unit, assume bytes
        numStr = limit
    }
    
    num, err := strconv.ParseInt(numStr, 10, 64)
    if err != nil {
        return 0, fmt.Errorf("invalid memory limit: %s", limit)
    }
    
    if num <= 0 {
        return 0, fmt.Errorf("memory limit must be positive")
    }
    
    return num * multiplier, nil
}

func formatBytes(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return fmt.Sprintf("%d B", bytes)
    }
    div, exp := int64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
