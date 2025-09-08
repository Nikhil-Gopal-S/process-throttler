package config

import (
    "fmt"
    "os"
    "path/filepath"
    "time"
    
    "github.com/spf13/viper"
    "gopkg.in/yaml.v3"
    
    "github.com/yourusername/process-throttler/internal/types"
)

// ConfigManager handles configuration loading and management
type ConfigManager struct {
    configPath string
    config     *types.Configuration
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(configPath string) *ConfigManager {
    return &ConfigManager{
        configPath: configPath,
    }
}

// LoadConfig loads configuration from file
func (cm *ConfigManager) LoadConfig() (*types.Configuration, error) {
    if cm.configPath == "" {
        return cm.getDefaultConfig(), nil
    }
    
    // Check if config file exists
    if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
        return nil, fmt.Errorf("configuration file not found: %s", cm.configPath)
    }
    
    // Initialize viper
    viper.SetConfigFile(cm.configPath)
    
    // Set defaults
    cm.setDefaults()
    
    // Read config
    if err := viper.ReadInConfig(); err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }
    
    // Unmarshal into struct
    var config types.Configuration
    if err := viper.Unmarshal(&config); err != nil {
        return nil, fmt.Errorf("failed to unmarshal config: %w", err)
    }
    
    // Validate configuration
    if err := cm.validateConfig(&config); err != nil {
        return nil, fmt.Errorf("invalid configuration: %w", err)
    }
    
    cm.config = &config
    return &config, nil
}

// SaveConfig saves configuration to file
func (cm *ConfigManager) SaveConfig(config *types.Configuration) error {
    // Create directory if it doesn't exist
    dir := filepath.Dir(cm.configPath)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return fmt.Errorf("failed to create config directory: %w", err)
    }
    
    // Marshal to YAML
    data, err := yaml.Marshal(config)
    if err != nil {
        return fmt.Errorf("failed to marshal config: %w", err)
    }
    
    // Write to file
    if err := os.WriteFile(cm.configPath, data, 0644); err != nil {
        return fmt.Errorf("failed to write config file: %w", err)
    }
    
    return nil
}

// GetConfig returns the loaded configuration
func (cm *ConfigManager) GetConfig() *types.Configuration {
    return cm.config
}

// setDefaults sets default configuration values
func (cm *ConfigManager) setDefaults() {
    viper.SetDefault("version", "1.0")
    viper.SetDefault("settings.update_interval", "5s")
    viper.SetDefault("settings.log_level", "info")
    viper.SetDefault("settings.cgroup_root", "/sys/fs/cgroup")
    viper.SetDefault("settings.enable_safety_mode", true)
    viper.SetDefault("settings.dry_run", false)
    
    // Default resource limits
    viper.SetDefault("default_limits.cpu_quota", 100000) // 100ms out of 100ms (100%)
    viper.SetDefault("default_limits.cpu_period", 100000) // 100ms
    viper.SetDefault("default_limits.cpu_shares", 1024) // Default shares
    viper.SetDefault("default_limits.memory_limit", 1073741824) // 1GB
    viper.SetDefault("default_limits.pids_limit", 1000)
    viper.SetDefault("default_limits.blkio_weight", 500) // Default weight
}

// getDefaultConfig returns a default configuration
func (cm *ConfigManager) getDefaultConfig() *types.Configuration {
    return &types.Configuration{
        Version: "1.0",
        DefaultLimits: types.ResourceLimits{
            CPUQuota:    100000, // 100% (100ms out of 100ms)
            CPUPeriod:   100000, // 100ms
            CPUShares:   1024,   // Default shares
            MemoryLimit: 1073741824, // 1GB
            PidsLimit:   1000,
            BlkioWeight: 500,
        },
        Rules: []types.ThrottleRule{},
        Settings: types.Settings{
            UpdateInterval:    5 * time.Second,
            LogLevel:         "info",
            CgroupRoot:       "/sys/fs/cgroup",
            EnableSafetyMode: true,
            DryRun:          false,
        },
    }
}

// validateConfig validates the configuration
func (cm *ConfigManager) validateConfig(config *types.Configuration) error {
    // Validate version
    if config.Version == "" {
        return fmt.Errorf("version is required")
    }
    
    // Validate resource limits
    if config.DefaultLimits.CPUQuota < 0 {
        return fmt.Errorf("cpu_quota cannot be negative")
    }
    
    if config.DefaultLimits.CPUPeriod <= 0 {
        return fmt.Errorf("cpu_period must be positive")
    }
    
    if config.DefaultLimits.MemoryLimit < 0 {
        return fmt.Errorf("memory_limit cannot be negative")
    }
    
    // Validate rules
    for i, rule := range config.Rules {
        if err := cm.validateRule(&rule); err != nil {
            return fmt.Errorf("rule %d is invalid: %w", i, err)
        }
    }
    
    // Validate settings
    if config.Settings.UpdateInterval < time.Second {
        return fmt.Errorf("update_interval must be at least 1 second")
    }
    
    // Validate cgroup root exists
    if _, err := os.Stat(config.Settings.CgroupRoot); os.IsNotExist(err) {
        return fmt.Errorf("cgroup_root directory does not exist: %s", config.Settings.CgroupRoot)
    }
    
    return nil
}

// validateRule validates a single throttle rule
func (cm *ConfigManager) validateRule(rule *types.ThrottleRule) error {
    // Validate name
    if rule.Name == "" {
        return fmt.Errorf("rule name is required")
    }
    
    // Validate matcher
    if rule.Matcher.Pattern == "" {
        return fmt.Errorf("matcher pattern is required")
    }
    
    // Validate match type
    validMatchTypes := []string{"name", "cmdline", "pid", "user", ""}
    matchTypeValid := false
    for _, validType := range validMatchTypes {
        if rule.Matcher.MatchType == validType {
            matchTypeValid = true
            break
        }
    }
    
    if !matchTypeValid {
        return fmt.Errorf("invalid match_type: %s", rule.Matcher.MatchType)
    }
    
    // Validate resource limits
    if rule.Limits.CPUQuota < 0 {
        return fmt.Errorf("cpu_quota cannot be negative")
    }
    
    if rule.Limits.CPUPeriod <= 0 {
        return fmt.Errorf("cpu_period must be positive")
    }
    
    if rule.Limits.MemoryLimit < 0 {
        return fmt.Errorf("memory_limit cannot be negative")
    }
    
    return nil
}

// CreateExampleConfig creates an example configuration file
func CreateExampleConfig(path string) error {
    config := &types.Configuration{
        Version: "1.0",
        DefaultLimits: types.ResourceLimits{
            CPUQuota:    50000,  // 50% CPU
            CPUPeriod:   100000, // 100ms
            CPUShares:   512,    // Lower priority
            MemoryLimit: 536870912, // 512MB
            PidsLimit:   500,
            BlkioWeight: 300,
        },
        Rules: []types.ThrottleRule{
            {
                Name:        "limit-backup-processes",
                Description: "Limit backup processes to 30% CPU and 1GB memory",
                Matcher: types.ProcessMatcher{
                    Pattern:    "backup.*",
                    MatchType:  "name",
                    ExactMatch: false,
                },
                Limits: types.ResourceLimits{
                    CPUQuota:    30000,      // 30% CPU
                    CPUPeriod:   100000,     // 100ms
                    MemoryLimit: 1073741824, // 1GB
                    PidsLimit:   100,
                },
                Enabled:  true,
                Priority: 1,
            },
            {
                Name:        "limit-heavy-processes",
                Description: "Limit processes consuming too much memory",
                Matcher: types.ProcessMatcher{
                    Pattern:    "chrome|firefox",
                    MatchType:  "name",
                    ExactMatch: false,
                },
                Limits: types.ResourceLimits{
                    CPUQuota:    80000,      // 80% CPU
                    CPUPeriod:   100000,     // 100ms
                    MemoryLimit: 2147483648, // 2GB
                    PidsLimit:   200,
                },
                Enabled:  false, // Disabled by default
                Priority: 2,
            },
        },
        Settings: types.Settings{
            UpdateInterval:    5 * time.Second,
            LogLevel:         "info",
            CgroupRoot:       "/sys/fs/cgroup",
            EnableSafetyMode: true,
            DryRun:          false,
        },
    }
    
    cm := &ConfigManager{configPath: path}
    return cm.SaveConfig(config)
}
