package types

import (
    "time"
)

// ProcessInfo represents detailed information about a process
type ProcessInfo struct {
    PID         int32              `json:"pid"`
    PPID        int32              `json:"ppid"`
    Name        string             `json:"name"`
    CommandLine string             `json:"command_line"`
    Executable  string             `json:"executable"`
    Username    string             `json:"username"`
    Status      string             `json:"status"`
    CreateTime  time.Time          `json:"create_time"`
    
    // Resource usage
    CPUPercent    float64 `json:"cpu_percent"`
    MemoryRSS     uint64  `json:"memory_rss"`
    MemoryVMS     uint64  `json:"memory_vms"`
    MemoryPercent float32 `json:"memory_percent"`
    
    // System information
    Priority     int32    `json:"priority"`
    Nice         int32    `json:"nice"`
    NumThreads   int32    `json:"num_threads"`
    NumFds       int32    `json:"num_fds"`
    
    // Network and I/O
    Connections []ConnectionInfo `json:"connections,omitempty"`
    IOCounters  IOInfo          `json:"io_counters"`
    
    // Security context
    UIDs []int32 `json:"uids"`
    GIDs []int32 `json:"gids"`
    
    // Cgroup information
    CgroupPath string `json:"cgroup_path,omitempty"`
}

// ConnectionInfo represents network connection information
type ConnectionInfo struct {
    Fd     uint32 `json:"fd"`
    Family uint32 `json:"family"`
    Type   uint32 `json:"type"`
    Laddr  Addr   `json:"local_addr"`
    Raddr  Addr   `json:"remote_addr"`
    Status string `json:"status"`
}

// Addr represents network address
type Addr struct {
    IP   string `json:"ip"`
    Port uint32 `json:"port"`
}

// IOInfo represents I/O statistics
type IOInfo struct {
    ReadCount  uint64 `json:"read_count"`
    WriteCount uint64 `json:"write_count"`
    ReadBytes  uint64 `json:"read_bytes"`
    WriteBytes uint64 `json:"write_bytes"`
}

// ResourceLimits represents resource limitation configuration
type ResourceLimits struct {
    CPUQuota      int64  `yaml:"cpu_quota" json:"cpu_quota"`           // CPU quota in microseconds
    CPUPeriod     int64  `yaml:"cpu_period" json:"cpu_period"`         // CPU period in microseconds  
    CPUShares     int64  `yaml:"cpu_shares" json:"cpu_shares"`         // CPU shares (relative weight)
    MemoryLimit   int64  `yaml:"memory_limit" json:"memory_limit"`     // Memory limit in bytes
    PidsLimit     int64  `yaml:"pids_limit" json:"pids_limit"`         // Maximum number of processes
    BlkioWeight   uint16 `yaml:"blkio_weight" json:"blkio_weight"`     // Block I/O weight
}

// ProcessMatcher defines how to identify processes
type ProcessMatcher struct {
    Pattern     string `yaml:"pattern" json:"pattern"`
    MatchType   string `yaml:"match_type" json:"match_type"` // name, cmdline, pid, user
    ExactMatch  bool   `yaml:"exact_match" json:"exact_match"`
}

// ThrottleRule combines process matching with resource limits
type ThrottleRule struct {
    Name        string          `yaml:"name" json:"name"`
    Description string          `yaml:"description" json:"description"`
    Matcher     ProcessMatcher  `yaml:"matcher" json:"matcher"`
    Limits      ResourceLimits  `yaml:"limits" json:"limits"`
    Enabled     bool           `yaml:"enabled" json:"enabled"`
    Priority    int            `yaml:"priority" json:"priority"` // Higher priority rules applied first
}

// ProcessDiscovery interface defines process discovery methods
type ProcessDiscovery interface {
    FindByPattern(pattern string, matchType string) ([]*ProcessInfo, error)
    FindByPID(pid int32) (*ProcessInfo, error)
    FindByUser(username string) ([]*ProcessInfo, error)
    GetAllProcesses() ([]*ProcessInfo, error)
    GetProcessInfo(pid int32) (*ProcessInfo, error)
}

// CgroupController interface defines cgroup management methods
type CgroupController interface {
    CreateGroup(name string) error
    DeleteGroup(name string) error
    SetCPULimit(group string, quota, period int64) error
    SetMemoryLimit(group string, limit int64) error
    SetPidsLimit(group string, limit int64) error
    MoveProcess(pid int32, group string) error
    GetProcesses(group string) ([]int32, error)
    GroupExists(name string) bool
    ListGroups() ([]string, error)
}

// Configuration represents the main configuration structure
type Configuration struct {
    Version     string         `yaml:"version" json:"version"`
    DefaultLimits ResourceLimits `yaml:"default_limits" json:"default_limits"`
    Rules       []ThrottleRule `yaml:"rules" json:"rules"`
    Settings    Settings       `yaml:"settings" json:"settings"`
}

// Settings represents application settings
type Settings struct {
    UpdateInterval    time.Duration `yaml:"update_interval" json:"update_interval"`
    LogLevel         string        `yaml:"log_level" json:"log_level"`
    CgroupRoot       string        `yaml:"cgroup_root" json:"cgroup_root"`
    EnableSafetyMode bool          `yaml:"enable_safety_mode" json:"enable_safety_mode"`
    DryRun          bool          `yaml:"dry_run" json:"dry_run"`
}
