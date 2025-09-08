package discovery

import (
    "fmt"
    "regexp"
    "strings"
    "time"
    
    "github.com/shirou/gopsutil/v3/process"
    "github.com/yourusername/process-throttler/internal/types"
    "github.com/yourusername/process-throttler/pkg/errors"
)

// ProcessDiscoveryEngine implements the ProcessDiscovery interface
type ProcessDiscoveryEngine struct {
    // Can add caching or other optimizations later
}

// NewProcessDiscoveryEngine creates a new process discovery engine
func NewProcessDiscoveryEngine() *ProcessDiscoveryEngine {
    return &ProcessDiscoveryEngine{}
}

// FindByPattern finds processes matching a given pattern
func (pde *ProcessDiscoveryEngine) FindByPattern(pattern string, matchType string) ([]*types.ProcessInfo, error) {
    allProcesses, err := pde.GetAllProcesses()
    if err != nil {
        return nil, fmt.Errorf("failed to get all processes: %w", err)
    }
    
    regex, err := regexp.Compile(pattern)
    if err != nil {
        return nil, fmt.Errorf("invalid pattern '%s': %w", pattern, err)
    }
    
    var matchedProcesses []*types.ProcessInfo
    
    for _, proc := range allProcesses {
        var matched bool
        
        switch matchType {
        case "name":
            matched = regex.MatchString(proc.Name)
        case "cmdline":
            matched = regex.MatchString(proc.CommandLine)
        case "user":
            matched = regex.MatchString(proc.Username)
        case "pid":
            matched = regex.MatchString(fmt.Sprintf("%d", proc.PID))
        default:
            // Default: match against name and command line
            matched = regex.MatchString(proc.Name) || regex.MatchString(proc.CommandLine)
        }
        
        if matched {
            matchedProcesses = append(matchedProcesses, proc)
        }
    }
    
    return matchedProcesses, nil
}

// FindByPID finds a process by its PID
func (pde *ProcessDiscoveryEngine) FindByPID(pid int32) (*types.ProcessInfo, error) {
    return pde.GetProcessInfo(pid)
}

// FindByUser finds all processes belonging to a specific user
func (pde *ProcessDiscoveryEngine) FindByUser(username string) ([]*types.ProcessInfo, error) {
    return pde.FindByPattern(fmt.Sprintf("^%s$", regexp.QuoteMeta(username)), "user")
}

// GetAllProcesses retrieves information about all running processes
func (pde *ProcessDiscoveryEngine) GetAllProcesses() ([]*types.ProcessInfo, error) {
    pids, err := process.Pids()
    if err != nil {
        return nil, fmt.Errorf("failed to get process list: %w", err)
    }
    
    var processes []*types.ProcessInfo
    
    for _, pid := range pids {
        procInfo, err := pde.GetProcessInfo(pid)
        if err != nil {
            // Skip processes we can't access (common for system processes)
            continue
        }
        processes = append(processes, procInfo)
    }
    
    return processes, nil
}

// GetProcessInfo retrieves detailed information about a specific process
func (pde *ProcessDiscoveryEngine) GetProcessInfo(pid int32) (*types.ProcessInfo, error) {
    proc, err := process.NewProcess(pid)
    if err != nil {
        return nil, errors.ProcessNotFound(pid)
    }
    
    // Basic process information
    name, _ := proc.Name()
    cmdline, _ := proc.Cmdline()
    exe, _ := proc.Exe()
    username, _ := proc.Username()
    status, _ := proc.Status()
    createTime, _ := proc.CreateTime()
    ppid, _ := proc.Ppid()
    
    // Resource usage
    cpuPercent, _ := proc.CPUPercent()
    memInfo, _ := proc.MemoryInfo()
    memPercent, _ := proc.MemoryPercent()
    
    // System information
    priority, _ := proc.Nice() // Note: gopsutil uses Nice() for priority
    numThreads, _ := proc.NumThreads()
    numFds, _ := proc.NumFDs()
    
    // UIDs and GIDs
    uids, _ := proc.Uids()
    gids, _ := proc.Gids()
    
    // I/O information
    ioCounters, _ := proc.IOCounters()
    
    // Network connections
    connections, _ := proc.Connections()
    
    procInfo := &types.ProcessInfo{
        PID:         pid,
        PPID:        ppid,
        Name:        name,
        CommandLine: cmdline,
        Executable:  exe,
        Username:    username,
        Status:      strings.Join(status, ","),
        CreateTime:  time.Unix(createTime/1000, 0),
        CPUPercent:  cpuPercent,
        Priority:    priority,
        NumThreads:  numThreads,
        NumFds:      numFds,
        UIDs:        uids,
        GIDs:        gids,
    }
    
    // Handle memory info
    if memInfo != nil {
        procInfo.MemoryRSS = memInfo.RSS
        procInfo.MemoryVMS = memInfo.VMS
    }
    procInfo.MemoryPercent = memPercent
    
    // Handle I/O counters
    if ioCounters != nil {
        procInfo.IOCounters = types.IOInfo{
            ReadCount:  ioCounters.ReadCount,
            WriteCount: ioCounters.WriteCount,
            ReadBytes:  ioCounters.ReadBytes,
            WriteBytes: ioCounters.WriteBytes,
        }
    }
    
    // Handle network connections
    if connections != nil {
        procInfo.Connections = make([]types.ConnectionInfo, len(connections))
        for i, conn := range connections {
            procInfo.Connections[i] = types.ConnectionInfo{
                Fd:     conn.Fd,
                Family: conn.Family,
                Type:   conn.Type,
                Status: conn.Status,
                Laddr: types.Addr{
                    IP:   conn.Laddr.IP,
                    Port: conn.Laddr.Port,
                },
                Raddr: types.Addr{
                    IP:   conn.Raddr.IP,
                    Port: conn.Raddr.Port,
                },
            }
        }
    }
    
    return procInfo, nil
}
