package cgroup

import (
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    
    "github.com/yourusername/process-throttler/pkg/errors"
)

// Cgroup v1 implementation

func (cm *CgroupManager) createGroupV1(name string) error {
    // Create directories for each controller
    controllers := []string{"cpu", "memory", "pids"}
    
    for _, controller := range controllers {
        groupPath := filepath.Join(cm.cgroupRoot, controller, name)
        
        if err := os.MkdirAll(groupPath, 0755); err != nil {
            return errors.CgroupCreateFailed(name, err)
        }
    }
    
    return nil
}

func (cm *CgroupManager) deleteGroupV1(name string) error {
    controllers := []string{"cpu", "memory", "pids"}
    
    var lastError error
    for _, controller := range controllers {
        groupPath := filepath.Join(cm.cgroupRoot, controller, name)
        if err := os.Remove(groupPath); err != nil && !os.IsNotExist(err) {
            lastError = err
        }
    }
    
    return lastError
}

func (cm *CgroupManager) setCPULimitV1(group string, quota, period int64) error {
    cpuPath := filepath.Join(cm.cgroupRoot, "cpu", group)
    
    // Set CPU period
    if err := cm.writeCgroupFile(filepath.Join(cpuPath, "cpu.cfs_period_us"), 
                                 strconv.FormatInt(period, 10)); err != nil {
        return fmt.Errorf("failed to set CPU period: %w", err)
    }
    
    // Set CPU quota
    if err := cm.writeCgroupFile(filepath.Join(cpuPath, "cpu.cfs_quota_us"), 
                                 strconv.FormatInt(quota, 10)); err != nil {
        return fmt.Errorf("failed to set CPU quota: %w", err)
    }
    
    return nil
}

func (cm *CgroupManager) setMemoryLimitV1(group string, limit int64) error {
    memoryPath := filepath.Join(cm.cgroupRoot, "memory", group)
    
    if err := cm.writeCgroupFile(filepath.Join(memoryPath, "memory.limit_in_bytes"), 
                                 strconv.FormatInt(limit, 10)); err != nil {
        return fmt.Errorf("failed to set memory limit: %w", err)
    }
    
    return nil
}

func (cm *CgroupManager) setPidsLimitV1(group string, limit int64) error {
    pidsPath := filepath.Join(cm.cgroupRoot, "pids", group)
    
    if err := cm.writeCgroupFile(filepath.Join(pidsPath, "pids.max"), 
                                 strconv.FormatInt(limit, 10)); err != nil {
        return fmt.Errorf("failed to set pids limit: %w", err)
    }
    
    return nil
}

func (cm *CgroupManager) moveProcessV1(pid int32, group string) error {
    controllers := []string{"cpu", "memory", "pids"}
    
    for _, controller := range controllers {
        cgroupProcs := filepath.Join(cm.cgroupRoot, controller, group, "cgroup.procs")
        
        if err := cm.writeCgroupFile(cgroupProcs, strconv.FormatInt(int64(pid), 10)); err != nil {
            return fmt.Errorf("failed to move process %d to %s/%s: %w", pid, controller, group, err)
        }
    }
    
    return nil
}

func (cm *CgroupManager) getProcessesV1(group string) ([]int32, error) {
    // Read from CPU controller (processes should be the same across controllers)
    cgroupProcs := filepath.Join(cm.cgroupRoot, "cpu", group, "cgroup.procs")
    
    data, err := cm.readCgroupFile(cgroupProcs)
    if err != nil {
        return nil, fmt.Errorf("failed to read cgroup processes: %w", err)
    }
    
    var pids []int32
    lines := strings.Split(strings.TrimSpace(data), "\n")
    
    for _, line := range lines {
        if line == "" {
            continue
        }
        
        pid, err := strconv.ParseInt(line, 10, 32)
        if err != nil {
            continue // Skip invalid PIDs
        }
        
        pids = append(pids, int32(pid))
    }
    
    return pids, nil
}

func (cm *CgroupManager) groupExistsV1(name string) bool {
    // Check if CPU controller directory exists
    cpuPath := filepath.Join(cm.cgroupRoot, "cpu", name)
    _, err := os.Stat(cpuPath)
    return err == nil
}

func (cm *CgroupManager) listGroupsV1() ([]string, error) {
    // List from CPU controller directory
    cpuPath := filepath.Join(cm.cgroupRoot, "cpu")
    
    entries, err := os.ReadDir(cpuPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read CPU cgroup directory: %w", err)
    }
    
    var groups []string
    for _, entry := range entries {
        if entry.IsDir() && entry.Name() != "." && entry.Name() != ".." {
            groups = append(groups, entry.Name())
        }
    }
    
    return groups, nil
}

// Cgroup v2 implementations (simplified for now)

func (cm *CgroupManager) createGroupV2(name string) error {
    groupPath := filepath.Join(cm.cgroupRoot, name)
    return os.MkdirAll(groupPath, 0755)
}

func (cm *CgroupManager) deleteGroupV2(name string) error {
    groupPath := filepath.Join(cm.cgroupRoot, name)
    return os.Remove(groupPath)
}

func (cm *CgroupManager) setCPULimitV2(group string, quota, period int64) error {
    groupPath := filepath.Join(cm.cgroupRoot, group)
    cpuMax := fmt.Sprintf("%d %d", quota, period)
    return cm.writeCgroupFile(filepath.Join(groupPath, "cpu.max"), cpuMax)
}

func (cm *CgroupManager) setMemoryLimitV2(group string, limit int64) error {
    groupPath := filepath.Join(cm.cgroupRoot, group)
    return cm.writeCgroupFile(filepath.Join(groupPath, "memory.max"), strconv.FormatInt(limit, 10))
}

func (cm *CgroupManager) setPidsLimitV2(group string, limit int64) error {
    groupPath := filepath.Join(cm.cgroupRoot, group)
    return cm.writeCgroupFile(filepath.Join(groupPath, "pids.max"), strconv.FormatInt(limit, 10))
}

func (cm *CgroupManager) moveProcessV2(pid int32, group string) error {
    groupPath := filepath.Join(cm.cgroupRoot, group)
    cgroupProcs := filepath.Join(groupPath, "cgroup.procs")
    return cm.writeCgroupFile(cgroupProcs, strconv.FormatInt(int64(pid), 10))
}

func (cm *CgroupManager) getProcessesV2(group string) ([]int32, error) {
    groupPath := filepath.Join(cm.cgroupRoot, group)
    cgroupProcs := filepath.Join(groupPath, "cgroup.procs")
    
    data, err := cm.readCgroupFile(cgroupProcs)
    if err != nil {
        return nil, err
    }
    
    var pids []int32
    lines := strings.Split(strings.TrimSpace(data), "\n")
    
    for _, line := range lines {
        if line == "" {
            continue
        }
        
        pid, err := strconv.ParseInt(line, 10, 32)
        if err != nil {
            continue
        }
        
        pids = append(pids, int32(pid))
    }
    
    return pids, nil
}

func (cm *CgroupManager) groupExistsV2(name string) bool {
    groupPath := filepath.Join(cm.cgroupRoot, name)
    _, err := os.Stat(groupPath)
    return err == nil
}

func (cm *CgroupManager) listGroupsV2() ([]string, error) {
    entries, err := os.ReadDir(cm.cgroupRoot)
    if err != nil {
        return nil, err
    }
    
    var groups []string
    for _, entry := range entries {
        if entry.IsDir() && entry.Name() != "." && entry.Name() != ".." {
            groups = append(groups, entry.Name())
        }
    }
    
    return groups, nil
}
