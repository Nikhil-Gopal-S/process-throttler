package cgroup

import (
    "os"
    "path/filepath"
)

// CgroupManager manages cgroup operations
type CgroupManager struct {
    cgroupRoot string
    version    int // 1 for cgroup v1, 2 for cgroup v2
}

// NewCgroupManager creates a new cgroup manager
func NewCgroupManager(cgroupRoot string) (*CgroupManager, error) {
    if cgroupRoot == "" {
        cgroupRoot = "/sys/fs/cgroup"
    }
    
    version := detectCgroupVersion(cgroupRoot)
    
    mgr := &CgroupManager{
        cgroupRoot: cgroupRoot,
        version:    version,
    }
    
    return mgr, nil
}

// detectCgroupVersion detects whether system uses cgroup v1 or v2
func detectCgroupVersion(cgroupRoot string) int {
    // Check if cgroup v2 unified hierarchy is available
    if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err == nil {
        return 2
    }
    return 1
}

// CreateGroup creates a new cgroup
func (cm *CgroupManager) CreateGroup(name string) error {
    if cm.version == 2 {
        return cm.createGroupV2(name)
    }
    return cm.createGroupV1(name)
}

// DeleteGroup removes a cgroup
func (cm *CgroupManager) DeleteGroup(name string) error {
    if cm.version == 2 {
        return cm.deleteGroupV2(name)
    }
    return cm.deleteGroupV1(name)
}

// SetCPULimit sets CPU quota and period
func (cm *CgroupManager) SetCPULimit(group string, quota, period int64) error {
    if cm.version == 2 {
        return cm.setCPULimitV2(group, quota, period)
    }
    return cm.setCPULimitV1(group, quota, period)
}

// SetMemoryLimit sets memory limit
func (cm *CgroupManager) SetMemoryLimit(group string, limit int64) error {
    if cm.version == 2 {
        return cm.setMemoryLimitV2(group, limit)
    }
    return cm.setMemoryLimitV1(group, limit)
}

// SetPidsLimit sets maximum number of processes
func (cm *CgroupManager) SetPidsLimit(group string, limit int64) error {
    if cm.version == 2 {
        return cm.setPidsLimitV2(group, limit)
    }
    return cm.setPidsLimitV1(group, limit)
}

// MoveProcess moves a process to a cgroup
func (cm *CgroupManager) MoveProcess(pid int32, group string) error {
    if cm.version == 2 {
        return cm.moveProcessV2(pid, group)
    }
    return cm.moveProcessV1(pid, group)
}

// GetProcesses returns list of processes in a cgroup
func (cm *CgroupManager) GetProcesses(group string) ([]int32, error) {
    if cm.version == 2 {
        return cm.getProcessesV2(group)
    }
    return cm.getProcessesV1(group)
}

// GroupExists checks if a cgroup exists
func (cm *CgroupManager) GroupExists(name string) bool {
    if cm.version == 2 {
        return cm.groupExistsV2(name)
    }
    return cm.groupExistsV1(name)
}

// ListGroups returns list of all cgroups
func (cm *CgroupManager) ListGroups() ([]string, error) {
    if cm.version == 2 {
        return cm.listGroupsV2()
    }
    return cm.listGroupsV1()
}

// Helper function to write to cgroup files
func (cm *CgroupManager) writeCgroupFile(path string, value string) error {
    return os.WriteFile(path, []byte(value), 0644)
}

// Helper function to read from cgroup files
func (cm *CgroupManager) readCgroupFile(path string) (string, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return "", err
    }
    return string(data), nil
}
