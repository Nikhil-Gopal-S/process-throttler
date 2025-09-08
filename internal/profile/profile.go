package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yourusername/process-throttler/internal/types"
	"github.com/yourusername/process-throttler/pkg/errors"
)

// Profile represents a complete configuration profile
type Profile struct {
	Name        string                  `yaml:"name" json:"name"`
	Version     string                  `yaml:"version" json:"version"`
	Description string                  `yaml:"description" json:"description"`
	Created     time.Time              `yaml:"created" json:"created"`
	Modified    time.Time              `yaml:"modified" json:"modified"`
	Author      string                  `yaml:"author" json:"author"`
	
	CriticalProcesses []CriticalProcess     `yaml:"critical_processes" json:"critical_processes"`
	ThrottlingRules   []types.ThrottleRule  `yaml:"throttling_rules" json:"throttling_rules"`
	Schedule          []ScheduleEntry       `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	Settings          types.Settings        `yaml:"settings" json:"settings"`
	
	// Runtime state
	Active    bool      `yaml:"-" json:"active"`
	AppliedAt time.Time `yaml:"-" json:"applied_at"`
}

// CriticalProcess represents a process that needs protection
type CriticalProcess struct {
	Pattern         string            `yaml:"pattern" json:"pattern"`
	ProtectionLevel string            `yaml:"protection_level" json:"protection_level"` // maximum, high, medium, low
	RestartPolicy   string            `yaml:"restart_policy" json:"restart_policy"`     // always, on-failure, never
	HealthCheck     HealthCheck       `yaml:"health_check,omitempty" json:"health_check,omitempty"`
	Priority        int32             `yaml:"priority" json:"priority"`
	OOMScoreAdj     int32             `yaml:"oom_score_adj" json:"oom_score_adj"` // -1000 to 1000
	Dependencies    []string          `yaml:"dependencies,omitempty" json:"dependencies,omitempty"`
	ResourceReserve ResourceReserve   `yaml:"resource_reserve,omitempty" json:"resource_reserve,omitempty"`
}

// HealthCheck defines how to check if a critical process is healthy
type HealthCheck struct {
	Type     string        `yaml:"type" json:"type"`         // port, http, command, file
	Target   string        `yaml:"target" json:"target"`     // port number, URL, command, file path
	Interval time.Duration `yaml:"interval" json:"interval"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
	Retries  int           `yaml:"retries" json:"retries"`
}

// ResourceReserve defines minimum resources to reserve for critical processes
type ResourceReserve struct {
	CPUPercent    float64 `yaml:"cpu_percent" json:"cpu_percent"`
	MemoryMB      int64   `yaml:"memory_mb" json:"memory_mb"`
	IOBandwidthMB int64   `yaml:"io_bandwidth_mb" json:"io_bandwidth_mb"`
}

// ScheduleEntry defines when to activate a profile
type ScheduleEntry struct {
	Time        string `yaml:"time" json:"time"`               // cron format or time range
	ProfileName string `yaml:"profile_name" json:"profile_name"`
	Days        []string `yaml:"days,omitempty" json:"days,omitempty"` // Mon, Tue, Wed, Thu, Fri, Sat, Sun
}

// Manager handles profile operations
type Manager struct {
	mu            sync.RWMutex
	profiles      map[string]*Profile
	activeProfile *Profile
	profileDir    string
	schedules     map[string]*ScheduleEntry
}

// NewManager creates a new profile manager
func NewManager(profileDir string) (*Manager, error) {
	if profileDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get home directory")
		}
		profileDir = filepath.Join(homeDir, ".config", "process-throttler", "profiles")
	}
	
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return nil, errors.Wrap(err, "failed to create profile directory")
	}
	
	m := &Manager{
		profiles:   make(map[string]*Profile),
		profileDir: profileDir,
		schedules:  make(map[string]*ScheduleEntry),
	}
	
	// Load existing profiles
	if err := m.loadProfiles(); err != nil {
		return nil, errors.Wrap(err, "failed to load profiles")
	}
	
	return m, nil
}

// Create creates a new profile
func (m *Manager) Create(profile *Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if profile.Name == "" {
		return errors.New(errors.ErrInvalidInput, "profile name cannot be empty")
	}
	
	if _, exists := m.profiles[profile.Name]; exists {
		return errors.New(errors.ErrAlreadyExists, fmt.Sprintf("profile '%s' already exists", profile.Name))
	}
	
	profile.Created = time.Now()
	profile.Modified = time.Now()
	if profile.Version == "" {
		profile.Version = "1.0"
	}
	
	// Validate profile
	if err := m.validateProfile(profile); err != nil {
		return errors.Wrap(err, "profile validation failed")
	}
	
	// Save to disk
	if err := m.saveProfile(profile); err != nil {
		return errors.Wrap(err, "failed to save profile")
	}
	
	m.profiles[profile.Name] = profile
	return nil
}

// List returns all available profiles
func (m *Manager) List() ([]*Profile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	profiles := make([]*Profile, 0, len(m.profiles))
	for _, p := range m.profiles {
		profiles = append(profiles, p)
	}
	
	return profiles, nil
}

// Get retrieves a profile by name
func (m *Manager) Get(name string) (*Profile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	profile, exists := m.profiles[name]
	if !exists {
		return nil, errors.New(errors.ErrNotFound, fmt.Sprintf("profile '%s' not found", name))
	}
	
	return profile, nil
}

// Update modifies an existing profile
func (m *Manager) Update(name string, profile *Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	existing, exists := m.profiles[name]
	if !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("profile '%s' not found", name))
	}
	
	// Preserve creation time
	profile.Created = existing.Created
	profile.Modified = time.Now()
	
	// Validate profile
	if err := m.validateProfile(profile); err != nil {
		return errors.Wrap(err, "profile validation failed")
	}
	
	// Save to disk
	if err := m.saveProfile(profile); err != nil {
		return errors.Wrap(err, "failed to save profile")
	}
	
	// If this was the active profile, update it
	if m.activeProfile != nil && m.activeProfile.Name == name {
		m.activeProfile = profile
	}
	
	m.profiles[name] = profile
	return nil
}

// Delete removes a profile
func (m *Manager) Delete(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if _, exists := m.profiles[name]; !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("profile '%s' not found", name))
	}
	
	// Cannot delete active profile
	if m.activeProfile != nil && m.activeProfile.Name == name {
		return errors.New(errors.ErrInvalidOperation, "cannot delete active profile")
	}
	
	// Remove from disk
	profilePath := filepath.Join(m.profileDir, name+".yaml")
	if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, "failed to delete profile file")
	}
	
	delete(m.profiles, name)
	return nil
}

// Clone creates a copy of an existing profile
func (m *Manager) Clone(sourceName, targetName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	source, exists := m.profiles[sourceName]
	if !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("source profile '%s' not found", sourceName))
	}
	
	if _, exists := m.profiles[targetName]; exists {
		return errors.New(errors.ErrAlreadyExists, fmt.Sprintf("target profile '%s' already exists", targetName))
	}
	
	// Deep copy the profile
	cloned := *source
	cloned.Name = targetName
	cloned.Created = time.Now()
	cloned.Modified = time.Now()
	cloned.Active = false
	cloned.Description = fmt.Sprintf("Cloned from %s", sourceName)
	
	// Save to disk
	if err := m.saveProfile(&cloned); err != nil {
		return errors.Wrap(err, "failed to save cloned profile")
	}
	
	m.profiles[targetName] = &cloned
	return nil
}

// Activate sets a profile as active
func (m *Manager) Activate(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	profile, exists := m.profiles[name]
	if !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("profile '%s' not found", name))
	}
	
	// Deactivate current profile
	if m.activeProfile != nil {
		m.activeProfile.Active = false
		m.activeProfile.AppliedAt = time.Time{}
	}
	
	// Activate new profile
	profile.Active = true
	profile.AppliedAt = time.Now()
	m.activeProfile = profile
	
	return nil
}

// GetActive returns the currently active profile
func (m *Manager) GetActive() (*Profile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.activeProfile == nil {
		return nil, errors.New(errors.ErrNotFound, "no active profile")
	}
	
	return m.activeProfile, nil
}

// Export exports a profile to a file
func (m *Manager) Export(name string, outputPath string, format string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	profile, exists := m.profiles[name]
	if !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("profile '%s' not found", name))
	}
	
	var data []byte
	var err error
	
	switch strings.ToLower(format) {
	case "yaml", "yml":
		data, err = yaml.Marshal(profile)
	case "json":
		data, err = json.MarshalIndent(profile, "", "  ")
	default:
		return errors.New(errors.ErrInvalidInput, fmt.Sprintf("unsupported format: %s", format))
	}
	
	if err != nil {
		return errors.Wrap(err, "failed to marshal profile")
	}
	
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return errors.Wrap(err, "failed to write profile file")
	}
	
	return nil
}

// Import imports a profile from a file
func (m *Manager) Import(inputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return errors.Wrap(err, "failed to read profile file")
	}
	
	var profile Profile
	
	// Try YAML first
	if err := yaml.Unmarshal(data, &profile); err != nil {
		// Try JSON
		if err := json.Unmarshal(data, &profile); err != nil {
			return errors.Wrap(err, "failed to parse profile file")
		}
	}
	
	return m.Create(&profile)
}

// Diff compares two profiles and returns the differences
func (m *Manager) Diff(profile1Name, profile2Name string) (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	p1, exists := m.profiles[profile1Name]
	if !exists {
		return nil, errors.New(errors.ErrNotFound, fmt.Sprintf("profile '%s' not found", profile1Name))
	}
	
	p2, exists := m.profiles[profile2Name]
	if !exists {
		return nil, errors.New(errors.ErrNotFound, fmt.Sprintf("profile '%s' not found", profile2Name))
	}
	
	diff := make(map[string]interface{})
	
	// Compare basic fields
	if p1.Version != p2.Version {
		diff["version"] = map[string]string{"profile1": p1.Version, "profile2": p2.Version}
	}
	
	if p1.Description != p2.Description {
		diff["description"] = map[string]string{"profile1": p1.Description, "profile2": p2.Description}
	}
	
	// Compare critical processes
	if len(p1.CriticalProcesses) != len(p2.CriticalProcesses) {
		diff["critical_process_count"] = map[string]int{
			"profile1": len(p1.CriticalProcesses),
			"profile2": len(p2.CriticalProcesses),
		}
	}
	
	// Compare throttling rules
	if len(p1.ThrottlingRules) != len(p2.ThrottlingRules) {
		diff["throttling_rule_count"] = map[string]int{
			"profile1": len(p1.ThrottlingRules),
			"profile2": len(p2.ThrottlingRules),
		}
	}
	
	return diff, nil
}

// Validate checks if a profile is valid
func (m *Manager) Validate(name string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	profile, exists := m.profiles[name]
	if !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("profile '%s' not found", name))
	}
	
	return m.validateProfile(profile)
}

// validateProfile performs validation checks on a profile
func (m *Manager) validateProfile(profile *Profile) error {
	// Check profile name
	if profile.Name == "" {
		return errors.New(errors.ErrInvalidInput, "profile name cannot be empty")
	}
	
	// Validate critical processes
	for i, cp := range profile.CriticalProcesses {
		if cp.Pattern == "" {
			return errors.New(errors.ErrInvalidInput, fmt.Sprintf("critical process %d: pattern cannot be empty", i))
		}
		
		// Validate protection level
		validLevels := map[string]bool{"maximum": true, "high": true, "medium": true, "low": true}
		if !validLevels[cp.ProtectionLevel] {
			return errors.New(errors.ErrInvalidInput, fmt.Sprintf("critical process %d: invalid protection level '%s'", i, cp.ProtectionLevel))
		}
		
		// Validate restart policy
		validPolicies := map[string]bool{"always": true, "on-failure": true, "never": true}
		if !validPolicies[cp.RestartPolicy] {
			return errors.New(errors.ErrInvalidInput, fmt.Sprintf("critical process %d: invalid restart policy '%s'", i, cp.RestartPolicy))
		}
		
		// Validate OOM score adjustment
		if cp.OOMScoreAdj < -1000 || cp.OOMScoreAdj > 1000 {
			return errors.New(errors.ErrInvalidInput, fmt.Sprintf("critical process %d: OOM score adjustment must be between -1000 and 1000", i))
		}
	}
	
	// Validate throttling rules
	for i, rule := range profile.ThrottlingRules {
		if rule.Name == "" {
			return errors.New(errors.ErrInvalidInput, fmt.Sprintf("throttling rule %d: name cannot be empty", i))
		}
		
		if rule.Matcher.Pattern == "" {
			return errors.New(errors.ErrInvalidInput, fmt.Sprintf("throttling rule %d: pattern cannot be empty", i))
		}
		
		// Validate match type
		validMatchTypes := map[string]bool{"name": true, "cmdline": true, "pid": true, "user": true}
		if !validMatchTypes[rule.Matcher.MatchType] {
			return errors.New(errors.ErrInvalidInput, fmt.Sprintf("throttling rule %d: invalid match type '%s'", i, rule.Matcher.MatchType))
		}
		
		// Validate resource limits
		if rule.Limits.CPUQuota < 0 || rule.Limits.CPUPeriod < 0 {
			return errors.New(errors.ErrInvalidInput, fmt.Sprintf("throttling rule %d: CPU limits cannot be negative", i))
		}
		
		if rule.Limits.MemoryLimit < 0 {
			return errors.New(errors.ErrInvalidInput, fmt.Sprintf("throttling rule %d: memory limit cannot be negative", i))
		}
	}
	
	return nil
}

// saveProfile saves a profile to disk
func (m *Manager) saveProfile(profile *Profile) error {
	profilePath := filepath.Join(m.profileDir, profile.Name+".yaml")
	
	data, err := yaml.Marshal(profile)
	if err != nil {
		return errors.Wrap(err, "failed to marshal profile")
	}
	
	if err := os.WriteFile(profilePath, data, 0644); err != nil {
		return errors.Wrap(err, "failed to write profile file")
	}
	
	return nil
}

// loadProfiles loads all profiles from disk
func (m *Manager) loadProfiles() error {
	files, err := os.ReadDir(m.profileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No profiles yet
		}
		return errors.Wrap(err, "failed to read profile directory")
	}
	
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		
		if !strings.HasSuffix(file.Name(), ".yaml") && !strings.HasSuffix(file.Name(), ".yml") {
			continue
		}
		
		profilePath := filepath.Join(m.profileDir, file.Name())
		data, err := os.ReadFile(profilePath)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to read profile file: %s", file.Name()))
		}
		
		var profile Profile
		if err := yaml.Unmarshal(data, &profile); err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to parse profile file: %s", file.Name()))
		}
		
		m.profiles[profile.Name] = &profile
	}
	
	return nil
}

// Schedule adds a scheduled profile activation
func (m *Manager) Schedule(profileName string, schedule *ScheduleEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if _, exists := m.profiles[profileName]; !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("profile '%s' not found", profileName))
	}
	
	schedule.ProfileName = profileName
	m.schedules[profileName] = schedule
	
	return nil
}

// GetSchedules returns all scheduled profile activations
func (m *Manager) GetSchedules() map[string]*ScheduleEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	schedules := make(map[string]*ScheduleEntry)
	for k, v := range m.schedules {
		schedules[k] = v
	}
	
	return schedules
}
