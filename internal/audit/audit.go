package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yourusername/process-throttler/pkg/errors"
)

// EventType represents the type of audit event
type EventType string

const (
	EventTypeProfileCreated    EventType = "PROFILE_CREATED"
	EventTypeProfileModified   EventType = "PROFILE_MODIFIED"
	EventTypeProfileDeleted    EventType = "PROFILE_DELETED"
	EventTypeProfileActivated  EventType = "PROFILE_ACTIVATED"
	EventTypeThrottleApplied   EventType = "THROTTLE_APPLIED"
	EventTypeThrottleRemoved   EventType = "THROTTLE_REMOVED"
	EventTypeProtectionApplied EventType = "PROTECTION_APPLIED"
	EventTypeProtectionRemoved EventType = "PROTECTION_REMOVED"
	EventTypeSystemStart       EventType = "SYSTEM_START"
	EventTypeSystemStop        EventType = "SYSTEM_STOP"
	EventTypeEmergencyStop     EventType = "EMERGENCY_STOP"
	EventTypeConfigChanged     EventType = "CONFIG_CHANGED"
	EventTypeSecurityViolation EventType = "SECURITY_VIOLATION"
	EventTypeHealthCheckFailed EventType = "HEALTH_CHECK_FAILED"
	EventTypeProcessRestarted  EventType = "PROCESS_RESTARTED"
)

// Severity represents the severity level of an audit event
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
	SeverityError    Severity = "ERROR"
)

// AuditEvent represents a single audit log entry
type AuditEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        EventType              `json:"type"`
	Severity    Severity               `json:"severity"`
	User        string                 `json:"user"`
	UID         int                    `json:"uid"`
	GID         int                    `json:"gid"`
	Action      string                 `json:"action"`
	Target      string                 `json:"target"`
	Result      string                 `json:"result"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Error       string                 `json:"error,omitempty"`
	SessionID   string                 `json:"session_id"`
	Source      string                 `json:"source"`
	IPAddress   string                 `json:"ip_address,omitempty"`
}

// Logger handles audit logging
type Logger struct {
	mu           sync.RWMutex
	logDir       string
	currentFile  *os.File
	encoder      *json.Encoder
	maxFileSize  int64
	maxFiles     int
	sessionID    string
	rotateSignal chan struct{}
	stopSignal   chan struct{}
	wg           sync.WaitGroup
}

// NewLogger creates a new audit logger
func NewLogger(logDir string) (*Logger, error) {
	if logDir == "" {
		logDir = "/var/log/process-throttler/audit"
	}

	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, errors.Wrap(err, "failed to create audit log directory")
	}

	logger := &Logger{
		logDir:       logDir,
		maxFileSize:  100 * 1024 * 1024, // 100MB
		maxFiles:     10,
		sessionID:    generateSessionID(),
		rotateSignal: make(chan struct{}, 1),
		stopSignal:   make(chan struct{}),
	}

	// Open initial log file
	if err := logger.openLogFile(); err != nil {
		return nil, err
	}

	// Start rotation monitor
	logger.wg.Add(1)
	go logger.rotationMonitor()

	// Log system start
	logger.LogEvent(EventTypeSystemStart, SeverityInfo, "Audit system started", "", nil)

	return logger, nil
}

// LogEvent logs an audit event
func (l *Logger) LogEvent(eventType EventType, severity Severity, action string, target string, details map[string]interface{}) error {
	return l.LogEventWithError(eventType, severity, action, target, details, nil)
}

// LogEventWithError logs an audit event with an error
func (l *Logger) LogEventWithError(eventType EventType, severity Severity, action string, target string, details map[string]interface{}, err error) error {
	event := &AuditEvent{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Type:      eventType,
		Severity:  severity,
		User:      getCurrentUser(),
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		Action:    action,
		Target:    target,
		Result:    "SUCCESS",
		Details:   details,
		SessionID: l.sessionID,
		Source:    getSource(),
	}

	if err != nil {
		event.Result = "FAILURE"
		event.Error = err.Error()
	}

	return l.writeEvent(event)
}

// LogSecurityViolation logs a security violation
func (l *Logger) LogSecurityViolation(action string, details map[string]interface{}) error {
	// Security violations are always critical
	return l.LogEvent(EventTypeSecurityViolation, SeverityCritical, action, "", details)
}

// writeEvent writes an event to the log file
func (l *Logger) writeEvent(event *AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.encoder == nil {
		return errors.New(errors.ErrInvalidOperation, "audit logger is not initialized")
	}

	// Encode the event
	if err := l.encoder.Encode(event); err != nil {
		return errors.Wrap(err, "failed to write audit event")
	}

	// Check if rotation is needed
	if info, err := l.currentFile.Stat(); err == nil {
		if info.Size() >= l.maxFileSize {
			select {
			case l.rotateSignal <- struct{}{}:
			default:
			}
		}
	}

	return nil
}

// openLogFile opens a new log file
func (l *Logger) openLogFile() error {
	filename := fmt.Sprintf("audit-%s.json", time.Now().Format("20060102-150405"))
	fullPath := filepath.Join(l.logDir, filename)

	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return errors.Wrap(err, "failed to open audit log file")
	}

	// Close previous file if exists
	if l.currentFile != nil {
		l.currentFile.Close()
	}

	l.currentFile = file
	l.encoder = json.NewEncoder(file)

	// Create symlink to current log
	currentLink := filepath.Join(l.logDir, "current.json")
	os.Remove(currentLink) // Remove old symlink
	os.Symlink(filename, currentLink)

	return nil
}

// rotateLogFile rotates the log file
func (l *Logger) rotateLogFile() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Close current file
	if l.currentFile != nil {
		l.currentFile.Close()
	}

	// Open new file
	if err := l.openLogFile(); err != nil {
		return err
	}

	// Clean up old files
	l.cleanupOldFiles()

	return nil
}

// cleanupOldFiles removes old log files
func (l *Logger) cleanupOldFiles() {
	files, err := os.ReadDir(l.logDir)
	if err != nil {
		return
	}

	// Filter audit files
	var auditFiles []os.DirEntry
	for _, file := range files {
		if !file.IsDir() && len(file.Name()) > 6 && file.Name()[:6] == "audit-" {
			auditFiles = append(auditFiles, file)
		}
	}

	// Remove oldest files if we have too many
	if len(auditFiles) > l.maxFiles {
		for i := 0; i < len(auditFiles)-l.maxFiles; i++ {
			os.Remove(filepath.Join(l.logDir, auditFiles[i].Name()))
		}
	}
}

// rotationMonitor monitors for log rotation signals
func (l *Logger) rotationMonitor() {
	defer l.wg.Done()

	for {
		select {
		case <-l.rotateSignal:
			if err := l.rotateLogFile(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to rotate audit log: %v\n", err)
			}
		case <-l.stopSignal:
			return
		}
	}
}

// Search searches audit logs for events matching criteria
func (l *Logger) Search(criteria SearchCriteria) ([]*AuditEvent, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var events []*AuditEvent

	// Get all audit files
	files, err := os.ReadDir(l.logDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read audit directory")
	}

	for _, file := range files {
		if file.IsDir() || !isAuditFile(file.Name()) {
			continue
		}

		// Check if file is within time range
		fileEvents, err := l.searchFile(filepath.Join(l.logDir, file.Name()), criteria)
		if err != nil {
			continue // Skip files with errors
		}

		events = append(events, fileEvents...)
	}

	return events, nil
}

// searchFile searches a single audit file
func (l *Logger) searchFile(filePath string, criteria SearchCriteria) ([]*AuditEvent, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []*AuditEvent
	decoder := json.NewDecoder(file)

	for {
		var event AuditEvent
		if err := decoder.Decode(&event); err != nil {
			break // End of file or error
		}

		if criteria.Matches(&event) {
			events = append(events, &event)
		}
	}

	return events, nil
}

// GetStats returns audit statistics
func (l *Logger) GetStats() (*AuditStats, error) {
	events, err := l.Search(SearchCriteria{
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
	})
	if err != nil {
		return nil, err
	}

	stats := &AuditStats{
		TotalEvents:      len(events),
		EventsByType:     make(map[EventType]int),
		EventsBySeverity: make(map[Severity]int),
		RecentEvents:     []*AuditEvent{},
	}

	for _, event := range events {
		stats.EventsByType[event.Type]++
		stats.EventsBySeverity[event.Severity]++
	}

	// Get last 10 events
	if len(events) > 10 {
		stats.RecentEvents = events[len(events)-10:]
	} else {
		stats.RecentEvents = events
	}

	return stats, nil
}

// Close closes the audit logger
func (l *Logger) Close() error {
	// Log system stop
	l.LogEvent(EventTypeSystemStop, SeverityInfo, "Audit system stopped", "", nil)

	// Stop rotation monitor
	close(l.stopSignal)
	l.wg.Wait()

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.currentFile != nil {
		return l.currentFile.Close()
	}

	return nil
}

// SearchCriteria defines search criteria for audit logs
type SearchCriteria struct {
	StartTime time.Time
	EndTime   time.Time
	EventType EventType
	Severity  Severity
	User      string
	Target    string
	SessionID string
}

// Matches checks if an event matches the search criteria
func (c *SearchCriteria) Matches(event *AuditEvent) bool {
	// Check time range
	if !c.StartTime.IsZero() && event.Timestamp.Before(c.StartTime) {
		return false
	}
	if !c.EndTime.IsZero() && event.Timestamp.After(c.EndTime) {
		return false
	}

	// Check event type
	if c.EventType != "" && event.Type != c.EventType {
		return false
	}

	// Check severity
	if c.Severity != "" && event.Severity != c.Severity {
		return false
	}

	// Check user
	if c.User != "" && event.User != c.User {
		return false
	}

	// Check target
	if c.Target != "" && event.Target != c.Target {
		return false
	}

	// Check session ID
	if c.SessionID != "" && event.SessionID != c.SessionID {
		return false
	}

	return true
}

// AuditStats represents audit statistics
type AuditStats struct {
	TotalEvents      int
	EventsByType     map[EventType]int
	EventsBySeverity map[Severity]int
	RecentEvents     []*AuditEvent
}

// Helper functions

func generateEventID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

func generateSessionID() string {
	return fmt.Sprintf("session-%d-%d", time.Now().Unix(), os.Getpid())
}

func getCurrentUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return fmt.Sprintf("uid-%d", os.Getuid())
}

func getSource() string {
	hostname, _ := os.Hostname()
	return hostname
}

func isAuditFile(filename string) bool {
	return len(filename) > 6 && filename[:6] == "audit-" && filepath.Ext(filename) == ".json"
}
