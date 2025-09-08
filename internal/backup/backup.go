package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourusername/process-throttler/internal/audit"
	"github.com/yourusername/process-throttler/pkg/errors"
)

// BackupManager handles configuration backups
type BackupManager struct {
	backupDir    string
	maxBackups   int
	auditLogger  *audit.Logger
	profileDir   string
	configFile   string
}

// BackupMetadata contains metadata about a backup
type BackupMetadata struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Version     string    `json:"version"`
	Description string    `json:"description"`
	User        string    `json:"user"`
	Hostname    string    `json:"hostname"`
	Profiles    []string  `json:"profiles"`
	ConfigFile  string    `json:"config_file"`
	Size        int64     `json:"size"`
	Checksum    string    `json:"checksum"`
}

// NewBackupManager creates a new backup manager
func NewBackupManager(backupDir string, auditLogger *audit.Logger) (*BackupManager, error) {
	if backupDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get home directory")
		}
		backupDir = filepath.Join(homeDir, ".config", "process-throttler", "backups")
	}

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return nil, errors.Wrap(err, "failed to create backup directory")
	}

	return &BackupManager{
		backupDir:   backupDir,
		maxBackups:  30, // Keep last 30 backups
		auditLogger: auditLogger,
		profileDir:  filepath.Join(filepath.Dir(backupDir), "profiles"),
		configFile:  "/etc/process-throttler/config.yaml",
	}, nil
}

// CreateBackup creates a backup of all configurations
func (m *BackupManager) CreateBackup(description string) (*BackupMetadata, error) {
	metadata := &BackupMetadata{
		ID:          generateBackupID(),
		Timestamp:   time.Now(),
		Version:     "1.0",
		Description: description,
		User:        getCurrentUser(),
		Hostname:    getHostname(),
		Profiles:    []string{},
	}

	// Create backup file
	backupFile := filepath.Join(m.backupDir, fmt.Sprintf("backup-%s.tar.gz", metadata.ID))
	
	file, err := os.Create(backupFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create backup file")
	}
	defer file.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Backup profiles
	if err := m.backupProfiles(tarWriter, metadata); err != nil {
		os.Remove(backupFile)
		return nil, errors.Wrap(err, "failed to backup profiles")
	}

	// Backup main configuration
	if err := m.backupConfig(tarWriter, metadata); err != nil {
		os.Remove(backupFile)
		return nil, errors.Wrap(err, "failed to backup configuration")
	}

	// Add metadata to archive
	if err := m.addMetadata(tarWriter, metadata); err != nil {
		os.Remove(backupFile)
		return nil, errors.Wrap(err, "failed to add metadata")
	}

	// Get file size
	if info, err := os.Stat(backupFile); err == nil {
		metadata.Size = info.Size()
	}

	// Save metadata separately
	if err := m.saveMetadata(metadata); err != nil {
		return nil, errors.Wrap(err, "failed to save metadata")
	}

	// Log backup creation
	if m.auditLogger != nil {
		m.auditLogger.LogEvent(
			audit.EventTypeConfigChanged,
			audit.SeverityInfo,
			"Configuration backup created",
			backupFile,
			map[string]interface{}{
				"backup_id":   metadata.ID,
				"description": description,
				"profiles":    len(metadata.Profiles),
			},
		)
	}

	// Cleanup old backups
	m.cleanupOldBackups()

	return metadata, nil
}

// RestoreBackup restores a backup
func (m *BackupManager) RestoreBackup(backupID string, force bool) error {
	// Find backup file
	backupFile := filepath.Join(m.backupDir, fmt.Sprintf("backup-%s.tar.gz", backupID))
	if _, err := os.Stat(backupFile); err != nil {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("backup %s not found", backupID))
	}

	// Create a safety backup before restore
	if !force {
		if _, err := m.CreateBackup("Pre-restore safety backup"); err != nil {
			return errors.Wrap(err, "failed to create safety backup")
		}
	}

	// Open backup file
	file, err := os.Open(backupFile)
	if err != nil {
		return errors.Wrap(err, "failed to open backup file")
	}
	defer file.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return errors.Wrap(err, "failed to create gzip reader")
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Extract files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "failed to read tar header")
		}

		// Skip metadata file
		if header.Name == "metadata.json" {
			continue
		}

		// Determine target path
		targetPath := m.getRestorePath(header.Name)
		if targetPath == "" {
			continue
		}

		// Create directory if needed
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return errors.Wrap(err, "failed to create directory")
		}

		// Extract file
		if err := m.extractFile(tarReader, targetPath, header.Mode); err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to extract %s", header.Name))
		}
	}

	// Log restore
	if m.auditLogger != nil {
		m.auditLogger.LogEvent(
			audit.EventTypeConfigChanged,
			audit.SeverityWarning,
			"Configuration restored from backup",
			backupID,
			map[string]interface{}{
				"backup_id": backupID,
				"force":     force,
			},
		)
	}

	return nil
}

// ListBackups lists all available backups
func (m *BackupManager) ListBackups() ([]*BackupMetadata, error) {
	files, err := os.ReadDir(m.backupDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read backup directory")
	}

	var backups []*BackupMetadata
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".meta.json") {
			metadata, err := m.loadMetadata(file.Name())
			if err != nil {
				continue
			}
			backups = append(backups, metadata)
		}
	}

	return backups, nil
}

// GetBackup gets a specific backup metadata
func (m *BackupManager) GetBackup(backupID string) (*BackupMetadata, error) {
	metaFile := fmt.Sprintf("backup-%s.meta.json", backupID)
	return m.loadMetadata(metaFile)
}

// DeleteBackup deletes a backup
func (m *BackupManager) DeleteBackup(backupID string) error {
	// Remove backup file
	backupFile := filepath.Join(m.backupDir, fmt.Sprintf("backup-%s.tar.gz", backupID))
	if err := os.Remove(backupFile); err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, "failed to remove backup file")
	}

	// Remove metadata file
	metaFile := filepath.Join(m.backupDir, fmt.Sprintf("backup-%s.meta.json", backupID))
	if err := os.Remove(metaFile); err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, "failed to remove metadata file")
	}

	// Log deletion
	if m.auditLogger != nil {
		m.auditLogger.LogEvent(
			audit.EventTypeConfigChanged,
			audit.SeverityWarning,
			"Backup deleted",
			backupID,
			map[string]interface{}{
				"backup_id": backupID,
			},
		)
	}

	return nil
}

// AutoBackup creates an automatic backup before major operations
func (m *BackupManager) AutoBackup(operation string) error {
	description := fmt.Sprintf("Auto-backup before: %s", operation)
	_, err := m.CreateBackup(description)
	return err
}

// Helper methods

func (m *BackupManager) backupProfiles(tw *tar.Writer, metadata *BackupMetadata) error {
	// Check if profiles directory exists
	if _, err := os.Stat(m.profileDir); os.IsNotExist(err) {
		return nil // No profiles to backup
	}

	files, err := os.ReadDir(m.profileDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml") {
			filePath := filepath.Join(m.profileDir, file.Name())
			if err := m.addFileToTar(tw, filePath, "profiles/"+file.Name()); err != nil {
				return err
			}
			
			// Extract profile name
			profileName := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
			metadata.Profiles = append(metadata.Profiles, profileName)
		}
	}

	return nil
}

func (m *BackupManager) backupConfig(tw *tar.Writer, metadata *BackupMetadata) error {
	if _, err := os.Stat(m.configFile); err == nil {
		if err := m.addFileToTar(tw, m.configFile, "config.yaml"); err != nil {
			return err
		}
		metadata.ConfigFile = m.configFile
	}
	return nil
}

func (m *BackupManager) addFileToTar(tw *tar.Writer, sourcePath, archivePath string) error {
	file, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    archivePath,
		Size:    info.Size(),
		Mode:    int64(info.Mode()),
		ModTime: info.ModTime(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = io.Copy(tw, file)
	return err
}

func (m *BackupManager) addMetadata(tw *tar.Writer, metadata *BackupMetadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    "metadata.json",
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = tw.Write(data)
	return err
}

func (m *BackupManager) saveMetadata(metadata *BackupMetadata) error {
	metaFile := filepath.Join(m.backupDir, fmt.Sprintf("backup-%s.meta.json", metadata.ID))
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metaFile, data, 0644)
}

func (m *BackupManager) loadMetadata(filename string) (*BackupMetadata, error) {
	metaFile := filepath.Join(m.backupDir, filename)
	data, err := os.ReadFile(metaFile)
	if err != nil {
		return nil, err
	}

	var metadata BackupMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (m *BackupManager) getRestorePath(archivePath string) string {
	if strings.HasPrefix(archivePath, "profiles/") {
		return filepath.Join(m.profileDir, strings.TrimPrefix(archivePath, "profiles/"))
	}
	if archivePath == "config.yaml" {
		return m.configFile
	}
	return ""
}

func (m *BackupManager) extractFile(tr io.Reader, targetPath string, mode int64) error {
	file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(mode))
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, tr)
	return err
}

func (m *BackupManager) cleanupOldBackups() {
	backups, err := m.ListBackups()
	if err != nil {
		return
	}

	if len(backups) <= m.maxBackups {
		return
	}

	// Sort by timestamp (oldest first)
	// Simple bubble sort for small dataset
	for i := 0; i < len(backups)-1; i++ {
		for j := 0; j < len(backups)-i-1; j++ {
			if backups[j].Timestamp.After(backups[j+1].Timestamp) {
				backups[j], backups[j+1] = backups[j+1], backups[j]
			}
		}
	}

	// Delete oldest backups
	for i := 0; i < len(backups)-m.maxBackups; i++ {
		m.DeleteBackup(backups[i].ID)
	}
}

// Helper functions

func generateBackupID() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func getCurrentUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	return fmt.Sprintf("uid-%d", os.Getuid())
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}
