package errors

import (
    "fmt"
)

// Custom error types for better error handling
type ErrorType string

const (
    ErrTypeProcessNotFound   ErrorType = "PROCESS_NOT_FOUND"
    ErrTypePermissionDenied  ErrorType = "PERMISSION_DENIED"
    ErrTypeCgroupNotFound    ErrorType = "CGROUP_NOT_FOUND"
    ErrTypeCgroupCreateFail  ErrorType = "CGROUP_CREATE_FAILED"
    ErrTypeInvalidConfig     ErrorType = "INVALID_CONFIG"
    ErrTypeSystemCall        ErrorType = "SYSTEM_CALL_FAILED"
    ErrTypeResourceExhausted ErrorType = "RESOURCE_EXHAUSTED"
    
    // Additional error types for profile management
    ErrInvalidInput         ErrorType = "INVALID_INPUT"
    ErrAlreadyExists        ErrorType = "ALREADY_EXISTS"
    ErrNotFound            ErrorType = "NOT_FOUND"
    ErrInvalidOperation    ErrorType = "INVALID_OPERATION"
    ErrProcessNotFound     ErrorType = "PROCESS_NOT_FOUND"
    ErrMaxRetriesExceeded  ErrorType = "MAX_RETRIES_EXCEEDED"
    ErrResourceExhausted   ErrorType = "RESOURCE_EXHAUSTED"
)

// ProcessThrottlerError represents a custom error with type and context
type ProcessThrottlerError struct {
    Type    ErrorType
    Message string
    Err     error
    Context map[string]interface{}
}

func (e *ProcessThrottlerError) Error() string {
    if e.Err != nil {
        return fmt.Sprintf("[%s] %s: %v", e.Type, e.Message, e.Err)
    }
    return fmt.Sprintf("[%s] %s", e.Type, e.Message)
}

func (e *ProcessThrottlerError) Unwrap() error {
    return e.Err
}

// NewError creates a new ProcessThrottlerError
func NewError(errType ErrorType, message string, err error) *ProcessThrottlerError {
    return &ProcessThrottlerError{
        Type:    errType,
        Message: message,
        Err:     err,
        Context: make(map[string]interface{}),
    }
}

// WithContext adds context information to the error
func (e *ProcessThrottlerError) WithContext(key string, value interface{}) *ProcessThrottlerError {
    e.Context[key] = value
    return e
}

// Helper functions for common errors
func ProcessNotFound(pid int32) *ProcessThrottlerError {
    return NewError(ErrTypeProcessNotFound, fmt.Sprintf("Process with PID %d not found", pid), nil).
           WithContext("pid", pid)
}

func PermissionDenied(operation string) *ProcessThrottlerError {
    return NewError(ErrTypePermissionDenied, fmt.Sprintf("Permission denied for operation: %s", operation), nil).
           WithContext("operation", operation)
}

func CgroupNotFound(name string) *ProcessThrottlerError {
    return NewError(ErrTypeCgroupNotFound, fmt.Sprintf("Cgroup '%s' not found", name), nil).
           WithContext("cgroup_name", name)
}

func CgroupCreateFailed(name string, err error) *ProcessThrottlerError {
    return NewError(ErrTypeCgroupCreateFail, fmt.Sprintf("Failed to create cgroup '%s'", name), err).
           WithContext("cgroup_name", name)
}

// New creates a new error with type and message
func New(errType ErrorType, message string) *ProcessThrottlerError {
    return &ProcessThrottlerError{
        Type:    errType,
        Message: message,
        Context: make(map[string]interface{}),
    }
}

// Wrap wraps an existing error with additional context
func Wrap(err error, message string) *ProcessThrottlerError {
    if err == nil {
        return nil
    }
    
    // If it's already our error type, preserve the type
    if pErr, ok := err.(*ProcessThrottlerError); ok {
        pErr.Message = message + ": " + pErr.Message
        return pErr
    }
    
    return &ProcessThrottlerError{
        Type:    ErrTypeSystemCall,
        Message: message,
        Err:     err,
        Context: make(map[string]interface{}),
    }
}
