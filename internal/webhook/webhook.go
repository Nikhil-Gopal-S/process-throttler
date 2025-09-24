package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/yourusername/process-throttler/internal/audit"
	"github.com/yourusername/process-throttler/pkg/errors"
)

// Notifier handles webhook notifications
type Notifier struct {
	mu          sync.RWMutex
	webhooks    map[string]*WebhookConfig
	client      *http.Client
	queue       chan *Notification
	workers     int
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	retryPolicy RetryPolicy
}

// WebhookConfig defines a webhook endpoint configuration
type WebhookConfig struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Secret      string            `json:"secret,omitempty"`
	Events      []string          `json:"events"`
	Enabled     bool              `json:"enabled"`
	Timeout     time.Duration     `json:"timeout"`
	MaxRetries  int               `json:"max_retries"`
}

// Notification represents a notification to be sent
type Notification struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Event     string                 `json:"event"`
	Severity  string                 `json:"severity"`
	Source    string                 `json:"source"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details"`
}

// WebhookPayload is the standard payload sent to webhooks
type WebhookPayload struct {
	Version      string                 `json:"version"`
	Notification Notification           `json:"notification"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// RetryPolicy defines retry behavior
type RetryPolicy struct {
	MaxAttempts int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

// DeliveryResult tracks webhook delivery results
type DeliveryResult struct {
	WebhookName string
	Success     bool
	StatusCode  int
	Error       error
	Attempts    int
	Duration    time.Duration
}

// NewNotifier creates a new webhook notifier
func NewNotifier(workers int) *Notifier {
	if workers <= 0 {
		workers = 5
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	n := &Notifier{
		webhooks: make(map[string]*WebhookConfig),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		queue:   make(chan *Notification, 1000),
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
		retryPolicy: RetryPolicy{
			MaxAttempts:  3,
			InitialDelay: 1 * time.Second,
			MaxDelay:     30 * time.Second,
			Multiplier:   2.0,
		},
	}
	
	// Start workers
	for i := 0; i < workers; i++ {
		n.wg.Add(1)
		go n.worker()
	}
	
	return n
}

// AddWebhook adds a webhook configuration
func (n *Notifier) AddWebhook(config *WebhookConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	
	if config.Name == "" {
		return errors.New(errors.ErrInvalidInput, "webhook name cannot be empty")
	}
	
	if config.URL == "" {
		return errors.New(errors.ErrInvalidInput, "webhook URL cannot be empty")
	}
	
	if config.Method == "" {
		config.Method = "POST"
	}
	
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	
	if config.MaxRetries == 0 {
		config.MaxRetries = n.retryPolicy.MaxAttempts
	}
	
	n.webhooks[config.Name] = config
	return nil
}

// RemoveWebhook removes a webhook configuration
func (n *Notifier) RemoveWebhook(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	
	if _, exists := n.webhooks[name]; !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("webhook '%s' not found", name))
	}
	
	delete(n.webhooks, name)
	return nil
}

// SendNotification sends a notification to all configured webhooks
func (n *Notifier) SendNotification(notification *Notification) error {
	// Generate ID if not provided
	if notification.ID == "" {
		notification.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), len(n.queue))
	}
	
	// Set timestamp if not provided
	if notification.Timestamp.IsZero() {
		notification.Timestamp = time.Now()
	}
	
	// Queue the notification
	select {
	case n.queue <- notification:
		return nil
	case <-n.ctx.Done():
		return errors.New(errors.ErrInvalidOperation, "notifier is shutting down")
	default:
		return errors.New(errors.ErrResourceExhausted, "notification queue is full")
	}
}

// worker processes notifications from the queue
func (n *Notifier) worker() {
	defer n.wg.Done()
	
	for {
		select {
		case notification := <-n.queue:
			n.processNotification(notification)
		case <-n.ctx.Done():
			return
		}
	}
}

// processNotification sends a notification to all matching webhooks
func (n *Notifier) processNotification(notification *Notification) {
	n.mu.RLock()
	webhooks := make([]*WebhookConfig, 0)
	for _, webhook := range n.webhooks {
		if webhook.Enabled && n.shouldNotify(webhook, notification) {
			webhooks = append(webhooks, webhook)
		}
	}
	n.mu.RUnlock()
	
	// Send to each webhook
	var wg sync.WaitGroup
	results := make(chan *DeliveryResult, len(webhooks))
	
	for _, webhook := range webhooks {
		wg.Add(1)
		go func(w *WebhookConfig) {
			defer wg.Done()
			result := n.sendToWebhook(w, notification)
			results <- result
		}(webhook)
	}
	
	// Wait for all deliveries to complete
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect results
	for result := range results {
		if !result.Success {
			fmt.Printf("Failed to deliver to webhook %s: %v\n", result.WebhookName, result.Error)
		}
	}
}

// shouldNotify checks if a webhook should receive a notification
func (n *Notifier) shouldNotify(webhook *WebhookConfig, notification *Notification) bool {
	// If no events specified, send all
	if len(webhook.Events) == 0 {
		return true
	}
	
	// Check if event matches
	for _, event := range webhook.Events {
		if event == "*" || event == notification.Event {
			return true
		}
	}
	
	return false
}

// sendToWebhook sends a notification to a specific webhook
func (n *Notifier) sendToWebhook(webhook *WebhookConfig, notification *Notification) *DeliveryResult {
	result := &DeliveryResult{
		WebhookName: webhook.Name,
	}
	
	startTime := time.Now()
	defer func() {
		result.Duration = time.Since(startTime)
	}()
	
	// Create payload
	payload := WebhookPayload{
		Version:      "1.0",
		Notification: *notification,
		Metadata: map[string]interface{}{
			"webhook_name": webhook.Name,
			"sent_at":      time.Now().Format(time.RFC3339),
			"source":       "process-throttler",
		},
	}
	
	// Retry loop
	delay := n.retryPolicy.InitialDelay
	for attempt := 1; attempt <= webhook.MaxRetries; attempt++ {
		result.Attempts = attempt
		
		err := n.sendRequest(webhook, payload)
		if err == nil {
			result.Success = true
			return result
		}
		
		result.Error = err
		
		// Don't retry on client errors (4xx)
		if httpErr, ok := err.(*httpError); ok && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
			break
		}
		
		// Wait before retry
		if attempt < webhook.MaxRetries {
			time.Sleep(delay)
			delay = time.Duration(float64(delay) * n.retryPolicy.Multiplier)
			if delay > n.retryPolicy.MaxDelay {
				delay = n.retryPolicy.MaxDelay
			}
		}
	}
	
	return result
}

// sendRequest sends the actual HTTP request
func (n *Notifier) sendRequest(webhook *WebhookConfig, payload WebhookPayload) error {
	// Marshal payload
	data, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, "failed to marshal payload")
	}
	
	// Create request
	req, err := http.NewRequest(webhook.Method, webhook.URL, bytes.NewBuffer(data))
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "process-throttler/1.0")
	
	for key, value := range webhook.Headers {
		req.Header.Set(key, value)
	}
	
	// Add authentication if configured
	if webhook.Secret != "" {
		// Simple bearer token auth - in production, use HMAC or similar
		req.Header.Set("Authorization", "Bearer "+webhook.Secret)
	}
	
	// Set timeout
	ctx, cancel := context.WithTimeout(context.Background(), webhook.Timeout)
	defer cancel()
	req = req.WithContext(ctx)
	
	// Send request
	resp, err := n.client.Do(req)
	if err != nil {
		return errors.Wrap(err, "request failed")
	}
	defer resp.Body.Close()
	
	// Check response
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	
	return &httpError{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
	}
}

// httpError represents an HTTP error response
type httpError struct {
	StatusCode int
	Status     string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Status)
}

// NotifyFromAuditEvent creates a notification from an audit event
func (n *Notifier) NotifyFromAuditEvent(event *audit.AuditEvent) error {
	notification := &Notification{
		ID:        event.ID,
		Timestamp: event.Timestamp,
		Event:     string(event.Type),
		Severity:  string(event.Severity),
		Source:    event.Source,
		Message:   event.Action,
		Details: map[string]interface{}{
			"user":      event.User,
			"target":    event.Target,
			"result":    event.Result,
			"session":   event.SessionID,
			"audit_details": event.Details,
		},
	}
	
	// Add error if present
	if event.Error != "" {
		notification.Details["error"] = event.Error
	}
	
	return n.SendNotification(notification)
}

// GetWebhooks returns all configured webhooks
func (n *Notifier) GetWebhooks() map[string]*WebhookConfig {
	n.mu.RLock()
	defer n.mu.RUnlock()
	
	webhooks := make(map[string]*WebhookConfig)
	for k, v := range n.webhooks {
		webhooks[k] = v
	}
	
	return webhooks
}

// TestWebhook tests a webhook configuration
func (n *Notifier) TestWebhook(name string) error {
	n.mu.RLock()
	webhook, exists := n.webhooks[name]
	n.mu.RUnlock()
	
	if !exists {
		return errors.New(errors.ErrNotFound, fmt.Sprintf("webhook '%s' not found", name))
	}
	
	// Create test notification
	testNotification := &Notification{
		Event:    "test",
		Severity: "info",
		Message:  "Test notification from process-throttler",
		Details: map[string]interface{}{
			"test": true,
			"timestamp": time.Now().Format(time.RFC3339),
		},
	}
	
	result := n.sendToWebhook(webhook, testNotification)
	if !result.Success {
		return errors.Wrap(result.Error, "webhook test failed")
	}
	
	return nil
}

// Stop stops the notifier
func (n *Notifier) Stop() {
	n.cancel()
	close(n.queue)
	n.wg.Wait()
}

// Standard notification types
const (
	// Critical events
	EventEmergencyStop        = "emergency_stop"
	EventCriticalProcessDown  = "critical_process_down"
	EventCriticalProcessRestart = "critical_process_restart"
	EventSecurityViolation    = "security_violation"
	
	// Throttling events
	EventThrottleApplied      = "throttle_applied"
	EventThrottleRemoved      = "throttle_removed"
	EventThrottleAdjusted     = "throttle_adjusted"
	EventResourceLimitReached = "resource_limit_reached"
	
	// System events
	EventSystemOverload       = "system_overload"
	EventConfigurationChanged = "configuration_changed"
	EventProfileActivated     = "profile_activated"
	EventBackupCreated        = "backup_created"
	
	// Health events
	EventHealthCheckFailed    = "health_check_failed"
	EventHealthCheckRecovered = "health_check_recovered"
)

// CreateStandardWebhooks creates common webhook configurations
func CreateStandardWebhooks() []*WebhookConfig {
	return []*WebhookConfig{
		{
			Name:    "slack-critical",
			URL:     "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
			Method:  "POST",
			Events:  []string{EventEmergencyStop, EventCriticalProcessDown, EventSecurityViolation},
			Enabled: false,
			Timeout: 10 * time.Second,
		},
		{
			Name:    "pagerduty",
			URL:     "https://events.pagerduty.com/v2/enqueue",
			Method:  "POST",
			Headers: map[string]string{
				"Authorization": "Token token=YOUR_API_KEY",
			},
			Events:  []string{EventCriticalProcessDown, EventSystemOverload},
			Enabled: false,
			Timeout: 10 * time.Second,
		},
		{
			Name:    "email-gateway",
			URL:     "https://your-email-gateway.com/send",
			Method:  "POST",
			Events:  []string{"*"}, // All events
			Enabled: false,
			Timeout: 15 * time.Second,
		},
	}
}
