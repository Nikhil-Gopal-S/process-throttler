package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/yourusername/process-throttler/internal/types"
)

// Collector collects and exposes metrics
type Collector struct {
	mu sync.RWMutex
	
	// Process metrics
	processCount        *prometheus.GaugeVec
	throttledProcesses  *prometheus.GaugeVec
	protectedProcesses  *prometheus.GaugeVec
	
	// Resource metrics
	cpuUsage           *prometheus.GaugeVec
	memoryUsage        *prometheus.GaugeVec
	cpuLimit           *prometheus.GaugeVec
	memoryLimit        *prometheus.GaugeVec
	
	// Throttling metrics
	throttleOperations *prometheus.CounterVec
	throttleErrors     *prometheus.CounterVec
	throttleDuration   *prometheus.HistogramVec
	
	// System metrics
	systemCPU          prometheus.Gauge
	systemMemory       prometheus.Gauge
	systemLoad         *prometheus.GaugeVec
	
	// Critical process metrics
	criticalProcessHealth *prometheus.GaugeVec
	criticalProcessRestarts prometheus.Counter
	
	// Profile metrics
	activeProfile      *prometheus.GaugeVec
	profileActivations prometheus.Counter
	
	// Audit metrics
	auditEvents        *prometheus.CounterVec
	
	// Custom metrics storage
	customMetrics      map[string]prometheus.Collector
	
	server             *http.Server
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	c := &Collector{
		customMetrics: make(map[string]prometheus.Collector),
	}
	
	// Initialize process metrics
	c.processCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "processes",
			Name:      "total",
			Help:      "Total number of monitored processes",
		},
		[]string{"state"},
	)
	
	c.throttledProcesses = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "processes",
			Name:      "throttled",
			Help:      "Number of currently throttled processes",
		},
		[]string{"rule", "severity"},
	)
	
	c.protectedProcesses = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "processes",
			Name:      "protected",
			Help:      "Number of protected critical processes",
		},
		[]string{"protection_level"},
	)
	
	// Initialize resource metrics
	c.cpuUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "resources",
			Name:      "cpu_usage_percent",
			Help:      "CPU usage percentage by process",
		},
		[]string{"pid", "process_name", "group"},
	)
	
	c.memoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "resources",
			Name:      "memory_usage_bytes",
			Help:      "Memory usage in bytes by process",
		},
		[]string{"pid", "process_name", "group"},
	)
	
	c.cpuLimit = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "resources",
			Name:      "cpu_limit_percent",
			Help:      "CPU limit percentage for throttled processes",
		},
		[]string{"pid", "process_name", "group"},
	)
	
	c.memoryLimit = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "resources",
			Name:      "memory_limit_bytes",
			Help:      "Memory limit in bytes for throttled processes",
		},
		[]string{"pid", "process_name", "group"},
	)
	
	// Initialize operation metrics
	c.throttleOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "process_throttler",
			Subsystem: "operations",
			Name:      "throttle_total",
			Help:      "Total number of throttle operations",
		},
		[]string{"operation", "result"},
	)
	
	c.throttleErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "process_throttler",
			Subsystem: "operations",
			Name:      "errors_total",
			Help:      "Total number of throttling errors",
		},
		[]string{"operation", "error_type"},
	)
	
	c.throttleDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "process_throttler",
			Subsystem: "operations",
			Name:      "duration_seconds",
			Help:      "Duration of throttle operations in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation"},
	)
	
	// Initialize system metrics
	c.systemCPU = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "system",
			Name:      "cpu_usage_percent",
			Help:      "System-wide CPU usage percentage",
		},
	)
	
	c.systemMemory = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "system",
			Name:      "memory_usage_percent",
			Help:      "System-wide memory usage percentage",
		},
	)
	
	c.systemLoad = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "system",
			Name:      "load_average",
			Help:      "System load average",
		},
		[]string{"period"},
	)
	
	// Initialize critical process metrics
	c.criticalProcessHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "critical",
			Name:      "process_health",
			Help:      "Health status of critical processes (1=healthy, 0=unhealthy)",
		},
		[]string{"process_name", "pattern"},
	)
	
	c.criticalProcessRestarts = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "process_throttler",
			Subsystem: "critical",
			Name:      "restarts_total",
			Help:      "Total number of critical process restarts",
		},
	)
	
	// Initialize profile metrics
	c.activeProfile = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "process_throttler",
			Subsystem: "profiles",
			Name:      "active",
			Help:      "Currently active profile (1=active, 0=inactive)",
		},
		[]string{"profile_name"},
	)
	
	c.profileActivations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "process_throttler",
			Subsystem: "profiles",
			Name:      "activations_total",
			Help:      "Total number of profile activations",
		},
	)
	
	// Initialize audit metrics
	c.auditEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "process_throttler",
			Subsystem: "audit",
			Name:      "events_total",
			Help:      "Total number of audit events",
		},
		[]string{"event_type", "severity"},
	)
	
	// Register all metrics
	c.registerMetrics()
	
	return c
}

// registerMetrics registers all metrics with Prometheus
func (c *Collector) registerMetrics() {
	prometheus.MustRegister(
		c.processCount,
		c.throttledProcesses,
		c.protectedProcesses,
		c.cpuUsage,
		c.memoryUsage,
		c.cpuLimit,
		c.memoryLimit,
		c.throttleOperations,
		c.throttleErrors,
		c.throttleDuration,
		c.systemCPU,
		c.systemMemory,
		c.systemLoad,
		c.criticalProcessHealth,
		c.criticalProcessRestarts,
		c.activeProfile,
		c.profileActivations,
		c.auditEvents,
	)
}

// StartServer starts the Prometheus metrics server
func (c *Collector) StartServer(address string) error {
	if address == "" {
		address = ":9090"
	}
	
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	c.server = &http.Server{
		Addr:    address,
		Handler: mux,
	}
	
	go func() {
		if err := c.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Metrics server error: %v\n", err)
		}
	}()
	
	fmt.Printf("Metrics server started on %s\n", address)
	return nil
}

// StopServer stops the metrics server
func (c *Collector) StopServer() error {
	if c.server == nil {
		return nil
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	return c.server.Shutdown(ctx)
}

// Update methods for various metrics

// UpdateProcessMetrics updates process-related metrics
func (c *Collector) UpdateProcessMetrics(processes []*types.ProcessInfo, throttledPIDs map[int32]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Reset gauges
	c.processCount.Reset()
	c.cpuUsage.Reset()
	c.memoryUsage.Reset()
	
	totalCount := float64(len(processes))
	throttledCount := float64(len(throttledPIDs))
	
	c.processCount.WithLabelValues("total").Set(totalCount)
	c.processCount.WithLabelValues("throttled").Set(throttledCount)
	c.processCount.WithLabelValues("normal").Set(totalCount - throttledCount)
	
	// Update individual process metrics
	for _, proc := range processes {
		pidStr := fmt.Sprintf("%d", proc.PID)
		group := "normal"
		if g, ok := throttledPIDs[proc.PID]; ok {
			group = g
		}
		
		c.cpuUsage.WithLabelValues(pidStr, proc.Name, group).Set(proc.CPUPercent)
		c.memoryUsage.WithLabelValues(pidStr, proc.Name, group).Set(float64(proc.MemoryRSS))
	}
}

// UpdateThrottleMetrics updates throttling operation metrics
func (c *Collector) UpdateThrottleMetrics(operation string, success bool, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	result := "success"
	if !success {
		result = "failure"
	}
	
	c.throttleOperations.WithLabelValues(operation, result).Inc()
	c.throttleDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// UpdateSystemMetrics updates system-wide metrics
func (c *Collector) UpdateSystemMetrics(cpuPercent, memPercent float64, loadAvg []float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.systemCPU.Set(cpuPercent)
	c.systemMemory.Set(memPercent)
	
	if len(loadAvg) >= 3 {
		c.systemLoad.WithLabelValues("1m").Set(loadAvg[0])
		c.systemLoad.WithLabelValues("5m").Set(loadAvg[1])
		c.systemLoad.WithLabelValues("15m").Set(loadAvg[2])
	}
}

// UpdateCriticalProcessHealth updates critical process health metrics
func (c *Collector) UpdateCriticalProcessHealth(processName, pattern string, healthy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	healthValue := 0.0
	if healthy {
		healthValue = 1.0
	}
	
	c.criticalProcessHealth.WithLabelValues(processName, pattern).Set(healthValue)
}

// IncrementCriticalProcessRestarts increments the restart counter
func (c *Collector) IncrementCriticalProcessRestarts() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.criticalProcessRestarts.Inc()
}

// UpdateActiveProfile updates the active profile metric
func (c *Collector) UpdateActiveProfile(profileName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Reset all profiles to 0
	c.activeProfile.Reset()
	
	// Set active profile to 1
	c.activeProfile.WithLabelValues(profileName).Set(1.0)
	c.profileActivations.Inc()
}

// UpdateAuditMetrics updates audit event metrics
func (c *Collector) UpdateAuditMetrics(eventType, severity string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.auditEvents.WithLabelValues(eventType, severity).Inc()
}

// UpdateResourceLimits updates resource limit metrics
func (c *Collector) UpdateResourceLimits(pid int32, processName string, limits types.ResourceLimits) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	pidStr := fmt.Sprintf("%d", pid)
	group := fmt.Sprintf("throttle_%d", pid)
	
	if limits.CPUQuota > 0 && limits.CPUPeriod > 0 {
		cpuPercent := float64(limits.CPUQuota) / float64(limits.CPUPeriod) * 100
		c.cpuLimit.WithLabelValues(pidStr, processName, group).Set(cpuPercent)
	}
	
	if limits.MemoryLimit > 0 {
		c.memoryLimit.WithLabelValues(pidStr, processName, group).Set(float64(limits.MemoryLimit))
	}
}

// RegisterCustomMetric registers a custom metric
func (c *Collector) RegisterCustomMetric(name string, metric prometheus.Collector) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if _, exists := c.customMetrics[name]; exists {
		return fmt.Errorf("metric %s already registered", name)
	}
	
	if err := prometheus.Register(metric); err != nil {
		return err
	}
	
	c.customMetrics[name] = metric
	return nil
}

// GetMetricsHandler returns the Prometheus metrics handler
func (c *Collector) GetMetricsHandler() http.Handler {
	return promhttp.Handler()
}
