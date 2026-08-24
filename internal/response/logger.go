package response

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// EventLog manages structured JSON logging for all response decisions and sensor events.
type EventLog struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
	logger  *slog.Logger
	entries []LogEntry
}

// LogEntry is a single structured log record.
type LogEntry struct {
	Timestamp     string                 `json:"timestamp"`
	Level         string                 `json:"level"`
	EventType     string                 `json:"event_type"`
	PID           uint32                 `json:"pid,omitempty"`
	PPID          uint32                 `json:"ppid,omitempty"`
	Comm          string                 `json:"comm,omitempty"`
	TrustScore    float64                `json:"trust_score,omitempty"`
	ConformalPVal float64                `json:"conformal_p_value,omitempty"`
	ResponseTier  string                 `json:"response_tier,omitempty"`
	Action        string                 `json:"action,omitempty"`
	TechniqueID   string                 `json:"technique_id,omitempty"`
	Technique     string                 `json:"technique,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// NewEventLog creates a new event logger.
func NewEventLog(path string, logger *slog.Logger) (*EventLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening log file: %w", err)
	}
	return &EventLog{
		file:    f,
		encoder: json.NewEncoder(f),
		logger:  logger,
	}, nil
}

// Log writes a structured log entry.
func (el *EventLog) Log(entry LogEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	el.mu.Lock()
	defer el.mu.Unlock()

	el.entries = append(el.entries, entry)
	// Keep last 1000 entries in memory
	if len(el.entries) > 1000 {
		el.entries = el.entries[len(el.entries)-1000:]
	}

	if err := el.encoder.Encode(entry); err != nil {
		el.logger.Error("failed to write log entry", "error", err)
	}
}

// LogDecision converts a Decision to a log entry and writes it.
func (el *EventLog) LogDecision(d Decision) {
	el.Log(LogEntry{
		Level:         tierToLevel(d.Tier),
		EventType:     "response_decision",
		PID:           d.PID,
		Comm:          d.Comm,
		TrustScore:    d.TrustScore,
		ConformalPVal: d.ConformalPVal,
		ResponseTier:  string(d.Tier),
		Action:        d.Action,
		TechniqueID:   d.TechniqueID,
		Technique:     d.Technique,
		Details: map[string]interface{}{
			"causal_summary": d.CausalSummary,
			"verified":       d.Verified,
			"evidence":       d.Evidence,
		},
	})
}

// RecentEntries returns the last N log entries.
func (el *EventLog) RecentEntries(n int) []LogEntry {
	el.mu.Lock()
	defer el.mu.Unlock()
	if len(el.entries) <= n {
		result := make([]LogEntry, len(el.entries))
		copy(result, el.entries)
		return result
	}
	result := make([]LogEntry, n)
	copy(result, el.entries[len(el.entries)-n:])
	return result
}

// Close flushes and closes the log file.
func (el *EventLog) Close() error {
	return el.file.Close()
}

func tierToLevel(tier Tier) string {
	switch tier {
	case TierHigh:
		return "CRITICAL"
	case TierMedium:
		return "WARNING"
	default:
		return "INFO"
	}
}
