// Package checkpoint implements CRIU checkpoint, replay in isolated netns, and malicious intent confirmation.
package checkpoint

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config for the CRIU verify path.
type Config struct {
	Enabled       bool
	CheckpointDir string
	SinkholePort  int
	TimeoutSecs   int
}

// DefaultConfig returns default CRIU configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		CheckpointDir: "/tmp/ksm-criu",
		SinkholePort:  9999,
		TimeoutSecs:   15,
	}
}

// VerifyResult from the CRIU checkpoint+replay verify path.
type VerifyResult struct {
	ConfirmedMalicious bool     `json:"confirmed_malicious"`
	Evidence           []string `json:"evidence"`
}

// Manager handles CRIU checkpoint and verify operations.
type Manager struct {
	config Config
	logger *slog.Logger
	mu     sync.Mutex
}

// NewManager creates a CRIU checkpoint manager.
func NewManager(cfg Config, logger *slog.Logger) *Manager {
	return &Manager{config: cfg, logger: logger}
}

// IsAvailable checks if CRIU is installed and accessible.
func (m *Manager) IsAvailable() bool {
	_, err := exec.LookPath("criu")
	return err == nil
}

// Verify performs the full checkpoint → isolated replay → confirm cycle.
// Scoped to PRE-CONNECTION state: process has staged payload (write+chmod) but not yet exec'd/connected.
// This avoids checkpointing established TCP sockets.
func (m *Manager) Verify(ctx context.Context, pid uint32) (*VerifyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.IsAvailable() {
		return nil, fmt.Errorf("CRIU is not installed")
	}

	checkpointDir := filepath.Join(m.config.CheckpointDir, fmt.Sprintf("pid-%d-%d", pid, time.Now().UnixNano()))
	if err := os.MkdirAll(checkpointDir, 0700); err != nil {
		return nil, fmt.Errorf("creating checkpoint dir: %w", err)
	}
	defer os.RemoveAll(checkpointDir)

	m.logger.Info("starting CRIU verify", "pid", pid, "checkpoint_dir", checkpointDir)

	// Step 1: Checkpoint the process (pre-connection state)
	if err := m.checkpoint(ctx, pid, checkpointDir); err != nil {
		return nil, fmt.Errorf("checkpoint failed: %w", err)
	}

	// Step 2: Create isolated network namespace with sinkhole
	nsName := fmt.Sprintf("ksm-verify-%d", pid)
	sinkhole, err := NewSinkhole(nsName, m.config.SinkholePort, m.logger)
	if err != nil {
		return nil, fmt.Errorf("creating sinkhole: %w", err)
	}
	defer sinkhole.Cleanup()

	// Step 3: Replay process in isolated namespace
	evidence, err := m.replay(ctx, checkpointDir, nsName, sinkhole)
	if err != nil {
		m.logger.Warn("replay failed", "pid", pid, "error", err)
		// Replay failure is not necessarily a sign of benign behavior
		return &VerifyResult{
			ConfirmedMalicious: false,
			Evidence:           []string{fmt.Sprintf("replay_error: %v", err)},
		}, nil
	}

	// Step 4: Analyze evidence from sinkhole
	result := m.analyzeEvidence(evidence, sinkhole.GetConnectionAttempts())
	m.logger.Info("CRIU verify complete",
		"pid", pid,
		"confirmed_malicious", result.ConfirmedMalicious,
		"evidence_count", len(result.Evidence))

	return result, nil
}

func (m *Manager) checkpoint(ctx context.Context, pid uint32, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(m.config.TimeoutSecs)*time.Second)
	defer cancel()

	args := []string{
		"dump",
		"-t", fmt.Sprintf("%d", pid),
		"-D", dir,
		"--shell-job",
		"--tcp-established",    // We're at pre-connection state, so this should be clean
		"--leave-stopped",       // Leave the original process stopped
	}

	cmd := exec.CommandContext(ctx, "criu", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("criu dump: %w (output: %s)", err, string(output))
	}

	m.logger.Info("checkpoint complete", "pid", pid, "dir", dir)
	return nil
}

func (m *Manager) replay(ctx context.Context, checkpointDir, nsName string, sinkhole *Sinkhole) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(m.config.TimeoutSecs)*time.Second)
	defer cancel()

	// Start sinkhole listener
	go sinkhole.Listen(ctx)

	// Restore process inside the isolated network namespace
	args := []string{
		"netns", "exec", nsName,
		"criu", "restore",
		"-D", checkpointDir,
		"--shell-job",
		"--tcp-established",
	}

	cmd := exec.CommandContext(ctx, "ip", args...)
	output, err := cmd.CombinedOutput()

	var evidence []string
	if err != nil {
		evidence = append(evidence, fmt.Sprintf("restore_output: %s", strings.TrimSpace(string(output))))
	}

	// Wait for sinkhole to collect connection attempts
	time.Sleep(3 * time.Second)

	return evidence, err
}

func (m *Manager) analyzeEvidence(replayEvidence []string, connections []ConnectionAttempt) *VerifyResult {
	var evidence []string
	evidence = append(evidence, replayEvidence...)
	confirmed := false

	for _, conn := range connections {
		evidence = append(evidence, fmt.Sprintf("c2_callback: %s:%d (family=%d)",
			conn.DstAddr, conn.DstPort, conn.Family))
		// Any outbound connection in the sandbox = C2 callback attempt
		confirmed = true
	}

	// Check for sensitive file access patterns
	for _, e := range replayEvidence {
		if strings.Contains(e, "/etc/shadow") ||
			strings.Contains(e, "/etc/passwd") ||
			strings.Contains(e, ".ssh/authorized_keys") {
			evidence = append(evidence, "sensitive_file_access")
			confirmed = true
		}
	}

	return &VerifyResult{
		ConfirmedMalicious: confirmed,
		Evidence:           evidence,
	}
}
