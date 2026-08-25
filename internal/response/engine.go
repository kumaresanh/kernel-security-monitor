// Package response implements the tiered response engine for Kernel Security Monitor.
package response

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kernel-security-monitor/ksm/internal/graph"
	"github.com/kernel-security-monitor/ksm/internal/sensor"
)

// Mode controls whether Kernel Security Monitor kills processes or only observes.
type Mode string

const (
	ModeObserve Mode = "observe" // Default: log only, never kill
	ModePause   Mode = "pause"   // SIGSTOP suspicious processes, wait for user approval
	ModeEnforce Mode = "enforce" // Kill confirmed threats (with whitelist protection)
)

// Tier represents the response severity tier.
type Tier string

const (
	TierLow    Tier = "low"    // p > 0.15 — log only
	TierMedium Tier = "medium" // 0.05 < p <= 0.15 — CRIU checkpoint verify
	TierHigh   Tier = "high"   // p <= 0.05 — BPF-LSM kill / signal kill
)

// ProcessStatus classifies a process for the dashboard.
type ProcessStatus string

const (
	StatusKnown      ProcessStatus = "known"      // Whitelisted / benign
	StatusUnknown    ProcessStatus = "unknown"     // Not whitelisted, not yet flagged
	StatusSuspicious ProcessStatus = "suspicious"  // Flagged by anomaly detection
	StatusPaused     ProcessStatus = "paused"      // SIGSTOP'd, waiting for user approval
)

// ConformalResult holds the output from the Python sidecar's conformal calibration.
type ConformalResult struct {
	AnomalyScore float64 `json:"anomaly_score"`
	RawScore     float64 `json:"raw_score"`
	PValue       float64 `json:"p_value"`
	Tier         Tier    `json:"tier"`
	IsAnomaly    bool    `json:"is_anomaly"`
}

// TierFromPValue maps conformal p-value to response tier.
func TierFromPValue(pValue float64) Tier {
	switch {
	case pValue > 0.15:
		return TierLow
	case pValue > 0.05:
		return TierMedium
	default:
		return TierHigh
	}
}

// Decision records a response decision.
type Decision struct {
	Timestamp     time.Time     `json:"timestamp"`
	PID           uint32        `json:"pid"`
	Comm          string        `json:"comm"`
	Tier          Tier          `json:"tier"`
	TrustScore    float64       `json:"trust_score"`
	ConformalPVal float64       `json:"conformal_p_value"`
	Action        string        `json:"action"`
	Status        ProcessStatus `json:"status"`
	Technique     string        `json:"technique,omitempty"`
	TechniqueID   string        `json:"technique_id,omitempty"`
	CausalSummary string        `json:"causal_summary,omitempty"`
	Verified      *bool         `json:"verified,omitempty"`
	Evidence      []string      `json:"evidence,omitempty"`
}

// UserTrust is the persistent user trust database.
type UserTrust struct {
	KnownComms   []string `json:"known_comms"`
	KnownPIDs    []uint32 `json:"known_pids"`
	UnknownComms []string `json:"unknown_comms"`
}

// ActionLogEntry records explicit user actions for the dashboard Action Log.
type ActionLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`    // e.g. "kill", "pause", "resume", "trust"
	PID       uint32    `json:"pid"`
	Comm      string    `json:"comm"`
	By        string    `json:"by"`        // "user" or "system"
	Result    string    `json:"result"`    // "ok" or error
}

// Engine is the response decision engine.
type Engine struct {
	loader             *sensor.Loader
	cg                 *graph.CausalGraph
	trustCfg           graph.TrustConfig
	scorer             *graph.TrustScorer
	logger             *slog.Logger
	mu                 sync.Mutex
	decisions          []Decision
	actionLog          []ActionLogEntry   // user-driven action history
	criuEnabled        bool
	mode               Mode
	customTrustedComms map[string]bool
	customTrustedPIDs  map[uint32]bool
	pausedPIDs         map[uint32]string // pid -> comm
	userTrustPath      string
	// Callback for CRIU verify (injected if Priority 2 is built)
	VerifyFunc func(pid uint32) (*VerifyResult, error)
}

// VerifyResult from the CRIU checkpoint+replay verify path.
type VerifyResult struct {
	ConfirmedMalicious bool     `json:"confirmed_malicious"`
	Evidence           []string `json:"evidence"`

}

// NewEngine creates a new response engine.
func NewEngine(loader *sensor.Loader, cg *graph.CausalGraph, logger *slog.Logger) *Engine {
	cfg := graph.DefaultTrustConfig()
	return &Engine{
		loader:             loader,
		cg:                 cg,
		trustCfg:           cfg,
		scorer:             graph.NewTrustScorer(cg, cfg),
		logger:             logger,
		mode:               ModeObserve, // Default: observe only
		customTrustedComms: make(map[string]bool),
		customTrustedPIDs:  make(map[uint32]bool),
		pausedPIDs:         make(map[uint32]string),
	}
}

// SetUserTrustPath sets the path for persisting user trust decisions.
func (e *Engine) SetUserTrustPath(path string) {
	e.userTrustPath = path
}

// LoadUserTrust loads user trust decisions from a JSON file.
func (e *Engine) LoadUserTrust(path string) error {
	e.userTrustPath = path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No file yet is fine
		}
		return err
	}
	var ut UserTrust
	if err := json.Unmarshal(data, &ut); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, comm := range ut.KnownComms {
		e.customTrustedComms[comm] = true
	}
	for _, pid := range ut.KnownPIDs {
		e.customTrustedPIDs[pid] = true
	}
	e.logger.Info("loaded user trust decisions", "known_comms", len(ut.KnownComms), "known_pids", len(ut.KnownPIDs))
	return nil
}

// SaveUserTrust persists user trust decisions to a JSON file.
func (e *Engine) SaveUserTrust() error {
	if e.userTrustPath == "" {
		return nil
	}
	e.mu.Lock()
	comms := make([]string, 0, len(e.customTrustedComms))
	for c := range e.customTrustedComms {
		comms = append(comms, c)
	}
	pids := make([]uint32, 0, len(e.customTrustedPIDs))
	for p := range e.customTrustedPIDs {
		pids = append(pids, p)
	}
	e.mu.Unlock()

	ut := UserTrust{
		KnownComms: comms,
		KnownPIDs:  pids,
	}
	data, err := json.MarshalIndent(ut, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(e.userTrustPath, data, 0644)
}

// PauseProcess sends SIGSTOP to a process and records it as paused.
func (e *Engine) PauseProcess(pid uint32, comm string) error {
	// Safety: never pause kernel threads or init
	if pid <= 10 {
		return fmt.Errorf("refusing to pause kernel/init process %d", pid)
	}
	if err := syscall.Kill(int(pid), syscall.SIGSTOP); err != nil {
		return fmt.Errorf("SIGSTOP pid %d: %w", pid, err)
	}
	e.mu.Lock()
	e.pausedPIDs[pid] = comm
	e.mu.Unlock()
	e.logger.Warn("process PAUSED (SIGSTOP) — waiting for user approval", "pid", pid, "comm", comm)
	return nil
}

// ResumeProcess sends SIGCONT to a paused process.
func (e *Engine) ResumeProcess(pid uint32) error {
	if err := syscall.Kill(int(pid), syscall.SIGCONT); err != nil {
		return fmt.Errorf("SIGCONT pid %d: %w", pid, err)
	}
	e.mu.Lock()
	comm := e.pausedPIDs[pid]
	delete(e.pausedPIDs, pid)
	e.mu.Unlock()
	e.logger.Info("process RESUMED (SIGCONT) by user", "pid", pid, "comm", comm)
	return nil
}

// GetPausedProcesses returns currently paused PIDs with their comm names.
func (e *Engine) GetPausedProcesses() map[uint32]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make(map[uint32]string, len(e.pausedPIDs))
	for k, v := range e.pausedPIDs {
		result[k] = v
	}
	return result
}

// IsProcessPaused returns true if the given PID is paused.
func (e *Engine) IsProcessPaused(pid uint32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.pausedPIDs[pid]
	return ok
}

// KillProcess sends SIGKILL to a process and records it in the action log.
func (e *Engine) KillProcess(pid uint32, comm string) error {
	if pid <= 10 {
		return fmt.Errorf("refusing to kill kernel/init process %d", pid)
	}
	entry := ActionLogEntry{
		Timestamp: time.Now(),
		Action:    "kill",
		PID:       pid,
		Comm:      comm,
		By:        "user",
	}
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		entry.Result = err.Error()
		e.appendActionLog(entry)
		return fmt.Errorf("SIGKILL pid %d: %w", pid, err)
	}
	entry.Result = "ok"
	e.appendActionLog(entry)
	e.logger.Warn("process KILLED (SIGKILL) by user", "pid", pid, "comm", comm)
	return nil
}

// appendActionLog adds an entry to the action log (max 200 entries).
func (e *Engine) appendActionLog(entry ActionLogEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actionLog = append([]ActionLogEntry{entry}, e.actionLog...)
	if len(e.actionLog) > 200 {
		e.actionLog = e.actionLog[:200]
	}
}

// RecordAction records a user-driven action (trust, pause, resume) in the log.
func (e *Engine) RecordAction(action, comm string, pid uint32, by, result string) {
	e.appendActionLog(ActionLogEntry{
		Timestamp: time.Now(),
		Action:    action,
		PID:       pid,
		Comm:      comm,
		By:        by,
		Result:    result,
	})
}

// GetActionLog returns recent action log entries.
func (e *Engine) GetActionLog(n int) []ActionLogEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	if n <= 0 || n > len(e.actionLog) {
		n = len(e.actionLog)
	}
	result := make([]ActionLogEntry, n)
	copy(result, e.actionLog[:n])
	return result
}

// GetSuspiciousBelow returns recent decisions for processes with trust below threshold.
func (e *Engine) GetSuspiciousBelow(threshold float64) []Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	// deduplicate by PID, keep latest
	seen := make(map[uint32]Decision)
	for _, d := range e.decisions {
		if d.TrustScore < threshold && d.Status != StatusKnown {
			existing, ok := seen[d.PID]
			if !ok || d.Timestamp.After(existing.Timestamp) {
				seen[d.PID] = d
			}
		}
	}
	result := make([]Decision, 0, len(seen))
	for _, d := range seen {
		result = append(result, d)
	}
	return result
}

// TrustProcess dynamically marks a process comm or PID as fully trusted (100% trust).
func (e *Engine) TrustProcess(comm string, pid uint32) {
	e.mu.Lock()
	if comm != "" {
		e.customTrustedComms[comm] = true
	}
	if pid > 0 {
		e.customTrustedPIDs[pid] = true
	}
	e.mu.Unlock()

	if pid > 0 && e.cg != nil {
		e.cg.SetProcessTrust(pid, 100.0)
	}

	e.logger.Info("process marked as custom trusted by user", "comm", comm, "pid", pid)
}

// IsTrusted checks if a process is statically or dynamically whitelisted.
func (e *Engine) IsTrusted(comm string, pid uint32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.customTrustedPIDs[pid] || e.customTrustedComms[comm] {
		return true
	}
	return isKnownProcess(comm) || pid <= 100
}

// SetMode sets the operating mode.
func (e *Engine) SetMode(m Mode) {
	e.mode = m
	e.logger.Info("engine mode set", "mode", string(m))
}

// GetMode returns the current operating mode.
func (e *Engine) GetMode() Mode {
	return e.mode
}

// SetCRIUEnabled enables/disables CRIU verify path.
func (e *Engine) SetCRIUEnabled(enabled bool) {
	e.criuEnabled = enabled
}

// ClassifyProcess returns the process status for dashboard display.
func ClassifyProcess(comm string, pValue float64) ProcessStatus {
	if isKnownProcess(comm) {
		return StatusKnown
	}
	if pValue <= 0.15 {
		return StatusSuspicious
	}
	return StatusUnknown
}


// Respond executes the tiered response for a given process and conformal result.
func (e *Engine) Respond(pid uint32, comm string, result ConformalResult, techniqueID, techniqueName string, severity float64) Decision {
	status := ClassifyProcess(comm, result.PValue)

	if e.IsTrusted(comm, pid) {
		status = StatusKnown
	}

	// KNOWN processes: always force trust=100, skip ML classification entirely
	var trustScore float64
	var tier Tier
	if status == StatusKnown {
		trustScore = 100.0
		tier = TierLow
		if e.cg != nil {
			e.cg.SetProcessTrust(pid, 100.0)
		}
		// Return immediately with known status — no further action needed
		decision := Decision{
			Timestamp:  time.Now(),
			PID:        pid,
			Comm:       comm,
			Tier:       tier,
			TrustScore: trustScore,
			Status:     StatusKnown,
			Action:     "trusted_allow",
		}
		e.mu.Lock()
		e.decisions = append(e.decisions, decision)
		e.mu.Unlock()
		return decision
	}

	tier = TierFromPValue(result.PValue)
	// Compute trust score for unknown/suspicious processes
	trustInput := graph.ScoringInput{
		ConformalPValue:          result.PValue,
		MatchedTechniqueSeverity: severity,
	}
	trustScore = e.scorer.UpdateProcessTrust(pid, trustInput)

	decision := Decision{
		Timestamp:     time.Now(),
		PID:           pid,
		Comm:          comm,
		Tier:          tier,
		TrustScore:    trustScore,
		ConformalPVal: result.PValue,
		TechniqueID:   techniqueID,
		Technique:     techniqueName,
		Status:        status,
	}

	// Build causal summary
	nodeID := fmt.Sprintf("proc:%d", pid)
	if sub, ok := e.cg.Subgraph(nodeID); ok {
		summary, _ := json.Marshal(map[string]interface{}{
			"nodes": len(sub.Nodes),
			"edges": len(sub.Edges),
		})
		decision.CausalSummary = string(summary)
	}

	// ---- OBSERVE MODE: never kill, only log ----
	if e.mode == ModeObserve {
		switch tier {
		case TierLow:
			decision.Action = "observe_log"
		case TierMedium:
			decision.Action = "observe_alert"
			e.logger.Warn("OBSERVE: medium anomaly detected",
				"pid", pid, "comm", comm, "trust", trustScore,
				"p_value", result.PValue, "status", status)
		case TierHigh:
			decision.Action = "observe_critical"
			e.logger.Warn("OBSERVE: high anomaly detected (would kill in enforce mode)",
				"pid", pid, "comm", comm, "trust", trustScore,
				"p_value", result.PValue, "status", status, "technique", techniqueID)
		}

		e.mu.Lock()
		e.decisions = append(e.decisions, decision)
		e.mu.Unlock()
		return decision
	}

	// ---- PAUSE MODE: SIGSTOP suspicious processes, wait for user approval ----
	if e.mode == ModePause {
		switch tier {
		case TierLow:
			decision.Action = "pause_log"
		case TierMedium, TierHigh:
			// Only pause if not already paused
			if !e.IsProcessPaused(pid) {
				err := e.PauseProcess(pid, comm)
				if err != nil {
					e.logger.Error("PAUSE: failed to SIGSTOP process", "pid", pid, "comm", comm, "error", err)
					decision.Action = "pause_failed_log"
				} else {
					decision.Action = "paused_sigstop"
					decision.Status = StatusPaused
					e.logger.Warn("PAUSE: process SUSPENDED awaiting user approval",
						"pid", pid, "comm", comm, "trust", trustScore,
						"p_value", result.PValue, "technique", techniqueID)
				}
			} else {
				decision.Action = "already_paused"
				decision.Status = StatusPaused
			}
		}
		e.mu.Lock()
		e.decisions = append(e.decisions, decision)
		e.mu.Unlock()
		return decision
	}

	// ---- ENFORCE MODE: actual response actions ----
	switch tier {
	case TierLow:
		decision.Action = "log_only"
		e.logger.Info("RESPONSE: log only",
			"pid", pid, "comm", comm, "trust", trustScore,
			"p_value", result.PValue, "technique", techniqueID)

	case TierMedium:
		if e.criuEnabled && e.VerifyFunc != nil {
			decision.Action = "criu_verify"
			e.logger.Warn("RESPONSE: CRIU checkpoint + verify",
				"pid", pid, "comm", comm, "trust", trustScore,
				"p_value", result.PValue, "technique", techniqueID)

			vResult, err := e.VerifyFunc(pid)
			if err != nil {
				e.logger.Error("CRIU verify failed, logging only", "pid", pid, "error", err)
				decision.Action = "criu_verify_failed_log"
			} else {
				confirmed := vResult.ConfirmedMalicious
				decision.Verified = &confirmed
				decision.Evidence = vResult.Evidence
				if confirmed {
					e.logger.Error("VERIFIED MALICIOUS — killing process",
						"pid", pid, "evidence", vResult.Evidence)
					if err := e.loader.DenyExec(pid); err != nil {
						e.logger.Error("kill failed", "pid", pid, "error", err)
					}
					decision.Action = "verified_kill"
				} else {
					decision.Action = "verified_benign"
					e.logger.Info("CRIU verify: benign", "pid", pid)
				}
			}
		} else {
			decision.Action = "log_elevated"
			e.logger.Warn("RESPONSE: elevated log (CRIU not available)",
				"pid", pid, "comm", comm, "trust", trustScore,
				"p_value", result.PValue, "technique", techniqueID)
		}

	case TierHigh:
		if isKnownProcess(comm) || pid <= 100 {
			decision.Action = "protected_log_only"
			e.logger.Warn("RESPONSE: High anomaly on protected process (skipped kill)",
				"pid", pid, "comm", comm, "trust", trustScore,
				"p_value", result.PValue, "technique", techniqueID)
		} else {
			decision.Action = "kill"
			e.logger.Error("RESPONSE: BPF-LSM deny / SIGKILL",
				"pid", pid, "comm", comm, "trust", trustScore,
				"p_value", result.PValue, "technique", techniqueID)
			if err := e.loader.DenyExec(pid); err != nil {
				e.logger.Error("kill failed", "pid", pid, "error", err)
				decision.Action = "kill_failed"
			}
		}
	}

	e.mu.Lock()
	e.decisions = append(e.decisions, decision)
	e.mu.Unlock()
	return decision
}

// Decisions returns all recorded decisions.
func (e *Engine) Decisions() []Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]Decision, len(e.decisions))
	copy(result, e.decisions)
	return result
}

// RecentDecisions returns the last N decisions.
func (e *Engine) RecentDecisions(n int) []Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.decisions) <= n {
		result := make([]Decision, len(e.decisions))
		copy(result, e.decisions)
		return result
	}
	result := make([]Decision, n)
	copy(result, e.decisions[len(e.decisions)-n:])
	return result
}

// isKnownProcess checks if a process name matches the comprehensive whitelist.
// Uses both exact match and prefix match to cover system daemon variants.
func isKnownProcess(comm string) bool {
	// Exact match list
	knownExact := map[string]bool{
		// System core
		"systemd": true, "init": true, "kthreadd": true, "ksoftirqd": true,
		"rcu_sched": true, "rcu_bh": true, "migration": true,
		// System daemons
		"sshd": true, "cron": true, "atd": true, "dbus-daemon": true,
		"polkitd": true, "udisksd": true, "accounts-daemon": true,
		"NetworkManager": true, "wpa_supplicant": true, "dhclient": true,
		"avahi-daemon": true, "cupsd": true, "rsyslogd": true,
		"udevd": true, "systemd-udevd": true, "upowerd": true,
		"logger": true, "logrotate": true, "syslogd": true,
		// Audio/Video
		"pulseaudio": true, "pipewire": true, "wireplumber": true,
		"pactl": true, "pavucontrol": true, "pw-cli": true,
		"pipewire-pulse": true, "pipewire-media-session": true,
		// Display & Desktop
		"Xorg": true, "Xwayland": true, "mutter": true, "kwin": true,
		"plasmashell": true, "nemo": true, "nautilus": true, "thunar": true,
		"dwm": true, "dwmblocks": true, "st": true, "dmenu": true,
		"rofi": true, "polybar": true, "i3": true, "i3bar": true, "i3status": true,
		"bspwm": true, "sxhkd": true, "xmonad": true,
		// Shells & Terminal
		"bash": true, "sh": true, "zsh": true, "fish": true, "dash": true,
		"tmux": true, "screen": true, "login": true, "getty": true,
		"sudo": true, "su": true, "passwd": true,
		"alacritty": true, "kitty": true, "urxvt": true, "xterm": true,
		// Common shell utilities that run briefly
		"dirname": true, "basename": true, "readlink": true, "realpath": true,
		"expr": true, "test": true, "[[": true, "true": true, "false": true,
		"echo": true, "printf": true, "sleep": true, "wait": true,
		"env": true, "nohup": true, "nice": true, "ionice": true,
		"type": true, "command": true, "source": true, "exec": true,
		// Browsers
		"chrome": true, "chromium": true, "firefox": true, "brave": true,
		"opera": true, "vivaldi": true,
		// IDEs & Editors
		"antigravity": true, "code": true, "vscode": true, "cursor": true,
		"nvim": true, "vim": true, "emacs": true, "nano": true, "gedit": true,
		"sublime_text": true, "kate": true,
		// Dev tools
		"node": true, "npm": true, "npx": true, "yarn": true, "pnpm": true,
		"go": true, "gopls": true, "clangd": true, "rust-analyzer": true,
		"cargo": true, "rustc": true, "gcc": true, "g++": true, "clang": true,
		"make": true, "cmake": true, "git": true, "git-remote-http": true,
		"tsserver": true, "eslint": true, "prettier": true,
		// Python
		"python": true, "python3": true, "python3.12": true, "python3.11": true,
		"pip": true, "pip3": true, "uvicorn": true, "gunicorn": true, "flask": true,
		// Java/JVM
		"java": true, "javac": true, "gradle": true, "mvn": true,
		// Package managers
		"apt": true, "apt-get": true, "dpkg": true, "pacman": true,
		"yum": true, "dnf": true, "snap": true, "flatpak": true,
		// System tools
		"free": true, "top": true, "htop": true, "btop": true, "ps": true,
		"grep": true, "find": true, "ls": true, "cat": true, "less": true,
		"more": true, "head": true, "tail": true, "wc": true, "sort": true,
		"awk": true, "sed": true, "cut": true, "tr": true, "xargs": true,
		"kill": true, "pkill": true, "pgrep": true, "lsof": true, "strace": true,
		"uname": true, "whoami": true, "id": true, "date": true, "which": true,
		"file": true, "stat": true, "df": true, "du": true, "mount": true,
		"ip": true, "ss": true, "netstat": true, "ping": true, "dig": true,
		"curl": true, "wget": true, "ssh": true, "scp": true, "rsync": true,
		"tar": true, "gzip": true, "unzip": true, "bzip2": true, "xz": true,
		"cp": true, "mv": true, "rm": true, "mkdir": true, "rmdir": true,
		"ln": true, "chmod": true, "chown": true, "touch": true,
		"tee": true, "xdg-open": true, "xclip": true, "dmesg": true,
		// Desktop utilities & X11 tools
		"volume.sh": true, "dbus-send": true, "xprop": true, "xsetroot": true,
		"feh": true, "picom": true, "slstatus": true,
		"brightness.sh": true, "battery.sh": true, "wifi.sh": true,
		// Kernel Security Monitor itself (including 15-char comm truncation)
		"kernel-security-monitor": true, "kernel-security": true, "ksm": true, "scorer": true, "scorer.py": true,
		// Worker threads (kernel/udev/systemd internal workers shown with parentheses)
		"(udev-worker)": true, "(sd-worker)": true, "(systemd)": true,
		// Thread pool names (from browsers, JVM, etc.)
		"ThreadPoolForeg": true, "ThreadPoolSingl": true, "JavaFX Applicat": true,
		"libuv-worker": true, "InputThread": true, "CompositorTileW": true,
		"Chrome_ChildIOT": true, "VizCompositorTh": true, "AudioOutputDevi": true,
	}

	if knownExact[comm] {
		return true
	}

	// Prefix-based matches for dynamic thread / worker / shell script names
	knownPrefixes := []string{
		"blocking-",
		"volume",
		"Thread",
		"Worker",
		"libuv",
		"Input",
		"Compositor",
		"Audio",
		"Viz",
		"Chrome_",
		"sd-",
		"systemd-",
		"pipewire",
		"wireplumber",
		"pulseaudio",
		"gvfs",
		"dbus",
		"electron",
		"language_server", "language-server",
		"antigravity", "code-", "vscode-",
		"npm ", "node ", "python",
		"kworker/", "irq/", "scsi_",
		// Kernel worker threads shown as "(name)"
		"(",
		// Thread pool names
		"Thread", "Worker", "libuv", "Input", "Compositor", "Audio",
		// Systemd slice workers
		"sd-",
	}
	for _, prefix := range knownPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return true
		}
	}

	return false
}
