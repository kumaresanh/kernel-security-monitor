package db

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcessRecord tracks full historical context of a process
type ProcessRecord struct {
	PID            uint32            `json:"pid"`
	PPID           uint32            `json:"ppid"`
	Comm           string            `json:"comm"`
	ParentComm     string            `json:"parent_comm,omitempty"`
	TrustScore     float64           `json:"trust_score"`
	Status         string            `json:"status"` // "known", "unknown", "suspicious", "paused", "killed"
	Tier           string            `json:"tier"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	SyscallCount   uint64            `json:"syscall_count"`
	AccessedFiles  map[string]int    `json:"accessed_files"`  // path -> count
	NetworkSockets map[string]int    `json:"network_sockets"` // ip:port -> count
	SpawnedSubPIDs []uint32          `json:"spawned_sub_pids"`
	AttackPatterns []AttackPattern   `json:"attack_patterns,omitempty"`
	Decisions      []DecisionSummary `json:"decisions,omitempty"`
	IsPaused       bool              `json:"is_paused"`
	IsKilled       bool              `json:"is_killed"`
	EndedAt        time.Time         `json:"ended_at,omitempty"`
}

// AttackPattern describes an identified suspicious or malicious sequence
type AttackPattern struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	PID         uint32    `json:"pid"`
	Comm        string    `json:"comm"`
	PPID        uint32    `json:"ppid"`
	ParentComm  string    `json:"parent_comm"`
	TechniqueID string    `json:"technique_id"`
	Technique   string    `json:"technique"`
	Severity    string    `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	PatternType string    `json:"pattern_type"`
	Description string    `json:"description"`
	Evidence    []string  `json:"evidence"`
}

// DecisionSummary records engine responses
type DecisionSummary struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	TrustScore  float64   `json:"trust_score"`
	TechniqueID string    `json:"technique_id,omitempty"`
}

// EventRecord records raw system call events
type EventRecord struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Comm      string    `json:"comm"`
	TypeStr   string    `json:"type_str"`
	Payload   string    `json:"payload,omitempty"`
	DstIP     string    `json:"dst_ip,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Ret       int64     `json:"ret"`
}

// ConversationRecord records AI queries and answers
type ConversationRecord struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Query     string    `json:"query"`
	Response  string    `json:"response"`
	TargetPID uint32    `json:"target_pid,omitempty"`
	Model     string    `json:"model"`
	Mode      string    `json:"mode"`
}

// ProcessTreeNode is used for hierarchical rendering (Parent -> Children)
type ProcessTreeNode struct {
	PID            uint32             `json:"pid"`
	PPID           uint32             `json:"ppid"`
	Comm           string             `json:"comm"`
	TrustScore     float64            `json:"trust_score"`
	Status         string             `json:"status"`
	Tier           string             `json:"tier"`
	FirstSeen      string             `json:"first_seen"`
	LastSeen       string             `json:"last_seen"`
	SyscallCount   uint64             `json:"syscall_count"`
	FilesCount     int                `json:"files_count"`
	SocketsCount   int                `json:"sockets_count"`
	RecentFiles    []string           `json:"recent_files"`
	RecentSockets  []string           `json:"recent_sockets"`
	AttackPatterns []AttackPattern    `json:"attack_patterns"`
	Children       []*ProcessTreeNode `json:"children"`
}

// ProductionGraphNode represents clean aggregated graph nodes
type ProductionGraphNode struct {
	ID         string  `json:"id"`
	Label      string  `json:"label"`
	Type       string  `json:"type"` // "parent_process", "process", "socket", "threat"
	Trust      float64 `json:"trust"`
	PID        uint32  `json:"pid,omitempty"`
	Comm       string  `json:"comm,omitempty"`
	PPID       uint32  `json:"ppid,omitempty"`
	Status     string  `json:"status,omitempty"`
	EventCount int     `json:"event_count"`
	IsCluster  bool    `json:"is_cluster,omitempty"`
}

// ProductionGraphEdge represents weighted contextual relationships
type ProductionGraphEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Type     string `json:"type"` // "FORK_EXEC", "CONNECT", "WRITE_STAGING", "SUSPICIOUS_ACCESS"
	Weight   int    `json:"weight"`
	Severity string `json:"severity"` // "critical", "warning", "normal"
	Label    string `json:"label"`
}

// ProductionGraphData is returned for the SIEM-grade graph
type ProductionGraphData struct {
	Nodes        []ProductionGraphNode `json:"nodes"`
	Edges        []ProductionGraphEdge `json:"edges"`
	ActiveThreat int                   `json:"active_threats"`
	TotalPIDs    int                   `json:"total_pids"`
}

// Store is the unified thread-safe persistent database
type Store struct {
	mu             sync.RWMutex
	dataDir        string
	processes      map[uint32]*ProcessRecord
	events         []EventRecord
	conversations  []ConversationRecord
	attackPatterns []AttackPattern
	eventCounter   uint64
	chatCounter    uint64
	maxEvents      int
}

// NewStore initializes the database engine
func NewStore(dataDir string) *Store {
	if dataDir == "" {
		dataDir = "data"
	}
	os.MkdirAll(dataDir, 0755)

	s := &Store{
		dataDir:        dataDir,
		processes:      make(map[uint32]*ProcessRecord),
		events:         make([]EventRecord, 0, 10000),
		conversations:  make([]ConversationRecord, 0, 500),
		attackPatterns: make([]AttackPattern, 0, 500),
		maxEvents:      10000,
	}

	s.loadPersistedData()
	return s
}

func (s *Store) loadPersistedData() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load session analysis log if present
	sessPath := filepath.Join(s.dataDir, "session_analysis.jsonl")
	data, err := os.ReadFile(sessPath)
	if err == nil && len(data) > 0 {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			var e struct {
				Timestamp string `json:"ts"`
				Query     string `json:"q"`
				Answer    string `json:"a"`
				Mode      string `json:"mode"`
			}
			if err := json.Unmarshal([]byte(line), &e); err == nil {
				t, _ := time.Parse(time.RFC3339, e.Timestamp)
				if t.IsZero() {
					t = time.Now()
				}
				s.chatCounter++
				s.conversations = append(s.conversations, ConversationRecord{
					ID:        s.chatCounter,
					Timestamp: t,
					Query:     e.Query,
					Response:  e.Answer,
					Mode:      e.Mode,
				})
			}
		}
	}
}

// RecordEvent ingests every raw kernel syscall and updates process provenance
func (s *Store) RecordEvent(pid, ppid uint32, comm, typeStr, payload, dstIP string, dstPort uint16, ret int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.eventCounter++
	now := time.Now()

	evt := EventRecord{
		ID:        s.eventCounter,
		Timestamp: now,
		PID:       pid,
		PPID:      ppid,
		Comm:      comm,
		TypeStr:   typeStr,
		Payload:   payload,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Ret:       ret,
	}

	s.events = append(s.events, evt)
	if len(s.events) > s.maxEvents {
		s.events = s.events[len(s.events)-s.maxEvents:]
	}

	// Update process record
	proc, exists := s.processes[pid]
	if !exists {
		parentComm := ""
		if parent, pExists := s.processes[ppid]; pExists {
			parentComm = parent.Comm
			parent.SpawnedSubPIDs = append(parent.SpawnedSubPIDs, pid)
		}

		proc = &ProcessRecord{
			PID:            pid,
			PPID:           ppid,
			Comm:           comm,
			ParentComm:     parentComm,
			TrustScore:     80.0,
			Status:         "unknown",
			Tier:           "medium",
			FirstSeen:      now,
			LastSeen:       now,
			SyscallCount:   0,
			AccessedFiles:  make(map[string]int),
			NetworkSockets: make(map[string]int),
			SpawnedSubPIDs: make([]uint32, 0),
			AttackPatterns: make([]AttackPattern, 0),
		}
		s.processes[pid] = proc
	}

	proc.LastSeen = now
	proc.SyscallCount++
	if comm != "" {
		proc.Comm = comm
	}
	if ppid > 0 {
		proc.PPID = ppid
	}

	if payload != "" {
		proc.AccessedFiles[payload]++
	}
	if dstIP != "" {
		sockKey := fmt.Sprintf("%s:%d", dstIP, dstPort)
		proc.NetworkSockets[sockKey]++
	}

	// Dynamic Attack Pattern Analysis
	s.detectAttackPatternsLocked(proc, typeStr, payload, dstIP, dstPort)
}

// detectAttackPatternsLocked analyzes multi-step behavior on the fly
func (s *Store) detectAttackPatternsLocked(proc *ProcessRecord, typeStr, payload, dstIP string, dstPort uint16) {
	now := time.Now()

	// 1. Ingress Tool Transfer / Staging Script Pattern (T1105 / T1059)
	if typeStr == "openat" && (strings.HasPrefix(payload, "/tmp/") || strings.HasPrefix(payload, "/var/tmp/")) {
		if strings.HasSuffix(payload, ".sh") || strings.Contains(payload, "installer") || strings.Contains(payload, "backdoor") || strings.Contains(payload, "payload") {
			s.addPatternIfNotExists(proc, AttackPattern{
				ID:          fmt.Sprintf("pat-staging-%d", proc.PID),
				Timestamp:   now,
				PID:         proc.PID,
				Comm:        proc.Comm,
				PPID:        proc.PPID,
				ParentComm:  proc.ParentComm,
				TechniqueID: "T1105 / T1059",
				Technique:   "Ingress Tool Transfer & Script Execution",
				Severity:    "HIGH",
				PatternType: "STAGING_SCRIPT",
				Description: fmt.Sprintf("Process staged executable script in temporary directory: %s", payload),
				Evidence:    []string{fmt.Sprintf("Path: %s", payload), fmt.Sprintf("Parent: %s (PID %d)", proc.ParentComm, proc.PPID)},
			})
		}
	}

	// 2. Command and Control (C2) Callback Pattern (T1071 / T1095)
	if typeStr == "connect" && dstIP != "" && dstIP != "127.0.0.1" && !strings.HasPrefix(dstIP, "::1") {
		if dstPort == 4444 || dstPort == 1337 || dstPort == 8888 || dstPort == 9999 || strings.Contains(proc.Comm, "backdoor") || strings.Contains(proc.Comm, "c2") {
			s.addPatternIfNotExists(proc, AttackPattern{
				ID:          fmt.Sprintf("pat-c2-%d", proc.PID),
				Timestamp:   now,
				PID:         proc.PID,
				Comm:        proc.Comm,
				PPID:        proc.PPID,
				ParentComm:  proc.ParentComm,
				TechniqueID: "T1071 / T1095",
				Technique:   "Application Layer Protocol / Non-Standard C2",
				Severity:    "CRITICAL",
				PatternType: "C2_BEACON",
				Description: fmt.Sprintf("Outbound socket connection to non-standard remote C2 endpoint %s:%d", dstIP, dstPort),
				Evidence:    []string{fmt.Sprintf("Remote: %s:%d", dstIP, dstPort), fmt.Sprintf("Comm: %s", proc.Comm)},
			})
		}
	}

	// 3. Credential Access / Sensitive File Discovery (T1003 / T1083)
	if typeStr == "openat" && (payload == "/etc/shadow" || payload == "/etc/passwd" || strings.Contains(payload, ".ssh") || strings.Contains(payload, ".aws")) {
		if proc.Comm != "login" && proc.Comm != "sudo" && proc.Comm != "passwd" && proc.Comm != "sshd" {
			s.addPatternIfNotExists(proc, AttackPattern{
				ID:          fmt.Sprintf("pat-cred-%d", proc.PID),
				Timestamp:   now,
				PID:         proc.PID,
				Comm:        proc.Comm,
				PPID:        proc.PPID,
				ParentComm:  proc.ParentComm,
				TechniqueID: "T1003 / T1083",
				Technique:   "OS Credential Dumping & File Discovery",
				Severity:    "HIGH",
				PatternType: "CREDENTIAL_PROBE",
				Description: fmt.Sprintf("Non-authentication process attempted access to sensitive system credential path %s", payload),
				Evidence:    []string{fmt.Sprintf("Sensitive Path: %s", payload)},
			})
		}
	}

	// 4. Persistence Attempt (T1053 Scheduled Task / Cron)
	if typeStr == "openat" && (strings.Contains(payload, "cron") || strings.Contains(payload, "systemd/system")) {
		if proc.Comm != "crond" && proc.Comm != "cron" && proc.Comm != "systemd" {
			s.addPatternIfNotExists(proc, AttackPattern{
				ID:          fmt.Sprintf("pat-persist-%d", proc.PID),
				Timestamp:   now,
				PID:         proc.PID,
				Comm:        proc.Comm,
				PPID:        proc.PPID,
				ParentComm:  proc.ParentComm,
				TechniqueID: "T1053.003",
				Technique:   "Scheduled Task/Job: Cron Persistence",
				Severity:    "CRITICAL",
				PatternType: "PERSISTENCE",
				Description: fmt.Sprintf("Process attempted modifying cron/systemd service configuration for persistence: %s", payload),
				Evidence:    []string{fmt.Sprintf("Persistence Target: %s", payload)},
			})
		}
	}
}

func (s *Store) addPatternIfNotExists(proc *ProcessRecord, pat AttackPattern) {
	for _, existing := range proc.AttackPatterns {
		if existing.PatternType == pat.PatternType && existing.TechniqueID == pat.TechniqueID {
			return
		}
	}
	proc.AttackPatterns = append(proc.AttackPatterns, pat)
	s.attackPatterns = append(s.attackPatterns, pat)
}

// RecordDecision logs response engine decisions into the process history
func (s *Store) RecordDecision(pid uint32, comm string, trust float64, status, action, techniqueID, technique string, pVal float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	proc, exists := s.processes[pid]
	if !exists {
		proc = &ProcessRecord{
			PID:            pid,
			Comm:           comm,
			FirstSeen:      now,
			AccessedFiles:  make(map[string]int),
			NetworkSockets: make(map[string]int),
		}
		s.processes[pid] = proc
	}

	proc.TrustScore = trust
	proc.Status = status
	proc.LastSeen = now
	if status == "paused" {
		proc.IsPaused = true
	}
	if action == "kill" || action == "verified_kill" {
		proc.IsKilled = true
		proc.Status = "killed"
		proc.EndedAt = now
	}

	proc.Decisions = append(proc.Decisions, DecisionSummary{
		Timestamp:   now,
		Action:      action,
		TrustScore:  trust,
		TechniqueID: techniqueID,
	})
}

// GetProcessSnapshot returns a copy suitable for an HTTP response. It keeps
// process evidence available to the inspector without exposing Store internals.
func (s *Store) GetProcessSnapshot(pid uint32) (*ProcessRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	proc, ok := s.processes[pid]
	if !ok {
		return nil, false
	}
	copyProc := *proc
	copyProc.AccessedFiles = make(map[string]int, len(proc.AccessedFiles))
	for path, count := range proc.AccessedFiles {
		copyProc.AccessedFiles[path] = count
	}
	copyProc.NetworkSockets = make(map[string]int, len(proc.NetworkSockets))
	for socket, count := range proc.NetworkSockets {
		copyProc.NetworkSockets[socket] = count
	}
	copyProc.SpawnedSubPIDs = append([]uint32(nil), proc.SpawnedSubPIDs...)
	copyProc.AttackPatterns = append([]AttackPattern(nil), proc.AttackPatterns...)
	copyProc.Decisions = append([]DecisionSummary(nil), proc.Decisions...)
	return &copyProc, true
}

// RecordConversation persists an AI Q&A exchange
func (s *Store) RecordConversation(query, response, model, mode string, targetPID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.chatCounter++
	now := time.Now()

	rec := ConversationRecord{
		ID:        s.chatCounter,
		Timestamp: now,
		Query:     query,
		Response:  response,
		TargetPID: targetPID,
		Model:     model,
		Mode:      mode,
	}
	s.conversations = append(s.conversations, rec)

	// Append to JSONL file asynchronously
	go func(r ConversationRecord) {
		type sessionEntry struct {
			Timestamp string `json:"ts"`
			Query     string `json:"q"`
			Answer    string `json:"a"`
			Mode      string `json:"mode"`
			PID       uint32 `json:"pid,omitempty"`
		}
		e := sessionEntry{
			Timestamp: r.Timestamp.Format(time.RFC3339),
			Query:     r.Query,
			Answer:    r.Response,
			Mode:      r.Mode,
			PID:       r.TargetPID,
		}
		b, _ := json.Marshal(e)
		sessPath := filepath.Join(s.dataDir, "session_analysis.jsonl")
		f, err := os.OpenFile(sessPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.Write(append(b, '\n'))
		}
	}(rec)
}

// GetProcessTree builds a hierarchical tree (Parent -> Subprocesses -> Accesses -> Attack Patterns)
func (s *Store) GetProcessTree() []*ProcessTreeNode {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Map of PID -> node
	nodes := make(map[uint32]*ProcessTreeNode)
	for pid, p := range s.processes {
		// The interactive tree is a live process view. Historical process
		// provenance stays in the database/search path, not in this large DOM.
		if p.IsKilled || !processStillExists(pid) {
			continue
		}
		// Keep access evidence deterministic. Map iteration otherwise makes the
		// hierarchy appear to change even when the underlying process did not.
		topFiles := topEvidence(p.AccessedFiles, 8)
		topSockets := topEvidence(p.NetworkSockets, 6)

		nodes[pid] = &ProcessTreeNode{
			PID:            p.PID,
			PPID:           p.PPID,
			Comm:           p.Comm,
			TrustScore:     p.TrustScore,
			Status:         p.Status,
			Tier:           p.Tier,
			FirstSeen:      p.FirstSeen.Format("15:04:05"),
			LastSeen:       p.LastSeen.Format("15:04:05"),
			SyscallCount:   p.SyscallCount,
			FilesCount:     len(p.AccessedFiles),
			SocketsCount:   len(p.NetworkSockets),
			RecentFiles:    topFiles,
			RecentSockets:  topSockets,
			AttackPatterns: p.AttackPatterns,
			Children:       make([]*ProcessTreeNode, 0),
		}
	}

	// Link parent-child
	var rootNodes []*ProcessTreeNode
	for pid, node := range nodes {
		if node.PPID > 0 && node.PPID != pid {
			if parent, exists := nodes[node.PPID]; exists {
				parent.Children = append(parent.Children, node)
				continue
			}
		}
		// If no tracked parent, it's a top-level root in our view
		rootNodes = append(rootNodes, node)
	}

	// Sort every level, not only roots. A stable order makes a deep process
	// family usable while telemetry is arriving continuously.
	sortProcessTree(rootNodes)

	return rootNodes
}

func topEvidence(values map[string]int, limit int) []string {
	type evidence struct {
		name  string
		count int
	}
	items := make([]evidence, 0, len(values))
	for name, count := range values {
		items = append(items, evidence{name: name, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].name < items[j].name
	})
	if len(items) > limit {
		items = items[:limit]
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.name)
	}
	return out
}

func sortProcessTree(nodes []*ProcessTreeNode) {
	sort.Slice(nodes, func(i, j int) bool {
		iThreats := len(nodes[i].AttackPatterns)
		jThreats := len(nodes[j].AttackPatterns)
		if iThreats != jThreats {
			return iThreats > jThreats
		}
		if nodes[i].SyscallCount != nodes[j].SyscallCount {
			return nodes[i].SyscallCount > nodes[j].SyscallCount
		}
		if nodes[i].Comm != nodes[j].Comm {
			return nodes[i].Comm < nodes[j].Comm
		}
		return nodes[i].PID < nodes[j].PID
	})
	for _, node := range nodes {
		sortProcessTree(node.Children)
	}
}

// GetAttackPatterns returns all detected MITRE ATT&CK patterns across processes
func (s *Store) GetAttackPatterns() []AttackPattern {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]AttackPattern, len(s.attackPatterns))
	copy(out, s.attackPatterns)

	// Sort most recent first
	sort.Slice(out, func(i, j int) bool {
		return out[i].Timestamp.After(out[j].Timestamp)
	})
	return out
}

// GetProductionGraph builds a clean, non-hairball, threat-clustered graph
func (s *Store) GetProductionGraph() ProductionGraphData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var nodes []ProductionGraphNode
	var edges []ProductionGraphEdge
	nodeSet := make(map[string]bool)
	threatCount := 0

	// The graph intentionally shows only live security narratives. The process
	// monitor remains the complete inventory; keeping normal process activity in
	// both places makes causality unreadable and makes the dashboard lag.
	live := make(map[uint32]bool, len(s.processes))
	for pid, p := range s.processes {
		if !p.IsKilled && processStillExists(pid) {
			live[pid] = true
		}
	}
	visible := make(map[uint32]bool)
	contextParent := make(map[uint32]bool)
	for pid, p := range s.processes {
		if !live[pid] {
			continue
		}
		hasThreat := isGraphThreat(p)
		if hasThreat {
			threatCount++
		}
		if !hasThreat {
			continue
		}

		visible[pid] = true
		// Show enough ancestry to explain where the interesting process came from,
		// without adding every unrelated sibling in the process tree.
		parentPID := p.PPID
		for level := 0; level < 2 && parentPID > 0 && live[parentPID]; level++ {
			visible[parentPID] = true
			contextParent[parentPID] = true
			parentPID = s.processes[parentPID].PPID
		}
	}

	pids := make([]uint32, 0, len(visible))
	for pid := range visible {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })

	for _, pid := range pids {
		p := s.processes[pid]
		nodeType := "process"
		if isGraphThreat(p) {
			nodeType = "threat"
		} else if contextParent[pid] {
			nodeType = "parent_process"
		}
		pNodeID := fmt.Sprintf("proc:%d", pid)
		nodes = append(nodes, ProductionGraphNode{
			ID:         pNodeID,
			Label:      fmt.Sprintf("%s [%d]", p.Comm, pid),
			Type:       nodeType,
			Trust:      p.TrustScore,
			PID:        pid,
			Comm:       p.Comm,
			PPID:       p.PPID,
			Status:     p.Status,
			EventCount: int(p.SyscallCount),
		})
		nodeSet[pNodeID] = true
	}

	for _, pid := range pids {
		p := s.processes[pid]
		pNodeID := fmt.Sprintf("proc:%d", pid)
		if visible[p.PPID] && p.PPID != pid {
			parentID := fmt.Sprintf("proc:%d", p.PPID)
			edgeSev := "normal"
			if isGraphThreat(p) {
				edgeSev = "critical"
			}
			edges = append(edges, ProductionGraphEdge{Source: parentID, Target: pNodeID, Type: "FORK_EXEC", Weight: 1, Severity: edgeSev, Label: "spawns"})
		}

		// Explicit ATT&CK evidence makes the graph explainable: the operator can
		// see exactly which technique caused this process to enter the graph.
		for _, pattern := range p.AttackPatterns {
			patternID := fmt.Sprintf("pattern:%s", pattern.ID)
			if !nodeSet[patternID] {
				nodes = append(nodes, ProductionGraphNode{
					ID:         patternID,
					Label:      fmt.Sprintf("%s — %s", pattern.TechniqueID, pattern.PatternType),
					Type:       "threat",
					Trust:      p.TrustScore,
					PID:        p.PID,
					Comm:       p.Comm,
					Status:     p.Status,
					EventCount: 1,
				})
				nodeSet[patternID] = true
			}
			edges = append(edges, ProductionGraphEdge{
				Source:   pNodeID,
				Target:   patternID,
				Type:     "ATTACK_PATTERN",
				Weight:   1,
				Severity: "critical",
				Label:    "detected",
			})
		}
	}

	return ProductionGraphData{
		Nodes:        nodes,
		Edges:        edges,
		ActiveThreat: threatCount,
		TotalPIDs:    len(live),
	}
}

func isGraphThreat(p *ProcessRecord) bool {
	return len(p.AttackPatterns) > 0 || p.TrustScore < 50 || p.Status == "suspicious" || p.IsPaused
}

func processStillExists(pid uint32) bool {
	if pid == 0 {
		return false
	}
	_, err := os.Stat(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10)))
	return err == nil
}

// SearchTelemetry provides grounded context to the AI Copilot from the database
func (s *Store) SearchTelemetry(query string, targetPID uint32) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("=== HISTORICAL DATABASE TELEMETRY ===\n")

	if targetPID > 0 {
		if proc, exists := s.processes[targetPID]; exists {
			sb.WriteString(fmt.Sprintf("TARGET PID %d (%s):\n", proc.PID, proc.Comm))
			sb.WriteString(fmt.Sprintf("- PPID: %d (%s)\n", proc.PPID, proc.ParentComm))
			sb.WriteString(fmt.Sprintf("- Trust Score: %.0f | Status: %s | Syscalls: %d\n", proc.TrustScore, proc.Status, proc.SyscallCount))
			sb.WriteString(fmt.Sprintf("- First Seen: %s | Last Seen: %s\n", proc.FirstSeen.Format(time.RFC3339), proc.LastSeen.Format(time.RFC3339)))
			if len(proc.AccessedFiles) > 0 {
				sb.WriteString("- Accessed Files: ")
				var fList []string
				for f, c := range proc.AccessedFiles {
					fList = append(fList, fmt.Sprintf("%s (%d)", f, c))
				}
				sb.WriteString(strings.Join(fList, ", ") + "\n")
			}
			if len(proc.NetworkSockets) > 0 {
				sb.WriteString("- Network Sockets: ")
				var sList []string
				for sock, c := range proc.NetworkSockets {
					sList = append(sList, fmt.Sprintf("%s (%d)", sock, c))
				}
				sb.WriteString(strings.Join(sList, ", ") + "\n")
			}
			if len(proc.AttackPatterns) > 0 {
				sb.WriteString("- IDENTIFIED ATTACK PATTERNS:\n")
				for _, pat := range proc.AttackPatterns {
					sb.WriteString(fmt.Sprintf("  • [%s] %s: %s\n", pat.Severity, pat.TechniqueID, pat.Description))
				}
			}
			return sb.String()
		}
	}

	// General search across patterns and processes
	if len(s.attackPatterns) > 0 {
		sb.WriteString("ACTIVE ATTACK PATTERNS IN DATABASE:\n")
		count := 0
		for _, pat := range s.attackPatterns {
			sb.WriteString(fmt.Sprintf("• PID %d (%s) -> [%s] %s: %s\n", pat.PID, pat.Comm, pat.Severity, pat.TechniqueID, pat.Description))
			count++
			if count >= 8 {
				break
			}
		}
	}

	// Recent processes
	sb.WriteString("\nTOP TRACKED PROCESSES IN DATABASE:\n")
	procList := make([]*ProcessRecord, 0, len(s.processes))
	for _, p := range s.processes {
		procList = append(procList, p)
	}
	sort.Slice(procList, func(i, j int) bool {
		return procList[i].SyscallCount > procList[j].SyscallCount
	})

	count := 0
	for _, p := range procList {
		if count >= 10 {
			break
		}
		sb.WriteString(fmt.Sprintf("• PID %d (%s) [Parent: %d %s] Trust=%.0f Status=%s Syscalls=%d Files=%d Sockets=%d\n",
			p.PID, p.Comm, p.PPID, p.ParentComm, p.TrustScore, p.Status, p.SyscallCount, len(p.AccessedFiles), len(p.NetworkSockets)))
		count++
	}

	return sb.String()
}
