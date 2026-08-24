// Package narration provides ATT&CK technique lookup and LLM narration via Ollama.
package narration

// AttackEntry maps a syscall/edge pattern to an ATT&CK technique.
type AttackEntry struct {
	PatternID   string   `json:"pattern_id"`
	Description string   `json:"description"`
	TechniqueID string   `json:"technique_id"`
	Technique   string   `json:"technique"`
	Tactic      string   `json:"tactic"`
	Severity    float64  `json:"severity"` // 0-10
	Indicators  []string `json:"indicators"`
}

// AttackTable is the hardcoded 10-15 entry lookup table for this demo's scenarios.
// LLM narrates around retrieved IDs — never generates technique IDs from scratch.
var AttackTable = []AttackEntry{
	{
		PatternID:   "curl_write_chmod",
		Description: "Download, write to disk, set executable — ingress tool transfer",
		TechniqueID: "T1105",
		Technique:   "Ingress Tool Transfer",
		Tactic:      "Command and Control",
		Severity:    7.0,
		Indicators:  []string{"curl", "wget", "write", "chmod", "+x"},
	},
	{
		PatternID:   "shell_exec_curl",
		Description: "Shell spawns curl/wget — command-line download",
		TechniqueID: "T1059.004",
		Technique:   "Unix Shell",
		Tactic:      "Execution",
		Severity:    5.0,
		Indicators:  []string{"bash", "sh", "curl", "wget"},
	},
	{
		PatternID:   "nonstandard_port_connect",
		Description: "Outbound connection to non-standard port",
		TechniqueID: "T1571",
		Technique:   "Non-Standard Port",
		Tactic:      "Command and Control",
		Severity:    6.0,
		Indicators:  []string{"connect", "nonstandard_port"},
	},
	{
		PatternID:   "crontab_write",
		Description: "Write to crontab — persistence via scheduled task",
		TechniqueID: "T1053.003",
		Technique:   "Cron",
		Tactic:      "Persistence",
		Severity:    8.0,
		Indicators:  []string{"/etc/crontab", "/var/spool/cron", "crontab"},
	},
	{
		PatternID:   "passwd_write",
		Description: "Write to /etc/passwd — local account creation",
		TechniqueID: "T1136.001",
		Technique:   "Local Account",
		Tactic:      "Persistence",
		Severity:    9.0,
		Indicators:  []string{"/etc/passwd", "useradd", "adduser"},
	},
	{
		PatternID:   "shadow_read",
		Description: "Read /etc/shadow — credential harvesting",
		TechniqueID: "T1003.008",
		Technique:   "/etc/passwd and /etc/shadow",
		Tactic:      "Credential Access",
		Severity:    8.5,
		Indicators:  []string{"/etc/shadow"},
	},
	{
		PatternID:   "write_chmod_exec",
		Description: "Write file, chmod +x, then exec — malicious file execution",
		TechniqueID: "T1204.002",
		Technique:   "Malicious File",
		Tactic:      "Execution",
		Severity:    7.5,
		Indicators:  []string{"write", "chmod", "exec"},
	},
	{
		PatternID:   "c2_callback",
		Description: "Outbound connection after exec — potential C2 callback",
		TechniqueID: "T1071.001",
		Technique:   "Web Protocols",
		Tactic:      "Command and Control",
		Severity:    8.0,
		Indicators:  []string{"connect", "exec", "443", "80", "8080"},
	},
	{
		PatternID:   "fork_bomb",
		Description: "Rapid fork/exec pattern — OS exhaustion flood",
		TechniqueID: "T1499.001",
		Technique:   "OS Exhaustion Flood",
		Tactic:      "Impact",
		Severity:    9.0,
		Indicators:  []string{"fork", "rapid_exec"},
	},
	{
		PatternID:   "ssh_key_write",
		Description: "Write to SSH authorized_keys — persistence",
		TechniqueID: "T1098.004",
		Technique:   "SSH Authorized Keys",
		Tactic:      "Persistence",
		Severity:    8.5,
		Indicators:  []string{".ssh/authorized_keys", "ssh"},
	},
	{
		PatternID:   "netcat_exec",
		Description: "Execution of netcat/ncat/socat — non-application layer protocol",
		TechniqueID: "T1095",
		Technique:   "Non-Application Layer Protocol",
		Tactic:      "Command and Control",
		Severity:    7.0,
		Indicators:  []string{"nc", "ncat", "socat"},
	},
	{
		PatternID:   "reverse_shell",
		Description: "Shell exec with network redirect — reverse shell",
		TechniqueID: "T1059.004",
		Technique:   "Unix Shell + Reverse Shell",
		Tactic:      "Execution",
		Severity:    9.5,
		Indicators:  []string{"bash", "/dev/tcp", "nc -e", "mkfifo"},
	},
}

// MatchPatterns checks sensor events against the ATT&CK lookup table.
// Returns matched entries. This is pattern-based retrieval, NOT LLM generation.
func MatchPatterns(comm string, payload string, eventType string, dstPort uint16) []AttackEntry {
	var matches []AttackEntry
	for _, entry := range AttackTable {
		if matchEntry(entry, comm, payload, eventType, dstPort) {
			matches = append(matches, entry)
		}
	}
	return matches
}

func matchEntry(entry AttackEntry, comm, payload, eventType string, dstPort uint16) bool {
	matchCount := 0
	for _, indicator := range entry.Indicators {
		if containsStr(comm, indicator) || containsStr(payload, indicator) || containsStr(eventType, indicator) {
			matchCount++
		}
		// Check for non-standard port
		if indicator == "nonstandard_port" && dstPort != 0 && dstPort != 80 && dstPort != 443 && dstPort != 22 && dstPort != 53 {
			matchCount++
		}
	}
	// Require at least 2 indicator matches for a hit (reduces false positives)
	return matchCount >= 2
}

func containsStr(s, substr string) bool {
	if len(substr) == 0 || len(s) == 0 {
		return false
	}
	// Simple case-insensitive contains
	ls := toLower(s)
	lsub := toLower(substr)
	for i := 0; i <= len(ls)-len(lsub); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		} else {
			b[i] = c
		}
	}
	return string(b)
}
