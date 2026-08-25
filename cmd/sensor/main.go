// Kernel Security Monitor — eBPF Verify-Before-Block Intrusion Response System
// Main control plane: wires sensor → graph → scorer → response → dashboard
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kernel-security-monitor/ksm/internal/checkpoint"
	"github.com/kernel-security-monitor/ksm/internal/graph"
	"github.com/kernel-security-monitor/ksm/internal/narration"
	"github.com/kernel-security-monitor/ksm/internal/response"
	"github.com/kernel-security-monitor/ksm/internal/sensor"
)

// CLI flags
var (
	flagSensorObj      = flag.String("sensor-obj", "bpf/sensor.o", "Path to compiled sensor BPF object")
	flagLSMObj         = flag.String("lsm-obj", "bpf/lsm.o", "Path to compiled LSM BPF object")
	flagFallbackKill   = flag.Bool("fallback-signal-kill", false, "Use SIGKILL instead of BPF-LSM deny")
	flagScorerAddr     = flag.String("scorer-addr", "http://127.0.0.1:8099", "Python scorer sidecar address")
	flagListenAddr     = flag.String("listen", ":8080", "Dashboard HTTP listen address")
	flagLogFile        = flag.String("log-file", "events.jsonl", "Event log file path")
	flagDataDir        = flag.String("data-dir", "data", "Data directory for baseline files")
	flagEnableCRIU       = flag.Bool("enable-criu", false, "Enable CRIU checkpoint+verify path")
	flagMode             = flag.String("mode", "observe", "Operating mode: observe (default, never kills) or enforce (kills threats)")
	flagMaxEventsPerSec  = flag.Int("max-events-per-sec", 50, "Max events processed per second (rate limit)")
	flagEnableNarration  = flag.Bool("enable-narration", true, "Enable LLM narration")
	flagOllamaEndpoint   = flag.String("ollama-endpoint", "http://localhost:11434", "Ollama API endpoint (alias for --llm-endpoint)")
	flagOllamaModel      = flag.String("ollama-model", "phi3:mini", "Ollama model name (alias for --llm-model)")
	flagLLMEndpoint      = flag.String("llm-endpoint", "", "Cloud or local LLM endpoint URL (e.g. https://api.openai.com/v1 or http://localhost:11434)")
	flagLLMModel         = flag.String("llm-model", "", "LLM model name (e.g. gpt-4o-mini, qwen2.5-3b, phi3:mini)")
	flagLLMAPIKey        = flag.String("llm-api-key", "", "API key for Cloud LLM (or set LLM_API_KEY / OPENAI_API_KEY env var)")
	flagLLMProvider      = flag.String("llm-provider", "auto", "LLM provider: auto, openai, ollama")
	flagNarrationTimeout = flag.Int("narration-timeout", 30, "LLM narration timeout in seconds")
)

func main() {
	flag.Parse()

	// Resolve LLM config
	endpoint := *flagLLMEndpoint
	if endpoint == "" {
		endpoint = *flagOllamaEndpoint
	}
	modelName := *flagLLMModel
	if modelName == "" {
		modelName = *flagOllamaModel
	}
	apiKey := *flagLLMAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("LLM_API_KEY")
		if apiKey == "" {
			apiKey = os.Getenv("OPENAI_API_KEY")
		}
	}

	// Setup structured logging
	logHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	logger.Info("Kernel Security Monitor starting",
		"sensor_obj", *flagSensorObj,
		"lsm_obj", *flagLSMObj,
		"fallback_kill", *flagFallbackKill,
		"scorer_addr", *flagScorerAddr,
		"listen", *flagListenAddr,
		"criu_enabled", *flagEnableCRIU,
		"narration_enabled", *flagEnableNarration,
	)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Initialize components
	// 1. Causal graph
	cg := graph.New()
	logger.Info("causal graph initialized")

	// 2. Feature extractor with n-gram baseline
	ngramPath := filepath.Join(*flagDataDir, "ngram_baseline.json")
	baseline, err := graph.LoadNgramBaseline(ngramPath)
	if err != nil {
		logger.Warn("could not load n-gram baseline, using empty", "error", err)
		baseline, _ = graph.LoadNgramBaseline("/dev/null")
	}
	featureExtractor := graph.NewFeatureExtractor(cg, baseline)

	// 3. Event logger
	eventLog, err := response.NewEventLog(*flagLogFile, logger)
	if err != nil {
		logger.Error("failed to create event log", "error", err)
		os.Exit(1)
	}
	defer eventLog.Close()

	// 4. eBPF sensor loader
	loaderCfg := sensor.Config{
		SensorObjPath:      *flagSensorObj,
		LSMObjPath:         *flagLSMObj,
		FallbackSignalKill: *flagFallbackKill,
	}
	ebpfLoader := sensor.NewLoader(loaderCfg, logger)
	if err := ebpfLoader.Load(loaderCfg); err != nil {
		logger.Error("failed to load eBPF programs", "error", err)
		os.Exit(1)
	}
	defer ebpfLoader.Close()

	logger.Info("eBPF sensor loaded",
		"lsm_available", ebpfLoader.LSMAvailable(),
		"fallback_kill", *flagFallbackKill,
	)

	// 5. Response engine
	respEngine := response.NewEngine(ebpfLoader, cg, logger)

	// Load persistent user trust decisions
	userTrustPath := filepath.Join(*flagDataDir, "user_trust.json")
	if err := respEngine.LoadUserTrust(userTrustPath); err != nil {
		logger.Warn("could not load user trust file", "error", err)
	}

	// Set operating mode
	switch *flagMode {
	case "enforce":
		respEngine.SetMode(response.ModeEnforce)
		logger.Warn("⚠ ENFORCE MODE: Kernel Security Monitor WILL kill suspicious processes")
	case "pause":
		respEngine.SetMode(response.ModePause)
		logger.Warn("⏸ PAUSE MODE: Kernel Security Monitor will SIGSTOP suspicious processes, waiting for your approval")
	default:
		respEngine.SetMode(response.ModeObserve)
		logger.Info("✓ OBSERVE MODE: Kernel Security Monitor will monitor but NOT kill any process")
	}

	// 6. CRIU verify (Priority 2)
	if *flagEnableCRIU {
		criuMgr := checkpoint.NewManager(checkpoint.DefaultConfig(), logger)
		if criuMgr.IsAvailable() {
			respEngine.SetCRIUEnabled(true)
			respEngine.VerifyFunc = func(pid uint32) (*response.VerifyResult, error) {
				result, err := criuMgr.Verify(ctx, pid)
				if err != nil {
					return nil, err
				}
				return &response.VerifyResult{
					ConfirmedMalicious: result.ConfirmedMalicious,
					Evidence:           result.Evidence,
				}, nil
			}
			logger.Info("CRIU verify path enabled")
		} else {
			logger.Warn("CRIU requested but not available")
		}
	}

	// 7. LLM narrator (Priority 3)
	narratorCfg := narration.NarratorConfig{
		Endpoint:    endpoint,
		Model:       modelName,
		APIKey:      apiKey,
		Provider:    *flagLLMProvider,
		TimeoutSecs: *flagNarrationTimeout,
		Enabled:     *flagEnableNarration,
	}
	narrator := narration.NewNarrator(narratorCfg, logger)
	if *flagEnableNarration {
		if apiKey != "" {
			logger.Info("✓ AI Copilot: NVIDIA NIM / Cloud LLM connected", "endpoint", narratorCfg.Endpoint, "model", narratorCfg.Model)
		} else if narrator.IsAvailable() {
			logger.Info("✓ AI Copilot: local Ollama LLM connected", "endpoint", narratorCfg.Endpoint, "model", narratorCfg.Model)
		} else {
			logger.Warn("⚠ AI Copilot offline: no LLM_API_KEY and Ollama not reachable. Set LLM_API_KEY env var.")
		}
	}

	// SSE hub for dashboard streaming
	sseHub := newSSEHub()

	// Start event processing pipeline
	eventCh := make(chan sensor.Event, 1024)
	var wg sync.WaitGroup

	// Ring buffer reader goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ebpfLoader.ReadEvents(ctx, eventCh); err != nil && ctx.Err() == nil {
			logger.Error("ring buffer reader error", "error", err)
		}
	}()

	// Event processor goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		processEvents(ctx, eventCh, cg, featureExtractor, respEngine, eventLog, narrator, sseHub, logger)
	}()

	// HTTP server for dashboard (Priority 4)
	mux := setupHTTP(cg, respEngine, eventLog, narrator, sseHub, logger)
	server := &http.Server{Addr: *flagListenAddr, Handler: mux}

	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("dashboard server starting", "addr", *flagListenAddr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	// Wait for signal
	<-sigCh
	logger.Info("shutting down...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)

	wg.Wait()
	logger.Info("Kernel Security Monitor stopped")
}

// isNoisyFile checks if a read-only file access is pure background noise (shared libraries, font caches, etc.).
func isNoisyFile(path string, isWrite bool) bool {
	if isWrite {
		return false // Always track file writes
	}
	noisyPrefixes := []string{
		"/usr/lib", "/lib64", "/lib", "/usr/share",
		"/etc/ld.so", "/usr/include", "/dev/null", "/sys/", "/proc/",
		"/etc/fonts", "/var/cache",
	}
	for _, p := range noisyPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// processEvents is the main event processing pipeline with rate limiting.
func processEvents(
	ctx context.Context,
	events <-chan sensor.Event,
	cg *graph.CausalGraph,
	fe *graph.FeatureExtractor,
	respEngine *response.Engine,
	eventLog *response.EventLog,
	narrator *narration.Narrator,
	sseHub *sseHub,
	logger *slog.Logger,
) {
	scorerClient := &http.Client{Timeout: 5 * time.Second}

	// Rate limiter: token bucket
	maxPerSec := *flagMaxEventsPerSec
	if maxPerSec <= 0 {
		maxPerSec = 50
	}
	ticker := time.NewTicker(time.Second / time.Duration(maxPerSec))
	defer ticker.Stop()

	var droppedCount int64
	var processedCount int64

	// LLM call throttling: per-PID cooldown + global rate limit
	llmCooldowns := make(map[uint32]time.Time)
	var llmMu sync.Mutex
	llmGlobalLast := time.Time{}
	const llmPIDCooldown = 30 * time.Second
	const llmGlobalCooldown = 5 * time.Second

	// SSE broadcast throttle
	lastSSEBroadcast := time.Time{}
	const sseBroadcastInterval = 400 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				return
			}

			// Rate limit: wait for token
			select {
			case <-ticker.C:
			default:
				droppedCount++
				continue
			}

			processedCount++

			// 1. Update causal graph (with noise suppression for read-only libs)
			procNode := cg.AddProcessNode(evt.PID, evt.PPID, evt.Comm)

			switch evt.Type {
			case sensor.EventExecve:
				if evt.Payload != "" {
					fileNode := cg.AddFileNode(evt.Payload)
					cg.AddEdge(procNode.ID, fileNode.ID, graph.EdgeExec, nil)
				}
				if evt.PPID > 0 {
					parentID := fmt.Sprintf("proc:%d", evt.PPID)
					cg.AddProcessNode(evt.PPID, 0, "")
					cg.AddEdge(parentID, procNode.ID, graph.EdgeFork, nil)
				}

			case sensor.EventOpenat:
				if evt.Payload != "" && !isNoisyFile(evt.Payload, evt.IsWrite) {
					fileNode := cg.AddFileNode(evt.Payload)
					edgeType := graph.EdgeOpenRead
					if evt.IsWrite {
						edgeType = graph.EdgeOpenWrite
					}
					cg.AddEdge(procNode.ID, fileNode.ID, edgeType, map[string]interface{}{
						"flags": evt.Flags,
					})
				}

			case sensor.EventConnect:
				if evt.DstIP != "" {
					sockNode := cg.AddSocketNode(evt.DstIP, evt.DstPort)
					cg.AddEdge(procNode.ID, sockNode.ID, graph.EdgeConnect, map[string]interface{}{
						"port":   evt.DstPort,
						"family": evt.SAFamily,
					})
				}
			}

			// 2. Skip scoring for known/whitelisted processes
			if respEngine.IsTrusted(evt.Comm, evt.PID) {
				fe.RecordSyscall(evt.PID, evt.TypeStr)
				if time.Since(lastSSEBroadcast) >= sseBroadcastInterval {
					lastSSEBroadcast = time.Now()
					sseHub.broadcast(sseEvent{
						Type: "event",
						Data: map[string]interface{}{
							"event": evt,
							"decision": response.Decision{
								Timestamp:     time.Now(),
								PID:           evt.PID,
								Comm:          evt.Comm,
								Tier:          response.TierLow,
								TrustScore:    95,
								ConformalPVal: 0.95,
								Action:        "known_safe",
								Status:        response.StatusKnown,
							},
							"graph_stats": cg.Stats(),
							"rate_info": map[string]interface{}{
								"processed": processedCount,
								"dropped":   droppedCount,
							},
						},
					})
				}
				continue
			}

			// 3. Record syscall for n-gram tracking (unknown/suspicious only)
			fe.RecordSyscall(evt.PID, evt.TypeStr)

			// 4. Extract features and score
			features := fe.Extract(evt.PID)

			// 5. Call Python sidecar for IF scoring + conformal calibration
			confResult := callScorer(scorerClient, *flagScorerAddr, evt.PID, features, logger)

			// 6. ATT&CK pattern matching
			matches := narration.MatchPatterns(evt.Comm, evt.Payload, evt.TypeStr, evt.DstPort)
			var techniqueID, techniqueName string
			var severity float64
			if len(matches) > 0 {
				best := matches[0]
				for _, m := range matches[1:] {
					if m.Severity > best.Severity {
						best = m
					}
				}
				techniqueID = best.TechniqueID
				techniqueName = best.Technique
				severity = best.Severity
			}

			// 7. Response decision
			decision := respEngine.Respond(evt.PID, evt.Comm, confResult, techniqueID, techniqueName, severity)

			// 8. Log the decision
			eventLog.LogDecision(decision)

			// 9. LLM narration (throttled: per-PID cooldown + global rate limit)
			if decision.Tier != response.TierLow && decision.Status != response.StatusKnown && narrator != nil {
				llmMu.Lock()
				now := time.Now()
				pidLastCall := llmCooldowns[evt.PID]
				canCallLLM := now.Sub(pidLastCall) >= llmPIDCooldown && now.Sub(llmGlobalLast) >= llmGlobalCooldown
				if canCallLLM {
					llmCooldowns[evt.PID] = now
					llmGlobalLast = now
				}
				llmMu.Unlock()

				if canCallLLM {
					go func(d response.Decision, m []narration.AttackEntry) {
						input := narration.NarrationInput{
							PID:               d.PID,
							Comm:              d.Comm,
							TrustScore:        d.TrustScore,
							ConformalPValue:   d.ConformalPVal,
							ResponseTier:      string(d.Tier),
							MatchedTechniques: m,
							CausalSummary:     d.CausalSummary,
							Action:            d.Action,
						}
						result, _ := narrator.Narrate(ctx, input)
						if result != nil {
							sseHub.broadcast(sseEvent{
								Type: "narration",
								Data: result,
							})
						}
					}(decision, matches)
				}
			}

			// 10. Broadcast to dashboard SSE (throttled)
			if time.Since(lastSSEBroadcast) >= sseBroadcastInterval {
				lastSSEBroadcast = time.Now()
				sseHub.broadcast(sseEvent{
					Type: "event",
					Data: map[string]interface{}{
						"event":    evt,
						"decision": decision,
						"features": features,
						"graph_stats": cg.Stats(),
						"rate_info": map[string]interface{}{
							"processed": processedCount,
							"dropped":   droppedCount,
						},
					},
				})
			}
		}
	}
}

// callScorer calls the Python sidecar for scoring.
func callScorer(client *http.Client, addr string, pid uint32, features graph.FeatureVector, logger *slog.Logger) response.ConformalResult {
	reqBody := map[string]interface{}{
		"pid": pid,
		"features": map[string]interface{}{
			"fan_out_degree":    features.FanOutDegree,
			"edge_type_entropy": features.EdgeTypeEntropy,
			"ngram_rarity":      features.NgramRarity,
			"ancestry_depth":    features.AncestryDepth,
		},
	}
	body, _ := json.Marshal(reqBody)

	resp, err := client.Post(addr+"/score", "application/json", jsonReader(body))
	if err != nil {
		return response.ConformalResult{
			PValue: 0.8, // Conservative safe default
			Tier:   response.TierLow,
		}
	}
	defer resp.Body.Close()

	var result struct {
		AnomalyScore float64 `json:"anomaly_score"`
		RawScore     float64 `json:"raw_score"`
		IsAnomaly    bool    `json:"is_anomaly"`
		PValue       float64 `json:"p_value"`
		Tier         string  `json:"tier"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return response.ConformalResult{PValue: 0.8, Tier: response.TierLow}
	}

	return response.ConformalResult{
		AnomalyScore: result.AnomalyScore,
		RawScore:     result.RawScore,
		PValue:       result.PValue,
		Tier:         response.Tier(result.Tier),
		IsAnomaly:    result.IsAnomaly,
	}
}

// ---- HTTP Handlers ----

func setupHTTP(cg *graph.CausalGraph, respEngine *response.Engine, eventLog *response.EventLog, narrator *narration.Narrator, hub *sseHub, logger *slog.Logger) *http.ServeMux {
	mux := http.NewServeMux()

	dashboardDir := "dashboard"
	if _, err := os.Stat(dashboardDir); err == nil {
		mux.Handle("/", http.FileServer(http.Dir(dashboardDir)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<h1>Kernel Security Monitor Dashboard</h1><p>Dashboard files not found.</p>")
		})
	}

	mux.HandleFunc("/api/graph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		snapshot := cg.Snapshot()
		if len(snapshot.Nodes) > 120 {
			pruned := make(map[string]*graph.Node, 120)
			count := 0
			for k, v := range snapshot.Nodes {
				if count >= 120 {
					break
				}
				pruned[k] = v
				count++
			}
			snapshot.Nodes = pruned
		}
		json.NewEncoder(w).Encode(snapshot)
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(cg.Stats())
	})

	mux.HandleFunc("/api/decisions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(respEngine.RecentDecisions(50))
	})

	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(eventLog.RecentEntries(50))
	})

	mux.HandleFunc("/api/trust", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		snapshot := cg.Snapshot()
		var trustScores []map[string]interface{}
		for _, node := range snapshot.Nodes {
			if node.Type == graph.NodeProcess {
				status := response.ClassifyProcess(node.Comm, 1.0)
				if respEngine.IsTrusted(node.Comm, node.PID) {
					status = response.StatusKnown
					node.Trust = 100.0
				}
				if respEngine.IsProcessPaused(node.PID) {
					status = response.StatusPaused
				}
				trustScores = append(trustScores, map[string]interface{}{
					"pid":        node.PID,
					"ppid":       node.PPID,
					"comm":       node.Comm,
					"trust":      node.Trust,
					"status":     status,
					"tier":       graph.TrustTier(node.Trust),
					"color":      graph.TrustColor(node.Trust),
					"label":      node.Label,
					"first_seen": node.FirstSeen,
					"paused":     respEngine.IsProcessPaused(node.PID),
				})
			}
		}
		json.NewEncoder(w).Encode(trustScores)
	})

	// Dynamic Trust Override API: allows user or chat to mark process as trusted
	mux.HandleFunc("/api/trust/override", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		var req struct {
			Comm string `json:"comm"`
			PID  uint32 `json:"pid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		respEngine.TrustProcess(req.Comm, req.PID)
		if req.PID > 0 {
			cg.SetProcessTrust(req.PID, 100.0)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": fmt.Sprintf("Process %s (PID %d) marked as trusted", req.Comm, req.PID),
		})
	})

	// Process management endpoints: mark as known, pause, resume

	// POST /api/process/known — mark process as KNOWN/trusted by user
	mux.HandleFunc("/api/process/known", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" { w.WriteHeader(http.StatusOK); return }
		if r.Method != "POST" { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }

		var req struct {
			Comm   string `json:"comm"`
			PID    uint32 `json:"pid"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		respEngine.TrustProcess(req.Comm, req.PID)
		if req.PID > 0 {
			cg.SetProcessTrust(req.PID, 100.0)
		}
		// Persist to user_trust.json
		if err := respEngine.SaveUserTrust(); err != nil {
			logger.Warn("could not save user trust", "error", err)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": fmt.Sprintf("✅ '%s' (PID %d) is now KNOWN — trust set to 100. This will persist across restarts.", req.Comm, req.PID),
		})
	})

	// POST /api/process/pause — SIGSTOP a suspicious process
	mux.HandleFunc("/api/process/pause", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" { w.WriteHeader(http.StatusOK); return }
		if r.Method != "POST" { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }

		var req struct {
			PID  uint32 `json:"pid"`
			Comm string `json:"comm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.PID == 0 {
			http.Error(w, "pid required", http.StatusBadRequest)
			return
		}
		if err := respEngine.PauseProcess(req.PID, req.Comm); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": fmt.Sprintf("⏸ Process '%s' (PID %d) has been SUSPENDED (SIGSTOP). Click Resume or chat 'resume PID %d' to allow it.", req.Comm, req.PID, req.PID),
		})
	})

	// POST /api/process/resume — SIGCONT a paused process
	mux.HandleFunc("/api/process/resume", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" { w.WriteHeader(http.StatusOK); return }
		if r.Method != "POST" { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }

		var req struct {
			PID uint32 `json:"pid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.PID == 0 {
			http.Error(w, "pid required", http.StatusBadRequest)
			return
		}
		if err := respEngine.ResumeProcess(req.PID); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": fmt.Sprintf("▶ Process (PID %d) has been RESUMED (SIGCONT).", req.PID),
		})
	})

	// GET /api/paused — return all currently paused processes
	mux.HandleFunc("/api/paused", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		paused := respEngine.GetPausedProcesses()
		var list []map[string]interface{}
		for pid, comm := range paused {
			list = append(list, map[string]interface{}{"pid": pid, "comm": comm})
		}
		if list == nil {
			list = []map[string]interface{}{}
		}
		json.NewEncoder(w).Encode(list)
	})

	// POST /api/process/kill — SIGKILL a process immediately
	mux.HandleFunc("/api/process/kill", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" { w.WriteHeader(http.StatusOK); return }
		if r.Method != "POST" { http.Error(w, "POST only", http.StatusMethodNotAllowed); return }

		var req struct {
			PID  uint32 `json:"pid"`
			Comm string `json:"comm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.PID == 0 {
			http.Error(w, "pid required", http.StatusBadRequest)
			return
		}
		if err := respEngine.KillProcess(req.PID, req.Comm); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}
		// If it was paused, clean that up too
		respEngine.ResumeProcess(req.PID) // attempt SIGCONT before SIGKILL has effect (no-op if already dead)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": fmt.Sprintf("💀 Process '%s' (PID %d) has been KILLED (SIGKILL).", req.Comm, req.PID),
		})
	})

	// GET /api/actionlog — return the user-driven action log (kill/pause/trust/resume)
	mux.HandleFunc("/api/actionlog", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		log := respEngine.GetActionLog(100)
		if log == nil {
			log = []response.ActionLogEntry{}
		}
		json.NewEncoder(w).Encode(log)
	})

	// Mode API — GET/POST, supports observe/pause/enforce
	mux.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == "POST" {
			var req struct {
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				switch req.Mode {
				case "enforce":
					respEngine.SetMode(response.ModeEnforce)
				case "pause":
					respEngine.SetMode(response.ModePause)
				default:
					respEngine.SetMode(response.ModeObserve)
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]string{"mode": string(respEngine.GetMode())})
	})

	// Smart AI Security Copilot Chat API
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Query   string `json:"query"`
			PID     uint32 `json:"pid,omitempty"`
			History []struct {
				Role string `json:"role"` // "user" or "ai"
				Text string `json:"text"`
			} `json:"history,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		query := strings.TrimSpace(req.Query)
		lowerQuery := strings.ToLower(query)

		// 1. Direct Trust / Whitelist Command
		// ── 1. TRUST / MARK KNOWN ──────────────────────────────────────────
		if strings.HasPrefix(lowerQuery, "trust ") || strings.HasPrefix(lowerQuery, "mark ") || strings.Contains(lowerQuery, " trusted") || strings.Contains(lowerQuery, " known") {
			parts := strings.Fields(query)
			targetName := ""
			for _, part := range parts {
				p := strings.Trim(strings.ToLower(part), ",'\"()")
				skip := map[string]bool{"trust": true, "mark": true, "as": true, "trusted": true, "known": true, "process": true, "this": true, "is": true, "the": true, "pid": true, "a": true, "an": true}
				if !skip[p] && len(p) > 1 {
					targetName = part
					break
				}
			}
			if targetName != "" || req.PID > 0 {
				respEngine.TrustProcess(targetName, req.PID)
				if req.PID > 0 {
					cg.SetProcessTrust(req.PID, 100.0)
				}
				respEngine.SaveUserTrust()
				respEngine.RecordAction("trust", targetName, req.PID, "user", "ok")
				json.NewEncoder(w).Encode(map[string]string{
					"response": fmt.Sprintf("✅ '%s' (PID %d) is now KNOWN & TRUSTED (trust=100). Saved to disk — will persist across restarts. It will no longer be flagged.", targetName, req.PID),
				})
				return
			}
		}

		// ── 2. RESUME / UNPAUSE ─────────────────────────────────────────────
		if strings.HasPrefix(lowerQuery, "resume ") || strings.HasPrefix(lowerQuery, "unpause ") {
			var targetPID uint32
			fmt.Sscanf(lowerQuery, "resume pid %d", &targetPID)
			if targetPID == 0 { fmt.Sscanf(lowerQuery, "resume %d", &targetPID) }
			if targetPID == 0 { fmt.Sscanf(lowerQuery, "unpause %d", &targetPID) }
			if targetPID > 0 {
				if err := respEngine.ResumeProcess(targetPID); err != nil {
					json.NewEncoder(w).Encode(map[string]string{"response": fmt.Sprintf("⚠️ Could not resume PID %d: %s", targetPID, err.Error())})
				} else {
					respEngine.RecordAction("resume", "", targetPID, "user", "ok")
					json.NewEncoder(w).Encode(map[string]string{"response": fmt.Sprintf("▶ PID %d is now RUNNING again (SIGCONT sent). You can see it in the Process Classification list.", targetPID)})
				}
				return
			}
		}

		// ── 3. PAUSE / SUSPEND SPECIFIC PID ────────────────────────────────
		if strings.HasPrefix(lowerQuery, "suspend ") || (strings.HasPrefix(lowerQuery, "pause ") && !strings.Contains(lowerQuery, "mode")) {
			var targetPID uint32
			fmt.Sscanf(lowerQuery, "pause pid %d", &targetPID)
			if targetPID == 0 { fmt.Sscanf(lowerQuery, "pause %d", &targetPID) }
			if targetPID == 0 { fmt.Sscanf(lowerQuery, "suspend %d", &targetPID) }
			if targetPID > 0 {
				if err := respEngine.PauseProcess(targetPID, "user-cmd"); err != nil {
					json.NewEncoder(w).Encode(map[string]string{"response": fmt.Sprintf("⚠️ Could not pause PID %d: %s", targetPID, err.Error())})
				} else {
					respEngine.RecordAction("pause", "", targetPID, "user", "ok")
					json.NewEncoder(w).Encode(map[string]string{"response": fmt.Sprintf("⏸ PID %d is now SUSPENDED (SIGSTOP). It will not consume CPU until you resume it. Type 'resume %d' or click ▶ Resume on the dashboard.", targetPID, targetPID)})
				}
				return
			}
		}

		// ── 4. KILL / TERMINATE SPECIFIC PID ───────────────────────────────
		if strings.HasPrefix(lowerQuery, "kill ") || strings.HasPrefix(lowerQuery, "terminate ") {
			var targetPID uint32
			fmt.Sscanf(lowerQuery, "kill pid %d", &targetPID)
			if targetPID == 0 { fmt.Sscanf(lowerQuery, "kill %d", &targetPID) }
			if targetPID == 0 { fmt.Sscanf(lowerQuery, "terminate %d", &targetPID) }
			if targetPID > 0 {
				if err := respEngine.KillProcess(targetPID, "user-cmd"); err != nil {
					json.NewEncoder(w).Encode(map[string]string{"response": fmt.Sprintf("⚠️ Could not kill PID %d: %s", targetPID, err.Error())})
				} else {
					json.NewEncoder(w).Encode(map[string]string{"response": fmt.Sprintf("💀 PID %d has been KILLED (SIGKILL). Check the Action Log tab to confirm.", targetPID)})
				}
				return
			}
		}

		// ── 5. BLOCK/PAUSE ALL BELOW THRESHOLD (ACTUALLY EXECUTES!) ────────
		if strings.Contains(lowerQuery, "block all") || strings.Contains(lowerQuery, "pause all") || strings.Contains(lowerQuery, "block all process") {
			var threshold float64 = 40
			fmt.Sscanf(lowerQuery, "block all process below %f", &threshold)
			if threshold == 40 { fmt.Sscanf(lowerQuery, "block all below %f", &threshold) }
			if threshold == 40 { fmt.Sscanf(lowerQuery, "pause all below %f", &threshold) }
			if threshold == 40 { fmt.Sscanf(lowerQuery, "block all processes below %f", &threshold) }

			targets := respEngine.GetSuspiciousBelow(threshold)
			if len(targets) == 0 {
				json.NewEncoder(w).Encode(map[string]string{"response": fmt.Sprintf("✅ No processes found with trust score below %.0f that aren't already known/trusted.", threshold)})
				return
			}
			var paused, failed []string
			for _, d := range targets {
				if respEngine.IsTrusted(d.Comm, d.PID) {
					continue // never pause trusted
				}
				if err := respEngine.PauseProcess(d.PID, d.Comm); err != nil {
					failed = append(failed, fmt.Sprintf("%s(%d): %s", d.Comm, d.PID, err.Error()))
				} else {
					respEngine.RecordAction("pause", d.Comm, d.PID, "user-bulk", "ok")
					paused = append(paused, fmt.Sprintf("⏸ %s (PID %d, trust=%.0f)", d.Comm, d.PID, d.TrustScore))
				}
			}
			reply := fmt.Sprintf("⏸ **Bulk PAUSE complete** — Paused %d process(es) with trust < %.0f:\n%s",
				len(paused), threshold, strings.Join(paused, "\n"))
			if len(failed) > 0 {
				reply += fmt.Sprintf("\n\n⚠️ Failed to pause %d (may already be dead):\n%s", len(failed), strings.Join(failed, "\n"))
			}
			reply += "\n\n→ Check the '⏸ PAUSED' banner on the dashboard. Click **▶ Resume** or type 'resume PID X' for any you want to allow."
			json.NewEncoder(w).Encode(map[string]string{"response": reply})
			return
		}

		// ── 6. SHOW PAUSED / BLOCKED ────────────────────────────────────────
		if strings.Contains(lowerQuery, "show paused") || strings.Contains(lowerQuery, "paused processes") || strings.Contains(lowerQuery, "blocked processes") || strings.Contains(lowerQuery, "currently paused") || strings.Contains(lowerQuery, "currently blocked") {
			paused := respEngine.GetPausedProcesses()
			if len(paused) == 0 {
				json.NewEncoder(w).Encode(map[string]string{"response": "✅ No processes are currently paused/blocked. The system is running normally."})
				return
			}
			var lines []string
			for pid, comm := range paused {
				lines = append(lines, fmt.Sprintf("⏸ %s (PID %d) — SUSPENDED", comm, pid))
			}
			reply := fmt.Sprintf("⏸ **Currently PAUSED processes** (%d total):\n%s\n\nTo resume: type 'resume PID X' or click ▶ Resume on the dashboard banner.", len(paused), strings.Join(lines, "\n"))
			json.NewEncoder(w).Encode(map[string]string{"response": reply})
			return
		}

		// ── 7. SHOW ACTION LOG ──────────────────────────────────────────────
		if strings.Contains(lowerQuery, "action log") || strings.Contains(lowerQuery, "show log") || strings.Contains(lowerQuery, "what did you do") || strings.Contains(lowerQuery, "killed process") || strings.Contains(lowerQuery, "show killed") {
			log := respEngine.GetActionLog(15)
			if len(log) == 0 {
				json.NewEncoder(w).Encode(map[string]string{"response": "📋 No actions recorded yet. The Action Log tracks kills, pauses, resumes, and trust decisions."})
				return
			}
			var lines []string
			icons := map[string]string{"kill": "💀", "pause": "⏸", "resume": "▶", "trust": "✅"}
			for _, e := range log {
				icon := icons[e.Action]
				if icon == "" { icon = "📋" }
				lines = append(lines, fmt.Sprintf("%s [%s] %s %s(PID %d) by=%s result=%s",
					icon, e.Timestamp.Format("15:04:05"), e.Action, e.Comm, e.PID, e.By, e.Result))
			}
			json.NewEncoder(w).Encode(map[string]string{"response": "📋 **Action Log** (most recent first):\n" + strings.Join(lines, "\n")})
			return
		}

		// ── 8. SHOW CHAT HISTORY (reads from session_analysis.jsonl) ─────────
		if strings.Contains(lowerQuery, "show history") || strings.Contains(lowerQuery, "previous conversation") ||
			strings.Contains(lowerQuery, "what did i ask") || strings.Contains(lowerQuery, "last conversation") ||
			strings.Contains(lowerQuery, "previous commands") || strings.Contains(lowerQuery, "chat history") {

			// First show current-session history from request
			if len(req.History) > 0 {
				var lines []string
				for i, h := range req.History {
					prefix := "👤 You"
					if h.Role == "ai" { prefix = "🤖 AI" }
					text := h.Text
					if len(text) > 120 { text = text[:120] + "..." }
					lines = append(lines, fmt.Sprintf("%d. %s: %s", i+1, prefix, text))
				}
				reply := fmt.Sprintf("💬 **Current session history** (%d messages):\n%s", len(req.History), strings.Join(lines, "\n"))

				// Also try to read from session file for past sessions
				data, err := os.ReadFile("data/session_analysis.jsonl")
				if err == nil && len(data) > 0 {
					lines2 := strings.Split(strings.TrimSpace(string(data)), "\n")
					if len(lines2) > 0 {
						reply += fmt.Sprintf("\n\n📂 **Past sessions on disk** (%d saved Q&As in data/session_analysis.jsonl)\n", len(lines2))
						start := len(lines2) - 5
						if start < 0 { start = 0 }
						for _, line := range lines2[start:] {
							var e struct {
								Timestamp string `json:"ts"`
								Query     string `json:"q"`
								Answer    string `json:"a"`
							}
							if json.Unmarshal([]byte(line), &e) == nil {
								ans := e.Answer
								if len(ans) > 80 { ans = ans[:80] + "..." }
								reply += fmt.Sprintf("• [%s] Q: %s\n  → %s\n", e.Timestamp[:16], e.Query, ans)
							}
						}
					}
				}
				json.NewEncoder(w).Encode(map[string]string{"response": reply})
				return
			}

			// No in-session history — read from file
			data, err := os.ReadFile("data/session_analysis.jsonl")
			if err != nil || len(data) == 0 {
				json.NewEncoder(w).Encode(map[string]string{"response": "📂 No conversation history saved yet. History is stored in data/session_analysis.jsonl after each AI Q&A session."})
				return
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			var histLines []string
			start := len(lines) - 10
			if start < 0 { start = 0 }
			for i, line := range lines[start:] {
				var e struct {
					Timestamp string `json:"ts"`
					Query     string `json:"q"`
					Answer    string `json:"a"`
				}
				if json.Unmarshal([]byte(line), &e) == nil {
					ans := e.Answer
					if len(ans) > 100 { ans = ans[:100] + "..." }
					histLines = append(histLines, fmt.Sprintf("%d. [%s] Q: %s\n   → %s", i+1, e.Timestamp[:16], e.Query, ans))
				}
			}
			if len(histLines) == 0 {
				json.NewEncoder(w).Encode(map[string]string{"response": "📂 No parseable history found in data/session_analysis.jsonl."})
				return
			}
			reply := fmt.Sprintf("📂 **Last %d conversations from disk:**\n%s", len(histLines), strings.Join(histLines, "\n\n"))
			json.NewEncoder(w).Encode(map[string]string{"response": reply})
			return
		}

		// ── 8. SIMPLE GREETINGS ─────────────────────────────────────────────
		if lowerQuery == "hi" || lowerQuery == "hello" || lowerQuery == "hey" || lowerQuery == "help" {
			paused := respEngine.GetPausedProcesses()
			pauseInfo := ""
			if len(paused) > 0 {
				pauseInfo = fmt.Sprintf("\n⏸ **%d process(es) are SUSPENDED** — check the amber banner on the dashboard!", len(paused))
			}
			json.NewEncoder(w).Encode(map[string]string{
				"response": fmt.Sprintf("👋 Hello! Kernel Security Monitor AI Copilot. Mode: **%s**%s\n\n**Real commands I can execute:**\n• `trust python3` / `trust PID 1234` — whitelist immediately\n• `resume 1234` — SIGCONT a paused process\n• `pause 1234` — SIGSTOP a specific process\n• `kill 1234` — SIGKILL a process\n• `block all below 30` — SIGSTOP all processes with trust < 30\n• `show paused` — list actually suspended processes\n• `show action log` — full history of kills/pauses/trusts\n\n**AI questions:**\n• 'Is PID 1234 safe?'\n• 'Any suspicious activity?'\n• 'What is volume.sh doing?'", string(respEngine.GetMode()), pauseInfo),
			})
			return
		}

		// ── 9. LLM FREE-FORM — with full real context ───────────────────────
		var pidContextStr string
		if req.PID > 0 {
			ctxMap := cg.GetProcessContext(req.PID)
			ctxBytes, _ := json.MarshalIndent(ctxMap, "", "  ")
			pidContextStr = fmt.Sprintf("\nTARGET PID %d CAUSAL PROVENANCE:\n%s\n", req.PID, string(ctxBytes))
		}

		// Real paused list for context
		pausedMap := respEngine.GetPausedProcesses()
		var pausedCtx string
		for pid, comm := range pausedMap {
			pausedCtx += fmt.Sprintf("  ⏸ %s (PID %d)\n", comm, pid)
		}
		if pausedCtx == "" { pausedCtx = "  (none)" }

		// Action log for context
		recentActions := respEngine.GetActionLog(5)
		var actionCtx string
		for _, e := range recentActions {
			actionCtx += fmt.Sprintf("  [%s] %s %s(PID %d)\n", e.Timestamp.Format("15:04:05"), e.Action, e.Comm, e.PID)
		}
		if actionCtx == "" { actionCtx = "  (none)" }

		recentDecs := respEngine.RecentDecisions(15)
		var contextStr string
		for _, d := range recentDecs {
			if d.Status == response.StatusKnown { continue } // skip known processes to save tokens
			contextStr += fmt.Sprintf("• PID=%d Comm=%s Trust=%.0f Status=%s Action=%s Tech=%s\n",
				d.PID, d.Comm, d.TrustScore, d.Status, d.Action, d.TechniqueID)
		}

		// Build conversation history section (placed FIRST so model reads it before security context)
		var historySection string
		if len(req.History) > 0 {
			historySection = "CONVERSATION HISTORY (use this to answer follow-up questions; the USER may refer to what was said before):\n"
			// Only include last 8 exchanges to save tokens
			histStart := 0
			if len(req.History) > 16 { histStart = len(req.History) - 16 }
			for _, h := range req.History[histStart:] {
				if h.Role == "user" {
					historySection += fmt.Sprintf("  USER: %s\n", h.Text)
				} else {
					text := h.Text
					if len(text) > 200 { text = text[:200] + "..." } // trim long AI replies
					historySection += fmt.Sprintf("  AI: %s\n", text)
				}
			}
			historySection += "\n"
		} else {
			historySection = "CONVERSATION HISTORY: None yet — this is the first message in this session.\n\n"
		}

		prompt := fmt.Sprintf(
			"%s"+ // history FIRST — model attends to it before security context
				"You are Kernel Security Monitor AI — a Linux kernel security expert using eBPF. "+
				"You are also a helpful general assistant. Answer questions DIRECTLY and ACCURATELY.\n"+
				"IMPORTANT RULES:\n"+
				"1. If asked about math, programming, or general topics — answer them CORRECTLY and directly.\n"+
				"2. If asked what was said before — ONLY use the CONVERSATION HISTORY above. NEVER fabricate previous conversations.\n"+
				"3. For security questions, use the CURRENT STATE below.\n"+
				"4. If a process is a known Linux system tool (dwmblocks, st, pipewire, udev-worker, etc.) say SAFE immediately.\n"+
				"5. Do NOT say 'I could not find info about PID X' — say 'PID X is not in my current telemetry window'.\n\n"+
				"CURRENT SYSTEM STATE:\n"+
				"- Mode: %s (observe=log only, pause=SIGSTOP suspicious, enforce=SIGKILL threats)\n"+
				"- Paused processes (SIGSTOP'd):\n%s"+
				"- Recent user actions:\n%s"+
				"- Recent suspicious decisions:\n%s\n"+
				"%s"+ // PID context if specific PID was provided
				"QUESTION: %s",
			historySection, string(respEngine.GetMode()), pausedCtx, actionCtx, contextStr, pidContextStr, query,
		)

		if narrator != nil {
			llmResponse, err := narrator.QueryCopilot(r.Context(), prompt)
			if err != nil || llmResponse == "" {
				json.NewEncoder(w).Encode(map[string]string{
					"response": fmt.Sprintf("🔍 AI offline. Recent suspicious activity:\n%s\n\nPaused: %s", contextStr, pausedCtx),
				})
				return
			}

			// Persist Q&A to session_analysis.jsonl for cross-session knowledge
			go func(q, a string) {
				type sessionEntry struct {
					Timestamp string `json:"ts"`
					Query     string `json:"q"`
					Answer    string `json:"a"`
					Mode      string `json:"mode"`
				}
				e := sessionEntry{
					Timestamp: time.Now().Format(time.RFC3339),
					Query:     q,
					Answer:    a,
					Mode:      string(respEngine.GetMode()),
				}
				b, _ := json.Marshal(e)
				f, err := os.OpenFile("data/session_analysis.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
				if err == nil {
					defer f.Close()
					f.Write(append(b, '\n'))
				}
			}(query, llmResponse)

			json.NewEncoder(w).Encode(map[string]string{"response": llmResponse})
		} else {
			json.NewEncoder(w).Encode(map[string]string{
				"response": fmt.Sprintf("🔍 AI narrator not enabled. Suspicious processes:\n%s\nPaused:\n%s", contextStr, pausedCtx),
			})
		}
	})

	mux.HandleFunc("/api/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		ch := hub.subscribe()
		defer hub.unsubscribe(ch)

		for {
			select {
			case <-r.Context().Done():
				return
			case evt := <-ch:
				data, _ := json.Marshal(evt.Data)
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
				flusher.Flush()
			}
		}
	})

	return mux
}

// ---- SSE Hub ----

type sseEvent struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type sseHub struct {
	mu          sync.RWMutex
	subscribers map[chan sseEvent]struct{}
}

func newSSEHub() *sseHub {
	return &sseHub{subscribers: make(map[chan sseEvent]struct{})}
}

func (h *sseHub) subscribe() chan sseEvent {
	ch := make(chan sseEvent, 64)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *sseHub) unsubscribe(ch chan sseEvent) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *sseHub) broadcast(evt sseEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subscribers {
		select {
		case ch <- evt:
		default: // Drop if slow
		}
	}
}

// ---- Helpers ----

func jsonReader(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}
