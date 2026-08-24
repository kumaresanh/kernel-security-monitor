# Kernel Security Monitor (eBPF) — Complete Knowledge Base
# Last Updated: 2026-08-24 | Build: PASSING ✅ | For: Token-boundary continuity

---

## PROJECT OVERVIEW

**Kernel Security Monitor** is a Linux kernel security monitor that uses eBPF to watch all process
executions, file opens, and network connections in real time. It has:
- A Go backend (`cmd/sensor/main.go`) that loads eBPF programs and runs an HTTP server
- A Python ML sidecar (`sidecar/scorer.py`) that scores process anomaly via Isolation Forest
- A dashboard (`dashboard/`) that shows process trust scores, events, and AI chat
- LLM integration via NVIDIA NIM / OpenAI API (`narrator.go`)

**Repo path**: `/home/unknown/vscodemanagement/projects/kernel-security-monitor`
**Build**: `make build` → produces `./kernel-security-monitor` (and `./ksm` symlink)
**Run**:
```bash
Terminal 1: cd /home/unknown/vscodemanagement/projects/kernel-security-monitor && source venv/bin/activate && python3 sidecar/scorer.py
Terminal 2: export LLM_API_KEY="your-nvidia-api-key" && sudo -E ./kernel-security-monitor --mode observe --llm-endpoint "https://integrate.api.nvidia.com/v1" --llm-model "meta/llama-3.1-8b-instruct"
Browser: http://localhost:8080
Demo: bash ./scripts/demo_attack.sh
```

---

## USER'S ENVIRONMENT

- **OS**: Arch Linux `7.1.8-arch1-3` x86_64
- **LLM**: NVIDIA NIM, endpoint `https://integrate.api.nvidia.com/v1`, model `meta/llama-3.1-8b-instruct`
- **WM**: DWM (dwmblocks, st terminal)
- **Desktop**: Minimal — no GNOME/KDE, just dwm + pipewire
- **Python venv**: `venv/` inside the project root (use `source venv/bin/activate`)
- **Key issue history**: System crashed when unconstrained background loops scored all processes. Resolved by comprehensive daemon whitelist.

---

## ARCHITECTURE

```
eBPF kernel programs (bpf/) 
  ↓ ring buffer events
Go sensor (cmd/sensor/main.go)
  ├── CausalGraph (internal/graph/) — tracks process→file→socket relationships
  ├── ResponseEngine (internal/response/engine.go) — makes trust decisions
  │     ├── Trusts known processes (whitelist)
  │     ├── Calls Python scorer via HTTP for ML anomaly score
  │     ├── Conformal calibration → trust score 0-100
  │     └── Actions: allow / log / pause (SIGSTOP) / kill (SIGKILL)
  ├── Narrator (internal/narration/narrator.go) — LLM integration
  │     └── QueryCopilot() → NVIDIA NIM API → natural language response
  └── HTTP server → dashboard (static files) + REST API + SSE stream

Python scorer (sidecar/scorer.py) — FastAPI on port 8099
  └── Isolation Forest model from data/isolation_forest_model.joblib
```

---

## FILES AND THEIR PURPOSE

| File | Purpose |
|------|---------|
| `cmd/sensor/main.go` | Main binary: loads eBPF, HTTP API, SSE stream, all endpoints |
| `internal/response/engine.go` | Trust decisions: pause/kill/allow/log logic |
| `internal/narration/narrator.go` | LLM connector — `QueryCopilot()` sends to NVIDIA NIM / OpenAI |
| `internal/graph/graph.go` | CausalGraph — tracks which process opened which file/socket |
| `sidecar/scorer.py` | FastAPI ML scorer on port 8099 |
| `sidecar/conformal.py` | Conformal calibration for trust scores |
| `dashboard/index.html` | Dashboard UI HTML with Process Inspector & Action Log |
| `dashboard/app.js` | Dashboard logic — SSE, process table, AI chat, graph |
| `dashboard/style.css` | All CSS — dark security aesthetic |
| `data/user_trust.json` | Persistent user trust decisions (survive restarts) |
| `data/isolation_forest_model.joblib` | Pre-trained ML anomaly model |
| `data/calibration_scores.json` | Conformal calibration scores |
| `thinking.md` | THIS FILE — knowledge base for LLM continuity |
| `bpf/sensor.c` | eBPF tracepoints: execve, openat, connect |
| `bpf/lsm.c` | BPF-LSM for enforcement (SIGKILL via deny_exec) |

---

## API ENDPOINTS (complete list)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/trust` | List all process trust scores |
| GET | `/api/decisions` | List response decisions |
| GET | `/api/stats` | Graph node/edge stats |
| GET | `/api/graph` | Full causal graph data |
| GET | `/api/paused` | Currently SIGSTOP'd processes |
| GET | `/api/actionlog` | Action log (kill/pause/trust/resume history) |
| GET | `/api/mode` | Current mode (observe/pause/enforce) |
| POST | `/api/mode` | Set mode: `{"mode":"pause"}` |
| POST | `/api/chat` | AI chat: `{"query":"...", "pid":0}` |
| POST | `/api/process/known` | Mark as trusted: `{"pid":0,"comm":"firefox"}` |
| POST | `/api/process/pause` | SIGSTOP: `{"pid":1234,"comm":"..."}` |
| POST | `/api/process/resume` | SIGCONT: `{"pid":1234}` |
| POST | `/api/process/kill` | SIGKILL: `{"pid":1234,"comm":"..."}` |
| GET | `/api/stream` | SSE event stream |
| GET | `/` | Dashboard HTML |

---

## /api/chat — REAL COMMANDS (direct execution)

The chat handler has LOCAL command dispatch BEFORE calling the LLM:

| Command pattern | What actually happens |
|----------------|----------------------|
| `trust python3` | Calls `TrustProcess("python3", 0)`, saves to disk |
| `trust PID 1234` | Trusts specific PID |
| `resume 1234` | SIGCONT to PID 1234, recorded in action log |
| `unpause 1234` | Same as resume |
| `pause 1234` | SIGSTOP to PID 1234, recorded in action log |
| `suspend 1234` | Same as pause |
| `kill 1234` | SIGKILL to PID 1234, recorded in action log |
| `terminate 1234` | Same as kill |
| `block all below 30` | SIGSTOP ALL processes with trust < 30 (bulk operation) |
| `block all below 50` | Same with threshold 50 |
| `pause all below 40` | Same pattern |
| `show paused` | Returns REAL list from pausedPIDs map |
| `currently paused` | Same |
| `show paused processes` | Same |
| `show action log` | Returns real ActionLogEntry list |
| `show killed` | Same as action log |
| `hi` / `hello` / `help` | Lists all commands + shows paused count |
| anything else | Sent to NVIDIA NIM LLM with full real context |

---

## engine.go — KEY TYPES AND METHODS

```go
// Modes
const (
    ModeObserve Mode = "observe"  // log only, no blocking
    ModePause   Mode = "pause"    // SIGSTOP suspicious processes
    ModeEnforce Mode = "enforce"  // SIGKILL threats
)

// ActionLogEntry — recorded for every user action
type ActionLogEntry struct {
    Timestamp time.Time
    Action    string  // "kill", "pause", "resume", "trust"
    PID       uint32
    Comm      string
    By        string  // "user", "system", "user-bulk"
    Result    string  // "ok" or error message
}

// Key engine methods:
engine.TrustProcess(comm, pid)        // whitelist a process
engine.PauseProcess(pid, comm)        // SIGSTOP
engine.ResumeProcess(pid)             // SIGCONT
engine.KillProcess(pid, comm)         // SIGKILL
engine.GetPausedProcesses()           // returns map[uint32]string (pid → comm)
engine.GetSuspiciousBelow(threshold)  // returns []Decision with trust < threshold
engine.GetActionLog(n)                // returns recent n ActionLogEntry
engine.RecordAction(action, comm, pid, by, result) // manual log entry
engine.SaveUserTrust()                // saves to data/user_trust.json
engine.IsTrusted(comm, pid)           // check if whitelisted
```

---

## WHITELIST — isKnownProcess() in engine.go

The whitelist is in `isKnownProcess()` function at the bottom of `engine.go`.
**Any comm in this list gets trust=100 automatically and is never scored by ML.**

Key patterns already whitelisted:
- `(udev-worker)`, `(sd-worker)` — kernel worker threads shown with `()`
- `dwmblocks`, `st`, `dmenu`, `rofi` — DWM ecosystem
- `libuv-worker`, `InputThread`, `ThreadPoolForeg` — browser thread pools
- `pipewire-pulse`, `pactl`, `logger`, `dirname`, `upowerd` — system daemons
- All prefixes starting with `(` are trusted (covers ALL `(foo)` style kernel threads)
- Prefixes: `Thread`, `Worker`, `libuv`, `Input`, `Compositor`, `Audio`, `sd-`

---

## DASHBOARD — TABS AND PANELS

**Left column**: Process Classification table + Response Decisions
- Search bar: Filter processes instantly by PID or comm name
- Process rows: Click any row to open the Process Inspector
- Action buttons: [✅ Known] [⏸] [▶] [💀] [🔍]
- Filter buttons: ALL | ⚠ SUSPICIOUS | ⏸ PAUSED | ✅ KNOWN

**Center column**: D3 Causal Graph
- Shows PROCESS and SOCKET nodes only (file nodes filtered out)
- Color: trust<40=red, trust<70=amber, else indigo
- Click a node → opens the Process Inspector modal

**Right column**: Live Events | AI Chat/Narration | Action Log (3 tabs)
- Tab 1: 🧠 AI NARRATION — ATT&CK narration from LLM
- Tab 2: 💬 ASK AI — interactive chat with quick-chips
- Tab 3: 📋 ACTION LOG — real-time kill/pause/trust/resume log

**Top**: Amber banner when processes are paused (slides in/out automatically)
**Mode button**: 🛡️ OBSERVE → ⏸ PAUSE → ⚡ ENFORCE (cycles on click)

---

## ML SCORING — HOW IT WORKS

1. eBPF event arrives → sensor extracts feature vector (syscall type, path, timing)
2. `scorer.py` on port 8099 receives POST `/score` with feature vector
3. Isolation Forest returns anomaly score → conformal calibration → p-value 0-1
4. engine.go: p-value < 0.15 = suspicious, else unknown
5. Trust score = 100 * p-value (roughly)
6. **If process is in whitelist** → SKIP step 2-4, force trust=100

---

## PERSISTENT TRUST — data/user_trust.json

```json
{
  "known_comms": ["chrome", "node", "firefox"],
  "known_pids": [],
  "unknown_comms": []
}
```

- Saved on every `TrustProcess()` call and `SaveUserTrust()` call
- Loaded at startup: `LoadUserTrust()` in engine.go init
- Path: `data/user_trust.json` (relative to working directory)

---

## QUICK TEST COMMANDS (curl)

```bash
# Test greeting
curl -s -X POST http://localhost:8080/api/chat -H "Content-Type: application/json" -d '{"query":"hi"}' | python3 -m json.tool

# Test block all below 30
curl -s -X POST http://localhost:8080/api/chat -H "Content-Type: application/json" -d '{"query":"block all below 30"}' | python3 -m json.tool

# Show paused
curl -s http://localhost:8080/api/paused | python3 -m json.tool

# Show action log
curl -s http://localhost:8080/api/actionlog | python3 -m json.tool

# Kill process
curl -s -X POST http://localhost:8080/api/process/kill -H "Content-Type: application/json" -d '{"pid":9999,"comm":"test"}' | python3 -m json.tool

# Mark as known
curl -s -X POST http://localhost:8080/api/process/known -H "Content-Type: application/json" -d '{"pid":0,"comm":"chrome"}' | python3 -m json.tool

# Switch to pause mode
curl -s -X POST http://localhost:8080/api/mode -H "Content-Type: application/json" -d '{"mode":"pause"}' | python3 -m json.tool
```
