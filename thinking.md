# Kernel Security Monitor (eBPF) — Complete Knowledge Base & Project Chronicle
# Last Updated: 2026-08-25 | Build: PASSING ✅ | Architecture: Persistent DB + SIEM Graph + ATT&CK Tree

---

## 1. PROJECT OVERVIEW

**Kernel Security Monitor** is a production-grade Linux kernel security monitor leveraging eBPF tracepoints (`execve`, `openat`, `connect`) and BPF-LSM (`security_bprm_check`) to monitor, analyze, and respond to threats in real time.

- **Go Backend** (`cmd/sensor/main.go`): eBPF loaders, Causal Graph, Response Engine, Unified Database (`internal/db/store.go`), REST API, SSE event hub.
- **Python ML Sidecar** (`sidecar/scorer.py`): FastAPI on port 8099, Isolation Forest anomaly scoring with conformal calibration.
- **AI Copilot** (`internal/narration/narrator.go`): NVIDIA NIM / Cloud LLM (`meta/llama-3.1-8b-instruct`) with grounded local database telemetry search.
- **Modern SIEM Dashboard** (`dashboard/`): 3-view top navigation (Security Dashboard with bottom Causal Graph, htop-style Process Monitor, and Attack Patterns & Process Provenance Tree).

**Repo Path**: `/home/unknown/vscodemanagement/projects/kernel-security-monitor`  
**Build Command**: `make build` → produces `./kernel-security-monitor`  
**Run Command**:
```bash
# Terminal 1: ML Scorer
cd /home/unknown/vscodemanagement/projects/kernel-security-monitor
source venv/bin/activate
python3 sidecar/scorer.py

# Terminal 2: Sensor & Monitor
export LLM_API_KEY="your-nvidia-api-key"
sudo -E ./kernel-security-monitor --mode observe \
  --llm-endpoint "https://integrate.api.nvidia.com/v1" \
  --llm-model "meta/llama-3.1-8b-instruct"

# Browser:
http://localhost:8080
```

---

## 2. CHRONOLOGICAL USER REQUESTS & SOLUTIONS (Checkpoint 7 to Present)

### Request 1: Process Table UI/UX — Rapid Jumping & Clickability
- **User Issue**:
  > *"after killed the process not ubdating in this calssicfications showing like process is running... process pid are over lapping... when i try to click the any process suddenly moving around i cannot click it it ubdating so fast"*
- **Root Cause**: Unthrottled SSE updates re-rendered the DOM on every single kernel event; killed processes had no visual tombstone state; small row heights caused misclicks.
- **Solution Implemented**:
  1. **Hover Lock**: Freezes DOM re-renders while mouse cursor is over the process container.
  2. **800ms Debounced Rendering**: Batches SSE events into smooth 800ms render ticks.
  3. **Visual Tombstone & Fade-Out**: Killed processes immediately switch to `status: killed` (`☠️`) with an 8-second CSS fade-out before removal from memory.
  4. **Stable 54px Min-Height Grid**: Fixed column dimensions with text truncation to prevent row wrapping or overlapping.

---

### Request 2: Process Inspector Modal & SOAR Actions
- **User Issue**:
  > *"my idea when i click that process clafficatons make it open pop it front so can i use all process create navigations bar with item for pid log and all details about process eveything all details of why this process is blocked and all details"*
- **Solution Implemented**:
  1. **Two-Column Inspector Modal**:
     - *Left*: Process Name, PID/PPID, Security Status badge, Trust score fill bar, First seen timestamp.
     - *Right (Threat Analysis)*: MITRE ATT&CK technique ID, Human-readable reason why flagged (`observe_critical`, `paused_sigstop`, `staging_script`, `c2_beacon`), Action taken, Conformal p-value.
  2. **SOAR Actions Injected**: `✅ Mark Known`, `⏸ Suspend (SIGSTOP)`, `▶ Resume (SIGCONT)`, `💀 Kill (SIGKILL)`, `🔍 Ask AI Copilot`.

---

### Request 3: htop-Style Process Monitor View
- **User Issue**:
  > *"create other navigations items like htop based that i can see all process normel htop is run on terminal but in this make wth clickable about current running process giving details like layer jsut like htop but with u element"*
- **Solution Implemented**:
  1. Added **`📊 PROCESS MONITOR`** top navigation tab.
  2. Full interactive table with columns: `PID | PPID | NAME | TRUST | BAR | STATUS | ACTIONS`.
  3. Real-time sorting by Trust (risk-first), Trust descending, PID, Name (A-Z), or Status.
  4. Instant search/filter box and live PID counter badge.

---

### Request 4: AI History & Non-Security Question Accuracy
- **User Issue**:
  > *"WHAT PREVIOUS CONVERISON WE HAD LAST 10 CONVERSIONS GIVE ME... WHAT IS 3+2+1*123... GIVE ME PYTHON CODE... INC++... THE AI NOT GIVING CORRECT OP"*
- **Root Cause**:
  - LLM system prompt had strict security constraints placed *before* the user question, confusing general queries (math, C++) with process queries.
  - History was not persisted across sessions, causing the 8B model to hallucinate previous dialogues.
- **Solution Implemented**:
  1. **History-First Prompt Structure**: Conversation history (up to last 16 messages) placed at the top of the prompt.
  2. **General Question Handling**: Prompt explicitly instructs the model to answer math, programming, and general topics directly and accurately.
  3. **Real `show history` Command**: Directly parses and displays the last 10 conversations from `data/session_analysis.jsonl` with zero hallucination.

---

### Request 5: Unified Database Telemetry & Storage (`internal/db/store.go`)
- **User Issue**:
  > *"WHY DONT U DO EVERY PROCESS AND ALL DETAILD STORE IN DB EVEN MY CONVERSATIONS SO WHEN I TRIED AI MODEL WILL CHECK THE DB GIVE DESIRED OUTPUTS"*
- **Solution Implemented**:
  1. Built **`internal/db/store.go`**:
     - `ProcessRecord`: Tracks full process lifecycle, parent PID, child sub-PIDs, opened files map, network sockets map, total syscall count, trust history, and threat detections.
     - `EventRecord`: Ingests and stores raw kernel events with circular ringbuffer retention.
     - `ConversationRecord`: Persists all AI chat queries, model responses, timestamps, and target PIDs to `data/session_analysis.jsonl`.
  2. **AI Telemetry Grounding**: In `cmd/sensor/main.go`, `database.SearchTelemetry(query, pid)` searches the local database and injects exact historical process records into the LLM prompt.

---

### Request 6: Production-Grade SIEM Provenance Graph (Solving the "Hairball Problem")
- **User Issue**:
  > *"NAV ITEMS HAS CASUAL GRAPH EMPTY BUT IN MAIN PAGE HAS THAT SO REMOVE THAT... LIVE EVENT STREAM AND RESPONSE DECSSIONS MAKE CENTER... UI DOES NOT SCROLLABLE MAKE IT SCROLABLE AND ON THAT BELOW GIVE CASUAL GRAPH IT SATISFY THE PRODUCTION GRADE GRAPH"*
- **Solution Implemented**:
  1. **Removed empty graph from top nav**.
  2. **Scrollable Security Dashboard**:
     - Top row (3 columns): Left (Process Classification), Center (Response Decisions + Live Event Stream), Right (AI Narration & Copilot Chat).
     - Bottom row: Full-width **Production Causal Provenance Graph** (520px height).
  3. **Production SIEM Graph Features**:
     - **Hairball Filtering**: Prunes noisy disconnected background nodes. Focuses on Parent Daemons (purple `#8b5cf6`), Child Processes (indigo `#6366f1`), Network Sockets (cyan `#06b6d4`), and Active Threats (pulsing red `#ef4444`).
     - **Filter Toggles**: `[All Provenance]`, `[⚠ Threats & Network Only]`, `[🌲 Parent-Child Trees]`.
     - **Weighted Directed Edges**: `FORK_EXEC`, `CONNECT`, `WRITE_STAGING` with directional arrowheads.
     - **Click-to-Inspect**: Clicking any graph node opens the Process Inspector modal directly.

---

### Request 7: Attack Patterns & Deep Hierarchical Process Tree View
- **User Issue**:
  > *"ADD NAV ITEM ATTACK PATTERN THAT IDENTIFIED IN PROCESS LIKE EXAMPLE BROWSER IT HAVE MORE PID AND DWM HAVE MORE PID SHOW ALL PARENT PROCESS INSIDE SHOW SUB PROCESS AND WHAT IS DOING WHAT ACESS IT HAS ALL"*
- **Solution Implemented**:
  1. Added **`🎯 ATTACK PATTERNS & TREE`** top navigation view.
  2. **Attack Patterns Feed (`/api/db/attack_patterns`)**:
     - Cards showing detected MITRE techniques (`T1105 Ingress Tool Transfer`, `T1071 C2 callbacks`, `T1053 Persistence`, `T1003 Credential access`).
     - Severity badges (`CRITICAL`, `HIGH`), timestamp, evidence chips, and 1-click SOAR action buttons.
  3. **Hierarchical Process Tree (`/api/db/tree`)**:
     - Groups processes by root Parent PIDs (e.g. `systemd [1]`, `dwm [1020]`, `chrome [2082]`, `bash [308781]`).
     - Expandable/collapsible subprocess branches with `[▼]`/`[▶]`.
     - Shows accessed files tags (`📄 /tmp/installer.sh`), network sockets tags (`🌐 192.168.1.50:4444`), syscall count, and status badges.
     - Search filter box and Expand/Collapse All buttons.

---

## 3. COMPLETE REPOSITORY STRUCTURE

```
kernel-security-monitor/
├── bpf/
│   ├── sensor.c                  # eBPF tracepoints: execve, openat, connect
│   ├── lsm.c                     # BPF-LSM for enforcement (deny_exec)
│   ├── vmlinux.h                 # Kernel BTF types
│   └── sensor.o, lsm.o           # Compiled BPF objects
├── cmd/
│   └── sensor/
│       └── main.go               # Control plane, HTTP server, SSE hub, DB wiring
├── internal/
│   ├── db/
│   │   └── store.go              # Unified Database (Process lifecycle, Tree, Attack Patterns)
│   ├── graph/
│   │   ├── graph.go              # CausalGraph node/edge structures
│   │   └── features.go           # Syscall feature extractor for ML model
│   ├── narration/
│   │   ├── narrator.go           # LLM connector (NVIDIA NIM / Ollama / OpenAI)
│   │   └── patterns.go           # MITRE ATT&CK rule matches
│   ├── response/
│   │   ├── engine.go             # Trust scoring, Whitelist, Pause/Kill/Allow SOAR
│   │   └── log.go                # Decision and event logging
│   └── sensor/
│       ├── loader.go             # cilium/ebpf loader and ring buffer reader
│       └── events.go             # RawEvent to Event parser
├── sidecar/
│   ├── scorer.py                 # FastAPI Isolation Forest scorer on :8099
│   └── conformal.py              # Conformal calibration logic
├── dashboard/
│   ├── index.html                # Multi-view SIEM UI (Dashboard, htop, Patterns Tree)
│   ├── app.js                    # UI state, D3 graph, tree rendering, SSE listeners
│   ├── style.css                 # Dark cybersecurity design system
│   └── d3.v7.min.js              # Bundled local D3 library
├── data/
│   ├── user_trust.json           # Whitelisted comms & PIDs
│   ├── session_analysis.jsonl    # Persistent AI chat and telemetry history
│   ├── isolation_forest_model.joblib # Pre-trained ML model
│   └── calibration_scores.json   # Calibration thresholds
├── scripts/
│   ├── live_demo.sh              # Persistent attack simulation script
│   └── demo_attack.sh            # Standard demo script
├── Makefile                      # Build automation (make build, make live-demo)
└── thinking.md                   # THIS FILE (Comprehensive Knowledge Base)
```

---

## 4. API ENDPOINTS REFERENCE

| Method | Path | Purpose |
|---|---|---|
| **GET** | `/` | Dashboard HTML application |
| **GET** | `/api/db/tree` | Hierarchical Process Tree (Parent -> Children -> Files/Sockets) |
| **GET** | `/api/db/attack_patterns` | Detected MITRE ATT&CK patterns list |
| **GET** | `/api/db/graph` | Production SIEM Causal Graph data (Hairball-filtered) |
| **GET** | `/api/trust` | List of tracked process trust scores |
| **GET** | `/api/decisions` | Recent response decisions (last 50) |
| **GET** | `/api/events` | Recent raw kernel events (last 50) |
| **GET** | `/api/stats` | Causal graph node/edge counts |
| **GET** | `/api/paused` | List of currently suspended processes (SIGSTOP) |
| **GET** | `/api/actionlog` | SOAR action history (kills, pauses, resumes, trusts) |
| **GET** | `/api/mode` | Current response mode (`observe`, `pause`, `enforce`) |
| **POST** | `/api/mode` | Set response mode: `{"mode":"pause"}` |
| **POST** | `/api/chat` | AI Copilot query with grounded DB telemetry |
| **POST** | `/api/process/known` | Whitelist process: `{"pid":0,"comm":"chrome"}` |
| **POST** | `/api/process/pause` | SIGSTOP process: `{"pid":1234,"comm":"..."}` |
| **POST** | `/api/process/resume` | SIGCONT process: `{"pid":1234}` |
| **POST** | `/api/process/kill` | SIGKILL process: `{"pid":1234,"comm":"..."}` |
| **GET** | `/api/stream` | Server-Sent Events (SSE) live telemetry stream |

---

## 5. REAL CHAT COMMANDS

| Chat Command | Real Action Executed |
|---|---|
| `show history` | Reads last 10 conversations from `data/session_analysis.jsonl` |
| `show paused` | Lists all currently suspended PIDs (SIGSTOP) |
| `show action log` | Displays audit log of all kill/pause/resume/trust actions |
| `trust <comm>` | Whitelists process across restarts (`data/user_trust.json`) |
| `pause <pid>` | Sends `SIGSTOP` to suspend process |
| `resume <pid>` | Sends `SIGCONT` to resume process |
| `kill <pid>` | Sends `SIGKILL` to terminate process |
| `block all below <N>` | Bulk `SIGSTOP` for all processes with trust < N |
| `hi` / `help` | Lists available real commands and system mode |
| Any general question | Answered directly by AI Copilot with DB telemetry grounding |
