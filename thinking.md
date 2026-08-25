# Kernel Security Monitor (eBPF) — Complete Master Knowledge Base & Audit Chronicle
# Last Updated: 2026-08-25 | Build: PASSING ✅ | Status: Production SIEM & Persistent DB

---

## 1. PROJECT OVERVIEW & SYSTEM ARCHITECTURE

**Kernel Security Monitor** is an enterprise-grade Linux kernel security monitoring and automated intrusion response system that uses eBPF tracepoints (`sys_enter_execve`, `sys_enter_openat`, `sys_enter_connect`) and BPF-LSM hooks (`security_bprm_check`) for real-time threat detection, provenance tracking, and mitigation.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   LINUX KERNEL (eBPF Layer)                                 │
│  Tracepoints: [execve] [openat] [connect]   │   BPF-LSM Hook: [security_bprm_check] (deny)  │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │ eBPF Ring Buffer
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           GO CONTROL PLANE SENSOR (cmd/sensor/main.go)                      │
│                                                                                             │
│  ┌───────────────────────┐   ┌──────────────────────────┐   ┌────────────────────────────┐  │
│  │     Causal Graph      │   │     Response Engine      │   │   Unified DB & Store       │  │
│  │ (internal/graph/)     │   │ (internal/response/)     │   │ (internal/db/store.go)     │  │
│  │ - Process/Socket provenance - Whitelist / Trust Score│   │ - Process Lifecycle Tree   │  │
│  │ - Syscall N-gram features │ - Pause (SIGSTOP) / Kill │   │ - Attack Pattern Detection │  │
│  └───────────┬───────────┘   └────────────┬─────────────┘   │ - Telemetry Grounding Search│ │
│              │                            │                 └─────────────┬──────────────┘  │
│              ▼                            ▼                               │                 │
│  ┌───────────────────────┐   ┌──────────────────────────┐                 │                 │
│  │  Python Scorer Sidecar│   │   AI Narrator & Copilot  │◄────────────────┘                 │
│  │ (:8099 FastAPI / ML)  │   │ (internal/narration/)    │                                   │
│  │ - Isolation Forest    │   │ - NVIDIA NIM / Cloud LLM │                                   │
│  │ - Conformal p-values  │   │ - Grounded DB context    │                                   │
│  └───────────────────────┘   └────────────┬─────────────┘                                   │
│                                           │                                                 │
│                                           ▼                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     HTTP REST Server (:8080) & SSE Live Hub                           │  │
│  │  /api/db/tree   /api/db/attack_patterns   /api/db/graph   /api/chat   /api/trust      │  │
│  └────────────────────────────────────────┬──────────────────────────────────────────────┘  │
└───────────────────────────────────────────┼─────────────────────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                        MODERN PRODUCTION SIEM DASHBOARD (dashboard/)                        │
│                                                                                             │
│  [Top Nav Tab 1: 🛡️ SECURITY DASHBOARD]                                                     │
│    - Left: Process Classification (Hover-Lock, 800ms Debounce, 54px Stable Grid)           │
│    - Center: Response Decisions & Live Event Stream (Spacious Central Priority)             │
│    - Right: AI Narration & Copilot Chat (History-Preserved & DB Telemetry Grounded)         │
│    - Bottom: Production SIEM Causal Provenance Graph (Hairball-Filtered, Weighted Edges)   │
│                                                                                             │
│  [Top Nav Tab 2: 📊 PROCESS MONITOR]                                                        │
│    - Interactive htop-style Process Table (Sort by Trust/PID/Name/Status, Live Badges)     │
│                                                                                             │
│  [Top Nav Tab 3: 🎯 ATTACK PATTERNS & TREE]                                                 │
│    - Left: Identified ATT&CK Patterns Feed (T1105 Staging, T1071 C2, T1053 Persistence)     │
│    - Right: Deep Hierarchical Process Tree (Parent PIDs -> Subprocesses -> Files & Sockets)│
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. EXHAUSTIVE RECORD OF LAST 5 USER REQUESTS & ALL CHANGES DONE

### ═══════════════════════════════════════════════════════════════════════════════════════════
### USER REQUEST 1: UI Glitches, Jitter, Overlapping, Killed State, Pop-up Inspector & htop View
### ═══════════════════════════════════════════════════════════════════════════════════════════

#### User Request:
> *"after killed the process not ubdating in this calssicfications showing like process is running and ad it does not show the process is active or not and and also process pid are over lapping make it not overlapping for any laptop display and when clock reset view in graph nothing happeningand in process classification when i try to click the any process suddenly moving around i cannot click it it ubdating so fast that icannot clicking make any betteer solutions and and that size is so small that i cannot see all process efficently 'my idea when i click that process clafficatons make it open pop it front so can i use all process' create navigations bar with item for pid log and all details about process eveything all details of why this process is blocked and all details and also create ohter navgivations items like htop based that i can see all process normel htop is run on terminal but in this make wth clickable about current running process giving details like layer jsut like htop but with u element"*

#### Exact Problems Identified:
1. **Unthrottled SSE Re-rendering**: The frontend re-rendered the entire process list on every incoming SSE packet, causing elements under the mouse cursor to jump around rapidly ("jitter").
2. **Killed Process Ghost State**: Killed processes remained in the UI as if still active because their status was not transitioned to a tombstone state.
3. **PID Text Overlapping**: Narrow column widths caused PID numbers and parent process arrows to wrap awkwardly.
4. **Lack of Focused Inspector**: Users had to squint at tiny table rows with no way to see why a process was flagged or take quick SOAR control actions.
5. **No Full Process Monitoring**: No full-screen sortable process view existed like `htop`.

#### All Changes Made:
- **`dashboard/app.js`**:
  - Implemented **Hover Lock**: `trustContainerHovered` flag pauses DOM re-renders whenever the user hovers over the process list.
  - Implemented **800ms Debounce**: `scheduledRender()` batches events into smooth 0.8s update cycles.
  - Added **Killed State (`☠️`)**: Processes marked `killed: true` transition to a grayed-out state and trigger an 8-second CSS fade-out animation before removal.
  - Added **Process Inspector Modal (`openProcessInspector`)**: Opens a modal displaying full PID provenance, trust bar, MITRE technique, human-readable reason why flagged, action taken, conformal p-value, and SOAR action buttons.
  - Built **`renderHtop()`**: Complete sortable `htop`-style process monitor table with search filter and action triggers.
- **`dashboard/index.html`**:
  - Added top navigation bar with view switching (`🛡️ SECURITY VIEW`, `📊 PROCESS MONITOR`).
  - Added full `<table class="htop-table">` markup.
  - Added two-column `<div id="inspector-modal">`.
- **`dashboard/style.css`**:
  - Increased `.process-row` minimum height to `54px` with a 5-column grid: `minmax(120px, 1.8fr) 80px 60px 36px 90px`.
  - Added styles for `.htop-table`, `.htop-th`, `.htop-tr`, and `@keyframes fadeRowOut`.

---

### ═══════════════════════════════════════════════════════════════════════════════════════════
### USER REQUEST 2: Session Persistence & Multi-Model Analysis Export
### ═══════════════════════════════════════════════════════════════════════════════════════════

#### User Request:
> *"after that all analysed all data each and every data u analysed store in any file format so if ur token completed i will use for other llm model"*

#### Exact Problems Identified:
- Telemetry analysis and AI conversations were volatile in memory; restarting the service or running out of LLM API tokens meant losing valuable investigation logs.

#### All Changes Made:
- **`cmd/sensor/main.go`**:
  - Added asynchronous persistence worker to append every conversation Q&A exchange to `data/session_analysis.jsonl`.
  - Record format:
    ```json
    {"ts":"2026-08-25T22:30:00+05:30", "q":"Explain why PID 1234 was flagged", "a":"Process staged /tmp/installer.sh and connected to remote port 4444.", "mode":"observe", "pid":1234}
    ```
  - This JSON Lines file is format-agnostic and can be ingested into OpenAI, Anthropic, Ollama, or custom fine-tuning pipelines.

---

### ═══════════════════════════════════════════════════════════════════════════════════════════
### USER REQUEST 3: AI Hallucination Fix, Conversation Memory & General Topic Accuracy
### ═══════════════════════════════════════════════════════════════════════════════════════════

#### User Request:
> *"HAT PREVIOUS CONVERISON WE HAD LAST 10 CONVERSIONS GIVE ME
> Kernel Security AI: You previously asked: ...
> WHAT IS 3+2+1*123 -> Kernel Security AI: 126
> GIVE ME PYTHON CODE FOR SUM OF ARRAY -> def sum_array(arr): return sum(arr)
> INC++ -> Kernel Security AI: INC++.
> I NEED INN C++ IF YOU DONT KNOW CHECK PREVIOUS OCNVERSIONS -> PID 417578 (acpid) is SAFE
> THE AI NOT GIVING CORRECT OP I ASKED WHAT PREVIOUS GIVING WRONG OP THIS IS THIS MY API AI PROBLEM OR ANYTHING EELSE WHY ITS CANT LEARN NFROM PREVIOUS SOLVE"*

#### Exact Problems Identified:
1. **Prompt Inversion**: The security system prompt preceded the user's question, causing the small 8B LLM to assume every question was about a process PID, replying about `acpid` when the user asked for C++ code.
2. **Missing History Context**: The frontend did not send historical exchanges, so when asked "what did I ask before", the LLM fabricated past questions.
3. **No Native `show history` Command**: There was no deterministic command to read past exchanges directly from the saved JSONL file.

#### All Changes Made:
- **`dashboard/app.js`**:
  - Added `state.chatHistory` maintaining the last 20 messages.
  - Included `history: state.chatHistory.slice(-10)` in every POST payload to `/api/chat`.
- **`cmd/sensor/main.go`**:
  - Added **`show history` / `previous conversations` Command**: Directly parses and returns the last 10 real Q&A pairs from `data/session_analysis.jsonl` with timestamps.
  - **Reordered LLM Prompt**: Placed `CONVERSATION HISTORY` section at the very top.
  - Added **Explicit Assistant Guidelines**:
    ```text
    1. If asked about math, programming, or general topics — answer them CORRECTLY and directly.
    2. If asked what was said before — ONLY use the CONVERSATION HISTORY above. NEVER fabricate previous conversations.
    3. For security questions, use the CURRENT STATE and DATABASE TELEMETRY below.
    ```

---

### ═══════════════════════════════════════════════════════════════════════════════════════════
### USER REQUEST 4: Unified Database Engine, SIEM Provenance Graph & Attack Patterns Tree
### ═══════════════════════════════════════════════════════════════════════════════════════════

#### User Request:
> *"HI I THAT IS JUST I ASKED THE AI WHAT WILL GIVE REPLAY NOT FOR COMMANDS WHY DONT U DO EVERY PROCESS AND ALL DETAILD STORE IN DB EVEN MY CONVERSATIONS SO WHEN I TRIED AI MODEL WILL CHECK THE DB GIVE DESIRED OUTPUTS AND NAV ITEMS HAS CASUAL GRAPH EMPTY BUT IN MAIN PAGE HAS THAT SO REMOVE THAT AND LIVE EVENT STREAM AND RESPONSE DECSSIONS MAKE CENTER IT MAY GET MORE SPACE WHAT AREE GOING TO DO IS THAT THE UI DOES NOT SCROLLABLE MAKE IT SCROLABLE AND ON THAT BELOW GIVE CASUAL GRAPH AND IT SATISFY THE PRODUCTION GRADE GRAPH Why the Visual in the Screenshot Needs Refinement for Production High Cognitive Load ('Hairball Problem'): Displaying dozens or hundreds of disconnected nodes without clear sub-clustering or visual hierarchy creates noise rather than actionable intelligence. Lack of Contextual Edge Aggregation: In production Threat Intelligence / SIEM dashboards (e.g., Splunk, Sentinel, Maltego), edges are weighted by traffic volume, timestamp, or alert severity, and isolated nodes are filtered out by default. Production vs. Prototype Graph Usage Feature Prototype / Basic UI Production-Grade Data Filtering Displays all nodes indiscriminately Aggregates logs; filters out non-malicious background noise Interactivity Dynamic force-directed layout only Layout algorithms, node expansion, drill-down Actionability Visual only Integrated directly with SOAR Playbooks AND AFTER REMVOEING THE NAV TIME CASUAL GRAPH, ADD NAV ITEM ATTACK PATTERN THAT IDENTIFIED IN PROCESS LIKE EXAMPLE BROWSER IT HAVE MORE PID AND DWM HAVE MORE PID SHOW ALL PARENT PROCESS INSIDE SHOW SUB PROCESS AND WHAT IS DOING WHAT ACESS IT HAS ALL EVERY PROCESS MIGHT HAVE CONNECTED WITH SOMETHING OR MAKE IT LOOP OR SOMETHING SO SO EVEN IF TRUSTED PROCESS ALSO MAKE ATTACK PATTERNS LEADS TO THREAD SO ONLY"*

#### Exact Problems Identified:
1. **Volatile Process History**: Sensor didn't store multi-step parent-child access histories (files, sockets, syscalls) in a queryable structured database.
2. **Nav Item Duplication**: The top nav had an empty `🕸️ CAUSAL GRAPH` view while the graph was already on the main page.
3. **Viewport Cramping**: The dashboard had fixed viewport heights without natural scrolling.
4. **The "Hairball Problem"**: The prototype graph displayed hundreds of isolated, noisy nodes with unweighted lines.
5. **No Deep Process Family Tree**: Multi-process applications (Browser renderers, DWM with helper scripts, bash staging loops) were displayed as disconnected flat rows without hierarchical sub-process drilldown.

#### All Changes Made:

#### 1. Created Unified Persistent Database (`internal/db/store.go`):
- `ProcessRecord`: Maps PID to full lifecycle metadata (`PPID`, `ParentComm`, `AccessedFiles`, `NetworkSockets`, `SyscallCount`, `AttackPatterns`, `Decisions`, `IsPaused`, `IsKilled`).
- **Dynamic Multi-Step Attack Pattern Engine**:
  - `T1105 / T1059`: Staging script in `/tmp/` or `/var/tmp/` (`installer.sh`, `backdoor.sh`).
  - `T1071 / T1095`: Non-standard C2 socket connections on ports `4444`, `1337`, `8888`, `9999`.
  - `T1003 / T1083`: Credential discovery attempts on `/etc/shadow`, `/etc/passwd`, `~/.ssh`, `~/.aws`.
  - `T1053.003`: Persistence attempts on cron tabs or systemd service configurations.
- `GetProcessTree()`: Builds a hierarchical tree (`ProcessTreeNode`) grouping root parent daemons with their children.
- `GetProductionGraph()`: Generates filtered SIEM graph nodes and weighted contextual edges.
- `SearchTelemetry()`: Performs full-text database lookups for the AI Copilot.

#### 2. Backend API Integration (`cmd/sensor/main.go`):
- Added routes:
  - `GET /api/db/tree`: Returns nested process hierarchy tree.
  - `GET /api/db/attack_patterns`: Returns identified MITRE ATT&CK patterns.
  - `GET /api/db/graph`: Returns hairball-filtered SIEM graph data.
- Injected `database.SearchTelemetry(query, req.PID)` directly into the AI prompt.

#### 3. Frontend SIEM Overhaul (`dashboard/index.html`, `dashboard/style.css`, `dashboard/app.js`):
- **Top Navigation Updated to 3 Core Views**:
  1. `🛡️ SECURITY DASHBOARD`: Main scrollable page.
     - Top row: Process Classification (Left), Response Decisions + Live Events (Center), AI Copilot (Right).
     - Bottom row: **Production Causal Provenance Graph** (520px height, hairball-filtered, filter toggles: `All`, `Threats Only`, `Hierarchy Only`, clickable nodes with SOAR actions).
  2. `📊 PROCESS MONITOR`: Sortable `htop`-style table.
  3. `🎯 ATTACK PATTERNS & TREE`:
     - Left: Identified ATT&CK pattern cards with severity badges and evidence paths.
     - Right: Nested process hierarchy tree with expandable/collapsible branches (`[▼]`/`[▶]`), showing accessed files tags and network socket tags.

---

### ═══════════════════════════════════════════════════════════════════════════════════════════
### USER REQUEST 5: Record All Changes & Master Documentation into thinking.md
### ═══════════════════════════════════════════════════════════════════════════════════════════

#### User Request:
> *"from after 7 cl to now what ever changes done store in thinking.md with all my request i ased" / "imeans last 5 request i made that stroe all changes u made all everythng in thinking.md store it every pieece of data u have done"*

#### Action:
- Compiled and committed this comprehensive master documentation capturing every user request verbatim, root-cause analyses, architectural decisions, code diff summaries, and API specifications.

---

## 3. FULL API ENDPOINTS SPECIFICATION

| Method | Endpoint | Description | Response Format |
|---|---|---|---|
| **GET** | `/` | Serves SIEM Dashboard HTML | `text/html` |
| **GET** | `/api/db/tree` | Hierarchical process tree (Parent -> Children -> Sockets/Files) | `JSON: []ProcessTreeNode` |
| **GET** | `/api/db/attack_patterns` | List of detected MITRE ATT&CK patterns | `JSON: []AttackPattern` |
| **GET** | `/api/db/graph` | Production SIEM graph data (Nodes, Edges, Threats) | `JSON: ProductionGraphData` |
| **GET** | `/api/trust` | List of tracked process trust scores | `JSON: []TrustRecord` |
| **GET** | `/api/decisions` | Recent response decisions (last 50) | `JSON: []Decision` |
| **GET** | `/api/events` | Recent raw kernel events (last 50) | `JSON: []Event` |
| **GET** | `/api/stats` | Causal graph node/edge counts | `JSON: Stats` |
| **GET** | `/api/paused` | List of currently suspended processes (SIGSTOP) | `JSON: []PausedProcess` |
| **GET** | `/api/actionlog` | SOAR action audit log (kills, pauses, resumes, trusts) | `JSON: []ActionLogEntry` |
| **GET** | `/api/mode` | Current mode (`observe`, `pause`, `enforce`) | `JSON: {"mode":"..."}` |
| **POST** | `/api/mode` | Set operating mode | `JSON: {"mode":"pause"}` |
| **POST** | `/api/chat` | AI Copilot query with grounded DB telemetry & history | `JSON: {"response":"..."}` |
| **POST** | `/api/process/known` | Whitelist process across restarts | `JSON: {"status":"ok"}` |
| **POST** | `/api/process/pause` | Suspend process via `SIGSTOP` | `JSON: {"status":"ok"}` |
| **POST** | `/api/process/resume` | Resume suspended process via `SIGCONT` | `JSON: {"status":"ok"}` |
| **POST** | `/api/process/kill` | Terminate process via `SIGKILL` | `JSON: {"status":"ok"}` |
| **GET** | `/api/stream` | Server-Sent Events (SSE) telemetry stream | `text/event-stream` |

---

## 4. PERSISTENT STORAGE LAYOUT

| File Path | Format | Purpose | Persistence |
|---|---|---|---|
| `data/user_trust.json` | JSON | Whitelisted comms (`known_comms`) and whitelisted PIDs (`known_pids`) | Permanent (survives restarts) |
| `data/session_analysis.jsonl` | JSON Lines | Audit log of all AI Q&A interactions and telemetry summaries | Permanent append-only WAL |
| `data/isolation_forest_model.joblib` | Binary (Joblib) | Pre-trained Scikit-Learn Isolation Forest model | Read-only model artifact |
| `data/calibration_scores.json` | JSON | Conformal calibration scores for non-conformity mapping | Calibration artifact |

---

## 5. VERIFICATION & RUN COMMANDS

```bash
# 1. Compile everything
make build

# 2. Start ML Scorer (Terminal 1)
source venv/bin/activate
python3 sidecar/scorer.py

# 3. Start Kernel Security Monitor with AI (Terminal 2)
export LLM_API_KEY="your-nvidia-api-key"
sudo -E ./kernel-security-monitor --mode observe \
  --llm-endpoint "https://integrate.api.nvidia.com/v1" \
  --llm-model "meta/llama-3.1-8b-instruct"

# 4. Open SIEM Dashboard
# Visit http://localhost:8080 in any web browser

# 5. Run Live Attack Simulation (Terminal 3)
bash ./scripts/live_demo.sh
```
