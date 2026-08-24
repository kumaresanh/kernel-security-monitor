# Kernel Security Monitor — eBPF Verify-Before-Block Intrusion Response

> **Novel contribution:** The verify-before-block loop (checkpoint → isolated replay → confirm → act)
> and the conformal-bounded FPR decision layer. Prior work (ThreaTrace, KAIROS, HuntGPT, AgentSight)
> builds provenance graphs or narrates alerts — none close the response loop.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Kernel Space (7.x)                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────┐ │
│  │ TP/execve  │  │ TP/openat  │  │ TP/connect │  │ BPF-LSM deny │ │
│  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘  └──────▲───────┘ │
│         └───────────────┼───────────────┘                │         │
│                    Ring Buffer                           │         │
└────────────────────────┬─────────────────────────────────┼─────────┘
                         │                                 │
┌────────────────────────▼─────────────────────────────────┼─────────┐
│                  Go Control Plane                        │         │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐     │         │
│  │ eBPF     │→ │ Causal Graph │→ │ Feature        │     │         │
│  │ Loader   │  │ (streaming)  │  │ Extractor      │     │         │
│  └──────────┘  └──────────────┘  └───────┬────────┘     │         │
│                                          │              │         │
│  ┌──────────────┐  ┌──────────────┐  ┌───▼────────┐    │         │
│  │ Response     │← │ Trust Scorer │← │ Conformal  │    │         │
│  │ Engine       │  │ (0-100)      │  │ Calibrator │    │         │
│  └──┬──┬──┬─────┘  └──────────────┘  └────────────┘    │         │
│     │  │  │                                             │         │
│  low│  │medium    high──────────────────────────────────┘         │
│  log│  │                                                          │
│     │  ▼                                                          │
│     │  ┌────────────────────────────┐                             │
│     │  │ CRIU: checkpoint → replay  │                             │
│     │  │ in isolated netns sinkhole │                             │
│     │  │ → confirm malicious → kill │                             │
│     │  └────────────────────────────┘                             │
└───────────────────────────────────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
  ┌────────────┐  ┌────────────┐  ┌────────────┐
  │ Python     │  │ Cloud/Local│  │ Dashboard  │
  │ IF Scorer  │  │ LLM Copilot│  │ (SSE+D3)   │
  └────────────┘  └────────────┘  └────────────┘
```

## Stack

| Component | Technology |
|-----------|-----------|
| eBPF Sensor | Go (cilium-ebpf), CO-RE tracepoints |
| BPF-LSM Kill | BPF LSM `bprm_check_security` hook |
| Causal Graph | Go, in-memory, streaming |
| Anomaly Detection | Python, scikit-learn Isolation Forest |
| Conformal Calibration | Python, precomputed offline thresholds |
| CRIU Verify | CRIU checkpoint + isolated netns replay |
| LLM Copilot | NVIDIA NIM / OpenAI / Ollama |
| Dashboard | HTML/CSS/JS, D3.js, SSE |
| Target Kernel | 6.x+ with BPF-LSM in lsm= chain |

## Quick Start

```bash
# 1. Install dependencies
make sidecar-deps

# 2. Generate vmlinux.h + compile BPF programs
make generate

# 3. Train offline baseline (Isolation Forest + conformal calibration)
make train-baseline

# 4. Build Go binary
make build

# 5. Start Python scorer sidecar (terminal 1)
make sidecar

# 6. Start Kernel Security Monitor (terminal 2, requires root)
make run

# 7. Open dashboard
open http://localhost:8080

# 8. Run demo attack (terminal 3)
make demo
```

## Full Setup (one command)

```bash
make setup
```

## Features by Priority

### Priority 1: Core (Demoable Alone)
- [x] eBPF sensor: execve, openat, connect via CO-RE tracepoints
- [x] Ring buffer to userspace with cilium/ebpf
- [x] Causal graph: process/file/socket nodes, causal edges
- [x] Isolation Forest on curated features (fan-out, entropy, n-gram rarity, ancestry depth)
- [x] Conformal calibration with precomputed offline thresholds
- [x] Tiered response: log (low), verify (medium), kill (high)
- [x] BPF-LSM deny with signal-kill fallback behind `--fallback-signal-kill`
- [x] Trust scoring: f(conformal_p, ancestry, severity), 0-100 scale

### Priority 2: CRIU Verify Path
- [x] CRIU checkpoint scoped to pre-connection state
- [x] Replay in isolated netns routed to sinkhole
- [x] Sinkhole captures C2 callback attempts as evidence
- [x] Confirm malicious intent before touching real process

### Priority 3: LLM Narration & Copilot
- [x] ATT&CK technique lookup and live investigation
- [x] Interactive Copilot with real command execution (kill, pause, resume, trust)
- [x] Template-based fallback when LLM unavailable
- [x] Narration timeout + skip flags

### Priority 4: Dashboard
- [x] Dark-mode SOC aesthetic
- [x] Process trust scores (0-100 bars, color-coded tiers)
- [x] D3.js force-directed causal graph visualization
- [x] Live SSE event stream
- [x] Interactive Process Inspector modal + Action Log tab

## Demo Scenario

**Malicious install-script pattern** (curl payload | chmod +x | pre-exec):

```bash
sudo bash scripts/demo_attack.sh
```

The monitor catches this because:
1. The sensor captures the write → chmod → exec sequence
2. Feature extraction shows elevated n-gram rarity (write→chmod→exec is rare in baseline)
3. Conformal calibration yields a low p-value (medium/high tier)
4. **If CRIU is enabled**: checkpoint before exec, replay in sandbox, sinkhole catches C2 callback → confirmed malicious → kill
5. **If CRIU is not available**: BPF-LSM deny or SIGKILL based on conformal tier

## Novelty Positioning

| System | What it does | What it doesn't do |
|--------|-------------|-------------------|
| ThreaTrace / FLASH | GNN provenance anomaly detection | No response loop |
| KAIROS (IEEE S&P '24) | Temporal GNN on streaming audit logs | No response loop |
| HuntGPT | LLM-narrated alerts | Network traffic + cloud LLM, not process provenance |
| AgentSight | eBPF + LLM causal correlation | AI agent observability, not intrusion response |
| **Kernel Security Monitor** | **Verify-before-block + conformal FPR** | **This is the novel part** |

## Flags

```
--sensor-obj         Path to compiled sensor BPF object (default: bpf/sensor.o)
--lsm-obj            Path to compiled LSM BPF object (default: bpf/lsm.o)
--fallback-signal-kill  Use SIGKILL instead of BPF-LSM deny
--scorer-addr        Python scorer sidecar address (default: http://127.0.0.1:8099)
--listen             Dashboard HTTP listen address (default: :8080)
--log-file           Event log file path (default: events.jsonl)
--data-dir           Data directory for baseline files (default: data)
--enable-criu        Enable CRIU checkpoint+verify path
--enable-narration   Enable LLM narration (default: true)
--llm-endpoint       Cloud or local LLM endpoint (e.g. https://api.openai.com/v1 or http://localhost:11434)
--llm-model          LLM model name (e.g. meta/llama-3.1-8b-instruct, gpt-4o-mini, phi3:mini)
--llm-api-key        API Key for Cloud LLM (or set LLM_API_KEY env var)
```
