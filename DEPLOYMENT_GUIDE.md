# 🛡️ Kernel Security Monitor (KSM) — Deployment Guide

This guide covers deploying **Kernel Security Monitor** across various environments (Bare-Metal Linux, Linux VMs, or Cloud Instances) and connecting it to Cloud LLM APIs (NVIDIA NIM, Groq, OpenAI) or local Ollama.

---

## 1. Quick One-Line Setup (Automated VM / Host Script)

Inside your Linux machine:

```bash
cd kernel-security-monitor
chmod +x scripts/deploy_guest_vm.sh
./scripts/deploy_guest_vm.sh
```

This script automatically:
1. Installs all kernel & compiler packages (`clang`, `bpftool`, `criu`, `libbpf`, `golang`, `python3`).
2. Configures the Python virtual environment and installs dependencies (`sidecar/requirements.txt`).
3. Generates kernel headers (`bpf/vmlinux.h`) and compiles eBPF programs (`bpf/sensor.o`, `bpf/lsm.o`).
4. Builds the Go executable (`kernel-security-monitor`).

---

## 2. Manual Installation Steps

### Step A: System Packages

* **Arch Linux**:
  ```bash
  sudo pacman -S base-devel clang llvm bpftool bpf libbpf go python python-pip criu
  ```
* **Ubuntu / Debian (22.04 / 24.04)**:
  ```bash
  sudo apt update
  sudo apt install -y build-essential clang llvm libbpf-dev linux-tools-generic golang python3 python3-pip python3-venv criu bpftool
  ```
* **Fedora / RHEL**:
  ```bash
  sudo dnf install -y clang llvm libbpf-devel kernel-devel bpftool golang python3 python3-pip criu
  ```

---

### Step B: Python Sidecar & Model Baseline

```bash
# 1. Create and activate venv
python3 -m venv venv
source venv/bin/activate

# 2. Install ML packages
pip install -r sidecar/requirements.txt

# 3. Train baseline (generates data/isolation_forest_model.joblib & data/calibration_scores.json)
make train-baseline
```

---

### Step C: Build Kernel Security Monitor

```bash
# Generate vmlinux.h and compile BPF C code:
make generate

# Compile Go control plane:
make build
```

---

## 3. Configuring LLM Models

### Option A: NVIDIA NIM API (Recommended)
1. Get a free API key from [build.nvidia.com](https://build.nvidia.com/).
2. Export your key and launch:
   ```bash
   export LLM_API_KEY="nvapi-your-key"
   sudo -E ./kernel-security-monitor --mode observe \
     --llm-endpoint "https://integrate.api.nvidia.com/v1" \
     --llm-model "meta/llama-3.1-8b-instruct"
   ```

### Option B: Groq API (High-Speed Cloud Inference)
1. Get a key from [console.groq.com](https://console.groq.com/).
2. Export and launch:
   ```bash
   export LLM_API_KEY="gsk_your_key"
   sudo -E ./kernel-security-monitor --mode observe \
     --llm-endpoint "https://api.groq.com/openai/v1" \
     --llm-model "llama-3.1-8b-instant"
   ```

### Option C: Local Ollama (100% Offline)
1. Pull model: `ollama pull phi3:mini`
2. Start server: `ollama serve`
3. Launch monitor:
   ```bash
   sudo -E ./kernel-security-monitor --mode observe \
     --llm-endpoint "http://localhost:11434" \
     --llm-model "phi3:mini"
   ```

---

## 4. Production Run Procedure

### Terminal 1: Start ML Scorer Microservice
```bash
cd kernel-security-monitor
source venv/bin/activate
python3 sidecar/scorer.py
```
*(Runs on `http://127.0.0.1:8099`)*

### Terminal 2: Start Kernel Security Monitor (Requires Root)
```bash
cd kernel-security-monitor
export LLM_API_KEY="your-api-key"
sudo -E ./kernel-security-monitor --mode observe
```

### Access Dashboard:
Open your browser at: **`http://localhost:8080`**

---

## 5. Testing & Verification

Run the attack demo in Terminal 3:
```bash
sudo bash scripts/demo_attack.sh
```
Watch the live D3 causal graph display the attack lineage, the trust score drop, and the AI Copilot narrate the MITRE ATT&CK techniques.
