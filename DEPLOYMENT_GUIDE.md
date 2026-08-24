# 🛡️ Kernel Security Monitor — Guest OS (Linux VM) Deployment Guide

This guide walks you through deploying **Kernel Security Monitor** inside a Linux Guest OS / Virtual Machine (Ubuntu, Debian, Fedora, Arch) and connecting it to a **Cloud API LLM Model** (e.g. Groq, Gemini, or NVIDIA NIM).

---

## 1. Copy Project to Your Guest OS (VM)

From your host machine, transfer the project folder into your VM:

```bash
# Option A: Using SSH / SCP
scp -r kernel-security-monitor user@<VM_IP>:~/kernel-security-monitor

# Option B: Or copy via shared folder in VirtualBox / VMware / KVM
```

---

## 2. Run the One-Click Deployment Script

Inside your Guest OS terminal:

```bash
cd kernel-security-monitor
chmod +x scripts/deploy_guest_vm.sh
./scripts/deploy_guest_vm.sh
```

This script automatically:
1. Installs `clang`, `bpftool`, `criu`, `libbpf-dev`, `golang`, and `python3`.
2. Sets up the Python virtual environment and installs AI dependencies.
3. Trains the Isolation Forest & Conformal Calibration baseline.
4. Compiles the eBPF kernel C code (`bpf/sensor.o`, `bpf/lsm.o`) and Go binary.

---

## 3. Connecting a Cloud LLM API (NVIDIA / Groq / OpenAI)

If you are using a **Cloud API Key**:

### Option A: Using NVIDIA NIM API
```bash
export LLM_API_KEY="nvapi-your-key"
```

### Option B: Using Groq
```bash
export LLM_API_KEY="gsk_your_groq_api_key"
```

*(If no cloud API key or Ollama is available, Kernel Security Monitor will automatically use its built-in fallback system without failing).*

---

## 4. Starting Kernel Security Monitor Inside Your VM

### Terminal 1: Start the Python ML Scorer Sidecar
```bash
source .venv/bin/activate
make sidecar
```
*(Runs on `http://127.0.0.1:8099`)*

---

### Terminal 2: Start the Kernel Security Monitor
```bash
# Standard mode (with BPF-LSM blocking & Dashboard on port 8080):
sudo ./kernel-security-monitor --listen :8080

# Or with CRIU sandbox verify enabled:
sudo ./kernel-security-monitor --listen :8080 --enable-criu
```

---

## 5. Accessing the Dashboard from Your Host Browser

To view the interactive D3.js security dashboard from your laptop's browser:
* Find your VM's IP address: `ip a`
* In your browser, open: **`http://<VM_IP>:8080`** (or `http://localhost:8080` if using port forwarding).

---

## 6. Running a Demo Attack Simulation

In a 3rd VM terminal:
```bash
sudo bash scripts/demo_attack.sh
```
Watch the live D3 graph turn red, the trust score drop to `0/100`, and the autonomous mitigation activate!
