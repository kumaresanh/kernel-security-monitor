#!/usr/bin/env bash
# ==============================================================================
# Kernel Security Monitor — One-Click Guest OS (VM) Deployment Script
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo " 🛡️  KERNEL SECURITY MONITOR — GUEST OS / VM SETUP"
echo "=========================================================="
echo ""

# 1. Detect Package Manager and Install Dependencies
echo "[1/5] Installing system packages (clang, bpftool, criu, libbpf)..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update
    sudo apt-get install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic \
                            linux-tools-$(uname -r) criu golang python3 python3-pip python3-venv git curl
elif command -v dnf &>/dev/null; then
    sudo dnf install -y clang llvm libbpf-devel bpftool criu golang python3 python3-pip git curl
elif command -v pacman &>/dev/null; then
    sudo pacman -Syu --noconfirm clang llvm libbpf bpftool criu go python python-pip git curl
else
    echo "[!] Unknown package manager. Please ensure clang, bpftool, criu, and libbpf are installed."
fi

# 2. Check Kernel BTF Support
echo ""
echo "[2/5] Checking Kernel eBPF/BTF Support..."
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "[!] WARNING: /sys/kernel/btf/vmlinux not found."
    echo "    Your VM kernel must support BTF (CONFIG_DEBUG_INFO_BTF=y)."
    echo "    Ubuntu 22.04+/24.04 and Debian 12+ have this enabled by default."
else
    echo "    [✓] Kernel BTF supported!"
fi

# 3. Setup Python Virtual Environment & Dependencies
echo ""
echo "[3/5] Setting up Python ML Sidecar..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r sidecar/requirements.txt

# 4. Train Offline Anomaly Baseline
echo ""
echo "[4/5] Training Isolation Forest & Conformal Baseline..."
cd sidecar
python train_baseline.py
cd ..

# 5. Compile eBPF Programs and Build Go Binary
echo ""
echo "[5/5] Compiling eBPF CO-RE programs and Go Control Plane..."
make generate
make build

echo ""
echo "=========================================================="
echo " ✅ DEPLOYMENT COMPLETE & READY TO RUN!"
echo "=========================================================="
echo ""
echo "To start Kernel Security Monitor in your VM:"
echo "  1. Terminal 1 (Start Python AI Scorer):"
echo "     source .venv/bin/activate && make sidecar"
echo ""
echo "  2. Terminal 2 (Start Monitor Sensor):"
echo "     sudo make run"
echo ""
echo "  3. Open Dashboard in Browser:"
echo "     http://<VM_IP_OR_LOCALHOST>:8080"
echo "=========================================================="
