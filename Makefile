# Kernel Security Monitor — eBPF Verify-Before-Block Intrusion Response
#
# Targets: generate (bpf), build, run, train-baseline, demo, test-criu-loop

CLANG     ?= clang
BPFTOOL   ?= bpftool
GO        ?= go
PYTHON    ?= python3
ARCH      := $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PHONY: all generate build run clean train-baseline demo test-criu-loop sidecar vmlinux

all: generate build

# ---------- vmlinux.h ----------
bpf/vmlinux.h:
	@echo ">>> Generating vmlinux.h via bpftool..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux: bpf/vmlinux.h

# ---------- BPF compilation ----------
bpf/sensor.o: bpf/sensor.c bpf/vmlinux.h
	@echo ">>> Compiling sensor.c..."
	$(CLANG) $(BPF_CFLAGS) -I bpf/ -c $< -o $@

bpf/lsm.o: bpf/lsm.c bpf/vmlinux.h
	@echo ">>> Compiling lsm.c..."
	$(CLANG) $(BPF_CFLAGS) -I bpf/ -c $< -o $@

generate: bpf/sensor.o bpf/lsm.o
	@echo ">>> BPF objects compiled"

# ---------- Go build ----------
build: generate
	@echo ">>> Fetching Go dependencies..."
	$(GO) mod tidy
	@echo ">>> Building kernel-security-monitor..."
	CGO_ENABLED=0 $(GO) build -o kernel-security-monitor ./cmd/sensor/
	@ln -sf kernel-security-monitor ksm

# ---------- Python sidecar ----------
sidecar-deps:
	@echo ">>> Installing Python sidecar dependencies..."
	$(PYTHON) -m pip install -r sidecar/requirements.txt

sidecar: sidecar-deps
	@echo ">>> Starting Python scorer sidecar..."
	cd sidecar && $(PYTHON) scorer.py

# ---------- Training ----------
train-baseline: sidecar-deps
	@echo ">>> Training Isolation Forest + generating calibration scores..."
	cd sidecar && $(PYTHON) train_baseline.py

# ---------- Run ----------
run: build
	@echo ">>> Starting Kernel Security Monitor (requires root for eBPF)..."
	sudo ./kernel-security-monitor \
		--sensor-obj bpf/sensor.o \
		--lsm-obj bpf/lsm.o \
		--data-dir data \
		--listen :8080

run-with-criu: build
	@echo ">>> Starting Kernel Security Monitor with CRIU verify..."
	sudo ./kernel-security-monitor \
		--sensor-obj bpf/sensor.o \
		--lsm-obj bpf/lsm.o \
		--data-dir data \
		--listen :8080 \
		--enable-criu

run-fallback: build
	@echo ">>> Starting Kernel Security Monitor with signal-kill fallback..."
	sudo ./kernel-security-monitor \
		--sensor-obj bpf/sensor.o \
		--lsm-obj bpf/lsm.o \
		--data-dir data \
		--listen :8080 \
		--fallback-signal-kill

# ---------- Demo ----------
demo:
	@echo ">>> Running demo attack scenario..."
	sudo bash scripts/demo_attack.sh

test-criu-loop:
	@echo ">>> Running CRIU flakiness test (10 iterations)..."
	sudo bash scripts/test_criu_loop.sh

# ---------- Clean ----------
clean:
	rm -f kernel-security-monitor ksm bpf/sensor.o bpf/lsm.o bpf/vmlinux.h
	rm -f events.jsonl
	rm -rf /tmp/ksm-criu

# ---------- Full setup ----------
setup: sidecar-deps train-baseline generate build
	@echo ">>> Full setup complete!"
	@echo "    1. Start sidecar:  make sidecar"
	@echo "    2. Start monitor:  make run"
	@echo "    3. Open dashboard: http://localhost:8080"
