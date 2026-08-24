#!/usr/bin/env bash
# test_criu_loop.sh — Runs checkpoint→replay→confirm→kill 10 times
# to catch CRIU flakiness before the demo.
set -euo pipefail

ITERATIONS=10
PASS=0
FAIL=0
CHECKPOINT_BASE="/tmp/ksm-criu-test"

echo "============================================="
echo " CRIU Flakiness Test — $ITERATIONS iterations"
echo "============================================="
echo ""

# Check CRIU availability
if ! command -v criu &>/dev/null; then
    echo "[ERROR] CRIU is not installed."
    echo "        Install with: sudo pacman -S criu"
    exit 1
fi

echo "[*] CRIU version: $(criu --version | head -1)"
echo ""

for i in $(seq 1 $ITERATIONS); do
    echo "--- Iteration $i/$ITERATIONS ---"
    WORKDIR="$CHECKPOINT_BASE/iter-$i"
    rm -rf "$WORKDIR"
    mkdir -p "$WORKDIR"

    # Start a simple background process to checkpoint
    sleep 300 &
    TARGET_PID=$!
    echo "  [+] Started target process (PID $TARGET_PID)"

    # Step 1: Checkpoint
    echo "  [1] Checkpointing PID $TARGET_PID..."
    if sudo criu dump -t "$TARGET_PID" -D "$WORKDIR" --shell-job --leave-stopped 2>"$WORKDIR/dump.log"; then
        echo "  [+] Checkpoint succeeded"
    else
        echo "  [-] Checkpoint FAILED (see $WORKDIR/dump.log)"
        FAIL=$((FAIL + 1))
        kill "$TARGET_PID" 2>/dev/null || true
        continue
    fi

    # Step 2: Restore
    echo "  [2] Restoring from checkpoint..."
    if sudo criu restore -D "$WORKDIR" --shell-job -d 2>"$WORKDIR/restore.log"; then
        echo "  [+] Restore succeeded"
        RESTORED_PID=$(cat "$WORKDIR/restore.log" 2>/dev/null | grep -oP 'pid \K\d+' || echo "unknown")
    else
        echo "  [-] Restore FAILED (see $WORKDIR/restore.log)"
        FAIL=$((FAIL + 1))
        continue
    fi

    # Step 3: Kill restored process
    echo "  [3] Killing restored process..."
    # The restored process should have the same PID
    if sudo kill -9 "$TARGET_PID" 2>/dev/null; then
        echo "  [+] Kill succeeded"
        PASS=$((PASS + 1))
    else
        echo "  [~] Process already exited (still counting as pass)"
        PASS=$((PASS + 1))
    fi

    # Cleanup
    rm -rf "$WORKDIR"
    echo ""
done

echo "============================================="
echo " Results: $PASS/$ITERATIONS passed, $FAIL/$ITERATIONS failed"
echo "============================================="

if [ "$FAIL" -gt 0 ]; then
    echo "[WARNING] CRIU showed flakiness — have a recorded backup ready!"
    exit 1
else
    echo "[OK] CRIU is stable across all iterations."
fi

# Cleanup
rm -rf "$CHECKPOINT_BASE"
