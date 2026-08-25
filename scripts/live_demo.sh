#!/usr/bin/env bash
# live_demo.sh — Spawns persistent suspicious payloads to test the Dashboard & AI Copilot in real time.
set -euo pipefail

DEMO_DIR="/tmp/ksm-live-demo"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

PAYLOAD_SCRIPT="$DEMO_DIR/c2_backdoor.sh"

echo "======================================================"
echo " 🛡️ KERNEL SECURITY MONITOR — LIVE DASHBOARD TEST"
echo "======================================================"
echo ""
echo "[*] Creating suspicious multi-stage payload: $PAYLOAD_SCRIPT"

# Write the payload script with suspicious sequence (write -> chmod +x -> network socket -> persistence)
cat > "$PAYLOAD_SCRIPT" << 'EOF'
#!/bin/bash
echo "[C2_BACKDOOR] Running payload under PID $$..."

while true; do
    # 1. Suspicious file reads
    cat /etc/passwd > /dev/null 2>&1 || true
    
    # 2. Suspicious file writes in /tmp
    echo "payload_beacon_$(date +%s)" >> /tmp/ksm-live-demo/beacon.log
    
    # 3. Network callback attempt (triggers sys_enter_connect)
    exec 3<>/dev/tcp/198.51.100.1/4444 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    
    # 4. Spawn short helper sub-process
    /bin/sh -c "whoami; uname -a" > /dev/null 2>&1 || true
    
    sleep 2
done
EOF

chmod +x "$PAYLOAD_SCRIPT"

echo "[*] Launching suspicious background process: 'c2_backdoor.sh'..."
"$PAYLOAD_SCRIPT" &
PAYLOAD_PID=$!

echo ""
echo "======================================================"
echo " 🚀 PAYLOAD IS NOW ACTIVE!"
echo "    Process Name : c2_backdoor.sh"
echo "    PID          : $PAYLOAD_PID"
echo "======================================================"
echo ""
echo "👉 Open your Dashboard now at: http://localhost:8080"
echo ""
echo "What you can test in the Dashboard:"
echo " 1. Search for 'c2_backdoor' or PID '$PAYLOAD_PID' in the search bar"
echo " 2. See the Trust Score drop (amber/red alert badge)"
echo " 3. Click the process row to open the [Process Inspector]"
echo " 4. Click [⏸] to freeze it with SIGSTOP (or [💀] to Kill it)"
echo " 5. Ask AI in chat: 'Why is PID $PAYLOAD_PID suspicious?'"
echo ""
echo "Payload will stay alive for 60 seconds (or press CTRL+C to stop)..."

for i in $(seq 60 -1 1); do
    if ! kill -0 "$PAYLOAD_PID" 2>/dev/null; then
        echo ""
        echo "[✅] Process $PAYLOAD_PID was TERMINATED by Kernel Security Monitor / User Action!"
        break
    fi
    printf "\r[Time Remaining: %02d seconds] (PID %d alive)" "$i" "$PAYLOAD_PID"
    sleep 1
done

echo ""
# Cleanup
kill -9 "$PAYLOAD_PID" 2>/dev/null || true
rm -rf "$DEMO_DIR"
echo "Demo finished and cleaned up."
