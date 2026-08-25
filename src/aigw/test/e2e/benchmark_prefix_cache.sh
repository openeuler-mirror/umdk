#!/bin/bash
#
# Prefix Cache E2E Benchmark Script
#
# Orchestrates:
# 1. Start mock K8s API server (port 18080)
# 2. Start mock vLLM workers (ports 19000-19003)
# 3. Start AIGW with prefix cache config
# 4. Run prefix cache test client
# 5. Cleanup
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AIGW_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AIGW_BIN="$AIGW_ROOT/output/aigw/aigw"
CONFIG_FILE="$SCRIPT_DIR/test_config_prefix_cache.json"
MOCK_LOG="/tmp/mock_pc_server.log"
AIGW_LOG="/tmp/aigw_pc.log"
MOCK_PID_FILE="/tmp/mock_pc_server.pid"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    echo -e "\n${YELLOW}Cleanup...${NC}"

    # Stop AIGW
    if [ -n "$AIGW_PID" ] && kill -0 "$AIGW_PID" 2>/dev/null; then
        echo "Stopping AIGW (PID $AIGW_PID)..."
        kill "$AIGW_PID" 2>/dev/null || true
        wait "$AIGW_PID" 2>/dev/null || true
    fi

    # Stop mock servers
    python3 "$SCRIPT_DIR/mock_prefix_cache_server.py" --action stop --pid-file "$MOCK_PID_FILE" 2>/dev/null || true

    # Clean up any remaining processes
    python3 -c "import os, signal; os.kill($MOCK_PID, signal.SIGTERM)" 2>/dev/null || true
    python3 -c "import os, signal; os.kill($AIGW_PID, signal.SIGTERM)" 2>/dev/null || true

    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT INT TERM

# Cleanup before starting
cleanup

# ==========================================
# Step 1: Build AIGW
# ==========================================
echo -e "\n${YELLOW}[1/5] Building AIGW...${NC}"
cd "$AIGW_ROOT"
if [ ! -f "$AIGW_BIN" ]; then
    bash build.sh
    if [ $? -ne 0 ]; then
        echo -e "${RED}[FAIL] Build failed${NC}"
        exit 1
    fi
    echo -e "${GREEN}[PASS] Build successful${NC}"
else
    echo -e "${GREEN}[SKIP] AIGW binary exists: $AIGW_BIN${NC}"
fi

# ==========================================
# Step 2: Start Mock Servers
# ==========================================
echo -e "\n${YELLOW}[2/5] Starting mock servers...${NC}"
python3 "$SCRIPT_DIR/mock_prefix_cache_server.py" --block-size 1 > "$MOCK_LOG" 2>&1 &
MOCK_PID=$!
echo "$MOCK_PID" > "$MOCK_PID_FILE"

# Wait for mock servers to be ready using curl-based health checks
echo "  Waiting for mock servers..."
for port in 18080 19000 19001 19002 19003; do
    for i in $(seq 1 15); do
        if python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$port', timeout=1)" 2>/dev/null; then
            break
        fi
        if [ "$port" = "18080" ]; then
            if curl -s http://127.0.0.1:18080/api/v1/endpoints >/dev/null 2>&1; then
                break
            fi
        fi
        sleep 1
    done
done
echo "  All mock servers ready"

# ==========================================
# Step 3: Start AIGW
# ==========================================
echo -e "\n${YELLOW}[3/5] Starting AIGW with prefix cache config...${NC}"

export AIGW_PREFIX_CACHE_ENABLED="true"
export AIGW_PREFIX_CACHE_BLOCK_SIZE="1"
export AIGW_PREFIX_CACHE_SEED="12345678901234567890"
export AIGW_PREFIX_CACHE_MATCH_THRESHOLD="50"
export AIGW_PREFIX_CACHE_FALLBACK_STRING_MATCHING="true"
export AIGW_KV_EVENTS_ENABLED="true"
export AIGW_KV_EVENTS_TOPIC="kv"
export AIGW_KV_EVENTS_USE_MOCK_PORTS="true"
export GIN_MODE="release"

"$AIGW_BIN" --config="$CONFIG_FILE" > "$AIGW_LOG" 2>&1 &
AIGW_PID=$!

# Wait for AIGW to start
for i in $(seq 1 15); do
    if curl -s http://127.0.0.1:8701/aigw/v1/health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! curl -s http://127.0.0.1:8701/aigw/v1/health >/dev/null 2>&1; then
    echo -e "${RED}[FAIL] AIGW did not start on port 8701${NC}"
    echo "--- Last 20 lines of AIGW log ---"
    tail -20 "$AIGW_LOG"
    exit 1
fi
echo -e "${GREEN}[PASS] AIGW started (PID $AIGW_PID)${NC}"

# ==========================================
# Step 4: Wait for Discovery
# ==========================================
echo -e "\n${YELLOW}[4/5] Waiting for AIGW to discover instances...${NC}"
sleep 5

# Health check
for i in $(seq 1 10); do
    if curl -s http://127.0.0.1:8701/aigw/v1/health >/dev/null 2>&1; then
        echo -e "${GREEN}[PASS] AIGW health check passed${NC}"
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo -e "${YELLOW}[WARN] AIGW health check did not return expected response, but continuing...${NC}"
    fi
    sleep 1
done

# ==========================================
# Step 5: Run Test Client
# ==========================================
echo -e "\n${YELLOW}[5/5] Running prefix cache E2E tests...${NC}"
set +e
python3 "$SCRIPT_DIR/test_prefix_cache_client.py" \
    --aigw-host 127.0.0.1 \
    --aigw-port 8701 \
    --model prefix-cache-test-model
TEST_EXIT=$?
set -e

# ==========================================
# Results
# ==========================================
echo ""
if [ $TEST_EXIT -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS] All prefix cache tests passed!${NC}"
else
    echo -e "${RED}[FAIL] Some prefix cache tests failed (exit code $TEST_EXIT)${NC}"
fi

exit $TEST_EXIT
