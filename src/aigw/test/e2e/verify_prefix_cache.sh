#!/bin/bash
#
# Prefix Cache Verification Script
#
# Verifies:
# 1. K8s API mock server is running
# 2. Mock workers are running
# 3. AIGW is running with prefix cache config
# 4. Health check responds
# 5. Config has prefix cache LB
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AIGW_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

check() {
    local name="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo -e "  ${GREEN}[PASS]${NC} $name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} $name"
        FAIL=$((FAIL + 1))
    fi
}

echo -e "${YELLOW}Prefix Cache E2E Verification${NC}"
echo ""

# 1. Check K8s mock server
echo "1. K8s API mock server (port 18080):"
lsof -i:18080 >/dev/null 2>&1
check "K8s mock on port 18080" $?

# 2. Check mock workers
echo "2. Mock workers (ports 19000-19003):"
for port in 19000 19001 19002 19003; do
    lsof -i:$port >/dev/null 2>&1
    check "Worker on port $port" $?
done

# 3. Check AIGW
echo "3. AIGW service (port 8701):"
lsof -i:8701 >/dev/null 2>&1
check "AIGW on port 8701" $?

# 4. Health check
echo "4. Health check:"
HEALTH=$(curl -s http://127.0.0.1:8701/aigw/v1/health 2>/dev/null || echo "")
if [ -n "$HEALTH" ]; then
    check "Health endpoint responds" 0
    echo "   Response: $HEALTH"
else
    check "Health endpoint responds" 1
fi

# 5. Config check
echo "5. Config verification:"
if grep -q "prefixCache" "$SCRIPT_DIR/test_config_prefix_cache.json" 2>/dev/null; then
    check "Config has prefixCache LB type" 0
else
    check "Config has prefixCache LB type" 1
fi

if grep -q "AIGW_PREFIX_CACHE_ENABLED" "$SCRIPT_DIR/benchmark_prefix_cache.sh" 2>/dev/null; then
    check "Benchmark script sets prefix cache env vars" 0
else
    check "Benchmark script sets prefix cache env vars" 1
fi

# 6. Check AIGW log for prefix cache initialization
echo "6. AIGW log check:"
if [ -f /tmp/aigw_pc.log ]; then
    if grep -qi "prefixCache" /tmp/aigw_pc.log 2>/dev/null; then
        check "AIGW log shows prefix cache initialization" 0
    else
        check "AIGW log shows prefix cache initialization" 1
        echo "   (prefix cache not found in logs - may need more time to initialize)"
    fi
else
    check "AIGW log file exists" 1
    echo "   (log file /tmp/aigw_pc.log not found)"
fi

# Summary
echo ""
echo -e "${YELLOW}Summary:${NC} $PASS passed, $FAIL failed"

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS] All verification checks passed!${NC}"
else
    echo -e "${RED}[FAIL] Some checks failed${NC}"
fi

exit $FAIL
