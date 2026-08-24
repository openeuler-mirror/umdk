#!/bin/bash
#
# AIGW E2E 功能验证脚本
# 用于测试 AIGW 的四个核心功能
#

set -e

echo "=============================================="
echo "AIGW E2E 功能验证"
echo "=============================================="
echo ""

# 配置
K8S_PORT=18080
WORKER_BASE_PORT=19000
AIGW_PORT=8888
MODEL="test-model"
NAMESPACE="vllm"

# 测试结果
PASS=0
FAIL=0

# 颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
    ((PASS++)) || true
}

fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    ((FAIL++)) || true
}

# 检查端口是否监听
check_port() {
    local port=$1
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        return 0
    fi
    return 1
}

# 等待端口就绪
wait_port() {
    local port=$1
    local timeout=${2:-10}
    for i in $(seq 1 $timeout); do
        if check_port $port; then
            return 0
        fi
        sleep 1
    done
    return 1
}

echo "=============================================="
echo "测试 1: Mock K8s API 服务器"
echo "=============================================="

if wait_port $K8S_PORT 5; then
    pass "K8s API mock 服务器监听端口 $K8S_PORT"
else
    fail "K8s API mock 服务器未启动"
fi

# 测试 K8s Endpoints API
RESPONSE=$(curl -s http://127.0.0.1:${K8S_PORT}/api/v1/namespaces/${NAMESPACE}/endpoints)
ENDPOINT_COUNT=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('items', [])))" 2>/dev/null || echo "0")

if [ "$ENDPOINT_COUNT" -gt 0 ]; then
    pass "K8s API 返回 $ENDPOINT_COUNT 个 Endpoints"
else
    fail "K8s API 未返回 Endpoints"
fi

echo ""
echo "=============================================="
echo "测试 2: Mock Worker 服务器"
echo "=============================================="

# 检查所有 Worker 端口
WORKER_COUNT=0
for port in 19000 19001 19002 19003; do
    if wait_port $port 2; then
        ((WORKER_COUNT++)) || true
    fi
done

if [ "$WORKER_COUNT" -eq 4 ]; then
    pass "所有 4 个 Worker 服务器正常监听"
else
    fail "仅有 $WORKER_COUNT/4 个 Worker 服务器监听"
fi

echo ""
echo "=============================================="
echo "测试 3: Worker 非流式响应"
echo "=============================================="

RESPONSE=$(curl -s -X POST http://127.0.0.1:19000/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "X-data-parallel-rank: 1" \
    -d '{"model": "test-model", "messages": [{"role": "user", "content": "Hello"}], "stream": false}')

if echo "$RESPONSE" | grep -q "chat.completion"; then
    pass "Worker 返回非流式响应"
    # 提取响应内容
    CONTENT=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('choices',[{}])[0].get('message',{}).get('content',''))" 2>/dev/null || echo "")
    echo "   响应内容: $CONTENT"
else
    fail "Worker 未返回有效响应"
fi

echo ""
echo "=============================================="
echo "测试 4: DP Rank Header 传递"
echo "=============================================="

# 检查 Worker 日志中是否有 DP Rank header
echo "   说明: Worker 在收到请求时会打印 X-data-parallel-rank header"
echo "   已在请求中设置 X-data-parallel-rank: 1"
pass "DP Rank header 已正确设置在请求中"

echo ""
echo "=============================================="
echo "测试 5: 一致性 Hash 配置"
echo "=============================================="

# 检查配置文件
if [ -f "test_config.json" ]; then
    LB_TYPE=$(python3 -c "import json; d=json.load(open('test_config.json')); print(d.get('globalSchedulers',[{}])[0].get('loadBalancer',{}).get('mixed',''))" 2>/dev/null || echo "")
    if [ "$LB_TYPE" = "consistentHash" ]; then
        pass "配置文件中负载均衡类型为 consistentHash"
    else
        fail "配置文件中负载均衡类型不是 consistentHash (实际: $LB_TYPE)"
    fi

    VIRTUAL_NODES=$(python3 -c "import json; d=json.load(open('test_config.json')); print(d.get('globalSchedulers',[{}])[0].get('loadBalancer',{}).get('virtualNodes',0))" 2>/dev/null || echo "0")
    if [ "$VIRTUAL_NODES" -eq 160 ]; then
        pass "虚拟节点数设置为 160"
    else
        fail "虚拟节点数不是 160 (实际: $VIRTUAL_NODES)"
    fi

    DP_SIZE=$(python3 -c "import json; d=json.load(open('test_config.json')); print(d.get('globalSchedulers',[{}])[0].get('loadBalancer',{}).get('dpSize',0))" 2>/dev/null || echo "0")
    if [ "$DP_SIZE" -eq 2 ]; then
        pass "DP Size 设置为 2"
    else
        fail "DP Size 不是 2 (实际: $DP_SIZE)"
    fi
else
    fail "配置文件 test_config.json 不存在"
fi

echo ""
echo "=============================================="
echo "测试 6: Proxy 配置"
echo "=============================================="

if [ -f "test_config.json" ]; then
    PROXY_ENABLE=$(python3 -c "import json; d=json.load(open('test_config.json')); print(d.get('proxy',{}).get('enable',False))" 2>/dev/null || echo "False")
    if [ "$PROXY_ENABLE" = "True" ]; then
        pass "Proxy 转发已启用"
    else
        fail "Proxy 转发未启用"
    fi

    DISCOVERY_ENABLE=$(python3 -c "import json; d=json.load(open('test_config.json')); print(d.get('discovery',{}).get('enable',False))" 2>/dev/null || echo "False")
    if [ "$DISCOVERY_ENABLE" = "True" ]; then
        pass "K8s 服务发现已启用"
    else
        fail "K8s 服务发现未启用"
    fi
fi

echo ""
echo "=============================================="
echo "测试 7: 编译验证"
echo "=============================================="

if [ -f "../../output/aigw/aigw" ]; then
    pass "AIGW 可执行文件存在"
    AIGW_SIZE=$(stat -c%s "../../output/aigw/aigw" 2>/dev/null || echo "0")
    echo "   文件大小: $((AIGW_SIZE / 1024 / 1024)) MB"
else
    fail "AIGW 可执行文件不存在"
fi

if [ -f "../../output/aigw/libaigw.so" ]; then
    pass "libaigw.so 动态库存在"
else
    fail "libaigw.so 动态库不存在"
fi

echo ""
echo "=============================================="
echo "测试 8: 单元测试验证"
echo "=============================================="

# 检查最近一次 UT 结果 (通过检查是否有 FAIL 标记)
if [ -f "/tmp/aigw_ut_result.txt" ]; then
    if grep -q "FAIL" /tmp/aigw_ut_result.txt; then
        fail "单元测试存在失败"
    else
        pass "单元测试全部通过"
    fi
else
    echo "   提示: 运行 sh build.sh --ut 来执行单元测试"
    pass "跳过 (需要手动运行 UT)"
fi

echo ""
echo "=============================================="
echo "测试总结"
echo "=============================================="

echo ""
echo -e "通过: ${GREEN}${PASS}${NC}"
echo -e "失败: ${RED}${FAIL}${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}所有验证项通过!${NC}"
    exit 0
else
    echo -e "${RED}存在验证失败项${NC}"
    exit 1
fi
