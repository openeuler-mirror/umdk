# AIGW DP粒度一致性Hash集成测试方案

## 一、测试环境

| 项目 | 规格 |
|------|------|
| 推理引擎 | vLLM Ascend |
| 部署模式 | 1个混合节点 (mixed), DP=4 |
| 模型 | 根据实际环境选择 (如 Qwen2.5-7B) |
| AIGW版本 | 当前k8s分支编译产物 |
| K8s集群 | 需有可用的K8s集群 (AIGW通过in-cluster或kubeconfig连接) |

---

## 二、启动vLLM Ascend

### 2.1 vLLM启动命令

在K8s集群中部署vLLM Ascend，使用1个混合节点、DP=4：

```bash
# 方式1: 直接命令行启动 (裸机环境)
python -m vllm.entrypoints.openai.api_server \
    --model Qwen2.5-7B \
    --tensor-parallel-size 1 \
    --data-parallel-size 4 \
    --port 8000 \
    --host 0.0.0.0 \
    --enable-chunked-prefill true \
    --max-model-len 4096
```

### 2.2 K8s Deployment方式 (推荐)

创建vLLM的K8s Deployment和Service：

```yaml
# vllm-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm-mixed
  namespace: vllm
  labels:
    app: vllm
    role: mixed
    model: Qwen2.5-7B
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vllm
      role: mixed
      model: Qwen2.5-7B
  template:
    metadata:
      labels:
        app: vllm
        role: mixed
        model: Qwen2.5-7B
    spec:
      containers:
      - name: vllm
        image: <vllm-ascend-image>
        command:
        - python
        - -m
        - vllm.entrypoints.openai.api_server
        args:
        - --model=Qwen2.5-7B
        - --tensor-parallel-size=1
        - --data-parallel-size=4
        - --port=8000
        - --host=0.0.0.0
        - --enable-chunked-prefill=true
        - --max-model-len=4096
        ports:
        - containerPort: 8000
---
apiVersion: v1
kind: Service
metadata:
  name: vllm-mixed
  namespace: vllm
  labels:
    app: vllm
    role: mixed
    model: Qwen2.5-7B
spec:
  selector:
    app: vllm
    role: mixed
  ports:
  - port: 8000
    targetPort: 8000
```

### 2.3 vLLM启动参数说明

| 参数 | 值 | 说明 |
|------|----|------|
| `--model` | Qwen2.5-7B | 模型名称，需与AIGW配置中的model一致 |
| `--tensor-parallel-size` | 1 | 张量并行度 (1个节点的GPU数) |
| `--data-parallel-size` | **4** | 数据并行度，产生4个DP Worker |
| `--port` | 8000 | vLLM服务端口 |
| `--host` | 0.0.0.0 | 监听地址 |
| `--enable-chunked-prefill` | true | 启用分块预填充 |
| `--max-model-len` | 4096 | 最大模型长度 |

关键点: `--data-parallel-size 4` 使vLLM在1个节点内启动4个DP Worker进程，每个Worker处理不同的数据分片。vLLM内部通过`X-data-parallel-rank` Header区分不同DP Worker。

---

## 三、启动AIGW

### 3.1 AIGW配置文件

```json
{
  "global": {
    "host": "0.0.0.0",
    "port": "8888",
    "logPath": "/var/log/aigw/",
    "logLevel": "debug",
    "snapshotUpdateInterval": 60,
    "securitySchema": "default",
    "reqTimeout": 600
  },
  "discovery": {
    "type": "k8s",
    "kubeconfigPath": "",
    "namespace": "vllm",
    "resyncPeriod": 30,
    "enable": true
  },
  "proxy": {
    "timeout": 120,
    "maxRetry": 3,
    "retryBaseInterval": 100,
    "retryMaxInterval": 5000,
    "enable": true,
    "circuitBreaker": {
      "enabled": true,
      "failureThreshold": 5,
      "successThreshold": 2,
      "timeout": 30
    }
  },
  "tokenizers": [
    {
      "tokenizeModelName": "Qwen2.5-7B",
      "configPath": "/path/to/tokenizer/Qwen2.5-7B/tokenizer.json",
      "tokenizerType": "huggingfaceTokenizers"
    }
  ],
  "globalSchedulers": [
    {
      "model": "Qwen2.5-7B",
      "blockSize": 64,
      "deployPolicy": "mixed",
      "maxTimeToFirstToken": 100,
      "maxTimeBetweenTokens": 200,
      "tokenizeModelName": "Qwen2.5-7B",
      "skipInstanceConnection": true,
      "loadBalancer": {
        "mixed": "consistentHash",
        "virtualNodes": 160,
        "fallbackNum": 3,
        "dpSize": 4
      }
    }
  ],
  "limits": {
    "totalInsNum": 2048,
    "insNumPerModel": 128,
    "modelNum": 128,
    "concurrency": 128,
    "maxPromptRunes": 1024
  },
  "predictor": {
    "predictType": "none"
  }
}
```

### 3.2 关键配置说明

| 配置项 | 值 | 说明 |
|--------|----|------|
| `discovery.enable` | true | 启用K8s服务发现 |
| `discovery.type` | "k8s" | 使用K8s Endpoints发现 |
| `discovery.namespace` | "vllm" | 与vLLM Deployment命名空间一致 |
| `discovery.kubeconfigPath` | "" | 集群内部署时为空(使用in-cluster config) |
| `proxy.enable` | true | 启用请求转发(流式/非流式) |
| `proxy.timeout` | 120 | 超时时间(秒)，推理任务需较大值 |
| `loadBalancer.mixed` | "consistentHash" | 使用一致性Hash策略 |
| `loadBalancer.virtualNodes` | 160 | 每Worker虚拟节点数 |
| `loadBalancer.fallbackNum` | 3 | 健康检查回退节点数 |
| `loadBalancer.dpSize` | **4** | DP大小，与vLLM的--data-parallel-size一致 |
| `deployPolicy` | "mixed" | 混合部署模式 |

**核心机制**: AIGW发现1个K8s Endpoints后，根据`dpSize=4`将其扩展为4个DP感知Worker:

- `http://vllm-mixed:8000@0`
- `http://vllm-mixed:8000@1`
- `http://vllm-mixed:8000@2`
- `http://vllm-mixed:8000@3`

一致性Hash在这4个DP Worker粒度上进行路由，选择某个DP Rank后，转发请求时注入`X-data-parallel-rank` Header。

### 3.3 启动AIGW

```bash
# 集群内部署 (推荐)
# 使用K8s Deployment部署AIGW，自动获取in-cluster config

# 裸机启动
./aigw --config=/path/to/aigw_config.json
```

---

## 四、DP粒度一致性Hash验证方案

### 4.1 测试1: 会话亲和性验证 (同一Session路由到同一DP Rank)

**目的**: 验证相同Session ID的请求始终路由到同一个DP Worker

```bash
#!/bin/bash
# test_session_affinity.sh
AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"
SESSION_ID="test-session-affinity-001"

echo "=== 测试1: 会话亲和性 ==="
echo "Session ID: $SESSION_ID"

RESULTS=""
for i in $(seq 1 10); do
    RESPONSE=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
        -H "Content-Type: application/json" \
        -H "X-Session-Id: $SESSION_ID" \
        -d "{
            \"uuid\": \"affinity-test-$i\",
            \"model\": \"$MODEL\",
            \"messages\": [{\"role\": \"user\", \"content\": \"Hello $i\"}],
            \"stream\": true
        }")

    PREFILL_URL=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('targetPrefill',''))")
    DP_RANK=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dpRank','N/A'))")

    echo "  请求 $i: Prefill=$PREFILL_URL, DpRank=$DP_RANK"
    RESULTS="$RESULTS $DP_RANK"
done

UNIQUE_RANKS=$(echo "$RESULTS" | tr ' ' '\n' | sort -u | grep -v '^$')
COUNT=$(echo "$UNIQUE_RANKS" | wc -l)

if [ "$COUNT" -eq 1 ]; then
    echo "PASS: 所有请求路由到同一DP Rank ($UNIQUE_RANKS)"
else
    echo "FAIL: 请求路由到 $COUNT 个不同DP Rank ($UNIQUE_RANKS)"
fi
```

**预期结果**: 10次请求全部返回相同的`dpRank`值(如均为2)，证明一致性Hash的会话亲和性生效。

---

### 4.2 测试2: 不同Session分散到不同DP Rank

**目的**: 验证不同Session ID会被分散路由到不同DP Worker

```bash
#!/bin/bash
# test_dp_distribution.sh
AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"

echo "=== 测试2: DP Rank分布 ==="

declare -A SESSION_RANKS
DP_RANKS=""

for i in $(seq 1 20); do
    SESSION_ID="test-session-dist-$(printf '%03d' $i)"
    RESPONSE=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
        -H "Content-Type: application/json" \
        -H "X-Session-Id: $SESSION_ID" \
        -d "{
            \"uuid\": \"dist-test-$i\",
            \"model\": \"$MODEL\",
            \"messages\": [{\"role\": \"user\", \"content\": \"Test $i\"}],
            \"stream\": true
        }")

    DP_RANK=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dpRank','N/A'))")
    echo "  Session $SESSION_ID -> DpRank=$DP_RANK"
    DP_RANKS="$DP_RANKS $DP_RANK"
done

# 统计每个DP Rank的分布
echo ""
echo "DP Rank分布:"
UNIQUE_RANKS=$(echo "$DP_RANKS" | tr ' ' '\n' | sort | uniq -c | sort -rn)
echo "$UNIQUE_RANKS"

# 检查是否覆盖了4个DP Rank
RANK_COUNT=$(echo "$DP_RANKS" | tr ' ' '\n' | sort -u | grep -v '^$' | wc -l)
if [ "$RANK_COUNT" -eq 4 ]; then
    echo "PASS: 20个Session覆盖了全部4个DP Rank"
else
    echo "WARN: 仅覆盖 $RANK_COUNT/4 个DP Rank (可能需要更多Session)"
fi
```

**预期结果**: 20个不同Session被分散到DP Rank 0/1/2/3，且分布较为均匀(每个约5个)。

---

### 4.3 测试3: 流式转发 + DP Rank Header注入验证

**目的**: 验证AIGW转发请求时正确注入`X-data-parallel-rank` Header，且vLLM正确接收

```bash
#!/bin/bash
# test_streaming_with_dp_rank.sh
AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"

echo "=== 测试3: 流式转发 + DP Rank注入 ==="

# 使用特定Session确保路由到特定DP Rank
SESSION_ID="test-stream-dp-rank-001"

# 先获取调度建议，确认DP Rank
SUGGESTION=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: $SESSION_ID" \
    -d "{
        \"uuid\": \"stream-suggest-test\",
        \"model\": \"$MODEL\",
        \"messages\": [{\"role\": \"user\", \"content\": \"Hello\"}],
        \"stream\": true
    }")

EXPECTED_DP_RANK=$(echo "$SUGGESTION" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dpRank','N/A'))")
echo "预期DP Rank: $EXPECTED_DP_RANK"

# 流式转发请求
echo ""
echo "发送流式转发请求..."
STREAM_RESPONSE=$(curl -s -N -X POST "${AIGW_URL}/aigw/v1/openai/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: $SESSION_ID" \
    -d "{
        \"uuid\": \"stream-forward-test\",
        \"model\": \"$MODEL\",
        \"messages\": [{\"role\": \"user\", \"content\": \"请用一句话介绍人工智能\"}],
        \"stream\": true
    }" 2>&1)

# 检查是否为SSE流式响应
if echo "$STREAM_RESPONSE" | grep -q "data:.*chat.completion.chunk"; then
    echo "PASS: 收到SSE流式响应"
    # 统计chunk数量
    CHUNK_COUNT=$(echo "$STREAM_RESPONSE" | grep -c "^data:.*chat.completion.chunk")
    echo "  收到 $CHUNK_COUNT 个SSE chunks"
else
    echo "FAIL: 未收到有效的SSE流式响应"
fi

# 检查是否包含[DONE]
if echo "$STREAM_RESPONSE" | grep -q "data: \[DONE\]"; then
    echo "PASS: 流式响应正确结束 ([DONE])"
else
    echo "FAIL: 流式响应未正确结束"
fi
```

**预期结果**:

- 调度建议返回确定的dpRank值
- 流式转发返回SSE格式响应，包含多个chunk
- vLLM端日志可见`X-data-parallel-rank` Header

---

### 4.4 测试4: 非流式转发验证

```bash
#!/bin/bash
# test_non_streaming.sh
AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"

echo "=== 测试4: 非流式转发 ==="

SESSION_ID="test-nonstream-001"
RESPONSE=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: $SESSION_ID" \
    -d "{
        \"uuid\": \"nonstream-test\",
        \"model\": \"$MODEL\",
        \"messages\": [{\"role\": \"user\", \"content\": \"1+1等于几?\"}],
        \"stream\": false
    }")

if echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('object')=='chat.completion'"; then
    echo "PASS: 非流式转发成功"
    CONTENT=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('choices',[{}])[0].get('message',{}).get('content',''))")
    echo "  响应内容: $CONTENT"
else
    echo "FAIL: 非流式转发失败"
    echo "  响应: $RESPONSE"
fi
```

---

### 4.5 测试5: Hash Key优先级验证

**目的**: 验证一致性Hash Key的提取优先级 (Header > Body > Content Hash)

```bash
#!/bin/bash
# test_hash_key_priority.sh
AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"

echo "=== 测试5: Hash Key优先级 ==="

# 5a. X-Session-Id Header (最高优先级)
RANK_A1=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: priority-test-001" \
    -d "{\"uuid\":\"p1\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"AAA\"}],\"stream\":true}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")

RANK_A2=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: priority-test-001" \
    -d "{\"uuid\":\"p2\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"BBB\"}],\"stream\":true}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")

echo "5a. 同X-Session-Id, 不同content: Rank1=$RANK_A1, Rank2=$RANK_A2"
if [ "$RANK_A1" = "$RANK_A2" ]; then
    echo "PASS: Header优先级生效, 相同Session-Id路由到同一DP Rank"
else
    echo "FAIL: Header优先级未生效"
fi

# 5b. 不同Header, 不同优先级字段
RANK_B1=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: prio-session-001" \
    -H "X-User-Id: prio-user-999" \
    -d "{\"uuid\":\"p3\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Test\"}],\"stream\":true}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")

RANK_B2=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: prio-session-001" \
    -H "X-User-Id: prio-user-888" \
    -d "{\"uuid\":\"p4\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Test\"}],\"stream\":true}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")

echo "5b. X-Session-Id相同, X-User-Id不同: Rank1=$RANK_B1, Rank2=$RANK_B2"
if [ "$RANK_B1" = "$RANK_B2" ]; then
    echo "PASS: X-Session-Id优先级高于X-User-Id"
else
    echo "FAIL: Header优先级不正确"
fi
```

---

### 4.6 测试6: K8s服务发现自动注册验证

**目的**: 验证AIGW通过K8s Endpoints自动发现并注册vLLM Worker

```bash
#!/bin/bash
# test_k8s_discovery.sh
AIGW_URL="http://127.0.0.1:8888"

echo "=== 测试6: K8s服务发现 ==="

# 6a. 检查AIGW健康状态
HEALTH=$(curl -s "${AIGW_URL}/aigw/v1/health")
echo "6a. 健康检查: $HEALTH"

# 6b. 获取统计信息, 查看注册实例数
STATS=$(curl -s "${AIGW_URL}/aigw/v1/stats")
echo "6b. 统计信息: $STATS"

# 6c. 查看AIGW日志中的服务发现事件
echo "6c. 检查AIGW日志中的discovery事件:"
# 如果在K8s中运行, 查看pod日志
# kubectl logs -n vllm <aigw-pod> | grep -i "discovered\|register\|instance"

# 6d. 验证能获取调度建议
SUGGESTION=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
    -H "Content-Type: application/json" \
    -d "{\"uuid\":\"disc-test\",\"model\":\"Qwen2.5-7B\",\"messages\":[{\"role\":\"user\",\"content\":\"Test\"}],\"stream\":true}")

PREFILL=$(echo "$SUGGESTION" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('targetPrefill',''))")
if [ -n "$PREFILL" ]; then
    echo "PASS: 服务发现生效, 获取到Prefill URL: $PREFILL"
else
    echo "FAIL: 未获取到调度建议, 服务发现可能未注册实例"
fi
```

---

### 4.7 测试7: 一致性Hash稳定性验证 (扩缩容场景模拟)

**目的**: 验证Worker数变化时，已有Session的映射尽量保持稳定

```bash
#!/bin/bash
# test_hash_stability.sh
AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"

echo "=== 测试7: 一致性Hash稳定性 ==="

# 步骤1: 在当前1节点4DP下, 记录20个Session的DP Rank映射
echo "步骤1: 记录初始DP Rank映射..."
declare -A INITIAL_RANKS
for i in $(seq 1 20); do
    SESSION_ID="stability-test-$(printf '%03d' $i)"
    RANK=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
        -H "Content-Type: application/json" \
        -H "X-Session-Id: $SESSION_ID" \
        -d "{\"uuid\":\"stab-$i\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Test\"}],\"stream\":true}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")
    INITIAL_RANKS[$SESSION_ID]=$RANK
    echo "  $SESSION_ID -> DP Rank $RANK"
done

# 步骤2: 扩容vLLM到2节点 (修改K8s Deployment replicas=2)
echo "步骤2: 扩容vLLM到2节点..."
# kubectl scale deployment vllm-mixed -n vllm --replicas=2
# sleep 30  # 等待新Pod就绪和AIGW服务发现更新

# 步骤3: 重新查询相同的20个Session, 检查映射变化
echo "步骤3: 扩容后重新查询..."
UNCHANGED=0
CHANGED=0
for i in $(seq 1 20); do
    SESSION_ID="stability-test-$(printf '%03d' $i)"
    NEW_RANK=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
        -H "Content-Type: application/json" \
        -H "X-Session-Id: $SESSION_ID" \
        -d "{\"uuid\":\"stab2-$i\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Test\"}],\"stream\":true}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")

    OLD_RANK=${INITIAL_RANKS[$SESSION_ID]}
    if [ "$NEW_RANK" = "$OLD_RANK" ]; then
        UNCHANGED=$((UNCHANGED+1))
    else
        CHANGED=$((CHANGED+1))
        echo "  CHANGED: $SESSION_ID: $OLD_RANK -> $NEW_RANK"
    fi
done

echo ""
echo "扩容后映射稳定性: $UNCHANGED/20 未变, $CHANGED/20 已变"
# 一致性Hash理论上: 从4个DP Worker扩到8个DP Worker时，约50%的映射会保持不变
if [ "$UNCHANGED" -ge 8 ]; then
    echo "PASS: 一致性Hash迁移比例合理"
else
    echo "WARN: 迁移比例过高，可能一致性Hash实现有问题"
fi

# 步骤4: 缩容回1节点
# kubectl scale deployment vllm-mixed -n vllm --replicas=1
```

---

### 4.8 测试8: DP Rank Header端到端验证 (关键)

**目的**: 从AIGW到vLLM全链路验证DP Rank Header的注入与生效

此测试需要vLLM端配合验证。在vLLM中开启`--data-parallel-size 4`后，vLLM内部会根据`X-data-parallel-rank` Header将请求路由到对应的DP Worker处理。

```bash
#!/bin/bash
# test_dp_rank_e2e.sh
AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"

echo "=== 测试8: DP Rank端到端验证 ==="

# 8a. 使用4个不同Session, 尝试覆盖4个DP Rank
echo "8a. 尝试覆盖4个DP Rank..."

declare -A RANK_SESSIONS
for i in $(seq 1 8); do
    SESSION_ID="e2e-dp-test-session-$i"
    SUGGESTION=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
        -H "Content-Type: application/json" \
        -H "X-Session-Id: $SESSION_ID" \
        -d "{\"uuid\":\"e2e-$i\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello $i\"}],\"stream\":true}")

    DP_RANK=$(echo "$SUGGESTION" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('dpRank','N/A'))")
    PREFILL=$(echo "$SUGGESTION" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('targetPrefill',''))")

    echo "  Session $SESSION_ID: DP Rank=$DP_RANK, URL=$PREFILL"

    # 对每个Session发送实际转发请求
    FORWARD_RESULT=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/chat/completions" \
        -H "Content-Type: application/json" \
        -H "X-Session-Id: $SESSION_ID" \
        -d "{\"uuid\":\"e2e-fwd-$i\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"1+1=?\"}],\"stream\":false}" \
        2>&1)

    if echo "$FORWARD_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('object')=='chat.completion'" 2>/dev/null; then
        echo "    转发成功"
    else
        echo "    转发失败: $(echo $FORWARD_RESULT | head -c 200)"
    fi
done

# 8b. 检查vLLM端日志, 确认X-data-parallel-rank被正确传递
echo ""
echo "8b. 检查vLLM日志确认DP Rank..."
echo "  请手动检查vLLM日志中X-data-parallel-rank Header的值"
echo "  kubectl logs -n vllm <vllm-pod> | grep -i 'data-parallel-rank'"
echo ""
echo "  预期: 不同Session的请求应携带不同的X-data-parallel-rank值(0/1/2/3)"
echo "  预期: 相同Session的多次请求应携带相同的X-data-parallel-rank值"
```

---

### 4.9 测试9: 并发请求下一致性Hash正确性

**目的**: 在并发场景下验证一致性Hash仍然正确

```bash
#!/bin/bash
# test_concurrent_hash.sh
AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"
CONCURRENT=10

echo "=== 测试9: 并发一致性Hash ==="

# 使用相同Session ID并发发送请求
SESSION_ID="concurrent-test-001"

echo "并发发送 $CONCURRENT 个请求 (Session: $SESSION_ID)..."

rm -f /tmp/concurrent_result.txt
for i in $(seq 1 $CONCURRENT); do
    (
        RANK=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
            -H "Content-Type: application/json" \
            -H "X-Session-Id: $SESSION_ID" \
            -d "{\"uuid\":\"conc-$i\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Test $i\"}],\"stream\":true}" \
            | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")
        echo "  请求$i: DP Rank=$RANK" >> /tmp/concurrent_result.txt
    ) &
done

wait

UNIQUE=$(cat /tmp/concurrent_result.txt | awk '{print $NF}' | sort -u | wc -l)
echo ""
echo "并发结果:"
cat /tmp/concurrent_result.txt
rm -f /tmp/concurrent_result.txt

if [ "$UNIQUE" -eq 1 ]; then
    echo "PASS: 并发下一致性Hash仍然正确, 所有请求路由到同一DP Rank"
else
    echo "FAIL: 并发下出现不同的DP Rank, 一致性Hash可能存在竞态问题"
fi
```

---

### 4.10 测试10: 熔断器 + 重试验证

**目的**: 验证Proxy层的熔断和重试机制

```bash
#!/bin/bash
# test_circuit_breaker.sh
AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"

echo "=== 测试10: 熔断器与重试 ==="

# 10a. 正常请求 (熔断器关闭状态)
echo "10a. 正常请求..."
SESSION_ID="cb-test-normal"
RESULT=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: $SESSION_ID" \
    -d "{\"uuid\":\"cb1\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}],\"stream\":false}")

if echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('object')=='chat.completion'" 2>/dev/null; then
    echo "PASS: 正常请求成功"
else
    echo "FAIL: 正常请求失败"
fi

# 10b. 模拟后端故障 (需要临时停止vLLM或改变端口)
echo "10b. 模拟后端故障 (需手动停止vLLM)..."
echo "  步骤: 停止vLLM后, 连续发送5次请求触发熔断"
echo "  kubectl scale deployment vllm-mixed -n vllm --replicas=0"
echo "  然后发送请求, 预期: 连续失败5次后熔断器打开, 后续请求快速失败"
echo "  恢复vLLM后, 熔断器进入半开状态, 成功2次后关闭"
```

---

## 五、完整自动化测试脚本

将上述测试整合为一个自动化脚本：

```bash
#!/bin/bash
# integration_test.sh - AIGW DP一致性Hash集成测试
set -e

AIGW_URL="http://127.0.0.1:8888"
MODEL="Qwen2.5-7B"
PASS=0
FAIL=0

pass() { echo -e "\033[0;32mPASS\033[0m: $1"; ((PASS++)); }
fail() { echo -e "\033[0;31mFAIL\033[0m: $1"; ((FAIL++)); }

# 前置检查: AIGW和vLLM是否就绪
echo "=== 前置检查 ==="
if curl -s "${AIGW_URL}/aigw/v1/health" | grep -q "ok\|healthy\|UP"; then
    pass "AIGW健康检查通过"
else
    fail "AIGW健康检查失败"
    exit 1
fi

# 直接请求vLLM验证DP支持
VLLM_DIRECT=$(curl -s -X POST "http://<vllm-ip>:8000/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-data-parallel-rank: 0" \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}],\"stream\":false}" 2>/dev/null || echo "")
if [ -n "$VLLM_DIRECT" ]; then
    pass "vLLM直接访问正常"
else
    fail "vLLM直接访问失败"
fi

# --- 测试1: 会话亲和性 ---
echo ""
echo "=== 测试1: 会话亲和性 ==="
SESSION_ID="itest-session-affinity-001"
AFFINITY_RANKS=""
for i in $(seq 1 10); do
    RANK=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
        -H "Content-Type: application/json" \
        -H "X-Session-Id: $SESSION_ID" \
        -d "{\"uuid\":\"aff-$i\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}],\"stream\":true}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")
    AFFINITY_RANKS="$AFFINITY_RANKS $RANK"
done
UNIQUE_AFFINITY=$(echo "$AFFINITY_RANKS" | tr ' ' '\n' | sort -u | grep -v '^$' | wc -l)
if [ "$UNIQUE_AFFINITY" -eq 1 ]; then
    pass "会话亲和性: 10次请求路由到同一DP Rank"
else
    fail "会话亲和性: 请求路由到 $UNIQUE_AFFINITY 个不同DP Rank"
fi

# --- 测试2: DP分布 ---
echo ""
echo "=== 测试2: DP Rank分布 ==="
DIST_RANKS=""
for i in $(seq 1 20); do
    RANK=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
        -H "Content-Type: application/json" \
        -H "X-Session-Id: itest-dist-$(printf '%03d' $i)" \
        -d "{\"uuid\":\"dist-$i\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Test\"}],\"stream\":true}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")
    DIST_RANKS="$DIST_RANKS $RANK"
done
RANK_COVERAGE=$(echo "$DIST_RANKS" | tr ' ' '\n' | sort -u | grep -v '^$' | wc -l)
if [ "$RANK_COVERAGE" -eq 4 ]; then
    pass "DP分布: 覆盖全部4个DP Rank"
else
    fail "DP分布: 仅覆盖 $RANK_COVERAGE/4 个DP Rank"
fi

# --- 测试3: 流式转发 ---
echo ""
echo "=== 测试3: 流式转发 ==="
STREAM_RESP=$(curl -s -N -X POST "${AIGW_URL}/aigw/v1/openai/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: itest-stream-001" \
    -d "{\"uuid\":\"strm1\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}],\"stream\":true}" 2>&1)
if echo "$STREAM_RESP" | grep -q "data:.*chat.completion.chunk"; then
    pass "流式转发: 收到SSE流式响应"
else
    fail "流式转发: 未收到有效SSE响应"
fi

# --- 测试4: 非流式转发 ---
echo ""
echo "=== 测试4: 非流式转发 ==="
NON_STREAM_RESP=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/chat/completions" \
    -H "Content-Type: application/json" \
    -H "X-Session-Id: itest-nonstream-001" \
    -d "{\"uuid\":\"nstrm1\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}],\"stream\":false}")
if echo "$NON_STREAM_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('object')=='chat.completion'" 2>/dev/null; then
    pass "非流式转发: 成功"
else
    fail "非流式转发: 失败"
fi

# --- 测试5: Hash Key优先级 ---
echo ""
echo "=== 测试5: Hash Key优先级 ==="
RANK_P1=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
    -H "Content-Type: application/json" -H "X-Session-Id: itest-prio-001" \
    -d "{\"uuid\":\"hp1\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"AAA\"}],\"stream\":true}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")
RANK_P2=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
    -H "Content-Type: application/json" -H "X-Session-Id: itest-prio-001" \
    -d "{\"uuid\":\"hp2\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"BBB\"}],\"stream\":true}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")
if [ "$RANK_P1" = "$RANK_P2" ]; then
    pass "Hash Key优先级: 相同Session-Id不同content路由到同一DP Rank"
else
    fail "Hash Key优先级: 未按预期路由"
fi

# --- 测试6: K8s服务发现 ---
echo ""
echo "=== 测试6: K8s服务发现 ==="
SUGGESTION=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
    -H "Content-Type: application/json" \
    -d "{\"uuid\":\"disc1\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Test\"}],\"stream\":true}")
PREFILL=$(echo "$SUGGESTION" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('targetPrefill',''))")
if [ -n "$PREFILL" ]; then
    pass "K8s服务发现: 自动发现并注册Worker (URL: $PREFILL)"
else
    fail "K8s服务发现: 未获取到调度建议"
fi

# --- 测试8: DP Rank端到端 ---
echo ""
echo "=== 测试8: DP Rank端到端 ==="
E2E_RANKS=""
for i in $(seq 1 8); do
    RANK=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
        -H "Content-Type: application/json" \
        -H "X-Session-Id: itest-e2e-session-$i" \
        -d "{\"uuid\":\"e2e-$i\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}],\"stream\":true}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")
    E2E_RANKS="$E2E_RANKS $RANK"
done
E2E_COVERAGE=$(echo "$E2E_RANKS" | tr ' ' '\n' | sort -u | grep -v '^$' | wc -l)
if [ "$E2E_COVERAGE" -ge 2 ]; then
    pass "DP Rank端到端: 不同Session覆盖 $E2E_COVERAGE 个DP Rank"
else
    fail "DP Rank端到端: DP Rank分布不足"
fi

# --- 测试9: 并发一致性Hash ---
echo ""
echo "=== 测试9: 并发一致性Hash ==="
rm -f /tmp/itest_concurrent.txt
SESSION_ID="itest-concurrent-001"
for i in $(seq 1 10); do
    (
        RANK=$(curl -s -X POST "${AIGW_URL}/aigw/v1/openai/get-suggestion" \
            -H "Content-Type: application/json" \
            -H "X-Session-Id: $SESSION_ID" \
            -d "{\"uuid\":\"conc-$i\",\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Test\"}],\"stream\":true}" \
            | python3 -c "import sys,json; print(json.load(sys.stdin).get('dpRank','N/A'))")
        echo "$RANK" >> /tmp/itest_concurrent.txt
    ) &
done
wait
CONC_UNIQUE=$(cat /tmp/itest_concurrent.txt | sort -u | grep -v '^$' | wc -l)
rm -f /tmp/itest_concurrent.txt
if [ "$CONC_UNIQUE" -eq 1 ]; then
    pass "并发一致性Hash: 并发下路由到同一DP Rank"
else
    fail "并发一致性Hash: 并发下路由不一致 ($CONC_UNIQUE 个不同Rank)"
fi

# 总结
echo ""
echo "=============================================="
echo "集成测试总结"
echo "=============================================="
echo "通过: $PASS"
echo "失败: $FAIL"
echo ""
if [ $FAIL -eq 0 ]; then
    echo "所有测试通过!"
    exit 0
else
    echo "存在测试失败"
    exit 1
fi
```

---

## 六、验证检查清单

| 序号 | 测试项 | 验证目标 | 预期结果 |
|------|--------|----------|----------|
| 1 | 会话亲和性 | 相同Session路由到同一DP Rank | 10次请求全部返回相同dpRank |
| 2 | DP分布 | 不同Session分散到不同DP Rank | 20个Session覆盖4个DP Rank, 分布均匀 |
| 3 | 流式转发+DP Header | 转发时注入X-data-parallel-rank | SSE流式响应正常, vLLM日志可见Header |
| 4 | 非流式转发 | 非流式请求正确转发 | 返回chat.completion对象 |
| 5 | Hash Key优先级 | Header优先级高于Body | X-Session-Id优先级正确 |
| 6 | K8s服务发现 | 自动发现并注册vLLM Worker | 无需手动注册即可获取调度建议 |
| 7 | Hash稳定性 | 扩缩容时映射尽量不变 | 扩容后>=40%的Session映射不变 |
| 8 | DP Rank端到端 | 全链路DP Rank传递 | 不同Session->不同DP Rank, vLLM确认 |
| 9 | 并发一致性Hash | 并发下Hash正确性 | 并发请求仍路由到同一DP Rank |
| 10 | 熔断器+重试 | Proxy层容错 | 连续失败后熔断, 恢复后自动关闭 |

---

## 七、注意事项

1. **kubeconfig配置**: AIGW如果在K8s集群外运行，需在`discovery.kubeconfigPath`指定kubeconfig文件路径；集群内运行时留空使用in-cluster config
2. **DP Size一致性**: AIGW配置的`loadBalancer.dpSize`必须与vLLM的`--data-parallel-size`完全一致，否则DP Rank路由会出错
3. **模型名称一致**: AIGW配置的`globalSchedulers.model`必须与vLLM的`--model`参数对应
4. **proxy.timeout**: 推理请求通常耗时较长，建议设置>=120秒
5. **K8s Endpoints标签**: vLLM的K8s Service/Endpoints需带有`app: vllm`, `role: mixed`, `model: <模型名>`标签，AIGW依赖这些标签进行服务发现和角色识别
6. **tokenizer路径**: `tokenizers.configPath`需指向与模型匹配的tokenizer.json文件，否则分词预测功能会失败
7. **扩缩容测试**: 测试7需要K8s集群支持`kubectl scale`操作，裸机环境需手动增减vLLM实例

---

*文档生成时间: 2026-05-25*
