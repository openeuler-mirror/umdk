# AIGW E2E 测试指南

## 概述

本目录包含用于测试 AIGW 端到端功能的 mock 服务器和测试客户端。

## 文件说明

- `mock_e2e_server.py` - Mock 服务器，模拟 Kubernetes API 和后端 DP Worker
- `test_e2e_client.py` - 测试客户端，测试 AIGW 的调度和转发功能
- `test_config.json` - AIGW 测试配置文件

## 快速开始

### 步骤 1: 启动 Mock 服务器

```bash
# 启动 mock 服务器 (模拟 k8s 和后端 worker)
python3 mock_e2e_server.py \
    --k8s-port 18080 \
    --worker-base-port 19000 \
    --num-workers 2 \
    --dp-size 2 \
    --namespace vllm \
    --model test-model
```

参数说明:
- `--k8s-port`: Mock Kubernetes API 端口 (默认: 18080)
- `--worker-base-port`: Worker 服务器基础端口 (默认: 19000)
- `--num-workers`: 物理服务器数量 (默认: 2)
- `--dp-size`: DP 大小 (默认: 2)
- `--namespace`: K8s 命名空间 (默认: vllm)
- `--model`: 模型名称 (默认: test-model)

### 步骤 2: 启动 AIGW

使用测试配置文件启动 AIGW:

```bash
# 复制测试配置
cp test_config.json /path/to/aigw/config.json

# 启动 AIGW
./aigw
```

### 步骤 3: 运行测试客户端

```bash
# 运行所有测试
python3 test_e2e_client.py \
    --aigw-host 127.0.0.1 \
    --aigw-port 8888 \
    --model test-model
```

## 测试说明

### Mock 服务器功能

1. **Kubernetes API 模拟**
   - 提供 `/api/v1/namespaces/{ns}/endpoints` 端点
   - 返回 DP Worker 的 Endpoints 信息
   - 支持 label selector 过滤

2. **后端 Worker 模拟**
   - 处理 `/v1/chat/completions` 请求
   - 支持 SSE 流式响应
   - 打印收到的 `X-data-parallel-rank` Header

### 测试客户端功能

| 测试项 | 说明 |
|--------|------|
| Health Check | 检查 AIGW 健康状态 |
| Get Suggestion | 测试调度建议获取，包含 DpRank |
| Forward Chat Completion | 测试请求转发和流式响应 |
| Consistent Hash Affinity | 测试一致性 Hash 会话亲和性 |
| DP Rank Injection | 测试 DP Rank Header 注入 |

## 测试配置示例

```json
{
  "global": {
    "host": "127.0.0.1",
    "port": "8888",
    "logLevel": "debug"
  },
  "discovery": {
    "type": "k8s",
    "kubeconfigPath": "",
    "namespace": "vllm",
    "enable": true
  },
  "proxy": {
    "timeout": 30,
    "maxRetry": 3,
    "enable": true
  },
  "globalSchedulers": [{
    "model": "test-model",
    "deployPolicy": "mixed",
    "loadBalancer": {
      "mixed": "consistentHash",
      "virtualNodes": 160,
      "fallbackNum": 3,
      "dpSize": 2
    }
  }]
}
```

## 验证要点

### 1. K8s 服务发现
- AIGW 能够从 Mock K8s API 获取 Endpoints
- 自动注册 DP Worker 实例

### 2. 一致性 Hash
- 相同 `X-Session-Id` 路由到相同 Worker
- 不同 Session ID 可能路由到不同 DP Rank

### 3. DP Worker 支持
- URL 格式: `http://worker:port@rank`
- DP Rank 正确注入到转发请求

### 4. 流式转发
- SSE 流式响应正确处理
- Header 正确透传

## 预期输出示例

### Mock 服务器输出

```
[K8s-Mock] Returning 2 endpoints for namespace vllm
[Worker-prefill-0] Request #1
  DP-Rank Header: 1
  Worker DP-Rank: 0
  Model: test-model
  Stream: True
[Worker-prefill-0] Sent chunk 1/8: [Worker-prefill-0|DP-0]
```

### 测试客户端输出

```
Test 2: Get Scheduling Suggestion
Session ID: test-session-123
Prefill URL: http://127.0.0.1:19000
Decode URL: http://127.0.0.1:19001
DP Rank: 1

Test 4: Consistent Hash Session Affinity
✅ PASS: All requests routed to same worker URL
```

## 故障排查

### 问题: AIGW 无法连接 Mock K8s

检查:
- Mock K8s 服务器是否运行
- AIGW 配置中的 discovery.namespace 是否正确
- 防火墙是否阻止连接

### 问题: 转发请求失败

检查:
- Mock Worker 服务器是否运行
- AIGW 配置中的 proxy.enable 是否为 true
- 查看 AIGW 日志中的错误信息

### 问题: 一致性 Hash 不生效

检查:
- LoadBalancer.mixed 是否设置为 "consistentHash"
- 请求是否包含 X-Session-Id 或其他 Hash Key
