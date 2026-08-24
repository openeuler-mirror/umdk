# Design: aigw 前缀缓存特性 ↔ 环境 vLLM 联调打通

- 日期: 2026-08-04
- 状态: Approved
- 关联代码: `internal/prefixcache/`, `internal/gs/prefix_cache_lb.go`, `internal/kvevents/`, `internal/renderclient/`
- 关联环境: 宿主机单 NPU 910B3,两个 vLLM 容器 `vllm-ascend-env`(8081)/`vllm-ascend-env-2`(8080),镜像 `bab0bb869c9c`(vllm-ascend v0.18.0-openeuler),模型 Qwen3.5-9B。

## 1. 目标与非目标

**目标**:把 aigw `internal/prefixcache` + `internal/gs/prefix_cache_lb` + `internal/kvevents` 这条前缀感知路由链路,接到环境里两个 vLLM 实例(8081/8080),端到端跑通:

- 请求经 aigw → aigw 调 vLLM `/v1/chat/completions/render` 拿 `token_ids` → 算前缀 hash 链 → 查 `hash→worker` 表选命中比例最高的 worker → proxy 转发 → KV 复用。
- vLLM 调度时通过 ZMQ:5557 推 `BlockStored/Removed/AllBlocksCleared` 事件 → aigw 实时维护 `hash→worker` 表。

**非目标**:
- 多 NPU 集群负载分散(当前单 NPU 双实例,路由收益有限,仅验证通路)。
- KV offload 到 DRAM、Redis 分布式同步(代码默认关闭,本次不开)。
- 改 vLLM 源码(已验证 stock vLLM 0.18 自带所需能力,无需改)。

## 2. 调查结论(两个原以为的"阻塞项"已证伪)

| 项 | 原判断 | 实测真相 |
|---|---|---|
| tokenize | stock vLLM 不返回 token_ids | **错**。vLLM 0.18 自带 `/v1/chat/completions/render` 与 `/v1/completions/render`,curl 实测返回 `{"token_ids":[...]}`。`RenderResponse.TokenIDs` 的 json tag `token_ids`(`internal/renderclient/types.go:28`)对齐。 |
| KV 事件流 | stock vLLM 不发 aibrix 事件 | **错**。vLLM 0.18 自带 `vllm/distributed/kv_events.py`:ZMQ PUB、默认 `tcp://*:5557`、msgpack、`BlockStored/BlockRemoved/AllBlocksCleared`,与 aigw `internal/kvevents/` 协议完全一致。`vllm/v1/core/sched/scheduler.py:113-139` 证实:仅 `enable_kv_cache_events=true` 即自动实例化 `ZmqEventPublisher`,不需要配 kv_connector。 |

**消息线兼容性已实测**:在容器内编码样本 `BlockStored`,wire 格式为 `['BlockStored', block_hashes, parent_block_hash, token_ids, block_size, lora_id, medium, lora_name, extra_keys]`(None 字段以 msgpack nil `0xc0` 传,**不被 omit**)。aigw `decodeBatch`(`internal/kvevents/client.go:236`)剥 tag、`decodeBlockStored`(`client.go:266`)按位置取 raw[0..4] 且有 `!= nil` 守卫——字段顺序、nil 处理全部对得上。

## 3. 数据流

```
client ─POST /aigw/v1/openai/chat/completions─▶ aigw server
   │
   ├─ prefixCacheLB.schedule()
   │     ├─ renderClient.RenderChat → POST vLLM:8081/v1/chat/completions/render → token_ids
   │     ├─ prefixCacheMgr.MatchPrefix(token_ids) → hash 链查表 → {instance: matchPercent}
   │     └─ selectFromMatched (≥matchThreshold) → PrefillUrl, 否则 fallback leastConn
   │
   ├─ proxy.ForwardRequest → POST PrefillUrl/v1/chat/completions → vLLM 生成
   │
   └─ (并行) vLLM scheduler 每步发 KV 事件:
         ZMQ PUB *:5557 ──[topic, seq, msgpack KVEventBatch]──▶ aigw ZMQClient
              ├─ decodeBatch → BlockStored{block_hashes, parent, token_ids, block_size, lora_id, ...}
              ├─ syncTable.ProcessBlockStored → 用 token_ids 重算 aigw xxhash → 存 hash→instance
              └─ 后续同前缀请求命中
```

## 4. 组件改动

### 4a. vLLM 侧(改启动参数,串行重启两容器)

启动命令在原有基础上追加两项:

```
--block-size 128
--kv-events-config '{"enable_kv_cache_events": true, "publisher": "zmq", "endpoint": "tcp://*:5557", "topic": ""}'
```

- `docker run` 增 `-p 5557:5557`(每容器;若宿主 5557 被占,映射到不同宿主端口并改 aigw 的 endpoint 模板)。
- **block_size 两侧统一为 128**:vLLM `--block-size 128` + aigw `AIGW_PREFIX_CACHE_BLOCK_SIZE=128`。原 vllm-ascend 默认 1024,粒度过粗(共享前缀需整 1024 token 对齐才命中);调到 128 显著提升前缀命中率,代价是 block 数量增多、元数据开销略升(可忽略)。
- 依据:`vllm/v1/core/sched/scheduler.py:113-139`,仅 `enable_kv_cache_events=true` 即自动起 `ZmqEventPublisher`,无需 kv_connector。
- 重启方式:两容器**串行重启**(保 HBM 分配平衡,沿用既有经验)。

### 4b. aigw 侧代码改动(1 处)

`internal/renderclient/adapter.go:90`:

```go
func (a *vllmAdapter) getChatPath() string {
    return "/v1/chat/completions/render"   // 原 "/v1/chat/completions"
}
```

依据:实测 vLLM `/v1/chat/completions/render` 返回 `{"token_ids":[...]}`;`RenderResponse.TokenIDs` json tag `token_ids`(`types.go:28`)对齐;`readSSEResponse`(`client.go:138`)对非流式 JSON 走 EOF 兜底 + `json.Unmarshal`。

> 备选:加 config 字段让路径可配,本次 YAGNI 不做,留 TODO。

### 4c. aigw 配置(`configs/aigw.json` 或环境变量)

| 项 | 值 | 说明 |
|---|---|---|
| `AIGW_PREFIX_CACHE_ENABLED` | `true` | 开 prefix cache 模块 |
| `AIGW_KV_EVENTS_ENABLED` | `true` | 开 ZMQ 订阅器 |
| `AIGW_PREFIX_CACHE_BLOCK_SIZE` | `128` | **必须等于 vLLM `--block-size 128`**,否则 aigw 自算 hash 粒度对不上,永远 0 命中(`internal/prefixcache/hash.go:57`) |
| `AIGW_PREFIX_CACHE_MATCH_THRESHOLD` | `10` | 默认 50 在 128 粒度下仍偏严,先设 10 观察 |
| `globalSchedulers[].model` | `Qwen3.5-9B` | 必须等于 vLLM `--served-model-name` |
| `globalSchedulers[].loadBalancer.mixed` | `"prefixCache"` | 启用前缀感知路由 |
| `globalSchedulers[].blockSize` | `128` | capacity/decode LB 用的 block 字段,与上面保持一致(`internal/base/aigw_type.go:145`) |
| `globalSchedulers[].renderClient.baseURL` | `http://127.0.0.1:8081` | 指向任一 vLLM 的 render 端口(tokenize 无状态,单值即可;每调度器一个 renderClient,不按 worker 分) |
| `AIGW_KV_EVENTS_ENDPOINT_TEMPLATE` | `tcp://{ip}:5557` | 默认值;若宿主端口非 5557 需小改 `internal/kvevents/manager.go:192-198` 的硬编码 |

### 4d. 运行时:worker 注册

对两个 vLLM 实例各发一次 `POST /aigw/v1/register-instance`(body: `instanceIp`/`instancePort`/`name`/`model`/`role=mixed`)。aigw 收到后才 `SubscribeInstance` 去 ZMQ 订阅(`internal/gs/gs_manager.go:411-421`)。

注意:`instancePort` 是 vLLM HTTP 端口(8081/8080,供 proxy 转发),ZMQ 端口独立为 5557(aigw 端硬编码)。

## 5. 关键决策

| 决策 | 选择 | 备选(不选原因) |
|---|---|---|
| tokenize 路径 | 改 `getChatPath()` 一行 | 加 config 字段(YAGNI) |
| block_size | 两侧统一 128,提升前缀命中粒度 | 保持 vllm-ascend 默认 1024(粒度太粗,命中率低) |
| ZMQ 端口 | vLLM 绑 5557 + `-p 5557:5557` | 映射到别的宿主端口(需改 `manager.go:192-198` 硬编码,能避就避) |
| 事件格式 | 直接对接(已实测样本字节流兼容) | 写适配层(无必要) |
| matchThreshold | 先 10 观察 | 默认 50(太严,可能频繁 fallback) |

## 6. 验证(分阶段,逐层)

1. **vLLM 单机**:`curl /v1/chat/completions/render` 仍返回 token_ids(已过);重启后 `docker exec <c> ss -tlnp` 应见 5557 LISTEN;`/metrics` 的 `cache_config_info` block_size 应为 128。
2. **ZMQ 抓包**:临时起 python ZMQ SUB 连 `tcp://127.0.0.1:5557`,发一次 vLLM 请求,确认收到 `['BlockStored', ...]`,block_size=128,字段位置与 `client.go:266` 一致。
3. **aigw tokenize**:起 aigw + 注册 worker,aigw 日志应见 `[render] chat tokenization: tokens=N`。
4. **aigw 订阅**:aigw 日志见 `[kvevents] Starting ZMQ subscriber tcp://...:5557` + `decodeBlockStored: blockSize=128`。
5. **端到端命中**:直连 8081 发 prompt A → 经 aigw 发相同前缀 prompt A' → `vllm:prefix_cache_hits_total` 增长 + aigw 选同一 worker + 二次延迟显著下降。
6. **fallback**:发完全不同 prompt → aigw 走 leastConn fallback,不报错。

## 7. 回滚

- vLLM:去掉 `--block-size 128` + `--kv-events-config` + `-p 5557` 重启(回到当前状态)。
- aigw:还原 `getChatPath()`,配置 `loadBalancer.mixed` 改回 `leastConn`。

## 8. 风险

1. **vllm-ascend 是否接受 `--block-size 128`**:原默认 1024(NPU 大块更高效)。重启时若启动失败或被强制回 1024,需保留 1024 并接受粗粒度命中(调低 matchThreshold 缓解)。
2. **ZMQ 端口硬编码**(`manager.go:192-198`):若 5557 宿主冲突需小改代码。
3. **ExternalBlockHash 类型**:默认 `VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=True` 走 int64,aigw `parseBlockHashes`(`client.go:330`)处理 ✓;若被关走 SHA-256 bytes 也支持,联调时确认。
4. **单 NPU 双实例**:两个 worker 实为同 NPU 两进程,前缀路由的负载分散价值有限,主要验证通路与前缀复用本身。
5. **matchThreshold 调参**:10 是经验起步值,需据实测命中/误命中比再调。
