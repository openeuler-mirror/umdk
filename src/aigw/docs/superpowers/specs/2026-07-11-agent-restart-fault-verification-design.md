# Agent 重启故障验证方案设计

**日期**：2026-07-11
**状态**：待评审
**目标**：在 agent 故障恢复场景，使用自造 terminal 风格任务，验证关闭 AIGW（基线）与开启 AIGW KVC 管理功能，对比 KVC 管理特性所带来的性能收益。

## 验证部署架构

- **agent 层** => 多个 Agent（最小 ReAct agent），每个 agent 一个 session，每个 session 跑一个推理任务
- **aigw** => session 管理，hints 构建（告诉 vLLM 是否预取和卸载 KVC）下发
- **vLLM** => 实现 KVC 预取、卸载

## 范围与交付边界

本方案交付 = 两份既有设计文档的实现 + 三层验证 harness + 端到端对比 benchmark。

来源设计文档：
- `aigw-kvc-management-design.md`（AIGW 侧 KVC 管理，2026-07-09）
- `vllm-kvc-offload-prefetch-design.md`（vLLM 侧控制面，2026-07-10）

### 已锁定前提（来自头脑风暴澄清）

| 维度 | 选定 | 理由 |
|---|---|---|
| vLLM 形态 | 真实 vLLM + CPU offloading connector + `/v1/kvc/*` 已实现 | 收益数字反映真实 KV block 卸载/预取行为 |
| AIGW 侧落地 | 未实现，需一并交付 | 本方案含 AIGW 侧实现 |
| Agent 层 | 自研最小 ReAct agent，主动调 AIGW register/heartbeat/recover | AIGW 感知 agent 靠 agent 主动调三端点 + 请求带 X-Agent-Id |
| 故障注入 | 多场景覆盖（kill+重启复用 agent_id、优雅注销、心跳超时） | 覆盖状态机全分支 |
| 核心指标 | 4 个：重启后首请求 TTFT、重启后 prefill token/cache hit、故障期间 HBM 释放/关键请求不被挤、单任务 wall-clock | 直接度量设计文档价值 |
| 任务 | 自造 terminal 风格任务（不用真 terminalBench 数据集） | 省 dataset 拉取/适配成本，"terminalBench"仅作风格描述 |
| 总体路线 | 方案 B：分层增量验证 | 复用两设计文档已写好的测试矩阵，契约偏差早暴露 |

### 交付分层

| 层 | 来源设计文档 | 交付物 | 验证 |
|---|---|---|---|
| L1 vLLM 控制面 | vllm 设计 §1-§7 | `KvcAPIRouter` + `AsyncLLM.kvc_*` + `KvcController` + `OffloadingManager.purge()`，CPU tier | 复用 vllm 设计 §7 测试矩阵 |
| L2 AIGW KVC 管理 | aigw 设计 §1-§8 | `AgentRegistry` + per-model `KvcSessionManager` + agent HTTP 端点 + `KvcHintSender`→vLLM | 复用 aigw 设计 §8 四层测试矩阵 |
| L3 Agent + 任务 | 新建 | 最小 ReAct agent + 自造任务 + 故障注入 driver | 故障可控、覆盖状态机全分支 |
| L4 端到端 benchmark | 新建 | baseline vs enabled 对比脚本 + 指标采集 + 报告 | 4 指标对比 |

### 不在本方案范围（YAGNI）

- AIGW 设计 Open Questions 全部按"假设最小接口"处理，不额外扩张
- AIGW 设计 §9 Phase 2 候选价值（speculative_prefill、priority、lineage、T4 archival 等）一律不实现
- 多 PD group、跨 AIGW HA、ZK 服务发现 pyMotor —— 设计文档已明确 phase 1 不含
- 真正的 terminalBench 数据集拉取/适配（用自造任务替代）
- 远程 tier（Mooncake/LMCache/FS/object store）—— vLLM 设计已明确 phase 2

### 依赖假设（需在 L1 启动时验证）

- vLLM 进程已配置 `OffloadingConnector` + CPU `SecondaryTier`（已确认）
- vLLM `block_hash`（int64）算法与 AIGW `pendingBlocks` 归因算法一致 —— 这是 AIGW 设计 Open Question #1，**L1 第一周必须用 vLLM 实际 BlockStored 事件采样验证**，否则 L2 归因全错。见风险 R1。

---

## § 1 — 总体路线：方案 B 分层增量验证

分 4 阶段逐层落地 + 逐层验证。每层交付代码 + 测试，最后跑 baseline vs enabled 对比。复用两篇设计文档已写好的测试矩阵。

### Phase 1 — vLLM 控制面（L1）

**实现**（按 vllm 设计 §3 的四个新增单元）：
- `vllm/entrypoints/serve/kvc/api_router.py` + `serving.py` —— FastAPI router，注册到 `register_vllm_serve_api_routers`
- `AsyncLLM.kvc_{offload,prefetch,evict,get_job_status}_async` + `EngineCore` utility handler 分派 `kvc_*`
- `vllm/v1/core/sched/kvc_controller.py` —— hash→block 解析、job 生命周期、hint-id LRU 幂等、逐 hash 锁、`on_schedule_end` 钩子
- `OffloadingManager.purge(keys)` + CPU `SecondaryTier` 默认实现

**API 契约**（vllm 设计 §6）：`POST /v1/kvc/{offload,prefetch,evict}` + `GET /v1/kvc/jobs/{id}`，`hint_id` 幂等，offload/evict 同步 ack、prefetch 异步 202+轮询+pin。

**验证**（复用 vllm 设计 §7）：
- §7.1 单元 `KvcController`（hash 解析、幂等、在途 decode、逐 hash 锁）
- §7.2 单元 `OffloadingManager.purge()`（按哈希选择性清除、不存在 key no-op）
- §7.3 单元 `KvcAPIRouter`（序列化、404、503 未配置 connector）
- §7.4 集成 e2e `test_kvc_control_e2e.py`（InprocClient + 真实 CPU tier + 小模型）：offload→block 释放+`BlockRemoved`；prefetch→pin+下个请求命中 prefix cache 跳 prefill；evict→CPU tier 清除+后续 load miss

**Phase 1 出口判据**：§7.4 e2e 通过 + 用 vLLM 实际 `BlockStored` 事件采样确认 `block_hash` 算法（为 L2 归因铺路）。

### Phase 2 — AIGW KVC 管理（L2）

**实现**（按 aigw 设计 §1-§5）：
- `internal/agentregistry/` —— `Agent`、`Registry`、`Subscriber`、状态机（5 态）、AgingLoop、Redis 持久化、`Clock` 依赖
- `internal/gs/kvc_session_manager.go` —— `Session`/`BlockInfo`/`BlockIndex`、`pendingBlocks` 归因、`OnRequestScheduled`/`OnBlockStored`/`OnBlockRemoved`
- `internal/gs/kvc_strategy.go` + `kvc_strategy_factory.go` —— `OffloadAllStrategy`/`PrefetchMRUStrategy`/`TTLAgingStrategy`
- `internal/gs/kvc_hint_sender.go` + `PyMotorClient`→**改为直连 vLLM**（因 pyMotor 不可用，`KvcHintSender` 的生产实现指向 vLLM `/v1/kvc/*`，而非设计文档原写的 `/pymotor/v1/kvc/hints`）
- HTTP 端点（11 个，aigw 设计 §1 集成点表）+ `X-Agent-Id` header 提取 + `kvc` 配置段
- `internal/stats/kvc_stats.go` + alarm 常量 + 健康检查扩展

**⚠️ 设计文档偏差修正**：AIGW 设计 §4 写的是 AIGW→pyMotor（`/pymotor/v1/kvc/hints`），但 vllm 设计已锁定 pyMotor 不可用、AIGW 直连 vLLM。`KvcHintSender` 的生产实现端点改为 vLLM 的 `/v1/kvc/{offload,prefetch,evict}`，且 `KvcHint`→vLLM `KvcHint` 的 `block_hashes` 字段映射要对齐（两边都用 `block_hashes: int64[]`，对齐干净）。详见 § 2 接缝对齐。

**验证**（复用 aigw 设计 §8 四层测试矩阵）：
- Layer 1 纯函数：状态转换表、EMA、UUID、Redis key、prefix hash
- Layer 2 组件单元：`AgentRegistry` 状态机、三策略、`HintDispatcher` 重试、`PyMotorClient`(→vLLM)、block 归因
- Layer 3 集成：`AgentRegistry`↔`KvcSessionManager` 订阅 + 事件传播 + BlockStored→归因→offload hint→ack→state；fake Redis driver + FakeClock
- Layer 4 HTTP e2e：`httptest` + mock vLLM，register→heartbeat→suspect→offload→restart→recover→prefetch 全流程 + HMAC + 100 agent 并发

**Phase 2 出口判据**：Layer 4 e2e 全流程通过（mock vLLM 收到正确 offload/prefetch/evict hint）+ 覆盖率达标（AgentRegistry ≥90%、KvcSessionManager ≥85%）。

### Phase 3 — Agent 层 + 故障注入（L3）

**实现**（新建，无设计文档）：
- `test/e2e/agent/minimal_react_agent.py` —— 最小 ReAct：system prompt + 工具集（bash exec / 文件读写 / grep-find / 跑测试）+ LLM 循环。每次 LLM 调用前：向 AIGW `get-suggestion` 取 prefill/decode 地址 + 注入 `X-Agent-Id`/`X-Session-Id` + 把请求转发到 vLLM。启动时 `register`、运行中 30s `heartbeat`、重启后 `recover`。
- `test/e2e/agent/tasks/` —— 自造 terminal 风格任务（如：在 mini repo 里定位并修一个 failing test、重构一个函数、补 docstring 并跑 lint），每个任务有评判器。
- `test/e2e/agent/fault_driver.py` —— 故障编排：选定 turn 后注入（a）`kill -SIGKILL` + 延迟重启复用 agent_id（崩溃恢复）、（b）`unregister`+重新 register（优雅注销）、（c）停止心跳 N 秒触发 SUSPECTED（假故障），覆盖状态机所有转换分支。
- 多 agent 编排：同时跑 N 个 agent 各一 session 各一任务（N 小，如 4-8，匹配一体机资源受限定位）。

**验证**：
- 每个故障场景单独可跑、可复现、可断言 AIGW 侧状态转换 + vLLM 侧 hint 收到
- 任务评判器能判 pass/fail（保证 agent 真在干活，不是空转发请求）

**Phase 3 出口判据**：三种故障场景下，agent 都能完成任务 + AIGW 状态机走对 + vLLM 收到对应 hint（从 AIGW debug API + vLLM `/v1/kvc/*` 调用日志双向断言）。

### Phase 4 — 端到端对比 benchmark（L4）

**实现**：
- `test/e2e/benchmark_agent_restart.sh` —— 仿 `benchmark_prefix_cache.sh` 模式：build → 起 vLLM → 起 AIGW → 起 N agent → 跑任务 → 采集 → cleanup
- **两组配置开关**：
  - **Baseline**：`kvc.enabled=false`（AIGW 不做 KVC 管理，agent 崩溃后 KVC 靠 vLLM 自身 LRU 演化）
  - **Enabled**：`kvc.enabled=true` + agent hints 全开
- **指标采集**见 § 3。
- `test/e2e/report_agent_restart.py` —— 出 baseline vs enabled 对比报告，见 § 4。

**Phase 4 出口判据**：两组各跑 ≥5 轮，4 指标全部出数 + enabled 组 TTFT/prefill token 优于 baseline（若不优，回查归因）。

---

## § 2 — 关键设计契约对齐与风险

两份设计文档之间有若干契约接缝，跨层验证成败全在这里。

### 接缝 1 — `KvcHint` ↔ vLLM `KvcHint` 字段映射

| AIGW 侧（设计 §4） | vLLM 侧（设计 §6） | 映射 | 状态 |
|---|---|---|---|
| `HintID` (UUID) | `hint_id` (str) | 直接映射，幂等键 | ✅ 干净 |
| `Type` (offload/prefetch/evict) | 路径 `/v1/kvc/{offload,prefetch,evict}` | AIGW 按 Type 选端点，不进 body 的 `op` | ✅ 干净 |
| `Sessions[].BlockHashes` (int64[]) | `block_hashes` (int64[]) | 直接映射，**通用句柄** | ✅ 干净 |
| `Sessions[].LastInstance` | — | vLLM 不需要（block_hashes 已是全局句柄） | ⚠️ AIGW 发了 vLLM 忽略，无害 |
| `Sessions[].SourceTier`/`TargetTier` | `target_tier?` (advisory) | AIGW 的 targetTier→vLLM 的 target_tier；SourceTier 被 vLLM 的 `lookup()` 替代 | ⚠️ 简化：AIGW 只发 target_tier |
| `HintAck.BlockPlacements` | vLLM `KvcAck.block_placements` | vLLM offload ack 回传 `{hash→"cpu"}`；prefetch 在 job 完成后才填 | ⚠️ AIGW 要轮询 prefetch job 才能拿到 |
| `HintAck.Status` (accepted/rejected/partial) | vLLM `KvcAck.status` (accepted/partial/rejected) | 直接映射 | ✅ 干净 |
| — | `accepted_hashes`/`in_flight_hashes`/`missing_hashes`/`failed_hashes` | AIGW 要消费这些细分来决定重试 | ⚠️ AIGW 重试逻辑要按 vLLM 细分 |

**关键修正 1**：AIGW 设计 §4 的 `HintDispatcher` 重试表只区分网络超时/5xx/4xx/409/Rejected/Partial。但 vLLM 引入了 `in_flight_hashes`（decode 在途）和 `missing_hashes`（非常驻）—— **这两个都不是错误，AIGW 不应重试**，而是更新 `BlockInfo.Tier` 并把 `in_flight` 的 hash 标记为"待 decode 完成后下次事件自然拾取"。这是 AIGW 设计文档没覆盖的细分，Phase 2 实现时补。

### 接缝 2 — `block_hash` 算法一致性

AIGW 的 `pendingBlocks` 归因（aigw 设计 §3）要"用与 vLLM 一致的算法计算 prefix hash"。vllm 设计 §1 明确 vLLM 已按内容哈希 `block_hash` (int64) 跟踪 block 并发 `BlockStored` ZMQ 事件。

**风险**：AIGW `tokenize → 按 blockSize 分块 → content hash` 必须与 vLLM 内部 `block_pool` 的 hash 逐位一致，否则 `pendingBlocks[hash]` 永远匹配不到 `BlockStored` 事件，`session.BlockHashes` 永远空，offload/prefetch hint 发出去 vLLM 在 `block_pool` 里找不到对应 block（全 `missing`）。

**缓解**：Phase 1 第一周用 vLLM 实际 `BlockStored` 事件采样 + AIGW tokenize 重算做对照测试（aigw 设计测试矩阵 `TestPrefixHashComputation`）。**若对不上，整个归因链路失效，方案需退回到"扩展引擎事件携带 session_id"（aigw 设计附录 A.4 选项 1）**——方案级回退路径，见风险 R1。

### 接缝 3 — prefetch 的异步轮询

AIGW 设计 §4 写的是 `Send()` 同步返回 `*HintAck`。但 vllm 设计 §6 的 prefetch 是 `202 + job_id`，`block_placements` 在 job 完成后才填。**AIGW 的 `KvcHintSender.Send()` 对 prefetch 要变成"提交 + 轮询 `GET /v1/kvc/jobs/{id}` 到 done"**，否则 AIGW 拿不到 prefetch 最终结果，`BlockInfo.Tier` 更新不了。

**修正**：`KvcHintSender` 接口加一个 `SendPrefetchAndWait(ctx, hint) (*HintAck, error)`，或 `Send()` 内部对 prefetch 类型自动轮询。Phase 2 实现时定。

### 接缝 4 — AIGW 直连 vLLM 的鉴权

AIGW 设计 §4 写 HMAC（`X-Aigw-Hmac`），假设 AIGW↔pyMotor 同机。vllm 设计 §6 说"与既有 router 同一中间件链，不引入新鉴权"。**两边鉴权模型不一致**。

**修正**：Phase 1 决定 —— 验证环境内 vLLM 不强制鉴权（开发/验证部署），AIGW 的 `KvcHintSender` 生产实现可配置 `hmacEnabled: false` 指向 vLLM。HMAC 留作 phase 2 跨机场景。不阻塞验证。

### 风险登记表

| # | 风险 | 概率 | 影响 | 缓解/回退 |
|---|---|---|---|---|
| R1 | block_hash 算法不一致 | 中 | 致命（归因全错） | Phase 1 第 1 周采样对照；失败则回退到"扩展引擎事件携带 session_id"（方案级回退） |
| R2 | prefetch 异步轮询未在 AIGW 接口建模 | 高 | 中（Tier 更新缺失） | 接缝 3 修正，Phase 2 实现时补 `SendPrefetchAndWait` |
| R3 | vLLM `in_flight`/`missing` 细分 AIGW 误重试 | 高 | 低（无谓重试，不致错） | 接缝 1 修正，Phase 2 重试表补细分 |
| R4 | 故障注入时序不可控（agent 崩在错误 turn） | 中 | 中（数据噪声） | fault_driver 用 turn 计数精确触发 |
| R5 | 自造任务评判器漏判（agent 没真干活但判 pass） | 中 | 中（指标失真） | 评判器检查可观察产物（diff/test pass），不只看 LLM 输出 |
| R6 | 多 agent 并发资源竞争压垮单卡一体机 | 中 | 中（OOM） | N 取小（4-8），任务串行化或限流 |
| R7 | baseline/enabled 两组配置切换不干净（残留状态） | 低 | 高（对比无效） | 每组独立起 vLLM+AIGW，不复用进程，benchmark 脚本强 reset |

---

## § 3 — 端到端验证流程（baseline vs enabled）

### 实验矩阵

| 维度 | 取值 |
|---|---|
| 组别 | **Baseline**（`kvc.enabled=false`）/ **Enabled**（`kvc.enabled=true`） |
| Agent 数 | N=4（多 agent 各一 session 各一任务，匹配一体机定位） |
| 故障场景 | kill+重启复用 agent_id（主场景）；优雅注销；心跳超时（覆盖场景，每场景独立跑） |
| 任务 | 自造 terminal 风格任务（每个 agent 一个，含评判器） |
| 重复轮次 | 每组每场景 ≥5 轮（取中位数 + 置信区间） |
| 存活 agent | 故障期间始终有 ≥1 个 agent 正常跑（验证"HBM 释放给关键请求"指标） |

### 单轮实验流程（以主场景 kill+重启为例）

```
T0   起 vLLM（CPU offloading connector 配好）+ AIGW（kvc.enabled 按组别）
T1   起 4 个 agent：各自 register → heartbeat → 拿任务开始跑 ReAct loop
     ├ agent A：task-1（将在第 k 个 turn 被注入故障）
     ├ agent B：task-2（存活，验证不被挤）
     ├ agent C：task-3（存活）
     └ agent D：task-4（存活）
T2   fault_driver 在 agent A 跑到第 k turn 时 SIGKILL agent A 进程
     ├ [Enabled] AIGW 90s 无心跳 → SUSPECTED → OffloadAll → POST /v1/kvc/offload A 的 session block_hashes
     │           vLLM: GPU→CPU 拷贝 + 释放 GPU block + BlockRemoved
     │           [期间 B/C/D 请求因 HBM 释放更宽裕]
     ├ [Baseline] AIGW 不感知，A 的 KVC 留在 GPU 直到 vLLM LRU 自然淘汰
     └ agent A 进程不存在
T3   等待 Δ 秒（Δ 取 30/120/300 三档，模拟不同恢复延迟；对应 SUSPECTED vs RECOVERING 入口）
T4   重启 agent A，复用同一 agent_id/session_id
     ├ agent A: POST /agents/{id}/recover
     ├ [Enabled] AIGW RECOVERING→ACTIVE → PrefetchMRU → POST /v1/kvc/prefetch A 的 block_hashes
     │           vLLM: CPU→GPU 拷贝 + pin → A 的下一个请求命中 prefix cache 跳 prefill
     └ [Baseline] A 的 KVC 早已被 LRU 淘汰（或还在但位置不定），首请求要重 prefill
T5   agent A 发恢复后第一个请求 → 记录 TTFT + prefill token / cache hit
T6   agent A 继续跑完任务 → 评判器判 pass/fail → 记录 wall-clock
T7   采集：AIGW debug API（状态转换日志）+ vLLM /metrics（GPU mem, cache hit, BlockStored/Removed）+ agent 客户端时间戳
```

### 4 指标采集点与归属

| 指标 | 采集方 | 来源 | Baseline 预期 | Enabled 预期 |
|---|---|---|---|---|
| 重启后首请求 TTFT | agent 客户端时间戳 + vLLM metrics | A 恢复后首请求的 TTFT | 高（重 prefill） | **低**（跳 prefill） |
| 重启后 prefill token / cache hit | vLLM `/metrics` prefix cache hit + `BlockStored` 计数 | A 恢复后首请求的 prefill token 数 | 高（全量 prefill） | **低**（命中 pin block） |
| 故障期间 HBM 释放 / 关键请求不被挤 | vLLM GPU mem gauge + B/C/D 的请求延迟 | T2-T3 期间 GPU 占用 + 存活 agent 请求是否 OOM/排队 | 高占用/可能 OOM | **低占用/不挤** |
| 单任务 wall-clock | agent driver 计时 | A 从 T1 到 T6 | 高（含恢复后重 prefill） | **低** |

---

## § 4 — 报告产出

`test/e2e/report_agent_restart.py` 输出：

1. **对比表**：4 指标 × 2 组 × 3 故障场景，中位数 + 95% CI
2. **归因分析**：若 enabled 不优 → 回查（R1 hash 不一致？prefetch 没命中？baseline 意外受益于 vLLM 自身 prefix cache？）
3. **状态机覆盖证明**：从 AIGW debug API 拉取本轮 agent A 的状态转换序列，贴进报告，证明 SUSPECTED→(RECOVERING)→ACTIVE + offload→prefetch 真发生
4. **vLLM hint 双向断言**：AIGW 发的 hint 列表 vs vLLM `/v1/kvc/*` 收到的调用日志，逐条对账

### 两组配置切换的干净性（R7 缓解）

- baseline 和 enabled **不复用同一 vLLM/AIGW 进程**，每组独立起停
- benchmark 脚本每组开始前 `reset_prefix_cache` + 清 vLLM CPU tier + 重启 AIGW（清 Redis kvc keys）
- N=4 agent 独立进程，故障注入靠 turn 计数精确触发（R4 缓解）

---

## § 5 — 与两份来源设计文档的关系

本方案不重新设计 AIGW 侧或 vLLM 侧的内部架构——那两份设计文档已定稿。本方案的职责是：

1. **实现**两份设计文档（它们当前都是纯设计，代码未落地）
2. **对齐**两份文档之间的契约接缝（§ 2），这些是单看任一文档看不到的
3. **搭建** agent 层 + 端到端 benchmark（两份设计文档都未覆盖的部分）
4. **产出** baseline vs enabled 的性能收益对比数字

两份设计文档是本方案的上游 spec；本方案是它们的验证层 spec。实现 AIGW 侧与 vLLM 侧时，以各自设计文档为准；出现契约偏差时，以本 spec § 2 的接缝对齐为准（pyMotor→vLLM 直连、prefetch 异步轮询、in_flight/missing 不重试、鉴权简化）。

---

## 附录 A — 头脑风暴阶段的澄清问题

本 spec 在头脑风暴阶段通过澄清问题明确了关键边界。所有问题与选定项记录如下，便于追溯决策依据。

### A.1 Q1：vLLM 形态

**问题**：验证方案里，vLLM 这一层是什么形态？这直接决定 harness 怎么搭、收益数字是否反映真实 KVC 行为。

| # | 选项 | 描述 |
|---|---|---|
| 1 | **真实 vLLM（含 CPU offloading connector）** ✅ | 跑一个真实 vLLM 引擎，已配置 OffloadingConnector/CPU secondary tier，且 vLLM 侧已实现 /v1/kvc/* 控制面 API。收益数字反映真实 KV block 卸载/预取行为。 |
| 2 | 真实 vLLM + 待补控制面 API | 有可运行的 vLLM（含 offloading 框架），但 /v1/kvc/* 尚未实现。 |
| 3 | Mock vLLM | 仿照 test/e2e/mock_prefix_cache_server.py，用 Python mock 一个暴露 /v1/kvc/* 的假 vLLM。 |
| 4 | 混合 | agent 与 AIGW 真实链路；AIGW→vLLM 的 /v1/kvc/* 先打到 mock，待 vLLM 就绪再切真。 |

**用户选择**：真实 vLLM（含 CPU offloading connector）

### A.2 Q2：AIGW 侧落地状态

**问题**：AIGW 侧的 KVC 管理目前落地到什么程度？

| # | 选项 | 描述 |
|---|---|---|
| 1 | AIGW 侧已实现，验证方案纯外部 | AgentRegistry/KvcSessionManager/HTTP 端点/HintSender 都在代码里。 |
| 2 | **AIGW 侧未实现，需一并交付** ✅ | 本验证方案与 AIGW 侧实现并行，AIGW 侧作为交付物一部分。 |
| 3 | 部分实现 | 比如只有 AgentRegistry+心跳，KvcSessionManager/策略未落地。 |

**用户选择**：AIGW 侧未实现，需一并交付

### A.3 Q3：Agent 层实现

**问题**：Agent 层（多 agent、每 agent 一个 session、跑推理任务）怎么实现？

| # | 选项 | 描述 |
|---|---|---|
| 1 | 自研最小 ReAct agent | Python，system prompt + 工具集 + 循环。每次 LLM 调用前 get-suggestion + 注入头。 |
| 2 | 复用现成 agent 框包包一层 | 如 Claude Code SDK / OpenCode / LiteLLM agent / smolagents。 |
| 3 | 请求回放器 | 录下 terminalBench 轨迹按 session 回放，不跑工具执行。 |
| — | **（用户反问后的明确）agent 主动调 AIGW register/heartbeat/recover** ✅ | AIGW 感知 agent 靠 agent 主动调三端点 + 请求带 X-Agent-Id 头，故 agent 必须是原生实现。 |

**用户选择**：agent 主动调 AIGW 的 register/heartbeat/recover（即自研最小 ReAct agent）

### A.4 Q4：故障注入

**问题**：「agent 重启故障」具体怎么注入？

| # | 选项 | 描述 |
|---|---|---|
| 1 | kill + 重启复用 agent_id | kill -SIGKILL + 延迟重启复用同 ID，触发 SUSPECTED→(recover)→ACTIVE + offload→prefetch。 |
| 2 | 优雅注销 + 重新注册 | unregister/close session 再 register。 |
| 3 | **多场景覆盖** ✅ | kill 崩溃 + 优雅注销 + 长时间无心跳（假故障），覆盖状态机所有转换分支。 |

**用户选择**：多场景覆盖

### A.5 Q5：核心指标

**问题**：收益对比要报哪些指标？（可多选）

| # | 选项 | 描述 |
|---|---|---|
| 1 | **重启后首请求 TTFT** ✅ | 设计文档「恢复后请求首 token 时延」的直接度量。 |
| 2 | **重启后 prefill token 数 / cache hit** ✅ | 比 TTFT 更直接归因到 KVC。 |
| 3 | **故障期间 HBM 释放 / 关键请求不被挤** ✅ | 验证「释放 HBM 给关键请求」价值。 |
| 4 | **单任务 wall-clock 总耗时** ✅ | 用户最直接感知的「性能收益」。 |

**用户选择**：全选（4 个指标）

### A.6 Q6：terminalBench 数据集

**问题**：terminalBench 数据集这层是什么状态？

| # | 选项 | 描述 |
|---|---|---|
| 1 | terminalBench 现成可用 | 直接拉取子集跑。 |
| 2 | terminalBench 需适配改造 | 默认直连 LLM，需改造成经 AIGW。 |
| 3 | **自造 terminal 风格任务** ✅ | 自己造 N 个 terminal 风格任务，省掉拉取/适配成本，"terminalBench"仅作风格描述。 |

**用户选择**：自造 terminal 风格任务

### A.7 Q7：总体路线

**问题**：总体路线选哪个？

| # | 选项 | 描述 |
|---|---|---|
| 1 | 全量竖井式 | 先全部实现完再统一验证。数字干净但周期长。 |
| 2 | **分层增量验证（方案 B）** ✅ | 4 阶段逐层落地 + 逐层验证，复用两设计文档已写好的测试矩阵，契约偏差早暴露。 |
| 3 | 最小可验证切片 | 只跑 kill+重启主线 1 agent/1 session/2 指标，最快出数但覆盖窄。 |

**用户选择**：方案 B：分层增量验证

### A.8 用户选择汇总

| # | 问题 | 用户选择 | 对方案的影响 |
|---|---|---|---|
| Q1 | vLLM 形态 | 真实 vLLM + CPU offloading connector | 收益数字真实；L1 含 vLLM 控制面实现 |
| Q2 | AIGW 侧落地 | 未实现，需一并交付 | 本方案含 AIGW 侧实现（L2） |
| Q3 | Agent 层 | agent 主动调 register/heartbeat/recover（自研 ReAct） | L3 自研最小 agent |
| Q4 | 故障注入 | 多场景覆盖 | fault_driver 支持 kill/优雅注销/心跳超时三场景 |
| Q5 | 核心指标 | 4 个全选 | L4 采集 4 指标 |
| Q6 | terminalBench | 自造 terminal 风格任务 | L3 含任务 + 评判器 |
| Q7 | 总体路线 | 方案 B 分层增量 | 4 阶段交付 |
