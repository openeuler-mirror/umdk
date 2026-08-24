# AIGW Provider Pool 设计

**日期**：2026-06-09（v2，2026-06-09 修订）
**状态**：待评审
**目标**：在 aigw 中新增 IntelliRouter 风格的 Provider 池调度能力，支持对 OpenAI 兼容 SaaS 后端的 API Key 池化、配额感知、自适应路由、per-endpoint 冷却。

**v2 修订摘要**（基于评审反馈）：
- State 从 per-pool 提升为跨 pool 共享，按 `(provider, hash(apiKey))` 寻址，避免同 key 多 model 配额估算偏高
- `mode` 字段改为可选，缺省 = `"instance"`，保持向后兼容
- 401/403 改为指数退避 cooldown（5min → 8h 封顶），避免对永久失效 key 反复试探
- Latency 拆分：流式记 TTFT，非流式记总耗时，避免输出长度污染信号
- 全部 cooldown 时直接返回 nil → 502，删除"最不绝望"原则
- SdkMode 不支持 Provider 模式（fail-fast），范围章节明确

---

## 背景

aigw 当前是一个面向自建推理集群的调度网关：

- 调度对象是 K8s/DNS 发现的推理实例（IP+Port），有 KV-cache、prefill/decode 等推理层指标
- 已具备代理转发（`/aigw/v1/openai/chat/completions`）、指数退避重试、全局熔断器
- 调度策略 7 种（含 ConsistentHash），均针对推理实例特性设计

IntelliRouter 是一个面向外部 SaaS API 的轻量 SDK：

- 调度对象是 API 端点（`api_key + api_base + provider`），有 quota、RPM 等业务层指标
- 提供 5 种以上策略（含 Token-aware、RPM-aware、Adaptive 多因子加权）
- 提供 per-endpoint 冷却自愈机制

本设计将 IntelliRouter 的能力以独立子模块的形式吸收到 aigw，**两条调度路径并存且互不干扰**：某些 model 走推理实例（现有），某些 model 走 Provider 池（新增）。

## 范围

**包含**：
1. 多 Provider 适配层（仅 OpenAI 兼容后端，无请求/响应 schema 转换）
2. Per-endpoint 冷却状态机（HEALTHY ↔ COOLDOWN，被动健康检查）
3. 5 种新调度策略（SimpleShuffle / LowestLatency / TokenAware / RateLimitAware / Adaptive）

**不包含**（YAGNI）：
- 异构协议适配（Anthropic Messages / Gemini generateContent）
- 事件总线/Observability hooks
- **Metrics emit**（后期再补；首版仅日志）
- 主动健康检查
- 配置热更新（首版静态配置）
- Tag-based 策略（保留 `Tags` 字段做扩展位）
- 性能压测 / benchmark 测试
- 总 deadline / Retry-After 头部解析（依赖 `req.Context()` 自然取消）
- API Key 文件引用（`@/path/to/file`）/ `${ENV_VAR}` 替换（首版仅明文）
- Azure OpenAI / Custom Adapter（首版仅 OpenAICompat 一种实现）

**SdkMode 与 Provider 模式的关系（明确边界）**：

SdkMode（C API 嵌入）下 **Provider 模式不可用**。理由：
- C API 接口语义是"返回 endpoint 给 caller 自己调"，但 Provider 池的产品价值在于网关托管 API key（不能把 key 返给 caller）
- 两种语义在同一接口下无法兼容

实现：`AigwManager.Init()` 在 SdkMode 下检测到 `mode == "provider"` 的 SchedulerConfig 直接 fail-fast。SdkMode 用户使用 SaaS 路由能力请直接接 IntelliRouter Python SDK。

---

## § 1 — 架构总览

```
┌──────────────────────────────────────────────────────────┐
│  HTTP Server (existing)                                  │
│  /aigw/v1/openai/chat/completions                        │
│  /aigw/v1/openai/get-suggestion                          │
└──────────────────┬───────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────┐
│  AigwManager.GetSuggestion (existing, +分流)              │
│                                                          │
│   if model.mode == "instance":                          │
│     → GlobalSchedulerManager (existing path, 不动)       │
│   elif model.mode == "provider":                        │
│     → ApiPoolManager (NEW)                              │
└──────────────────┬───────────────────────────────────────┘
                   │ provider 模式
                   ▼
┌──────────────────────────────────────────────────────────┐
│  internal/apipool/  (NEW — 完全新增)                      │
│                                                          │
│  ApiPoolManager                                          │
│   ├─ deployments     []*Deployment                      │
│   ├─ state           *State (quota / cooldown / latency)│
│   ├─ strategy        Strategy                           │
│   ├─ adapterCache    map[provider]Adapter                │
│   └─ Select(req) → *Deployment                          │
│                                                          │
│  Adapter 接口                                            │
│   - BuildURL(dep, route, stream) string                 │
│   - InjectAuth(headers, dep)                             │
│                                                          │
│  Strategy 接口                                           │
│   - Name() string                                       │
│   - Select(deps, ctx) *Deployment                       │
│                                                          │
│  CooldownTracker (集成在 State 中)                        │
│   - per-deployment 失败计数 → cooldown_until 时间戳      │
│   - 到期 lazy 自动恢复 HEALTHY                           │
└──────────────────┬───────────────────────────────────────┘
                   │ 选出的 Deployment + adapter
                   ▼
┌──────────────────────────────────────────────────────────┐
│  internal/proxy/ (existing, 小改动)                       │
│  ForwardRequest 增加 FullURL 字段                         │
└──────────────────────────────────────────────────────────┘
```

**关键边界**：
- `internal/apipool/` 完全新增，纯进程内，不依赖 ZK / K8s / Cache
- `internal/gs/` 0 改动
- **State 实例位于 `AigwManager` 级，跨 ApiPool 共享**（v2 修订，详见 §2）
- `internal/core/aigw_manager.go` 改 `GetSuggestion`：按 `model.mode` 分流（约 30 行）+ 持有共享 State（约 20 行）
- `internal/proxy/proxy.go` 改 `ForwardRequest`：新增 `FullURL` 字段（约 50 行）
- `internal/server/http_server.go` 改 `forwardChatCompletions`：分流 + 新增 `forwardToProvider`（约 200 行）

**设计决策**（已与用户确认）：
- 仅 OpenAI 兼容后端，无 schema 转换
- 静态配置（aigw.json），首版不支持热更
- 被动健康检查（仅靠失败计数）
- 流式一律不重试单端点内（沿用现有 proxy），但**首 chunk 前可跨端点 failover**
- Quota 配置写死 + 本地滑动窗口计数；**State 跨 pool 共享**，按 `(provider, hash(apiKey))` 寻址
- API Key 配置文件中明文（不支持 `${ENV_VAR}` 或文件引用）
- 业务模型名 = 后端模型名（不支持 actualModelName 映射）
- `mode` 字段**可选**，缺省 = `"instance"`（v2 修订，向后兼容）
- 401/403 走**指数退避** cooldown（v2 修订，详见 §4 / §8）
- Latency 拆分：流式记 **TTFT**，非流式记总耗时（v2 修订，详见 §5）
- 全部 cooldown 时**返回 nil → 502**，由客户端 retry（v2 修订，详见 §5）
- SdkMode 不支持 Provider 模式，启动 fail-fast（详见上节"SdkMode 与 Provider 模式的关系"）
- 不实现总 deadline；依赖 `req.Context()` 取消传播 + 每轮 failover 检查 `ctx.Done()`

---

## § 2 — 核心数据模型

### Deployment（不可变配置）

```go
// internal/apipool/deployment.go

type DeploymentStatus int
const (
    StatusHealthy  DeploymentStatus = iota
    StatusCooldown
)

type Deployment struct {
    ID         string
    ModelName  string
    APIKey     string
    APIBase    string
    Provider   string

    TPM        int  // 0 = 不限
    RPM        int  // 0 = 不限

    Tags       []string
    Timeout    time.Duration
    VerifySSL  bool
}

// StateKey 计算 (provider, sha256(apiKey)[:16])，用于跨 pool 共享 State。
// 同一个 (provider, apiKey) 即使在不同 model pool 注册多个 Deployment，
// 它们的 quota / cooldown / latency / 401 计数都会合并。
func (d *Deployment) StateKey() StateKey
```

### State（运行时状态，进程内，**跨 pool 共享**）

```go
// internal/apipool/state.go

// StateKey 是跨 pool 共享 quota 的寻址 key。
// 同一个 (provider, apiKey) 在不同 model pool 中共写一份配额/cooldown 状态。
type StateKey struct {
    Provider     string
    KeyFingerprint string  // = sha256(apiKey)[:16]，避免直接保留明文 key
}

type State struct {
    mu               sync.RWMutex  // 顶层锁，保护 map 增删
    cfg              *CooldownConfig

    // 每个 StateKey 一份独立子状态，子状态内部用自己的 RWMutex
    entries map[StateKey]*stateEntry
}

type stateEntry struct {
    mu sync.RWMutex

    // 状态机
    status           DeploymentStatus
    cooldownUntil    int64
    consecutiveFails int
    auth401Attempts  int  // 401/403 累计次数，用于指数退避

    // Quota 滑动窗口（1 分钟）
    tokenBucket *slidingWindow
    rpmBucket   *slidingWindow

    // 延迟 EMA（v2 修订：拆分流式 TTFT 与非流式总耗时）
    avgTTFT        float64  // 流式请求的首 chunk 延迟 EMA
    avgTotalLatency float64 // 非流式请求的总耗时 EMA

    // 累计统计（运维定位用）
    totalRequests int64
    totalTokens   int64
    totalFailures int64
}

// 按 (provider, key) 寻址的查询接口
func (s *State) IsAvailable(k StateKey) bool
func (s *State) RemainingTPM(k StateKey, tpm int) int
func (s *State) RemainingRPM(k StateKey, rpm int) int

// 记录调用结果。
// stream=true 时 latency 应是 TTFT；stream=false 时是总耗时。
func (s *State) RecordSuccess(k StateKey, stream bool, latency time.Duration, tokens int)
// errKind 决定 cooldown 时长（普通 / 限流 / 鉴权）
func (s *State) RecordFailure(k StateKey, errKind ErrorKind)
```

**设计点**：
- **State 单例位于 `AigwManager`**，多个 `ApiPoolManager` 持 `*State` 引用共写
- 寻址 `StateKey = (provider, sha256(apiKey)[:16])`：同 key 多 model 自动共享 quota
- 锁分两层：顶层锁仅保护 `entries` map 增删；具体状态读写走 `stateEntry.mu`，避免全局锁
- 滑动窗口用 ring buffer，lazy eviction（查询时 evict 过期项）
- EMA：`avg = α·newSample + (1-α)·avg`，α=0.2；首样本直接赋值（避免冷启动严重低估）
- Deployment（不可变）与 State（可变）分离，避免锁粒度混乱

**为什么用 hash(apiKey) 而不是 dep.ID**：
- 真实场景：同一个 OpenAI key 给 `gpt-4o-mini` 和 `gpt-4o` 两个 model pool 用，TPM/RPM 配额是 key 级（实际是 org 级）共享的。
- 若按 dep.ID 寻址，两个 pool 各自计数，估算余量会高出真实余量一倍 → token-aware/rate-limit-aware 决策失真，更易撞 429
- 用 `(provider, hash(key))` 自动归并，不需要用户配置额外 group 字段

**API key 隐私**：
- State 不保留明文 key，只保留 16 位 hash 前缀做寻址
- 日志中如需打印 key 标识，统一用 `key=<KeyFingerprint>` 不打印明文
- 配置文件中的 apiKey 由 `Deployment` 内部持有，不传入 State

---

## § 3 — Provider Adapter 层

### 接口

```go
// internal/apipool/adapter/base.go

type Adapter interface {
    BuildURL(dep *Deployment, route string, stream bool) string
    InjectAuth(headers http.Header, dep *Deployment)
}

// internal/apipool/adapter/registry.go
type Registry struct {
    adapters map[string]Adapter
}
func (r *Registry) Get(provider string) (Adapter, error)
func (r *Registry) Register(name string, a Adapter)
```

### 首版 Adapter 列表

| Provider 标识 | URL 构造 | Auth header |
|--------------|---------|-------------|
| `openai` | `{APIBase}{route}` | `Authorization: Bearer {APIKey}` |
| `vllm` | `{APIBase}{route}` | `Authorization: Bearer {APIKey}`（可选） |
| `deepseek` | `{APIBase}{route}` | `Authorization: Bearer {APIKey}` |
| `dashscope` | `{APIBase}/compatible-mode{route}` | `Authorization: Bearer {APIKey}` |
| `siliconflow` | `{APIBase}{route}` | `Authorization: Bearer {APIKey}` |
| `zhipu` | `{APIBase}{route}` | `Authorization: Bearer {APIKey}` |
| `azure-openai` | `{APIBase}/openai/deployments/{model}{route}?api-version=...` | `api-key: {APIKey}` |
| `custom` | `{APIBase}{route}` | 由 `authHeaderName/authHeaderPrefix` 驱动 |

`OpenAICompatAdapter` 一个实现覆盖大多数 provider，构造时传 provider 名做日志区分。`azure-openai` 和 `custom` 单独实现。

**Adapter 注册时机**：`ApiPoolManager` 构造时按配置 lookup registry，未知 provider 启动 fail-fast。

---

## § 4 — Cooldown 状态机

### 状态机

```
       ┌──────────────────────────────────────────┐
       │   ┌─────────────┐  consecutiveFails ≥ N │
       │   │   HEALTHY   │ ───────────────────┐  │
       │   └─────────────┘                    ▼  │
       │         ▲                  ┌─────────────┐
       │         │ now ≥ until      │  COOLDOWN   │
       │         │ (lazy 检查)       │ until=t+D  │
       │         └───────────────────│             │
       │                              └─────────────┘
       │                                            │
       │                  Select() 跳过             │
       └────────────────────────────────────────────┘
```

### 行为定义

**进入 COOLDOWN**：
- `consecutiveFails ≥ failureThreshold`（默认 3）
- 失败定义见错误分类表（§ 8）

**离开 COOLDOWN（lazy）**：
- 在 `IsAvailable()` 检查 `now ≥ cooldownUntil`，是则原地置回 `HEALTHY` 并清零 `consecutiveFails`
- 不开后台 goroutine
- 不设半开态（OpenAI 兼容后端的瞬时故障，恢复后第一次调用就能反馈）

**成功调用**：`consecutiveFails` 与 `auth401Attempts` 一并清零

### 401/403 指数退避（v2 修订）

普通错误（5xx / 网络 / 429）每次失败 cooldown 用配置的固定时长。**401/403 单独处理**：

```
auth401Attempts 累计次数（成功调用清零）：
  1st  → 5min
  2nd  → 10min
  3rd  → 20min
  4th  → 40min
  5th  → 80min
  ...  → 翻倍
  8th+ → 8h（封顶）

公式：cooldown = min(5min × 2^(attempts-1), 8h)
```

**理由**：401/403 几乎一定是 key 永久失效（撤销 / 欠费 / quota 上限）。固定 5 分钟 cooldown 后再试几乎一定还失败 → 死循环消耗资源。指数退避兼顾"假 401 恢复机会"与"震荡保护"。

**实现**：State 在 `RecordFailure(key, ErrAuth)` 时把 `auth401Attempts++`，cooldown 时长按上表算。下次成功调用清零。

**跨 pool 计数合并**：State 按 `(provider, hash(key))` 寻址，所以同一个 key 即使在多个 model pool 出现，401 计数合并。同一个失效 key 不会因为出现在两个 pool 就被试两轮。

### 与 proxy.go 的协作

```
单次请求生命周期：
  1. ApiPool.Select() —— 跳过 COOLDOWN 端点，按策略选 HEALTHY
  2. proxy.ForwardRequest() —— 单端点内 0~N 次重试（已有逻辑）
  3. 仍失败 → State.RecordFailure() → 可能进 COOLDOWN
  4. 选下一个端点（failover），回到 1
  5. 全部失败 → 返回 502
```

**单次请求总尝试上限**：`maxFailoverEndpoints × (1 + maxRetriesPerEndpoint)`，默认 `3 × 3 = 9`。

---

## § 5 — 策略层

### 接口

```go
// internal/apipool/strategy/base.go

type Context struct {
    Model     string
    Messages  []map[string]any
    PromptLen int  // 由调用方填，缺省 0
    Stream    bool // 决定 latency 信号选 TTFT 还是 total
}

type Strategy interface {
    Name() string
    Select(deployments []*Deployment, ctx *Context) *Deployment
}
```

`OnSuccess/OnFailure` 不在 Strategy 接口里，由 `ApiPoolManager` 统一写入 `State`，所有策略读同一份。

**关于 PromptLen**：
- `PromptLen` 是为未来扩展（如基于 prompt 长度预估当前请求 token 消耗）保留的字段
- **首版策略不读 `PromptLen` 做决策**。token-aware 只看 deployment 的剩余 TPM 余量，不预估当前请求会消耗多少 token
- 调用方默认填 0；如果未来加入预估能力，由 HTTP handler 调用 tokenizer 预填
- 这样避免"PromptLen=0 默认值导致 token-aware 决策失真"

### 5 个策略

| 策略 | 决策 |
|------|------|
| `simple-shuffle` | `IsAvailable` 过滤后随机选 |
| `lowest-latency` | EMA latency 升序，10% ε-greedy 探索 |
| `token-aware` | 剩余 TPM 降序，全部 < 阈值时退化到 SimpleShuffle |
| `rate-limit-aware` | 剩余 RPM 降序，全部 < 阈值时退化到 SimpleShuffle |
| `adaptive` | `1.0·health + 0.5·token + 0.3·rpm + 0.2·latency`，最高分胜出（同分随机） |

**`lowest-latency` 与 `adaptive` 用哪个 latency 信号**（v2 修订）：
- `ctx.Stream == true` → 读 `avgTTFT`
- `ctx.Stream == false` → 读 `avgTotalLatency`
- 理由：流式输出长度差异大，总耗时被输出 tokens 数污染；TTFT 才是 lowest-latency 真正想优化的"端点响应快"信号

### Adaptive 子分数归一化

- `health_score` = 1 if HEALTHY else 0（COOLDOWN 已被 filter，恒为 1，保留扩展位）
- `token_score` = `min(1.0, remainingTPM / tpm)`，tpm=0 时恒为 1
- `rpm_score` = `min(1.0, remainingRPM / rpm)`，rpm=0 时恒为 1
- `latency_score` = `1 / (1 + chosenLatency / baseline)`，baseline=1s；`chosenLatency` 按上节流式/非流式选

### 退化策略（v2 修订）

所有策略的 `Select` 第一步都先 `filterAvailable`（过滤 COOLDOWN）。如果过滤后为空：

- **直接返回 nil**
- 上层 `forwardToProvider` 收到 nil 立即返回 502
- 由客户端 retry，不在网关内做"最不绝望"试探

理由：cooldown 中的端点 99% 仍会失败，强行选会浪费一次调用 + 让 fail count 继续涨，反而推迟自然恢复。直接 502 让客户端拿到明确信号。

### 工厂

```go
// internal/apipool/strategy/factory.go
func Create(name string, state *State, opts map[string]any) (Strategy, error)
```

---

## § 6 — 配置 schema

### 现有 instance 模式（mode 字段可选，缺省 = "instance"，向后兼容）

```jsonc
{
  "globalSchedulers": [
    {
      "model": "DeepSeek-R1-Distill-Qwen-7B",
      "mode": "instance",   // ← 可选，缺省即此值；现有部署不需改配置
      "blockSize": 128,
      "deployPolicy": "mixed",
      "loadBalancer": { ... },
      "instanceConnectType": "sse"
    }
  ]
}
```

**兼容性**：现有 aigw.json 不需任何修改即可在新版本启动；mode 缺失按 instance 处理。新部署建议显式声明 `"mode": "instance" | "provider"`。

### 新增 provider 池模式

```jsonc
{
  "globalSchedulers": [
    {
      "model": "gpt-4o-mini",
      "mode": "provider",

      "providerPool": {
        "strategy": "adaptive",
        "strategyOptions": {
          "tokenThreshold": 1000,
          "rpmThreshold": 10,
          "explorationRatio": 0.1,
          "weights": {
            "health": 1.0,
            "token": 0.5,
            "rpm": 0.3,
            "latency": 0.2
          }
        },

        "cooldown": {
          "failureThreshold": 3,
          "durationSec": 60,           // 网络/5xx/408 cooldown
          "rateLimitDurationSec": 90,  // 429 cooldown
          "auth401FloorSec": 300       // 首次 401/403 时长；后续按指数退避
        },

        "retry": {
          "maxFailoverEndpoints": 3,
          "maxRetriesPerEndpoint": 2
        },

        "deployments": [
          {
            "id": "openai-primary",
            "provider": "openai",
            "apiBase": "https://api.openai.com",
            "apiKey": "sk-xxxx",
            "tpm": 60000,
            "rpm": 500,
            "tags": ["primary", "us"],
            "timeout": 30,
            "verifySsl": true
          },
          {
            "id": "deepseek-backup",
            "provider": "deepseek",
            "apiBase": "https://api.deepseek.com",
            "apiKey": "sk-yyyy",
            "tpm": 100000,
            "rpm": 1000
          }
        ]
      }
    }
  ]
}
```

### Go 类型

```go
// internal/base/aigw_type.go 扩展

type SchedulerConfig struct {
    Model        string         `json:"model"`
    Mode         string         `json:"mode,omitempty"`  // "instance" | "provider"，可选；缺省 "instance"

    // mode=instance（现有，含缺省）
    BlockSize    int            `json:"blockSize,omitempty"`
    DeployPolicy string         `json:"deployPolicy,omitempty"`
    LoadBalancer *LBConfig      `json:"loadBalancer,omitempty"`

    // mode=provider（新）
    ProviderPool *ProviderPoolConfig `json:"providerPool,omitempty"`
}

type ProviderPoolConfig struct {
    Strategy        string                 `json:"strategy"`
    StrategyOptions map[string]any         `json:"strategyOptions,omitempty"`
    Cooldown        *CooldownConfig        `json:"cooldown,omitempty"`
    Retry           *RetryConfig           `json:"retry,omitempty"`
    Deployments     []DeploymentConfig     `json:"deployments"`
}

type DeploymentConfig struct {
    ID        string   `json:"id,omitempty"`
    Provider  string   `json:"provider"`
    APIBase   string   `json:"apiBase"`
    APIKey    string   `json:"apiKey"`
    TPM       int      `json:"tpm,omitempty"`
    RPM       int      `json:"rpm,omitempty"`
    Tags      []string `json:"tags,omitempty"`
    Timeout   int      `json:"timeout,omitempty"`
    VerifySSL *bool    `json:"verifySsl,omitempty"`
    AuthHeaderName   string `json:"authHeaderName,omitempty"`
    AuthHeaderPrefix string `json:"authHeaderPrefix,omitempty"`
}
```

### 配置校验（启动 fail-fast）

- `mode` 缺失 → 按 `"instance"` 处理；非 `instance|provider` 字面量 → 启动失败
- `mode=instance`（含缺省）必须有 `loadBalancer`，不能有 `providerPool`
- `mode=provider` 必须有 `providerPool`，可以没有 `loadBalancer/blockSize/deployPolicy/instanceConnectType`
- `providerPool.deployments` 不能为空
- `provider` 字段未注册 → 启动失败
- `provider="custom"` 必须有 `authHeaderName`
- **SdkMode 启动时遇到 `mode=provider` 配置 → 启动失败**（详见 §1 SdkMode 边界）

---

## § 7 — HTTP 入口集成 & proxy 调用

### 入口分流

```go
// internal/server/http_server.go (改造 forwardChatCompletions)

func (s *HttpServer) forwardChatCompletions(w http.ResponseWriter, r *http.Request) {
    // ... 解析 body 等现有逻辑

    mode, err := s.manager.GetModelMode(req.Model)
    if err != nil {
        http.Error(w, "unknown model", http.StatusNotFound)
        return
    }

    switch mode {
    case "instance":
        s.forwardToInstance(w, r, req, body)
    case "provider":
        s.forwardToProvider(w, r, req, body)
    default:
        http.Error(w, "invalid model mode", http.StatusInternalServerError)
    }
}
```

### Instance 路径

把现有 `forwardChatCompletions` 里 `GetSuggestion → proxy.ForwardRequest` 的逻辑原样搬到 `forwardToInstance`，**逻辑不变**。

### Provider 路径

```go
func (s *HttpServer) forwardToProvider(w, r, req, body) {
    pool := s.manager.GetApiPool(req.Model)
    ctx := &apipool.Context{Model: req.Model, Messages: req.Messages, PromptLen: 0}

    var lastErr error
    triedKeys := map[apipool.StateKey]bool{}

    for attempt := 0; attempt < pool.MaxFailoverEndpoints(); attempt++ {
        // v2: 每轮先检查请求是否已被取消，避免在客户端断开后继续浪费 quota
        if err := r.Context().Err(); err != nil {
            return
        }

        dep := pool.SelectExcept(ctx, triedKeys)
        if dep == nil {
            break  // 全部 cooldown / 全部试过 → 退出循环走 502
        }
        triedKeys[dep.StateKey()] = true

        adapter, _ := pool.GetAdapter(dep.Provider)
        targetURL := adapter.BuildURL(dep, "/v1/chat/completions", req.Stream)

        forwardHeaders := r.Header.Clone()
        adapter.InjectAuth(forwardHeaders, dep)

        forwardReq := &proxy.ForwardRequest{
            Method:  "POST",
            FullURL: targetURL,
            Headers: forwardHeaders,
            Body:    body,
            Stream:  req.Stream,
        }

        startTS := time.Now()
        result, err := s.proxyMgr.ForwardRequest(r.Context(), forwardReq)
        if err != nil {
            pool.OnFailure(dep, err)
            lastErr = err
            continue
        }

        if req.Stream && result.StreamReader != nil {
            firstChunkReceived := false
            ttftCb := func() { pool.OnFirstChunk(dep, time.Since(startTS)) } // 记 TTFT
            err := writeSSEStream(w, result.StreamReader, &firstChunkReceived, ttftCb)
            if err != nil && !firstChunkReceived {
                pool.OnFailure(dep, err)
                continue
            }
            // 首 chunk 后断流不 failover（HTTP 200 已写）
            // 完整流结束后才记成功（不再记 latency，TTFT 已记）
            if err == nil {
                pool.OnStreamSuccess(dep, result.TokensUsed)
            }
            return
        }

        // 非流式记总耗时
        pool.OnSuccess(dep, time.Since(startTS), result.TokensUsed)
        writeNonStream(w, result)
        return
    }

    http.Error(w, fmt.Sprintf("all providers failed: %v", lastErr), http.StatusBadGateway)
}
```

### proxy.go 最小改动

```go
// internal/proxy/proxy.go
type ForwardRequest struct {
    Method    string
    TargetURL string
    Route     string
    FullURL   string  // 新增：非空时优先于 TargetURL+Route
    Headers   http.Header
    Body      []byte
    Stream    bool
    DpRank    *int
}

// 内部
targetURL := req.FullURL
if targetURL == "" {
    targetURL = req.TargetURL + req.Route
}
```

**全局熔断器**：保持现状。Provider 池有 per-deployment cooldown，两层叠加但不冲突：
- 全局熔断保护：所有外部调用都失败时（如本地网络挂了）
- per-deployment cooldown 保护：单个 provider 端点失效

### AigwManager 接口扩展

```go
// internal/core/aigw_manager.go
func (m *AigwManager) GetModelMode(model string) (string, error)
func (m *AigwManager) GetApiPool(model string) *apipool.ApiPoolManager
```

`AigwManager` 维护：
- `gsTable map[string]*gs.GlobalSchedulerManager` — 现有
- `poolTable map[string]*apipool.ApiPoolManager` — 新增
- `apiPoolState *apipool.State` — **新增（v2）**，所有 ApiPoolManager 共享同一个 State 实例

`Init()` 阶段：
1. 按 `mode` 字段分流：`instance` → 初始化 GlobalSchedulerManager；`provider` → 初始化 ApiPoolManager 并注入共享 State
2. mode 缺失按 `instance` 处理
3. **SdkMode 下若发现任一 `mode=provider` 配置则 fail-fast**

### Get-Suggestion 在 Provider 模式下不可用

`/aigw/v1/openai/get-suggestion` 的语义是"返回 instance URL 给客户端自己调"。Provider 模式下不能暴露 API key，因此：

- Provider 模式只支持代理路径 `/aigw/v1/openai/chat/completions`
- Provider 模式下 `/get-suggestion` 直接返回 `400 model is in provider mode, must use /chat/completions endpoint`

---

## § 8 — 错误处理 & 重试边界

### 三层错误处理

```
┌────────────────────────────────────────────────────────────┐
│ Layer 3: HTTP Handler (forwardToProvider)                  │
│   - 跨端点 failover 循环                                    │
│   - 全部失败 → 502 Bad Gateway                             │
└──────────────────┬─────────────────────────────────────────┘
                   │
┌──────────────────▼─────────────────────────────────────────┐
│ Layer 2: ApiPool.OnFailure()                               │
│   - 错误分类                                                │
│   - 写入 consecutiveFails / 触发 cooldown                   │
└──────────────────┬─────────────────────────────────────────┘
                   │
┌──────────────────▼─────────────────────────────────────────┐
│ Layer 1: proxy.ForwardRequest()                            │
│   - 单端点内重试（已有，不动）                              │
│   - 流式 POST 一律不重试                                    │
└────────────────────────────────────────────────────────────┘
```

### 错误分类表

| 错误来源 | failover | cooldown 时长 | 计入 fail count | 客户端响应 |
|---------|----------|---------------|----------------|-----------|
| 网络错误 | ✅ | 60s（固定） | ✅ | 全败则 502 |
| 5xx | ✅ | 60s（固定） | ✅ | 全败则透传 status |
| 429 | ✅ | 90s（固定） | ✅ | 全败则透传 429 |
| 408 | ✅ | 60s（固定） | ✅ | 同上 |
| **401/403** | ✅ | **指数退避 5min→8h**（v2） | ✅ + auth401Attempts++ | 同上 |
| 404 | ✅ | 0 | ❌ | failover 但不 cooldown |
| 422 / 400 | ❌ | 0 | ❌ | 直接透传，不 failover |
| context canceled | — | 0 | ❌ | 直接退出 forward 循环（v2 修订） |

### 401/403 处理（v2 修订）

每个 deployment 的 key 是独立的，**401/403 应该 failover**（试别的 dep），但**对当前 dep 走指数退避 cooldown**：

```
auth401Attempts: 1 → 5min
                 2 → 10min
                 3 → 30min
                 4 → 2h
                 5+ → 8h（封顶）

cooldown = min(5min × 2^(attempts-1), 8h)
```

成功调用清零 `auth401Attempts`。详见 §4 "401/403 指数退避"。

### Context 取消处理（v2 修订）

`forwardToProvider` 主循环每轮先检查 `r.Context().Err()`：
- 已取消（客户端断开 / 上游 deadline）→ 直接退出，不再 failover
- 不写错误响应到 `w`（连接已断）
- 已发起的 ForwardRequest 通过 `proxy` 共享同一个 ctx 自动取消

不实现"总 deadline"显式配置；以 client 提供的 ctx deadline 为准。

### 流式重试边界

- **流式连接前失败**：可以 failover
- **首个 chunk 已发出后失败**：直接断流给客户端，**不 failover**（HTTP 200 已写）
- 与"流式一律不重试"的决策一致：那是指 proxy **单端点内**不重试，跨端点 failover 在首 chunk 之前仍可

### Cooldown 配置

```jsonc
"cooldown": {
  "failureThreshold": 3,           // consecutiveFails 达到此值进入 cooldown
  "durationSec": 60,               // 网络/5xx/408
  "rateLimitDurationSec": 90,      // 429
  "auth401FloorSec": 300           // 401/403 首次 cooldown；后续 = floor × 2^(attempts-1)，封顶 8h
}
```

---

## § 9 — 测试策略

### 测试金字塔

```
         ┌─────────────────────┐
         │  E2E (mock server)  │  ~5 cases
         ├─────────────────────┤
         │  Integration         │  ~15 cases
         ├─────────────────────┤
         │  Unit                │  ~50 cases
         └─────────────────────┘
```

### Unit 测试

| 包 | 测试重点 |
|----|---------|
| `internal/apipool/state` | 滑动窗口、cooldown 进入/退出/lazy 恢复、并发安全（`-race`）、EMA |
| `internal/apipool/cooldown` | 错误分类、阈值触发、三档时长、4xx 不计数 |
| `internal/apipool/strategy/*` | 边界：空池 / 全 cooldown 退化 / 配额耗尽 / 评分排序、确定性（seeded random） |
| `internal/apipool/adapter/*` | URL 拼接、auth header、provider 名映射 |
| `internal/apipool/pool_manager` | Select / OnSuccess / OnFailure 状态写入、SelectExcept |

`go test ./internal/apipool/... -race -cover`

### Integration 测试

`httptest.Server` 起假后端，覆盖：

| 场景 | 验证点 |
|------|--------|
| 单端点正常调用 | adapter URL/auth、State 计数 |
| 5xx 触发 cooldown | 3 次失败后端点不可选；60s 后恢复 |
| 双端点 failover | 主败切备 |
| **全部 cooldown 直接 502**（v2） | Select 返回 nil；客户端拿到 502 |
| **401 指数退避**（v2） | 第 1/2/3/4/5 次连续 401 的 cooldown 分别为 5/10/30/120/480 min |
| 401 后成功调用清零 | auth401Attempts 归零，下次 401 仍从 5min 起 |
| 流式首 chunk 前 failover | 客户端正常拿到第二端点的流 |
| 流式中途失败断流 | 客户端拿部分响应 + EOF；不 failover |
| **流式 TTFT 记录**（v2） | TTFT 写入 avgTTFT；非流式总耗时写入 avgTotalLatency |
| **lowest-latency 流式选 TTFT 低的**（v2） | 即使总耗时高，TTFT 低则被选 |
| Adaptive 评分主导 | 高延迟排后 / token 余量主导 |
| **跨 model pool 共享 quota**（v2） | 同 (provider, key) 在两个 model pool 配置，TPM 计数累加；一边耗尽对另一边可见 |
| **SdkMode + provider 配置 → fail-fast**（v2） | C API 初始化阶段返回错误 |
| **mode 缺失按 instance 处理**（v2） | 现有不带 mode 字段的配置正常启动 |
| **ctx 取消时 forwardToProvider 立即退出**（v2） | client 断开后不再 failover |
| 100 并发 | State 计数对得上，跨 pool 并发安全 |

### E2E 测试

复用 `test/e2e/`，新增 `mock_e2e_provider_server.py` 模拟 OpenAI 兼容接口（含 5xx/429/401 注入），加 `test_e2e_provider.py`：

- 启动 aigw + mock provider servers
- 走真实 HTTP `/aigw/v1/openai/chat/completions`
- 验证流式响应、failover、cooldown、并发

### TDD 实施顺序

1. `state.go` + `state_test.go`
2. `cooldown` 分类逻辑 + 测试
3. `adapter/openai_compat.go` + 测试
4. `strategy/simple_shuffle.go` + 测试
5. 其余 4 个 strategy 各自 + 测试
6. `pool_manager.go` 串起来 + 测试
7. `internal/core/aigw_manager.go` 分流 + 测试
8. `internal/server/http_server.go` 入口集成 + integration test
9. E2E

### 不覆盖

- 真实第三方 API（mock 足够）
- 性能/压测 benchmark
- Adapter 的 Azure/custom（首版只实现 OpenAICompat）

---

## 附录：模块清单

新增：

```
internal/apipool/
  deployment.go             Deployment 数据模型 + StateKey() 方法
  state.go                  State（跨 pool 共享）+ stateEntry + 滑动窗口 + EMA
                            含 401/403 指数退避（auth401Attempts）
                            含 avgTTFT / avgTotalLatency 拆分
  cooldown.go               错误分类 + ErrorKind 枚举（Auth 单独走指数退避）
  pool_manager.go           ApiPoolManager（持 *State 引用）
  adapter/
    base.go                 Adapter 接口
    registry.go             provider → adapter 映射
    openai_compat.go        OpenAICompatAdapter（覆盖大多数 provider）
    （azure_openai.go / custom.go 首版不实现，详见 §1 不包含）
  strategy/
    base.go                 Strategy 接口 + Context（+Stream 字段）
    factory.go              Create()
    simple_shuffle.go
    lowest_latency.go       按 ctx.Stream 选 TTFT 或 total latency
    token_aware.go
    rate_limit_aware.go
    adaptive.go             同上 latency 选择逻辑
```

修改：

```
internal/base/aigw_type.go            +ProviderPoolConfig +DeploymentConfig +Mode 字段(可选)
internal/core/aigw_manager.go         +GetModelMode +GetApiPool +Init 分流
                                      +apiPoolState 共享 State 持有
                                      +SdkMode fail-fast on mode=provider
internal/core/config_manager.go       +Provider 池配置校验（mode 缺省 = instance）
internal/proxy/proxy.go               +FullURL 字段
internal/server/http_server.go        forwardChatCompletions 分流 +forwardToProvider
                                      +ctx.Done() 检查；+TTFT 回调
configs/aigw.json                     +示例 provider 池配置（明确 mode 字段可选）
```
