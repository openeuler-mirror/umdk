# AIGW 模块详细设计文档

## 一、概述

AIGW (AI Gateway) 是一个企业级的大语言模型推理网关，采用 Go 语言实现，支持 SDK 和独立服务两种部署模式。本文档详细描述 AIGW 的模块架构、各模块职责与接口定义。

### 架构层次

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           应用层 (API)                                        │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐  │
│  │   HTTP RESTful API    │  │      C API (CGO)     │  │   CLI (cmd/aigw)  │  │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           网关层 (Gateway Layer)                              │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐  │
│  │    core.AigwManager   │  │ server.HttpServer    │  │   zk.ZkManager   │  │
│  │    (全局管理器)        │  │   (HTTP服务)          │  │  (ZK服务发现)     │  │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           调度层 (Scheduling Layer)                          │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐  │
│  │  gs.GlobalScheduler   │  │  gs.InstanceManager  │  │ gs.LoadBalancer  │  │
│  │  Manager (全局调度器)  │  │   (实例管理器)        │  │   (负载均衡)      │  │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           基础设施层 (Infrastructure)                         │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐  │
│  │ cachecenter.Cache     │  │   tokenizers.*       │  │   stats.Stats    │  │
│  │ Manager (缓存中心)     │  │   (分词器)            │  │   (统计)          │  │
│  └──────────────────────┘  └──────────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 二、核心模块详解

### 2.1 核心管理器 (internal/core)

#### 2.1.1 AigwManager

**文件**: `internal/core/aigw_manager.go`

**职责**:
- AIGW 全局管理器，协调所有子模块
- 管理模型注册表 (gsTable)
- 管理分词器表 (tkTable)
- 提供统一的请求调度入口
- 管理生命周期 (Init/Uninit)

**数据结构**:

```go
type AigwManager struct {
    rwLock       sync.RWMutex                    // 读写锁
    ctx          context.Context                 // 上下文
    cancel       context.CancelFunc              // 取消函数
    config       *base.AigwConfig               // 配置
    gsTable      map[string]*gs.GlobalSchedulerManager  // 模型->调度器映射
    HmacMgr      *crypto.HmacManager            // HMAC管理器
    AesMgr       *crypto.AesManager             // AES管理器
    lightgbm     *lightgbm.Booster              // LightGBM预测模型
    tkTable      map[string]tokenizers.Tokenizer // 分词器映射
    securitySchema string                        // 安全模式
    runtimeMode   base.RuntimeMode              // 运行模式 (SDK/Service)
    CacheDriverOps *cachecenter.CacheDriverOps  // 缓存驱动
}
```

**关键方法**:

| 方法 | 功能 | 调用关系 |
|------|------|----------|
| `NewAigwManager` | 创建全局管理器 | 初始化时调用 |
| `Init` | 初始化管理器 | 加载 LightGBM、分词器、注册模型 |
| `RegisterModel` | 注册模型 | 创建 GlobalSchedulerManager |
| `UnregisterModel` | 注销模型 | 停止并删除 GlobalSchedulerManager |
| `GetSuggestion` | 获取调度建议 | 委托给 GlobalSchedulerManager |
| `SelectOptimalNode` | 选择最优节点 | SDK 模式主入口 |
| `RegisterInstance` | 注册实例 | 委托给 GlobalSchedulerManager |
| `HandlerReqEvent` | 处理请求事件 | 事件通知入口 |

---

### 2.2 全局调度器 (internal/gs)

#### 2.2.1 GlobalSchedulerManager

**文件**: `internal/gs/gs_manager.go`

**职责**:
- 管理特定模型的调度逻辑
- 协调实例管理器、缓存管理器、负载均衡器
- 处理控制消息 (注册/注销实例)
- 处理调度请求
- 维护统计信息

**数据结构**:

```go
type GlobalSchedulerManager struct {
    ctx             context.Context
    cancel          context.CancelFunc
    wg              *sync.WaitGroup
    config          globalSchedulerManagerConfig
    controlChannel  chan *ControlMessage    // 控制消息通道
    scheduleChannel chan *ControlMessage    // 调度消息通道
    reqStatusChannel chan *ControlMessage   // 请求状态通道
    hmacMgr         *crypto.HmacManager
    aesMgr          *crypto.AesManager
    dispatcher      *globalScheduleDispatcher  // 分发器
    instanceManager *InstanceManager           // 实例管理器
    cacheManager    *cachecenter.CacheManager  // 缓存管理器
    scheduler       loadBalancer               // 负载均衡器
    tokenizer       tokenizers.Tokenizer       // 分词器
    lgm             *lightgbm.Booster          // LightGBM模型
    stats           *stats.DataPlaneStats      // 统计
    lastAccessTime  time.Time
    cacheDriverOps  *cachecenter.CacheDriverOps
    runtimeMode     base.RuntimeMode
    metricProvider  MetricProvider             // 指标提供者
}
```

**配置结构**:

```go
type globalSchedulerManagerConfig struct {
    model             string
    deployPolicy      DeploymentPolicy        // mixed/separated
    predictType       PredictorType           // none/ema/lightgbm
    lbConfig          AlgorithmParams         // 负载均衡配置
    insSnapShotFreq   time.Duration
    insConnectType    string
    maxInsNumPerGS    int
    tokenizationRatio float64
    reqSurvivalDuration time.Duration
}
```

**关键方法**:

| 方法 | 功能 |
|------|------|
| `NewGlobalSchedulerManager` | 创建调度器管理器 |
| `Start` | 启动调度器 (启动各后台循环) |
| `Stop` | 停止调度器 |
| `registerInstance` | 注册实例 |
| `unregisterInstance` | 注���实例 |
| `handleSchedule` | 处理调度请求 |
| `PreprocessForSchedule` | 预处理 (分词、预测) |
| `HandleReqEvent` | 处理请求事件 |

#### 2.2.2 InstanceManager

**文件**: `internal/gs/instance_manager.go`

**职责**:
- 管理实例池 (insPool)
- 维护实例快照 (insSnapshots)
- 监控实例健康状态
- 管理请求的生命周期
- EMA 预测长度计算

**数据结构**:

```go
type InstanceManager struct {
    poolRWLock      sync.RWMutex
    insPool         map[string]*instance      // 实例池
    snapshotRWLock  sync.RWMutex
    insSnapshots    []*insSnapshot            // 实例快照
    emaRWLock       sync.RWMutex
    emaPredictLen   map[RequestType]int       // EMA预测长度
    insWG           *sync.WaitGroup
    snapWG          *sync.WaitGroup
    ctx             context.Context
    cancel          context.CancelFunc
    insSnapShotFreq time.Duration
    insConnectType  string
    hmacMgr         *crypto.HmacManager
    aesMgr          *crypto.AesManager
    cacheManager    *cachecenter.CacheManager
    runtimeMode     base.RuntimeMode
}
```

**关键方法**:

| 方法 | 功能 |
|------|------|
| `addInstance` | 添加实例到池 |
| `removeInstance` | 从池移除实例 |
| `updatePoolShot` | 更新实例快照 |
| `getSpecifiedSnaps` | 获取指定角色的实例快照 |
| `addReq` | 向实例添加请求 |
| `checkReqSurvival` | 检查请求存活状态 |
| `predictTokensByEMA` | EMA预测token数 |
| `loadInsFromCache` | 从缓存加载实例 |

#### 2.2.3 LoadBalancer

**文件**: `internal/gs/load_balancer.go`

**职责**:
- 定义负载均衡接口
- 实现多种负载均衡策略
- 支持 Prefill-Decode 分离模式的组合调度

**负载均衡类型**:

```go
const (
    LoadBalancerNone             LoadBalancerType = iota
    LoadBalancerRoundRobin                        // 轮询
    LoadBalancerLeastConn                         // 最少连接
    LoadBalancerCapacity                          // 容量感知
    LoadBalancerToken                             // Token感知
    LoadBalancerDecode                            // Decode专用
    LoadBalancerPrefillTimeAware                  // Prefill时间感知
)
```

**负载均衡接口**:

```go
type loadBalancer interface {
    schedule(request *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult
}
```

**策略实现**:

| 策略 | 结构体 | 选择逻辑 |
|------|--------|----------|
| RoundRobin | `rrLoadBalancer` | 按顺序轮询选择 |
| LeastConn | `leastConnLoadBalancer` | 选择请求数最少的实例 |
| Capacity | `capacityLoadBalancer` | 基于容量和延迟选择 |
| Token | `tokenLoadBalancer` | 基于token负载选择 |
| PrefillTimeAware | `prefillTimeLoadBalancer` | 基于预测prefill时间选择 |
| Decode | `decodeLoadBalancer` | Decode阶段专用策略 |
| PD | `pdLoadBalancer` | Prefill-Decode组合策略 |

---

### 2.3 缓存中心 (internal/cachecenter)

#### 2.3.1 CacheManager

**文件**: `internal/cachecenter/cache_manager.go`

**职责**:
- 管理本地缓存和远程缓存 (Redis)
- 请求信息的增删改查
- 实例指标管理
- 与 Redis 的同步 (增量合并)
- 过期请求清理

**数据结构**:

```go
type CacheManager struct {
    modelName       string
    cache           *localCache               // 本地缓存
    syncCh          chan *syncTask            // 同步通道
    remoteCache     CentralCache             // 远程缓存接口
    wg              *sync.WaitGroup
    ctx             context.Context
    cancel          context.CancelFunc
    refreshInterval time.Duration            // 刷新间隔
    reqTtl          time.Duration            // 请求TTL
    activeInstances sync.Map                 // 活跃实例
    deletedReqs     sync.Map                 // 已删除请求墓碑
}
```

**关键方法**:

| 方法 | 功能 |
|------|------|
| `AddRequest` | 添加请求到缓存 |
| `RemoveRequest` | 从缓存移除请求 |
| `UpdateRequestOnPrefillFinished` | Prefill完成时更新请求 |
| `RangeMetrics` | 遍历所有实例指标 |
| `EnsureInstanceMetrics` | 确保实例指标存在 |
| `rebuildCache` | 从Redis重建缓存 |
| `syncLoop` | 同步循环 |

---

### 2.4 HTTP 服务器 (internal/server)

#### 2.4.1 HttpServer

**文件**: `internal/server/http_server.go`

**职责**:
- 提供 HTTP RESTful API
- 处理并发限制
- 健康检查
- 统计接口

**API 端点**:

| 端点 | 方法 | 功能 |
|------|------|------|
| `/aigw/v1/health` | GET | 健康检查 |
| `/aigw/v1/register-instance` | POST | 注册实例 |
| `/aigw/v1/unregister-instance` | POST | 注销实例 |
| `/aigw/v1/openai/get-suggestion` | POST | 获取调度建议 |
| `/aigw/v1/stats` | GET | 获取统计信息 |

---

### 2.5 ZooKeeper 集成 (internal/zk)

#### 2.5.1 ZkManager

**文件**: `internal/zk/zk_manager.go`

**职责**:
- 与 ZooKeeper 建立连接
- 实例注册与发现
- 监听实例变化
- 服务发现回调

**关键方法**:

| 方法 | 功能 |
|------|------|
| `NewZkManager` | 创建 ZK 管理器 |
| `RegisterInstance` | 注册实例到 ZK |
| `WatchInstances` | 监听实例变化 |
| `GetInstances` | 获取所有实例 |

---

### 2.6 分词器 (internal/tokenizers)

**文件**: `internal/tokenizers/tokenizer.go`, `internal/tokenizers/hg_tokenizers.go`

**职责**:
- 集成 HuggingFace Tokenizers
- 文本编码/解码
- 支持 FF I 调用 Rust 实现

**接口**:

```go
type Tokenizer interface {
    Encode(text string) ([]uint, error)
    Decode(tokens []uint) (string, error)
    InitFromFile(path string) error
    Uninit()
}
```

---

### 2.7 统计模块 (internal/stats)

**文件**: `internal/stats/stats.go`

**职责**:
- 统计数据收集
- 支持多种统计类型
- 线程安全计数

**统计类型**:

```go
const (
    ScheduleSuccess StatType = iota
    ScheduleFailure
    TokenizerEncodeError
    LightGbmPredictError
    LbNoInstances
    // ... 更多类型
)
```

---

## 三、数据流与调用关系

### 3.1 请求调度流程

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           请求调度流程                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  HTTP Request (POST /v1/openai/get-suggestion)                             │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ HttpServer.scheduleForOpenAi                                         │   │
│  │   - 解析请求体                                                         │   │
│  │   - 构建 GetSuggestionIn                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ AigwManager.GetSuggestion                                             │   │
│  │   - 查找对应模型的 GlobalSchedulerManager                              │   │
│  │   - 调用 scheduleRequest                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ GlobalSchedulerManager.scheduleRequest                                │   │
│  │   - PreprocessForSchedule (分词、预测)                                 │   │
│  │   - 发送 ScheduleRequestMsg 到 scheduleChannel                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ GlobalSchedulerManager.handleSchedule                                 │   │
│  │   - 调用 scheduler.schedule (负载均衡)                                 │   │
│  │   - 返回 ScheduleResult                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ LoadBalancer.schedule                                                 │   │
│  │   - 获取实例快照                                                        │   │
│  │   - 根据策略选择实例                                                    │   │
│  │   - 返回 ScheduleResult                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       ▼                                                                     │
│  HTTP Response (ScheduleResult)                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 实例注册流程

```
ZooKeeper Watch Event
       │
       ▼
ZkManager 回调
       │
       ▼
AigwManager.RegisterInstance
       │
       ▼
GlobalSchedulerManager.registerInstance
       │
       ├── 验证实例数量限制
       ├── 验证部署策略
       └── InstanceManager.addInstance
              │
              ├── 创建 instance 结构
              ├── 启动实例连接 (SSE)
              └── 更新实例快照
```

---

## 四、与 vLLM Router 对比分析

### 4.1 架构对比

| 维度 | AIGW (Go) | vLLM Router (Rust) |
|------|-----------|-------------------|
| **语言** | Go | Rust |
| **部署模式** | SDK + 独立服务 | 独立服务 |
| **服务发现** | ZooKeeper | Kubernetes |
| **负载均衡** | 6种策略 | 5种策略 |
| **一致性哈希** | ❌ 不支持 | ✅ 支持 |
| **DP感知** | ❌ 不支持 | ✅ 支持 |
| **请求转发** | ❌ 仅输出建议 | ✅ 流式转发 |
| **K8s服务发现** | ❌ 不支持 | ✅ 支持 |
| **缓存** | Redis | 内置 (可选) |
| **延迟预测** | LightGBM | 无 |

### 4.2 功能差距分析

| 功能 | AIGW 当前状态 | vLLM Router | 影响 |
|------|--------------|-------------|------|
| 流式转发推理请求 | ❌ 无 | ✅ 有 | 无法作为真正的网关代理 |
| K8s 服务发现 | ❌ 无 | ✅ 有 | 无法在 K8s 环境自动发现 |
| DP Worker 支持 | ❌ 无 | ✅ 有 | 无法细粒度负载均衡 |
| 一致性哈希 | ❌ 无 | ✅ 有 | 会话亲和性差 |

### 4.3 优势对比

| 优势 | AIGW | vLLM Router |
|------|------|-------------|
| SDK 模式 | ✅ 支持 | ❌ 不支持 |
| C API | ✅ 支持 | ❌ 不支持 |
| 延迟预测 | ✅ LightGBM | ❌ 无 |
| 分词器集成 | ✅ HuggingFace | ❌ 无 |
| 统计监控 | ✅ 完善 | ⚠️ 基础 |

---

## 五、模块依赖关系

```
cmd/aigw/main.go
    │
    └── internal/server
              │
              ├── internal/core
              │         │
              │         ├── internal/gs
              │         │         │
              │         │         ├── internal/cachecenter
              │         │         ├── internal/stats
              │         │         ├── pkg/lightgbm
              │         │         └── pkg/crypto
              │         │
              │         ├── internal/tokenizers
              │         ├── internal/vectorizer
              │         └── pkg/crypto
              │
              └── internal/zk
```

---

## 六、配置结构

### 6.1 全局配置

```go
type AigwConfig struct {
    GlobalConfig   GlobalConfig
    ZkConfig       ZkConfig
    GsConfigs      []GlobalSchedulerConfig
    Predictor      PredictorConfig
    Tokenizers     []TokenizerConfig
    Limits         LimitsConfig
}
```

### 6.2 模型配置

```go
type GlobalSchedulerConfig struct {
    Model                string
    DeployPolicy         string         // mixed/separated
    MaxTimeToFirstToken  int            // 首token最大延迟
    MaxTimeBetweenTokens int            // token间最大延迟
    TokenizeModelName    string
    LoadBalancer         LoadBalancerConfig
    BlockSize            int
    CacheRefreshIntervalMs uint32
    TokenizationRatio    float64
}
```

---

## 七、总结

AIGW 是一个功能完善的 LLM 推理网关，具备：

1. **完善的调度能力**: 6种负载均衡策略，支持 Prefill-Decode 分离
2. **灵活的部署模式**: SDK 和独立服务两种模式
3. **智能预测**: LightGBM 延迟预测
4. **缓存管理**: Redis + 本地缓存
5. **服务发现**: ZooKeeper 集成

需要增强的功能：

1. **流式转发**: 支持 HTTP SSE 流式转发推理请求
2. **K8s 服务发现**: 支持 Kubernetes 环境自动发现
3. **DP Worker**: 支持 DP 感知的负载均衡
4. **一致性哈希**: 支持会话亲和性

---

*文档生成时间: 2026-04-29*
