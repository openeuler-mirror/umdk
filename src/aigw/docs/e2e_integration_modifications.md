# AIGW 端到端功能集成修改方案

**实施日期**: 2026-05-08
**目的**: 将新增的四个功能模块集成到主流程，实现端到端功能打通

---

## 一、修改摘要

| 优先级 | 修改项 | 涉及文件 | 状态 |
|--------|--------|----------|------|
| P0 | 添加配置结构字段 | `aigw_type.go`, `msg_type.go` | ✅ 完成 |
| P1 | 集成K8s服务发现 | `server.go` | ✅ 完成 |
| P1 | 集成Proxy转发 | `http_server.go` | ✅ 完成 |
| P2 | 打通DpRank传递链 | `dispatcher.go`, `aigw_manager.go` | ✅ 完成 |
| P2 | 添加配置验证和默认值 | `config_manager.go` | ✅ 完成 |

---

## 二、详细修改内容

### 2.1 配置结构修改 (P0)

#### 文件: `internal/base/aigw_type.go`

**修改1: GetSuggestionOut 添加 DpRank 字段**
```go
type GetSuggestionOut struct {
    TargetPrefillUrl string `json:"targetPrefill"`
    TargetDecodeUrl  string `json:"targetDecode"`
    DpRank           *int   `json:"dpRank,omitempty"` // DP rank for data parallel routing
}
```

**修改2: LoadBalancerConfig 添加一致性Hash配置字段**
```go
type LoadBalancerConfig struct {
    // ... 现有字段 ...
    VirtualNodes int `json:"virtualNodes"` // Number of virtual nodes per worker (default: 160)
    FallbackNum  int `json:"fallbackNum"`  // Number of fallback nodes on hash miss (default: 3)
    DpSize       int `json:"dpSize"`       // Data parallel size for DP-aware routing
}
```

**修改3: 新增 DiscoveryConfig 结构**
```go
type DiscoveryConfig struct {
    Type           string `json:"type"`           // Discovery type: "k8s", "dns", "zk"
    KubeconfigPath string `json:"kubeconfigPath"` // K8s kubeconfig path
    Namespace      string `json:"namespace"`      // K8s namespace to watch
    ResyncPeriod   int    `json:"resyncPeriod"`  // Resync period in seconds
    Enable         bool   `json:"enable"`        // Enable service discovery
}
```

**修改4: 新增 ProxyConfig 和 CircuitBreakerConfig 结构**
```go
type ProxyConfig struct {
    Timeout           int  `json:"timeout"`           // Request timeout in seconds
    MaxRetry          int  `json:"maxRetry"`          // Maximum retry attempts
    RetryBaseInterval int  `json:"retryBaseInterval"` // Retry base interval in milliseconds
    RetryMaxInterval  int  `json:"retryMaxInterval"`  // Retry max interval in milliseconds
    Enable            bool `json:"enable"`            // Enable request forwarding
    CircuitBreaker    CircuitBreakerConfig `json:"circuitBreaker"`
}

type CircuitBreakerConfig struct {
    Enabled          bool `json:"enabled"`
    FailureThreshold int  `json:"failureThreshold"`
    SuccessThreshold int  `json:"successThreshold"`
    Timeout          int  `json:"timeout"`
}
```

**修改5: AigwConfig 添加 Discovery 和 Proxy 字段**
```go
type AigwConfig struct {
    // ... 现有字段 ...
    Discovery      DiscoveryConfig `json:"discovery"`
    Proxy          ProxyConfig     `json:"proxy"`
}
```

#### 文件: `internal/gs/msg_type.go`

**修改: SuggestionResultMsg 添加 DpRank 字段**
```go
type SuggestionResultMsg struct {
    PrefillUrl string
    DecodeUrl  string
    DpRank     *int // DP rank for data parallel routing
}
```

---

### 2.2 DpRank传递链打通 (P2)

#### 文件: `internal/gs/dispatcher.go`

**修改: executeDispatching 函数保留 DpRank**
```go
func (d *globalScheduleDispatcher) executeDispatching(result *ScheduleResult, response chan<- interface{}) {
    if result == nil {
        response <- &SuggestionResultMsg{
            PrefillUrl: "",
            DecodeUrl:  "",
            DpRank:     nil,
        }
        return
    }

    response <- &SuggestionResultMsg{
        PrefillUrl: result.PrefillUrl,
        DecodeUrl:  result.DecodeUrl,
        DpRank:     result.DpRank,
    }
}
```

#### 文件: `internal/core/aigw_manager.go`

**修改1: scheduleRequest 函数传递 DpRank**
```go
case *gs.SuggestionResultMsg:
    return &base.GetSuggestionOut{
        TargetPrefillUrl: result.PrefillUrl,
        TargetDecodeUrl:  result.DecodeUrl,
        DpRank:           result.DpRank,
    }, nil
```

**修改2: 新增 GetContext 方法**
```go
func (manager *AigwManager) GetContext() context.Context {
    return manager.ctx
}
```

---

### 2.3 K8s服务发现集成 (P1)

#### 文件: `internal/server/server.go`

**修改1: 添加导入**
```go
import (
    // ... 现有导入 ...
    "time"
    "huawei.com/aigw/internal/discovery"
    "huawei.com/aigw/internal/proxy"
)
```

**修改2: aigwServerHandler 添加 discovery 和 proxy 字段**
```go
type aigwServerHandler struct {
    // ... 现有字段 ...
    discoveryMgr *discovery.ServiceRegistry
    k8sDiscovery  discovery.ServiceDiscovery
    proxyMgr     *proxy.ProxyManager
}
```

**修改3: 新增 initDiscovery 函数**
```go
func initDiscovery(cfg *base.DiscoveryConfig) (discovery.ServiceDiscovery, *discovery.ServiceRegistry, error) {
    if !cfg.Enable {
        return nil, nil, nil
    }

    var disc discovery.ServiceDiscovery
    var err error

    switch cfg.Type {
    case "k8s":
        disc, err = discovery.NewK8sDiscovery(&discovery.DiscoveryConfig{
            Type:          cfg.Type,
            KubeconfigPath: cfg.KubeconfigPath,
            Namespace:     cfg.Namespace,
            ResyncPeriod:  time.Duration(cfg.ResyncPeriod) * time.Second,
        })
    default:
        return nil, nil, fmt.Errorf("unsupported discovery type: %s", cfg.Type)
    }

    registry := discovery.NewServiceRegistry(disc)
    return disc, registry, nil
}
```

**修改4: 新增 startDiscoveryWatch 函数**
- 监听服务发现事件
- 自动注册/注销实例到 AigwManager

**修改5: startManagers 中初始化 discovery 和 proxy**
```go
// Initialize service discovery
if discoveryCfg.Enable {
    k8sDisc, discoveryMgr, err := initDiscovery(&discoveryCfg)
    serverHandler.k8sDiscovery = k8sDisc
    serverHandler.discoveryMgr = discoveryMgr
    startDiscoveryWatch(serverHandler.aigwMgr.GetContext(), discoveryMgr, serverHandler.aigwMgr, discoveryCfg.Namespace)
}

// Initialize proxy manager
if proxyCfg.Enable {
    serverHandler.proxyMgr = proxy.NewProxyManager(...)
}
```

**修改6: stopManagers 中清理 discovery 和 proxy**
```go
if serverHandler.discoveryMgr != nil {
    serverHandler.discoveryMgr.StopDiscovery()
}
if serverHandler.k8sDiscovery != nil {
    serverHandler.k8sDiscovery.Close()
}
if serverHandler.proxyMgr != nil {
    serverHandler.proxyMgr.Stop()
}
```

---

### 2.4 Proxy转发集成 (P1)

#### 文件: `internal/server/http_server.go`

**修改1: 添加导入**
```go
import (
    // ... 现有导入 ...
    "io"
    "huawei.com/aigw/internal/proxy"
)
```

**修改2: HttpServer 添加 proxyMgr 字段**
```go
type HttpServer struct {
    // ... 现有字段 ...
    proxyMgr *proxy.ProxyManager
}
```

**修改3: 修改 NewHttpServer**
```go
func NewHttpServer(manager *core.AigwManager, host string, port string, proxyMgr *proxy.ProxyManager) *HttpServer
```

**修改4: Start 函数添加转发路由**
```go
if s.proxyMgr != nil {
    mx.HandleFunc("/aigw/v1/openai/chat/completions",
        s.serHmacMgr.WithHMAC(s.serAesMgr.WithAesDecrypt(s.forwardChatCompletions)))
}
```

**修改5: 新增 forwardChatCompletions 函数**
- 解析请求获取 model 和 stream 标志
- 调用 GetSuggestion 获取调度建议
- 构建 ForwardRequest 并执行转发
- 处理流式/非流式响应

---

### 2.5 配置验证和默认值 (P2)

#### 文件: `internal/core/config_manager.go`

**修改1: resetDefault 添加 Discovery 和 Proxy 默认值**
```go
// Discovery defaults
if discoveryCfg.Enable {
    if discoveryCfg.ResyncPeriod == 0 {
        discoveryCfg.ResyncPeriod = 30
    }
    if discoveryCfg.Namespace == "" {
        discoveryCfg.Namespace = "default"
    }
}

// Proxy defaults
if proxyCfg.Enable {
    if proxyCfg.Timeout == 0 {
        proxyCfg.Timeout = 30
    }
    // ... 其他默认值
}

// LoadBalancer consistent hash defaults
for i := range cfg.GsConfigs {
    if lbCfg.VirtualNodes == 0 {
        lbCfg.VirtualNodes = 160
    }
    if lbCfg.FallbackNum == 0 {
        lbCfg.FallbackNum = 3
    }
}
```

**修改2: 添加 consistentHash 到有效负载均衡类型**
```go
var validCommonLBTypes = map[string]bool{
    // ... 现有类型 ...
    "consistentHash": true,
}
```

**修改3: 新增 validateDiscoveryConfig 函数**
- 验证 discovery type (k8s/dns/zk)
- 验证 kubeconfig 路径
- 验证 resync period

**修改4: 新增 validateProxyConfig 函数**
- 验证 timeout, maxRetry
- 验证重试间隔配置
- 验证熔断器配置

**修改5: ValidateConfig 调用新增验证函数**
```go
if err := validateDiscoveryConfig(&config.Discovery); err != nil {
    return err
}
if err := validateProxyConfig(&config.Proxy); err != nil {
    return err
}
```

---

## 三、配置示例

```json
{
  "global": {
    "host": "127.0.0.1",
    "port": "8888",
    "logLevel": "debug"
  },
  "discovery": {
    "type": "k8s",
    "namespace": "vllm",
    "enable": true
  },
  "proxy": {
    "timeout": 30,
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

---

## 四、端到端流程

### 4.1 调度建议模式 (原有)

```
客户端请求 → AIGW HTTP Server
                ↓
           调度器选择最优节点
                ↓
           返回 {targetPrefill: "http://worker:8000", dpRank: 0}
                ↓
           客户端自行请求 worker
```

### 4.2 代理转发模式 (新增)

```
客户端请求 → AIGW HTTP Server (/aigw/v1/openai/chat/completions)
                ↓
           调度器选择最优节点
                ↓
           ProxyManager.ForwardRequest()
                ↓
           转发到 worker (注入 X-data-parallel-rank header)
                ↓
           流式/非流式响应返回客户端
```

### 4.3 K8s服务发现模式 (新增)

```
K8s Endpoints 变化
        ↓
K8sDiscovery.Watch() 监听
        ↓
ServiceRegistry 处理事件
        ↓
自动 RegisterInstance/UnregisterInstance
        ↓
AigwManager 更新实例列表
```

---

## 五、验证清单

- [x] 配置结构添加 Discovery、Proxy、LoadBalancer 扩展字段
- [x] SuggestionResultMsg 和 GetSuggestionOut 添加 DpRank
- [x] DpRank 传递链打通 (ScheduleResult → SuggestionResultMsg → GetSuggestionOut)
- [x] K8s 服务发现初始化和事件监听
- [x] Proxy 转发初始化和转发端点
- [x] 配置默认值和验证
- [x] 编译验证通过
- [x] 单元测试通过
- [x] Mock 服务器实现 (test/mock_e2e_server.py)
- [ ] 集成测试通过 (使用 mock 服务器运行 test_e2e_client.py)

---

*文档生成时间: 2026-05-08*
