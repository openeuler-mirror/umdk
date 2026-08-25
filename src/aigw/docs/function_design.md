# AIGW 功能增强设计文档

## 一、概述

本文档详细设计 AIGW 需要增强的四个核心功能：
1. 流式转发推理请求
2. k8s服务发现
3. DP worker 支持
4. 一致性hash算法

每个功能的设计参考 vLLM Router 的实现，并结合 AIGW 现有架构进行适配。

---

## 二、流式转发推理请求设计

### 2.1 功能概述

**当前状态**: AIGW 仅输出调度建议 (ScheduleResult)，不实际转发请求到后端 Worker。

**目标**: 支持流式 (SSE) 转发推理请求到后端 vLLM Worker，实现真正的网关代理功能。

### 2.2 vLLM Router 参考实现

vLLM Router 在 `src/routers/http/router.rs` 中实现请求转发：

```rust
// src/routers/http/router.rs:766-838
async fn send_typed_request<T>(
    &self,
    headers: Option<&HeaderMap>,
    typed_req: &T,
    route: &str,      // "/v1/chat/completions"
    worker_url: &str, // "http://worker1:8000@2"
    ...
) -> Response {
    // 6.1 提取DP Rank
    let (request_builder, extracted_dp_rank, request_url) =
        if self.intra_node_data_parallel_size > 1 {
            // 解析: "http://worker1:8000@2" → ("http://worker1:8000", 2)
            let (worker_url_prefix, dp_rank) = dp_utils::extract_dp_rank(worker_url)?;
            // 构造请求URL (不含@rank)
            let request_url = format!("{}{}", worker_url_prefix, route);
            // "http://worker1:8000/v1/chat/completions"
            ...
        } else { ... };

    // 6.2 复制原始Headers
    if let Some(headers) = headers {
        for (name, value) in headers {
            request_builder = request_builder.header(name, value);
        }
    }

    // 6.3 注入 X-data-parallel-rank Header
    if let Some(dp_rank) = extracted_dp_rank {
        request_builder = request_builder.header("X-data-parallel-rank", dp_rank.to_string());
    }

    // 6.4 发送HTTP请求
    let res = otel_http::send_client_request(request_builder, ...).await;
    res
}
```

**关键特性**:
1. **流式响应**: 使用 HTTP SSE (Server-Sent Events)
2. **Header 透传**: 原始请求头完整透传
3. **DP Header 注入**: 自动注入 `X-data-parallel-rank`
4. **超时重试**: RetryExecutor 包装

### 2.3 AIGW 设计方案

#### 2.3.1 新增模块结构

```
internal/proxy/
├── proxy.go              // 代理管理器
├── stream_reader.go      // SSE 流式读取器
├── request_forwarder.go  // 请求转发器
└── response_writer.go    // 响应写入器
```

#### 2.3.2 核心数据结构

```go
// internal/proxy/proxy.go

package proxy

import (
    "context"
    "net/http"
    "sync"
    "time"

    "huawei.com/aigw/internal/base"
    "huawei.com/aigw/pkg/log"
)

// ProxyManager 管理请求代理
type ProxyManager struct {
    ctx           context.Context
    cancel        context.CancelFunc
    rwLock        sync.RWMutex
    client        *http.Client               // HTTP客户端
    timeout       time.Duration              // 请求超时
    maxRetry      int                        // 最大重试次数
    circuitBreaker *CircuitBreaker           // 熔断器
}

// ForwardRequest 转发请求参数
type ForwardRequest struct {
    Method        string                     // HTTP方法
    TargetURL     string                     // 目标URL (不含DP rank)
    Route         string                     // API路由 (如 /v1/chat/completions)
    Headers       http.Header                // 原始请求头
    Body          []byte                     // 请求体
    DpRank        *int                       // DP rank (可选)
    Stream        bool                       // 是否流式
}

// ForwardResult 转发结果
type ForwardResult struct {
    StatusCode    int
    Headers       http.Header
    Body          []byte                     // 非流式时
    StreamReader  *StreamReader             // 流式时
    Error         error
}
```

#### 2.3.3 流式转发实现

```go
// internal/proxy/request_forwarder.go

// ForwardRequest 转发HTTP请求
func (pm *ProxyManager) ForwardRequest(ctx context.Context, req *ForwardRequest) (*ForwardResult, error) {
    // 1. 构造完整URL
    targetURL := req.TargetURL + req.Route

    // 2. 创建HTTP请求
    httpReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, bytes.NewReader(req.Body))
    if err != nil {
        return nil, fmt.Errorf("create request failed: %w", err)
    }

    // 3. 透传原始Headers
    for key, values := range req.Headers {
        for _, value := range values {
            httpReq.Header.Add(key, value)
        }
    }

    // 4. 注入DP Rank Header
    if req.DpRank != nil {
        httpReq.Header.Set("X-data-parallel-rank", strconv.Itoa(*req.DpRank))
    }

    // 5. 设置Content-Type
    if httpReq.Header.Get("Content-Type") == "" {
        httpReq.Header.Set("Content-Type", "application/json")
    }

    // 6. 发送请求
    resp, err := pm.client.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("send request failed: %w", err)
    }

    // 7. 处理响应
    result := &ForwardResult{
        StatusCode: resp.StatusCode,
        Headers:    resp.Header,
    }

    // 8. 流式响应
    if req.Stream {
        result.StreamReader = NewStreamReader(resp.Body)
        return result, nil
    }

    // 9. 非流式响应
    defer resp.Body.Close()
    result.Body, err = io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("read response failed: %w", err)
    }

    return result, nil
}
```

#### 2.3.4 SSE 流式读取器

```go
// internal/proxy/stream_reader.go

// StreamReader SSE流式读取器
type StreamReader struct {
    reader   *bufio.Reader
    closed   bool
    mu       sync.Mutex
    closeCh  chan struct{}
}

// NewStreamReader 创建流式读取器
func NewStreamReader(body io.ReadCloser) *StreamReader {
    return &StreamReader{
        reader:  bufio.NewReader(body),
        closeCh: make(chan struct{}),
    }
}

// ReadEvent 读取下一个SSE事件
func (sr *StreamReader) ReadEvent() (*SSEEvent, error) {
    sr.mu.Lock()
    defer sr.mu.Unlock()

    if sr.closed {
        return nil, io.EOF
    }

    event := &SSEEvent{}

    for {
        line, err := sr.reader.ReadString('\n')
        if err != nil {
            return nil, err
        }

        line = strings.TrimSpace(line)

        // 空行表示事件结束
        if line == "" {
            if event.Data != "" {
                return event, nil
            }
            continue
        }

        // 解析SSE字段
        parts := strings.SplitN(line, ": ", 2)
        if len(parts) < 2 {
            continue
        }

        switch parts[0] {
        case "event":
            event.Event = parts[1]
        case "data":
            if event.Data != "" {
                event.Data += "\n"
            }
            event.Data += parts[1]
        case "id":
            event.ID = parts[1]
        case "retry":
            event.Retry, _ = strconv.Atoi(parts[1])
        }
    }
}

// SSEEvent SSE事件结构
type SSEEvent struct {
    Event string
    Data  string
    ID    string
    Retry int
}
```

#### 2.3.5 HTTP服务器集成

修改 `internal/server/http_server.go`:

```go
// 新增API端点
func (s *HttpServer) Start() error {
    mx := http.NewServeMux()
    // ... 现有端点 ...

    // 新增: 流式转发端点
    mx.HandleFunc("/v1/chat/completions", s.proxyManager.WithProxy(s.forwardChatCompletion))
    mx.HandleFunc("/v1/completions", s.proxyManager.WithProxy(s.forwardCompletion))
    mx.HandleFunc("/v1/embeddings", s.proxyManager.WithProxy(s.forwardEmbeddings))

    // ...
}

// forwardChatCompletion 转发聊天完成请求
func (s *HttpServer) forwardChatCompletion(w http.ResponseWriter, r *http.Request) {
    // 1. 解析请求
    var req base.ChatCompletionRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // 2. 获取调度建议
    scheduleResult, err := s.manager.GetSuggestion(&core.GetSuggestionIn{
        Model:  req.Model,
        Prompt: processMessages(req.Messages),
    })
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // 3. 构造转发请求
    forwardReq := &proxy.ForwardRequest{
        Method:    "POST",
        TargetURL: scheduleResult.PrefillUrl,
        Route:     "/v1/chat/completions",
        Headers:   r.Header,
        Body:      reqBytes,
        Stream:    req.Stream != nil && *req.Stream,
    }

    // 4. 转发请求
    result, err := s.proxyManager.ForwardRequest(r.Context(), forwardReq)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }

    // 5. 写回响应
    if result.StreamReader != nil {
        // 流式响应
        s.writeStreamResponse(w, result)
    } else {
        // 非流式响应
        s.writeResponse(w, result)
    }
}
```

### 2.4 接口变更

#### 2.4.1 新增配置

```go
type ProxyConfig struct {
    Enabled           bool          // 是否启用代理
    Timeout           time.Duration // 请求超时
    MaxRetry          int           // 最大重试
    RetryInterval     time.Duration // 重试间隔
    CircuitBreaker    CircuitBreakerConfig // 熔断器配置
}

type CircuitBreakerConfig struct {
    Enabled           bool
    FailureThreshold  int
    SuccessThreshold  int
    Timeout           time.Duration
}
```

#### 2.4.2 新增API端点

| 端点 | 方法 | 功能 |
|------|------|------|
| `/v1/chat/completions` | POST | 转发聊天完成请求 |
| `/v1/completions` | POST | 转发文本完成请求 |
| `/v1/embeddings` | POST | 转发嵌入请求 |

---

## 三、k8s服务发现设计

### 3.1 功能概述

**当前状态**: AIGW 仅支持 ZooKeeper 服务发现。

**目标**: 支持 Kubernetes 环境自动发现 vLLM Worker Pod。

### 3.2 vLLM Router 参考实现

vLLM Router 在 `src/routers/http/vllm_pd_router.rs` 中支持服务发现:

```rust
// src/routers/http/vllm_pd_router.rs
pub struct VllmPDRouter {
    pd_router: PDRouter,
    service_registry: Arc<ServiceRegistry>,  // 服务注册表
    use_discovery: bool,                      // 是否使用服务发现
    kv_connector: KvConnector,                // KV连接器
    ...
}

// Kubernetes服务发现
fn discover_services(&self) -> Result<Vec<WorkerUrl>, String> {
    // 通过 K8s API 或 DNS 发现服务
    // 支持 label selector 过滤
    ...
}
```

### 3.3 AIGW 设计方案

#### 3.3.1 新增模块结构

```
internal/discovery/
├── discovery.go           // 服务发现接口
├── k8s_discovery.go       // Kubernetes 发现实现
├── dns_discovery.go       // DNS 发现实现
├── service_watcher.go     // 服务监听器
└── service_registry.go    // 服务注册表
```

#### 3.3.2 核心数据结构

```go
// internal/discovery/discovery.go

package discovery

import (
    "context"
    "time"

    "huawei.com/aigw/internal/base"
)

// ServiceDiscovery 服务发现接口
type ServiceDiscovery interface {
    // Discover 发现服务实例
    Discover(ctx context.Context, opts *DiscoverOptions) ([]*ServiceInstance, error)

    // Watch 监听服务变化
    Watch(ctx context.Context, opts *DiscoverOptions) (<-chan WatchEvent, error)

    // Close 关闭
    Close() error
}

// ServiceInstance 服务实例
type ServiceInstance struct {
    ID         string               // 实例ID
    Name       string               // 服务名
    Namespace  string               // K8s命名空间
    IP         string               // IP地址
    Port       int                  // 端口
    Role       base.InstanceRole    // 实例角色
    Labels     map[string]string    // 标签
    Annotations map[string]string  // 注解
    Healthy    bool                 // 健康状态
}

// DiscoverOptions 发现选项
type DiscoverOptions struct {
    Namespace     string            // 命名空间
    ServiceName   string            // 服务名
    LabelSelector map[string]string // 标签选择器
    Role          base.InstanceRole // 角色过滤
}

// WatchEvent 监听事件
type WatchEvent struct {
    Type     WatchEventType  // ADD/MODIFY/DELETE
    Instance *ServiceInstance
}

type WatchEventType int

const (
    WatchEventAdd WatchEventType = iota
    WatchEventModify
    WatchEventDelete
)
```

#### 3.3.3 Kubernetes 发现实现

```go
// internal/discovery/k8s_discovery.go

import (
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/informers"
    "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// K8sDiscovery Kubernetes服务发现
type K8sDiscovery struct {
    clientset  *kubernetes.Clientset
    informer   informers.SharedInformerFactory
    config     *K8sDiscoveryConfig
}

type K8sDiscoveryConfig struct {
    KubeconfigPath string            // kubeconfig路径 (集群内为空)
    ResyncPeriod   time.Duration     // 同步周期
    Namespace      string            // 命名空间 (空为所有)
}

// NewK8sDiscovery 创建K8s服务发现
func NewK8sDiscovery(config *K8sDiscoveryConfig) (*K8sDiscovery, error) {
    var clientset *kubernetes.Clientset
    var err error

    if config.KubeconfigPath == "" {
        // 集群内: 使用 in-cluster config
        clientset, err = k8s.NewInClusterClient()
    } else {
        // 集群外: 使用 kubeconfig
        clientset, err = k8s.NewClientFromConfig(config.KubeconfigPath)
    }

    if err != nil {
        return nil, err
    }

    return &K8sDiscovery{
        clientset: clientset,
        config:    config,
    }, nil
}

// Discover 发现服务实例
func (kd *K8sDiscovery) Discover(ctx context.Context, opts *DiscoverOptions) ([]*ServiceInstance, error) {
    // 1. 获取Endpoints
    endpoints, err := kd.clientset.CoreV1().Endpoints(opts.Namespace).List(ctx, metav1.ListOptions{
        LabelSelector: buildLabelSelector(opts.LabelSelector),
    })
    if err != nil {
        return nil, err
    }

    // 2. 转换为ServiceInstance
    var instances []*ServiceInstance
    for _, ep := range endpoints.Items {
        for _, subset := range ep.Subsets {
            for _, addr := range subset.Addresses {
                for _, port := range subset.Ports {
                    instance := &ServiceInstance{
                        ID:        string(ep.UID) + "-" + addr.IP,
                        Name:      ep.Name,
                        Namespace: ep.Namespace,
                        IP:        addr.IP,
                        Port:      int(port.Port),
                        Labels:    ep.Labels,
                        Healthy:   true,
                    }

                    // 解析角色
                    if role, ok := ep.Labels["role"]; ok {
                        instance.Role, _ = base.ToInstanceRole(role)
                    }

                    // 角色过滤
                    if opts.Role != base.InvalidRoleInstance && instance.Role != opts.Role {
                        continue
                    }

                    instances = append(instances, instance)
                }
            }
        }
    }

    return instances, nil
}

// Watch 监听服务变化
func (kd *K8sDiscovery) Watch(ctx context.Context, opts *DiscoverOptions) (<-chan WatchEvent, error) {
    eventCh := make(chan WatchEvent, 100)

    // 使用 Informer 监听
    factory := informers.NewSharedInformerFactoryWithOptions(
        kd.clientset,
        kd.config.ResyncPeriod,
        informers.WithNamespace(opts.Namespace),
    )

    endpointsInformer := factory.Core().V1().Endpoints().Informer()

    endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(obj interface{}) {
            ep := obj.(*v1.Endpoints)
            for _, instance := range endpointsToInstances(ep, opts) {
                select {
                case eventCh <- WatchEvent{Type: WatchEventAdd, Instance: instance}:
                default:
                }
            }
        },
        UpdateFunc: func(old, new interface{}) {
            // 处理更新
            ...
        },
        DeleteFunc: func(obj interface{}) {
            // 处理删除
            ...
        },
    })

    factory.Start(ctx.Done())

    return eventCh, nil
}
```

#### 3.3.4 DNS 发现实现

```go
// internal/discovery/dns_discovery.go

// DNSDiscovery DNS服务发现 (适用于 Headless Service)
type DNSDiscovery struct {
    resolver *net.Resolver
    config   *DNSDiscoveryConfig
}

type DNSDiscoveryConfig struct {
    DNSHost     string        // DNS服务器
    LookupTimeout time.Duration
}

// Discover 通过DNS SRV记录发现服务
func (dd *DNSDiscovery) Discover(ctx context.Context, opts *DiscoverOptions) ([]*ServiceInstance, error) {
    // SRV记录格式: _service._proto.namespace.svc.cluster.local
    srvName := fmt.Sprintf("_%s._tcp.%s.%s.svc.cluster.local",
        opts.ServiceName, opts.Namespace, "cluster.local")

    // 查询SRV记录
    _, addrs, err := dd.resolver.LookupSRV(ctx, "tcp", opts.Namespace, srvName)
    if err != nil {
        return nil, err
    }

    var instances []*ServiceInstance
    for _, addr := range addrs {
        instance := &ServiceInstance{
            ID:     fmt.Sprintf("%s:%d", addr.Target, addr.Port),
            Name:   opts.ServiceName,
            IP:     strings.TrimSuffix(addr.Target, "."),
            Port:   int(addr.Port),
            Healthy: true,
        }
        instances = append(instances, instance)
    }

    return instances, nil
}
```

#### 3.3.5 服务注册表集成

```go
// internal/discovery/service_registry.go

// ServiceRegistry 服务注册表
type ServiceRegistry struct {
    mu         sync.RWMutex
    instances  map[string]*ServiceInstance  // ID -> Instance
    watchers   []chan WatchEvent
    discovery  ServiceDiscovery
}

// StartDiscovery 启动服务发现
func (sr *ServiceRegistry) StartDiscovery(ctx context.Context, opts *DiscoverOptions) error {
    eventCh, err := sr.discovery.Watch(ctx, opts)
    if err != nil {
        return err
    }

    go func() {
        for event := range eventCh {
            sr.handleEvent(event)
        }
    }()

    return nil
}

// handleEvent 处理监听事件
func (sr *ServiceRegistry) handleEvent(event WatchEvent) {
    sr.mu.Lock()
    defer sr.mu.Unlock()

    switch event.Type {
    case WatchEventAdd:
        sr.instances[event.Instance.ID] = event.Instance
        log.Info().Msgf("discovered instance: %s", event.Instance.ID)

    case WatchEventModify:
        sr.instances[event.Instance.ID] = event.Instance

    case WatchEventDelete:
        delete(sr.instances, event.Instance.ID)
        log.Info().Msgf("removed instance: %s", event.Instance.ID)
    }

    // 通知所有监听者
    for _, ch := range sr.watchers {
        select {
        case ch <- event:
        default:
        }
    }
}

// GetInstances 获取所有实例
func (sr *ServiceRegistry) GetInstances(role base.InstanceRole) []*ServiceInstance {
    sr.mu.RLock()
    defer sr.mu.RUnlock()

    var result []*ServiceInstance
    for _, inst := range sr.instances {
        if role == base.InvalidRoleInstance || inst.Role == role {
            result = append(result, inst)
        }
    }
    return result
}
```

### 3.4 配置变更

```go
type DiscoveryConfig struct {
    Type       string            // "k8s", "dns", "zk"
    K8s        K8sDiscoveryConfig
    DNS        DNSDiscoveryConfig
    Zk         ZkConfig
    PollInterval time.Duration   // 轮询间隔 (DNS用)
}

type K8sDiscoveryConfig struct {
    Enabled        bool
    KubeconfigPath string
    Namespace      string
    LabelSelector  map[string]string
    ResyncPeriod   time.Duration
}
```

---

## 四、DP Worker 支持设计

### 4.1 功能概述

**当前状态**: AIGW 不支持 DP (Data Parallel) Worker。

**目标**: 支持 DP Worker，实现细粒度负载均衡。

### 4.2 vLLM Router 参考实现

vLLM Router 在 `src/core/worker.rs` 中实现 DP Worker:

```rust
// src/core/worker.rs:548-572
pub struct DPAwareWorker {
    base_worker: BasicWorker,  // 底层worker
    dp_rank: usize,            // DP rank
    dp_size: usize,            // DP组大小
    base_url: String,          // 无DP后缀的基础URL
}

impl DPAwareWorker {
    pub fn new(base_url: String, dp_rank: usize, dp_size: usize, ...) -> Self {
        // 创建带DP rank后缀的URL用于标识
        let worker_url = format!("{}@{}", base_url, dp_rank);
        // ...
    }

    pub fn url(&self) -> String {
        format!("{}@{}", self.base_url, self.dp_rank)  // 标识URL
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone()  // 基础URL (无@rank)
    }

    pub fn endpoint_url(&self, route: &str) -> String {
        format!("{}{}", self.base_url, route)  // 实际请求URL (无@rank)
    }

    pub fn dp_rank(&self) -> Option<usize> {
        Some(self.dp_rank)
    }
}

// DP扩展
// src/routers/http/dp_utils.rs:26-48
pub async fn get_dp_aware_workers(
    worker_urls: &[String],
    dp_size: usize,
) -> Result<Vec<String>, String> {
    let mut dp_aware_workers: Vec<String> = Vec::new();
    for url in worker_urls {
        // 每个物理worker扩展为dp_size个DP感知worker
        for rank in 0..dp_size {
            dp_aware_workers.push(format!("{}@{}", url, rank));
        }
    }
    Ok(dp_aware_workers)
}
```

**URL格式**:
- 标识URL: `http://worker:8000@2` (含@rank，用于一致性hash)
- 请求URL: `http://worker:8000/v1/chat/completions` (无@rank，实际发送)

### 4.3 AIGW 设计方案

#### 4.3.1 核心数据结构

```go
// internal/gs/dp_worker.go

package gs

import (
    "fmt"
    "strings"

    "huawei.com/aigw/internal/base"
)

// DPAwareWorker DP感知Worker
type DPAwareWorker struct {
    BaseWorker   *instance          // 底层实例
    DpRank       int                // DP rank (0, 1, 2, ...)
    DpSize       int                // DP组大小
    BaseURL      string             // 基础URL (无@rank)
    InsRole      base.InstanceRole  // 实例角色
    GroupID      string             // 组ID
}

// NewDPAwareWorker 创建DP感知Worker
func NewDPAwareWorker(baseURL string, dpRank, dpSize int, role base.InstanceRole, groupID string) *DPAwareWorker {
    return &DPAwareWorker{
        DpRank:  dpRank,
        DpSize:  dpSize,
        BaseURL: baseURL,
        InsRole: role,
        GroupID: groupID,
    }
}

// URL 获取标识URL (含@rank)
func (dw *DPAwareWorker) URL() string {
    return fmt.Sprintf("%s@%d", dw.BaseURL, dw.DpRank)
}

// BaseURL2 获取基础URL (无@rank)
func (dw *DPAwareWorker) BaseURL2() string {
    return dw.BaseURL
}

// EndpointURL 获取实际请求URL (无@rank)
func (dw *DPAwareWorker) EndpointURL(route string) string {
    return fmt.Sprintf("%s%s", dw.BaseURL, route)
}

// DpRankOpt 获取DP rank (可选)
func (dw *DPAwareWorker) DpRankOpt() *int {
    return &dw.DpRank
}
```

#### 4.3.2 DP工具函数

```go
// internal/gs/dp_utils.go

// GetDPAwareWorkers 扩展Worker URL为DP感知格式
func GetDPAwareWorkers(workerURLs []string, dpSize int) []string {
    var dpAwareWorkers []string
    for _, url := range workerURLs {
        // 每个物理worker扩展为dpSize个DP感知worker
        for rank := 0; rank < dpSize; rank++ {
            dpAwareWorkers = append(dpAwareWorkers, fmt.Sprintf("%s@%d", url, rank))
        }
    }
    return dpAwareWorkers
}

// ExtractDpRank 从URL提取DP rank
func ExtractDpRank(workerURL string) (baseURL string, dpRank *int, err error) {
    parts := strings.Split(workerURL, "@")
    if len(parts) != 2 {
        // 无DP rank
        return workerURL, nil, nil
    }

    rank, err := strconv.Atoi(parts[1])
    if err != nil {
        return "", nil, fmt.Errorf("invalid dp rank: %s", parts[1])
    }

    return parts[0], &rank, nil
}

// ParseDPAwareWorkerURL 解析DP感知Worker URL
func ParseDPAwareWorkerURL(url string) (baseURL string, dpRank int, hasRank bool) {
    parts := strings.Split(url, "@")
    if len(parts) == 2 {
        rank, err := strconv.Atoi(parts[1])
        if err == nil {
            return parts[0], rank, true
        }
    }
    return url, 0, false
}
```

#### 4.3.3 InstanceManager 集成

修改 `internal/gs/instance_manager.go`:

```go
// InstanceManager 添加DP支持
type InstanceManager struct {
    // ... 现有字段 ...

    dpSize         int                    // DP大小
    dpAwarePools   map[string]*DPAwareWorker  // DP感知Worker池
}

// SetDpSize 设置DP大小
func (im *InstanceManager) SetDpSize(dpSize int) {
    im.poolRWLock.Lock()
    defer im.poolRWLock.Unlock()
    im.dpSize = dpSize
}

// GetDPAwareWorkers 获取所有DP感知Worker
func (im *InstanceManager) GetDPAwareWorkers(role base.InstanceRole) []*DPAwareWorker {
    im.poolRWLock.RLock()
    defer im.poolRWLock.RUnlock()

    var workers []*DPAwareWorker
    for _, ins := range im.insPool {
        if ins.insRole == role || role == base.InvalidRoleInstance {
            // 为每个物理实例创建dpSize个DP感知Worker
            for rank := 0; rank < im.dpSize; rank++ {
                dw := &DPAwareWorker{
                    BaseURL: ins.insUrl,
                    DpRank:  rank,
                    DpSize:  im.dpSize,
                    InsRole: ins.insRole,
                    GroupID: ins.groupID,
                }
                workers = append(workers, dw)
            }
        }
    }
    return workers
}

// GetDPAwareSnapshot 获取DP感知快照
func (im *InstanceManager) GetDPAwareSnapshot(role base.InstanceRole) []*DPAwareSnapshot {
    im.snapshotRWLock.RLock()
    defer im.snapshotRWLock.RUnlock()

    var snapshots []*DPAwareSnapshot
    for _, snap := range im.insSnapshots {
        if snap.insRole == role || role == base.InvalidRoleInstance {
            for rank := 0; rank < im.dpSize; rank++ {
                dpSnap := &DPAwareSnapshot{
                    InsUrl:     fmt.Sprintf("%s@%d", snap.insUrl, rank),
                    BaseURL:    snap.insUrl,
                    DpRank:     rank,
                    DpSize:     im.dpSize,
                    FreeBlocks: snap.freeBlocks,
                    TokenNum:   snap.tokenNum,
                    TBT:        snap.tbt,
                    TTFT:       snap.ttft,
                    InsRole:    snap.insRole,
                    GroupID:    snap.groupID,
                }
                snapshots = append(snapshots, dpSnap)
            }
        }
    }
    return snapshots
}

// DPAwareSnapshot DP感知快照
type DPAwareSnapshot struct {
    InsUrl      string
    BaseURL     string
    DpRank      int
    DpSize      int
    FreeBlocks  int
    TokenNum    int
    TBT         float64
    TTFT        float64
    InsRole     base.InstanceRole
    GroupID     string
}
```

#### 4.3.4 负载均衡集成

修改 `internal/gs/load_balancer.go`:

```go
// MetricProvider 接口添加DP支持
type MetricProvider interface {
    // 现有方法 ...

    // 新增: 获取DP感知指标
    GetDPAwareMetrics(query *MetricQueryOptions) ([]*DPAwareMetric, error)
}

// DPAwareMetric DP感知指标
type DPAwareMetric struct {
    InsUrl      string
    BaseURL     string
    DpRank      int
    FreeBlocks  int
    TokenNum    int
    TBT         float64
    TTFT        float64
    GroupID     string
}
```

### 4.4 配置变更

```go
type GlobalSchedulerConfig struct {
    // ... 现有字段 ...

    DpSize int  // DP大小 (默认1)
}
```

---

## 五、一致性Hash算法设计

### 5.1 功能概述

**当前状态**: AIGW 无一致性Hash支持，无法实现会话亲和性。

**目标**: 实现一致性Hash策略，支持会话亲和性。

### 5.2 vLLM Router 参考实现

vLLM Router 在 `src/policies/consistent_hash.rs` 中实现:

```rust
// src/policies/consistent_hash.rs
pub const VIRTUAL_NODES_PER_WORKER: u32 = 160;  // 每个物理worker 160个虚拟节点

pub struct ConsistentHashPolicy {
    hash_ring: RwLock<BTreeMap<u64, String>>,  // 哈希值 -> Worker URL
    current_workers: RwLock<Vec<String>>,
}

// 哈希环构建
fn update_hash_ring(&self, workers: &[Arc<dyn Worker>]) {
    let mut new_ring = BTreeMap::new();

    for worker_url in &worker_urls {
        // 为每个Worker创建160个虚拟节点
        for i in 0..VIRTUAL_NODES_PER_WORKER {
            let virtual_key = format!("{}:{}", worker_url, i);
            let hash_value = Self::fbi_hash(&virtual_key);
            new_ring.insert(hash_value, worker_url.clone());
        }
    }

    *self.hash_ring.write().unwrap() = new_ring;
}

// 一致性Hash查找
fn find_worker_by_hash(&self, hash_key: &str) -> Option<String> {
    let hash_value = Self::fbi_hash(hash_key);
    let ring = self.hash_ring.read().unwrap();

    // BTreeMap范围查找: O(log n)
    // 找到第一个 hash >= 请求hash 的节点
    let selected_worker = ring
        .range(hash_value..)
        .next()
        .or_else(|| ring.iter().next())  // 如果没找到，回绕到第一个节点
        .map(|(_, worker_url)| worker_url.clone());

    selected_worker
}

// FurcHash算法 (Facebook mcrouter)
fn furc_hash(key: &str, m: u32) -> u32 {
    // ... Facebook的一致性Hash实现
}

fn fbi_hash(key: &str) -> u64 {
    const LARGE_MODULUS: u32 = (1u32 << 23) - 1;
    let furc_result = Self::furc_hash(key, LARGE_MODULUS);
    Self::murmur_hash_64a(&furc_result.to_le_bytes(), 4193360111)
}
```

**哈希键提取优先级**:

```rust
// src/policies/hash_key.rs
pub(crate) const SESSION_HEADER_NAMES: &[&str] = &[
    "x-session-id",      // 最高优先级
    "x-user-id",
    "x-tenant-id",
    "x-correlation-id",
    "x-request-id",
    "x-trace-id",
];

// 优先级顺序:
// 1. HTTP Headers (x-session-id > x-user-id > ...)
// 2. 请求体字段 (session_params.session_id > user > session_id > user_id)
// 3. 回退: 请求内容Hash
```

### 5.3 AIGW 设计方案

#### 5.3.1 新增模块结构

```
internal/gs/policy/
├── consistent_hash.go     // 一致性Hash策略
├── hash_ring.go           // 哈希环
├── hash_key.go            // 哈希键提取
└── virtual_node.go        // 虚拟节点
```

#### 5.3.2 核心数据结构

```go
// internal/gs/policy/consistent_hash.go

package policy

import (
    "sort"
    "sync"

    "huawei.com/aigw/internal/base"
)

const (
    VirtualNodesPerWorker = 160  // 每个Worker的虚拟节点数
)

// ConsistentHashPolicy 一致性Hash策略
type ConsistentHashPolicy struct {
    mu             sync.RWMutex
    hashRing       *HashRing              // 哈希环
    currentWorkers []string               // 当前Worker列表
    virtualNodes   int                    // 虚拟节点数
}

// HashRing 哈希环
type HashRing struct {
    nodes    []*VirtualNode  // 排序的虚拟节点
    nodeMap  map[uint64]string  // hash -> workerURL
}

// VirtualNode 虚拟节点
type VirtualNode struct {
    Hash      uint64  // 哈希值
    WorkerURL string  // Worker URL
    Index     int     // 虚拟节点索引
}

// HashKey 哈希键
type HashKey struct {
    Source    string  // 来源 (header/body)
    Key       string  // 键名
    Value     string  // 值
    Priority  int     // 优先级 (越小越高)
}
```

#### 5.3.3 哈希环实现

```go
// internal/gs/policy/hash_ring.go

// NewHashRing 创建哈希环
func NewHashRing() *HashRing {
    return &HashRing{
        nodes:   make([]*VirtualNode, 0),
        nodeMap: make(map[uint64]string),
    }
}

// Build 构建哈希环
func (hr *HashRing) Build(workerURLs []string, virtualNodes int) {
    newNodes := make([]*VirtualNode, 0, len(workerURLs)*virtualNodes)
    newNodeMap := make(map[uint64]string)

    for _, workerURL := range workerURLs {
        // 为每个Worker创建虚拟节点
        for i := 0; i < virtualNodes; i++ {
            virtualKey := fmt.Sprintf("%s:%d", workerURL, i)
            hashValue := FbiHash(virtualKey)

            node := &VirtualNode{
                Hash:      hashValue,
                WorkerURL: workerURL,
                Index:     i,
            }
            newNodes = append(newNodes, node)
            newNodeMap[hashValue] = workerURL
        }
    }

    // 按哈希值排序
    sort.Slice(newNodes, func(i, j int) bool {
        return newNodes[i].Hash < newNodes[j].Hash
    })

    hr.nodes = newNodes
    hr.nodeMap = newNodeMap
}

// Find 查找最近的Worker
func (hr *HashRing) Find(hashValue uint64) string {
    if len(hr.nodes) == 0 {
        return ""
    }

    // 二分查找第一个 hash >= hashValue 的节点
    idx := sort.Search(len(hr.nodes), func(i int) bool {
        return hr.nodes[i].Hash >= hashValue
    })

    // 如果没找到，回绕到第一个节点
    if idx >= len(hr.nodes) {
        idx = 0
    }

    return hr.nodes[idx].WorkerURL
}

// FindN 查找最近的N个Worker (用于fallback)
func (hr *HashRing) FindN(hashValue uint64, n int) []string {
    if len(hr.nodes) == 0 {
        return nil
    }

    idx := sort.Search(len(hr.nodes), func(i int) bool {
        return hr.nodes[i].Hash >= hashValue
    })

    result := make([]string, 0, n)
    for i := 0; i < n; i++ {
        pos := (idx + i) % len(hr.nodes)
        workerURL := hr.nodes[pos].WorkerURL
        // 去重
        if !contains(result, workerURL) {
            result = append(result, workerURL)
        }
        if len(result) >= n {
            break
        }
    }

    return result
}
```

#### 5.3.4 哈希键提取

```go
// internal/gs/policy/hash_key.go

// 哈希键提取优先级
var sessionHeaderNames = []string{
    "x-session-id",      // 优先级 1
    "x-user-id",         // 优先级 2
    "x-tenant-id",       // 优先级 3
    "x-correlation-id",  // 优先级 4
    "x-request-id",      // 优先级 5
    "x-trace-id",        // 优先级 6
}

// ExtractHashKey 从请求提取哈希键
func ExtractHashKey(headers http.Header, body map[string]interface{}) string {
    // 1. 优先从HTTP Headers提取
    for _, headerName := range sessionHeaderNames {
        if value := headers.Get(headerName); value != "" {
            return fmt.Sprintf("header:%s:%s", headerName, value)
        }
    }

    // 2. 从请求体提取
    // session_params.session_id
    if sessionParams, ok := body["session_params"].(map[string]interface{}); ok {
        if sessionID, ok := sessionParams["session_id"].(string); ok {
            return fmt.Sprintf("session:%s", sessionID)
        }
    }

    // user (OpenAI格式)
    if user, ok := body["user"].(string); ok {
        return fmt.Sprintf("user:%s", user)
    }

    // session_id (遗留格式)
    if sessionID, ok := body["session_id"].(string); ok {
        return fmt.Sprintf("session:%s", sessionID)
    }

    // user_id (遗留格式)
    if userID, ok := body["user_id"].(string); ok {
        return fmt.Sprintf("user:%s", userID)
    }

    // 3. 回退: 请求内容Hash
    bodyBytes, _ := json.Marshal(body)
    return fmt.Sprintf("request_hash:%016x", FbiHash(string(bodyBytes)))
}
```

#### 5.3.5 Hash函数实现

```go
// internal/gs/policy/hash_func.go

import (
    "github.com/spaolacci/murmur3"
)

// FbiHash Facebook风格的Hash函数
func FbiHash(key string) uint64 {
    const largeModulus uint32 = (1 << 23) - 1

    furcResult := FurcHash(key, largeModulus)

    // MurmurHash64A
    return MurmurHash64A(furcResult, 4193360111)
}

// FurcHash Facebook一致性Hash
func FurcHash(key string, m uint32) uint32 {
    // 简化实现 (完整实现需要参考Facebook mcrouter)
    h := murmur3.New32()
    h.Write([]byte(key))
    return h.Sum32() % m
}

// MurmurHash64A MurmurHash64A
func MurmurHash64A(data uint32, seed uint32) uint64 {
    h := murmur3.New64WithSeed(uint32(seed))
    binary.Write(h, binary.LittleEndian, data)
    return h.Sum64()
}
```

#### 5.3.6 负载均衡策略实现

```go
// internal/gs/policy/consistent_hash_policy.go

// NewConsistentHashLB 创建一致性Hash负载均衡器
func NewConsistentHashLB(metricProvider MetricProvider, params *AlgorithmParams) (*ConsistentHashLB, error) {
    return &ConsistentHashLB{
        baseLoadBalancer: baseLoadBalancer{
            metricProvider:    metricProvider,
            instanceRoleType:  params.InstanceRoleType,
        },
        virtualNodes:     VirtualNodesPerWorker,
        hashRing:         NewHashRing(),
    }, nil
}

// ConsistentHashLB 一致性Hash负载均衡器
type ConsistentHashLB struct {
    baseLoadBalancer
    virtualNodes int
    hashRing     *HashRing
    mu           sync.RWMutex
    lastWorkers  []string
}

// schedule 调度实现
func (lb *ConsistentHashLB) schedule(request *ScheduleRequestMsg, options *ScheduleOptions) *ScheduleResult {
    // 1. 提取Hash Key
    hashKey := ExtractHashKey(request.Headers, request.Body)

    // 2. 计算Hash值
    hashValue := FbiHash(hashKey)

    // 3. 获取Worker快照
    metrics, err := lb.metricProvider.GetInstanceMetrics(nil, lb.buildQueryOptions(options))
    if err != nil {
        log.Error().Msgf("[ConsistentHash] failed to get instance metrics: %v", err)
        return createEmptyScheduleResult()
    }

    // 4. 更新哈希环 (如果Worker列表变化)
    lb.updateHashRingIfNeeded(metrics)

    // 5. 查找Worker
    targetWorkerURL := lb.hashRing.Find(hashValue)
    if targetWorkerURL == "" {
        return createEmptyScheduleResult()
    }

    // 6. 健康检查
    targetMetric := lb.findMetricByURL(metrics, targetWorkerURL)
    if targetMetric == nil || !lb.isHealthy(targetMetric) {
        // Fallback: 找下一个健康的Worker
        fallbackURLs := lb.hashRing.FindN(hashValue, 3)
        for _, url := range fallbackURLs {
            if metric := lb.findMetricByURL(metrics, url); metric != nil && lb.isHealthy(metric) {
                targetWorkerURL = url
                targetMetric = metric
                break
            }
        }
        if targetMetric == nil {
            return createEmptyScheduleResult()
        }
    }

    // 7. 解析DP信息
    baseURL, dpRank := ParseDPAwareWorkerURL(targetWorkerURL)

    // 8. 返回结果
    return &ScheduleResult{
        ResultType:     DispatchRequest,
        PrefillUrl:     baseURL,
        PrefillGroupID: targetMetric.GroupID,
        DpRank:         dpRank,
    }
}

// updateHashRingIfNeeded 在需要时更新哈希环
func (lb *ConsistentHashLB) updateHashRingIfNeeded(metrics []*InstanceMetric) {
    workerURLs := make([]string, len(metrics))
    for i, m := range metrics {
        workerURLs[i] = m.InsUrl
    }

    lb.mu.Lock()
    defer lb.mu.Unlock()

    // 检查是否变化
    if equalStringSlices(lb.lastWorkers, workerURLs) {
        return
    }

    // 重建哈希环
    lb.hashRing.Build(workerURLs, lb.virtualNodes)
    lb.lastWorkers = workerURLs

    log.Info().Msgf("[ConsistentHash] rebuilt hash ring with %d workers, %d virtual nodes",
        len(workerURLs), len(workerURLs)*lb.virtualNodes)
}
```

### 5.4 配置变更

```go
type LoadBalancerConfig struct {
    // ... 现有字段 ...

    Type           string  // "round_robin", "least_conn", "consistent_hash", ...
    VirtualNodes   int     // 虚拟节点数 (一致性Hash用)
}

type GlobalSchedulerConfig struct {
    // ... 现有字段 ...

    LoadBalancer LoadBalancerConfig
}
```

### 5.5 API变更

新增负载均衡策略类型:

```go
const (
    LoadBalancerNone             LoadBalancerType = iota
    LoadBalancerRoundRobin
    LoadBalancerLeastConn
    LoadBalancerCapacity
    LoadBalancerToken
    LoadBalancerDecode
    LoadBalancerPrefillTimeAware
    LoadBalancerConsistentHash      // 新增
)
```

---

## 六、实现优先级

### 6.1 优先级排序

| 优先级 | 功能 | 原因 |
|--------|------|------|
| P0 | 流式转发推理请求 | 核心网关功能，当前AIGW无法实际转发请求 |
| P1 | 一致性Hash算法 | 会话亲和性关键，影响多轮对话体验 |
| P2 | DP Worker支持 | 细粒度负载均衡，提高均衡效果 |
| P3 | k8s服务发现 | K8s环境必需，但可用DNS临时替代 |

### 6.2 依赖关系

```
流式转发推理请求
    │
    ├── 依赖: DP Worker支持 (DP Header注入)
    │
    └── 依赖: 一致性Hash算法 (会话亲和路由)

一改性Hash算法
    │
    └── 依赖: DP Worker支持 (DP感知快照)

DP Worker支持
    │
    └── 无依赖

k8s服务发现
    │
    └── 无依赖
```

建议实现顺序:
1. DP Worker支持 (无依赖)
2. 一致性Hash算法 (依赖DP Worker)
3. 流式转发推理请求 (依赖两者)
4. k8s服务发现 (独立实现)

---

## 七、测试计划

### 7.1 流式转发测试

```
测试用例:
1. 非流式请求转发
2. SSE流式请求转发
3. Header透传验证
4. DP Header注入验证
5. 超时重试
6. 熔断器触发
```

### 7.2 K8s服务发现测试

```
测试用例:
1. Endpoints发现
2. Pod监听 (Add/Modify/Delete)
3. Label Selector过滤
4. 角色过滤
5. DNS发现回退
```

### 7.3 DP Worker测试

```
测试用例:
1. URL格式解析 (含/不含@rank)
2. DP扩展正确性 (N × dpSize)
3. DP感知快照生成
4. DP Header注入
```

### 7.4 一致性Hash测试

```
测试用例:
1. 哈希键提取 (Header优先级)
2. 哈希键提取 (Body字段)
3. 哈希键提取 (回退到请求Hash)
4. 哈希环构建 (虚拟节点)
5. 一致性验证 (同一key始终路由到同一Worker)
6. 均衡性验证 (Worker分布均匀)
7. 健康Worker Fallback
8. 扩缩容迁移比例验证
```

---

## 八、总结

本文档详细设计了四个核心功能:

1. **流式转发推理请求**: 实现真正的网关代理，支持SSE流式转发
2. **k8s服务发现**: 支持Kubernetes环境自动发现Worker
3. **DP Worker支持**: 支持细粒度负载均衡
4. **一致性Hash算法**: 支持会话亲和性，优化多轮对话

所有设计参考 vLLM Router 的实现，并结合 AIGW 现有架构进行适配。

---

*文档生成时间: 2026-04-29*
