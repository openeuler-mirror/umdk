# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 常用命令

### 构建项目
```bash
# 基础构建
./build.sh

# 带单元测试构建
./build.sh --ut

# 调试模式构建
./build.sh --debug

# 清理构建产物
./build.sh --clean
```

### 运行测试
```bash
# 运行所有单元测试
go test ./...

# 运行特定包的测试
go test ./internal/gs/...

# 运行特定测试函数
go test -run TestLoadBalancer ./internal/gs/

# 带覆盖率运行测试
go test -cover ./...
```

### 运行服务
```bash
# 作为独立服务运行
./output/aigw --config=/etc/aigw/conf/aigw.json
```

### 构建示例
```bash
cd example
mkdir build && cd build
cmake ..
make
./aigw_test_demo
```

## 项目架构

### 核心组件

**AigwManager** (`internal/core/`) - 中央协调器
- 管理多个 GlobalSchedulerManager 实例（每个模型一个）
- 处理配置管理和初始化

**GlobalScheduler** (`internal/gs/`) - 全局调度器
- **Dispatcher**: 路由调度请求到工作节点
- **LoadBalancer**: 6种负载均衡策略（RoundRobin, LeastConn, Capacity, Token, PrefillTimeAware, Decode）
- **InstanceManager**: 管理推理实例状态
- **MetricProvider**: 可插拔的指标提供者接口（支持缓存和实例两种来源）

**CacheCenter** (`internal/cachecenter/`) - 缓存中心
- Redis + 本地缓存双重机制
- 通过回调函数模式支持可插拔的缓存后端

**Tokenizers** (`internal/tokenizers/`) - 分词器
- 集成 HuggingFace Tokenizers
- 通过 Rust FFI 实现高性能分词

### 关键接口

**MetricProvider** (`internal/gs/metric_provider.go`):
```go
type MetricProvider interface {
    GetInstanceMetrics(ctx context.Context, opts *MetricQueryOptions) ([]*InstanceMetric, error)
    AddRequest(req *LlmRequest, instanceCtx *InstanceContext) error
    RemoveRequest(req *LlmRequest, instanceCtx *InstanceContext) error
    PredictTokensByEMA(req *LlmRequest) int
}
```

**loadBalancer** (`internal/gs/load_balancer.go`):
```go
type loadBalancer interface {
    schedule(request *ScheduleRequestMsg, groupID string, excludeGroupId map[string]bool) *ScheduleResult
    withdraw(request *ScheduleRequestMsg, insUrl string)
}
```

### 部署模式

1. **ServiceMode** - 独立 HTTP 服务
   - 入口: `cmd/aigw/main.go`
   - 提供 RESTful API

2. **SdkMode** - 共享库嵌入应用
   - CGO 绑定: `src/libaigw.go`
   - C API: `include/aigw.h`

### 请求调度流程

1. `AigwManager.GetSuggestion()` 接收请求
2. 查找/创建模型的 `GlobalSchedulerManager`
3. `Dispatcher` 路由到 `ControlMessage` 处理器
4. `LoadBalancer` 查询 `MetricProvider` 获取实例指标
5. `LoadBalancer.schedule()` 选择最优实例
6. 返回 prefill/decode 节点地址

### 技术栈

| 组件 | 语言 | 用途 |
|------|------|------|
| 核心逻辑 | Go 1.24 | 业务逻辑、HTTP服务、调度算法 |
| Tokenizers | Rust | 高性能文本分词（FFI） |
| 外部 API | C/C++ (CGO) | C API 绑定、缓存驱动回调 |
| ML 训练 | Python | LightGBM 模型训练、HuggingFace Tokenizers |
| 基础设施 | Go | ZooKeeper 客户端、logrus 日志 |

### 配置文件

主配置文件: `configs/aigw.json`

关键配置部分:
- `global`: 全局配置（监听地址、日志路径、超时等）
- `zookeeper`: ZooKeeper 连接配置
- `globalSchedulers`: 模型配置数组，每个模型包含负载均衡策略、部署策略等

### 负载均衡策略

| 策略 | 适用场景 |
|------|----------|
| `roundRobin` | 通用场景 |
| `leastConn` | 长连接场景 |
| `capacity` | 资源敏感场景 |
| `token` | Token 敏感场景 |
| `prefillTimeAware` | Prefill 阶段 |
| `decode` | Decode 阶段 |
