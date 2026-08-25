# Cachecenter 变更日志方案设计（最终实现）

**设计日期:** 2026-04-23

**实现状态:** ✅ 已完成

---

## 一、需求与约束

### 1.1 功能需求
- 多实例部署，每个实例有独立的本地缓存
- 本地缓存与Redis数据需要保持一致
- 支持请求的增删改操作
- 支持跨实例数据共享

### 1.2 非功能需求
1. **异步读写** - 写操作不能阻塞调度选择流程，延迟敏感
2. **不支持Pub/Sub** - 缓存产品不支持发布订阅
3. **生产可维护** - 方案简单清晰，问题易排查

### 1.3 当前问题
- PrefillInstance被清空后，RemoveRequest无法找到正确的Redis实例删除请求
- 版本号+增量合并方案复杂度高，可维护性差

---

## 二、最终实现方案

### 2.1 核心思想

**本地缓存为主，Redis为辅，变更日志异步同步**

```
┌─────────────────────────────────────────────────────────────────┐
│                         实例 A                                   │
│                                                                  │
│   ┌────────────┐      ┌─────────────────┐                      │
│   │  本地缓存   │      │   变更日志队列    │                      │
│   │ (主数据源)  │ ───→ │ [ADD, DEL, UPD] │ ──异步批量──→ Redis  │
│   │            │      │                 │                      │
│   │ 读操作直接读 │      │ 最大容量: 10000  │                      │
│   │ 写操作立即生效│      │                 │                      │
│   └────────────┘      └─────────────────┘                      │
│         ↑                                                       │
│         │                                                       │
│         │ 定期刷新(每100ms)                                       │
│         │ 从Redis拉取其他实例数据                                  │
│         │ 【关键：只更新，不删除本地数据】                           │
│         │                                                        │
│         └──────────────────────────────────��────────────────────┘
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 关键设计决策

#### 本地数据保护机制（最重要）
- `refreshFromRedis` **只做更新，不做删除**
- 本地数据只能通过 `RemoveRequest` 显式删除
- 新创建还没flush的请求自然保留在本地
- **不需要 OwnerID 字段**（简化方案）

### 2.3 数据模型简化

**移除的字段：**
- `Version` - 不再需要版本号
- `Dirty` - 不再需要脏标志
- `Deleted` - 不再需要延迟删除标记

**保留的字段：**
- `StorageInstance` - 必须保留，记录请求存储的Redis实例

**最终结构：**
```go
type RequestInfo struct {
    ReqId              string  `json:"-"`
    PrefillInstance    string  `json:"pi"`
    DecodeInstance     string  `json:"di"`
    IsPrefill          bool    `json:"isp"`
    PromptTokenLen     int     `json:"ptl"`
    DecodeTokenLen     int     `json:"dtl"`
    PredictPrefillTime float64 `json:"ppt"`
    PrefillStartTimeMs int64   `json:"pst"`
    TimeStamp          int64   `json:"ts"`
    GroupID            string  `json:"gp"`

    // StorageInstance: 请求存储的Redis实例，永不改变
    StorageInstance string `json:"si"`
}
```

### 2.4 变更日志设计

```go
// ChangeType 操作类型
type ChangeType int

const (
    ChangeAdd    ChangeType = iota  // 新增请求
    ChangeDelete                    // 删除请求
    ChangeUpdate                    // 更新请求
)

// ChangeLog 变更日志
type ChangeLog struct {
    Type      ChangeType
    ReqId     string
    Data      *RequestInfo  // 携带StorageInstance信息
    Timestamp int64         // 操作时间戳
}

// ChangeQueue 变更队列（线程安全）
type ChangeQueue struct {
    mu      sync.Mutex
    logs    []ChangeLog
    maxSize int           // 最大容量 10000
}
```

### 2.5 同步策略

#### 写操作流程（异步）

```
AddRequest(info):
    1. 设置 StorageInstance = info.PrefillInstance
    2. 本地缓存立即存储 ← 调度可立即使用
    3. 更新实例指标
    4. 变更日志追加(ADD, info) ← 异步
    5. return nil ← 立即返回，不等待Redis

RemoveRequest(reqId):
    1. 从本地缓存读取请求（获取StorageInstance）
    2. 本地缓存立即删除 ← 调度可立即使用
    3. 更新实例指标
    4. 变更日志追加(DELETE, req, StorageInstance) ← 异步
    5. return nil ← 立即返回
```

#### 同步循环（100ms周期）

```go
func (cm *CacheManager) syncLoop() {
    // 初始化：从Redis全量加载
    cm.loadFromRedis()

    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            // 1. 将变更日志批量写入Redis
            cm.flushChanges()

            // 2. 从Redis刷新其他实例数据
            cm.refreshFromRedis()

        case <-cm.ctx.Done():
            // 退出前确保变更已写入
            cm.flushChanges()
            return
        }
    }
}
```

#### 数据刷新（核心简化）

```go
func (cm *CacheManager) refreshFromRedis() error {
    // 1. 从所有活跃实例获取数据
    instanceRequests, err := cm.remoteCache.FetchAllInstanceRequests(modelName, instanceIDs)

    // 2. 合并策略：只更新，不删除
    for reqID, remoteReq := range allRemoteRequests {
        // 检查过期
        if cm.reqTtl > 0 && time.Since(remoteReq.TimeStamp) > cm.reqTtl {
            continue  // 跳过过期请求
        }

        // 本地有，时间戳比较
        if localReq, exists := cache.requestMap.Load(reqID); exists {
            if localReq.TimeStamp >= remoteReq.TimeStamp {
                continue  // 本地更新或相同，跳过
            }
        }
        // 本地没有或本地更旧，更新
        cache.requestMap.Store(reqID, remoteReq)
    }

    // 3. 重建指标
    cm.rebuildMetrics()
    return nil
}
```

---

## 三、实现文件清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `types.go` | 修改 | 新增 ChangeLog/ChangeQueue，移除 Version/Dirty/Deleted |
| `change_queue.go` | 新建 | 变更队列实现 |
| `cache_manager.go` | 重构 | 核心逻辑简化，移除 syncCh |
| `local_cache.go` | 简化 | 移除 swapInNewState |
| `cache_manager_test.go` | 更新 | 适配新逻辑 |
| `local_cache_test.go` | 更新 | 适配新逻辑 |
| `change_queue_test.go` | 新建 | 变更队列测试 |
| `version_merge_test.go` | 删除 | 被新测试替代 |

---

## 四、方案对比

### 4.1 与原版本号方案对比

| 维度 | 版本号+增量合并 | 变更日志方案 |
|------|----------------|-------------|
| **字段数量** | Version, Dirty, Deleted, StorageInstance | StorageInstance |
| **代码复杂度** | 高（版本比较、合并逻辑） | 低（队列、时间戳比较） |
| **并发问题** | clearRequestDirtyFlag有竞争 | 无竞争（本地优先） |
| **可维护性** | 中等 | 高 |
| **性能** | 每次修改需要更新版本 | 仅追加队列 |
| **一致性** | 最终一致 | 最终一致 |
| **问题排查** | 复杂（需分析版本演变） | 简单（查看变更日志） |

### 4.2 复杂度量化

```
版本号方案代码量：
- 版本比较逻辑: ~50行
- 合并逻辑(swapInNewState): ~100行
- Dirty标志管理: ~30行
- 测试用例: ~400行
总计: ~580行

变更日志方案代码量：
- ChangeQueue实现: ~50行
- flushChanges: ~60行
- refreshFromRedis: ~50行
- 测试用例: ~200行
总计: ~360行

代码量减少约 38%
```

---

## 五、异常处理

### 5.1 变更队列满

```go
// 策略：丢弃最旧的变更，记录告警
if len(q.logs) >= q.maxSize {
    log.Warn().Msgf("change queue full, dropped oldest change: type=%v, reqId=%s",
        dropped.Type, dropped.ReqId)
    q.logs = q.logs[1:]
}
```

### 5.2 Redis写入失败

```go
// 策略：重试3次，指数退避
for i := 0; i < maxTaskRetries; i++ {
    err = cm.remoteCache.AddRequest(...)
    if err == nil {
        break
    }
    if i == maxTaskRetries-1 {
        log.Error().Msgf("flush change failed after %d retries", maxTaskRetries)
        break
    }
    time.Sleep(retryBaseTime * time.Duration(1<<uint(i)))
}
```

### 5.3 实例重启

```go
// 策略：启动时从Redis全量加载
func (cm *CacheManager) syncLoop() {
    // 初始加载（同步）
    if err := cm.loadFromRedis(); err != nil {
        log.Warn().Msgf("init local cache from remote failed, %v", err)
    }
    // ... 开始定期刷新
}
```

### 5.4 网络分区

```
策略：本地缓存继续服务，Redis恢复后自动同步
- 变更日志持续追加
- 定期重试连接
- 连接恢复后批量同步
```

---

## 六、监控与可观测性

### 6.1 关键指标

```go
// 建议添加的指标
type CacheMetrics struct {
    // 变更队列
    ChangeQueueSize      int     // 当前队列大小
    ChangeQueueDropCount int64   // 队列满丢弃次数

    // 同步延迟
    LastFlushTime        int64   // 上次刷新时间
    FlushLatencyMs       int64   // 刷新延迟

    // Redis操作
    RedisWriteCount      int64   // Redis写入次数
    RedisWriteFailCount  int64   // Redis写入失败次数

    // 数据量
    LocalCacheSize       int     // 本地缓存大小
    ActiveInstanceCount  int     // 活跃实例数
}
```

---

## 七、验证方式

```bash
# 运行单元测试
go test ./internal/cachecenter/... -v -count=1

# 确认测试通过
# ok      huawei.com/aigw/internal/cachecenter    0.520s
```

---

## 八、总结

### 8.1 方案优势

1. **简单性**
   - 无版本号维护
   - 无复杂合并逻辑
   - 无OwnerID字段
   - 代码量减少约38%

2. **可维护性**
   - 变更日志可追踪
   - 问题排查简单
   - 并发问题少

3. **性能**
   - 写操作不阻塞
   - 仅追加队列操作
   - 批量写入Redis

4. **可靠性**
   - 本地缓存为主，Redis故障不影响服务
   - 变更队列保证数据不丢失
   - 定期同步保证最终一致

### 8.2 方案劣势

1. 变更队列满时可能丢失旧变更（可配置告警）
2. 依赖定期刷新，实时性略低于Pub/Sub（100ms延迟）
3. refreshFromRedis后需要重建metrics（轻微开销）

### 8.3 核心简化点

1. **无版本号维护** - 不需要每次修改递增版本
2. **无脏标志管理** - 变更队列自动管理
3. **无复杂合并** - 时间戳比较即可
4. **无OwnerID字段** - refreshFromRedis只更新不删除
5. **本地数据保护** - 只能通过RemoveRequest显式删除
