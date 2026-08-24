# Cachecenter 变更日志方案实现报告

**实现日期:** 2026-04-23

**实现状态:** ✅ 已完成并测试通过

---

## 一、实现概述

本次实现采用"本地为主 + 变更日志异步同步"的方案，显著简化了数据一致性逻辑：

- **移除字段**: Version, Dirty, Deleted
- **保留字段**: StorageInstance（记录请求存储的Redis实例）
- **新增结构**: ChangeType, ChangeLog, ChangeQueue
- **核心简化**: refreshFromRedis只更新不删除本地数据

---

## 二、实现变更清单

### 2.1 types.go 变更

**新增结构：**
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
    Data      *RequestInfo
    Timestamp int64
}

// ChangeQueue 变更队列（线程安全）
type ChangeQueue struct {
    mu      sync.Mutex
    logs    []ChangeLog
    maxSize int
}
```

**移除字段：**
```go
// 从 RequestInfo 移除：
// Version   uint64 `json:"ver"`  // 移除
// Dirty     bool   `json:"-"`    // 移除
// Deleted   bool   `json:"del"`  // 移除
```

### 2.2 change_queue.go（新建）

实现变更队列，核心方法：
- `NewChangeQueue()` - 创建队列，默认大小10000
- `Push(log)` - 追加变更，满时丢弃最旧
- `PopAll()` - 取出所有变更
- `Len()` - 当前长度

### 2.3 cache_manager.go 变更

**结构变更：**
```go
type CacheManager struct {
    // ...
    changeQueue   *ChangeQueue   // 替代 syncCh
    // 移除 syncCh
}
```

**方法变更：**

| 方法 | 变更类型 | 说明 |
|------|---------|------|
| `AddRequest` | 简化 | 移除版本号/Dirty处理，立即本地存储 |
| `RemoveRequest` | 简化 | 立即删除本地数据，移除延迟删除 |
| `UpdateRequestOnPrefillFinished` | 简化 | 移除版本号/Dirty处理 |
| `flushChanges` | 新增 | 刷新变更到Redis |
| `refreshFromRedis` | 新增 | 从Redis刷新（只更新不删除） |
| `rebuildMetrics` | 新增 | 重建指标 |
| `syncLoop` | 修改 | 改用ticker触发flush+refresh |
| `sendTask` | 删除 | 不再需要 |
| `clearRequestDirtyFlag` | 删除 | 不再需要 |
| `handleTask` | 删除 | 逻辑移至flushChanges |
| `rebuildCache` | 删除 | 被refreshFromRedis替代 |
| `parseRequests` | 删除 | 被parseRequestsForRefresh替代 |

### 2.4 local_cache.go 变更

**移除方法：**
- `swapInNewState` - 不再需要版本号合并逻辑

**保留方法：**
- `findEarliestRequest` - 查找最早请求
- `calculateTokenLoad` - 计算Token负载
- `calculateQueueTime` - 计算排队时间

### 2.5 测试文件变更

| 文件 | 操作 | 说明 |
|------|------|------|
| `cache_manager_test.go` | 更新 | 适配新逻辑，更新mockJSON |
| `local_cache_test.go` | 更新 | 移除swapInNewState测试 |
| `change_queue_test.go` | 新建 | 变更队列完整测试 |
| `version_merge_test.go` | 删除 | 不再适用 |

---

## 三、核心设计决策

### 3.1 本地数据保护机制（最重要）

```go
func (cm *CacheManager) refreshFromRedis() error {
    // ...
    // 合并策略：只更新，不删除
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
    // 注意：没有删除本地数据的逻辑！
}
```

**关键点：**
- 本地数据只能通过 `RemoveRequest` 显式删除
- 新创建还没flush的请求自然保留在本地
- 不需要 OwnerID 字段来区分数据归属

### 3.2 变更队列设计

```go
func (q *ChangeQueue) Push(changeLog ChangeLog) {
    q.mu.Lock()
    defer q.mu.Unlock()

    if len(q.logs) >= q.maxSize {
        // 队列满，丢弃最旧
        dropped := q.logs[0]
        q.logs = q.logs[1:]
        log.Warn().Msgf("change queue full, dropped oldest: type=%v, reqId=%s",
            dropped.Type, dropped.ReqId)
    }
    q.logs = append(q.logs, changeLog)
}
```

**关键点：**
- 默认容量10000
- 满时丢弃最旧变更（保留最新）
- 线程安全

### 3.3 同步循环

```go
func (cm *CacheManager) syncLoop() {
    // 初始加载（同步）
    cm.loadFromRedis()

    ticker := time.NewTicker(100 * time.Millisecond)
    for {
        select {
        case <-ticker.C:
            cm.flushChanges()      // 1. 刷新变更到Redis
            cm.refreshFromRedis()  // 2. 刷新其他实例数据
        case <-cm.ctx.Done():
            cm.flushChanges()      // 退出前确保写入
            return
        }
    }
}
```

**关键点：**
- 100ms周期
- 先flush后refresh
- 退出前确保数据写入

---

## 四、测试验证

### 4.1 测试执行结果

```bash
$ go test ./internal/cachecenter/... -v -count=1

=== RUN   TestCacheManager_FullWorkflow
--- PASS: TestCacheManager_FullWorkflow (0.36s)
    --- PASS: TestCacheManager_FullWorkflow/AddRequest_should_sync_to_remote_and_update_metrics
    --- PASS: TestCacheManager_FullWorkflow/UpdateRequestOnPrefillFinished_should_promote_next_head
    --- PASS: TestCacheManager_FullWorkflow/RemoveRequest_should_delete_and_sync
    --- PASS: TestCacheManager_FullWorkflow/refreshFromRedis_recovers_from_remote_state
    --- PASS: TestCacheManager_FullWorkflow/Stop_should_gracefully_shutdown

=== RUN   TestChangeQueue_Basic
--- PASS: TestChangeQueue_Basic (0.00s)

=== RUN   TestChangeQueue_Overflow
--- PASS: TestChangeQueue_Overflow (0.00s)

=== RUN   TestChangeQueue_Concurrent
--- PASS: TestChangeQueue_Concurrent (0.00s)

PASS
ok      huawei.com/aigw/internal/cachecenter    0.520s
```

### 4.2 测试覆盖要点

- [x] 变更队列基本操作
- [x] 变更队列溢出处理
- [x] 变更队列并发安全
- [x] AddRequest立即本地生效
- [x] RemoveRequest立即删除
- [x] refreshFromRedis只更新不删除
- [x] 定期同步机制
- [x] 优雅退出

---

## 五、与原方案对比

| 维度 | 原方案（版本号） | 新方案（变更日志） |
|------|----------------|-------------------|
| 数据结构 | Version + Dirty + Deleted | 仅StorageInstance |
| 合并逻辑 | swapInNewState（~100行） | refreshFromRedis（~50行） |
| 并发问题 | clearRequestDirtyFlag有竞争 | 无 |
| 删除机制 | 延迟删除（标记Deleted） | 立即删除 |
| 本地数据保护 | 需要比较版本号 | 只更新不删除 |
| 代码量 | ~580行 | ~360行（减少38%） |
| 可维护性 | 中等 | 高 |

---

## 六、注意事项

### 6.1 向后兼容

- Version/Dirty/Deleted字段移除后，读取旧数据时会忽略这些字段
- 不影响新数据的正确性

### 6.2 变更队列容量

- 默认10000
- 队列满时丢弃最旧变更并告警
- 生产环境建议监控队列大小

### 6.3 本地数据保护

- refreshFromRedis不会删除本地数据
- 只能通过RemoveRequest显式删除
- 新创建的请求在flush前不会被其他实例数据覆盖

### 6.4 指标重建

- refreshFromRedis后需要重建metrics
- 开销较小，随缓存大小线性增长

---

## 七、后续建议

### 7.1 监控指标

建议添加以下监控指标：
- 变更队列当前大小
- 变更队列丢弃次数
- flush延迟
- refresh延迟
- Redis操作失败次数

### 7.2 性能优化

可考虑的优化方向：
- 批量写入时按instance分组合并
- 增量式重建metrics（仅更新变更部分）

### 7.3 文档补充

建议添加：
- 变更日志格式说明
- 故障排查指南
- 性能调优建议
