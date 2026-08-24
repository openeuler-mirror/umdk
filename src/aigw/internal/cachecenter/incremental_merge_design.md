# CacheCenter 增量合并方案

## 一、问题描述

### 1.1 背景

AIGW 是多实例无状态服务，状态数据（实例负载、请求负载）保存在中心数据库（DCS/Redis）中。

### 1.2 现有问题

**问题场景**：
1. 异步写入：本地更新后，通过 `syncCh` 通道异步写入 Redis
2. 定时全量刷新：每 100ms 从 Redis 全量读取数据并替换本地缓存
3. 数据丢失问题：
   - `T0`: 实例A 本地更新数据（如 AddRequest），发送异步任务到 syncCh
   - `T1`: 实例A 的 syncCh 还没处理完任务，Redis 中还是旧数据
   - `T2`: 实例A 的定时器触发，从 Redis 全量读取（读到的是旧数据）
   - `T3`: 实例A 用旧数据替换本地缓存，**丢失了本地的新数据**
   - `T4`: 异步任务终于写入 Redis，但本地缓存已经是旧数据了
   - `T5`: 下一次定时器触发（100ms后），才能读到新数据

### 1.3 问题根源

`local_cache.go` 中的 `swapInNewState()` 是**全量替换**，不是增量合并：

```go
func (lc *localCache) swapInNewState(requests []*RequestInfo) {
    newRequestMap := &sync.Map{}
    newMetrics := &sync.Map{}
    // ... 从 requests 重建
    lc.holder.Store(&cacheHolder{...})  // 全量替换！
}
```

## 二、解决方案

### 2.1 方案选择

**增量合并**：在重建本地缓存时，将本地新数据与 Redis 数据合并，以版本号大的为准。

### 2.2 核心思路

1. **添加版本号**：每个 RequestInfo 携带最后修改时间（纳秒时间戳）
2. **本地修改时更新**：AddRequest、UpdateRequestOnPrefillFinished 时设置版本号
3. **rebuild 时增量合并**：从 Redis 读取 + 本地快照 → 合并（版本号大的优先）

### 2.3 时间窗口分析

```
T0: AddRequest(req1, lmt=T0)
    → 本地缓存: req1@lmt=T0
    → syncCh <- task

T1: 定时器触发 rebuildCache
    → 从 Redis 读取: {} (task 还没处理)
    → getLocalRequests(): {req1@lmt=T0}
    → mergeRequests(): 合并后 = {req1@lmt=T0} ✓
    → swapInNewState(): 本地保留了 req1 ✓

T2: syncLoop 处理 task，写入 Redis
```

**结果**：本地新数据被正确保留，不会被 Redis 旧数据覆盖。

## 三、修改详情

### 3.1 types.go

**添加字段**：

```go
// RequestInfo holds metadata for a single request
type RequestInfo struct {
    ReqId              string `json:"-"`
    PrefillInstance    string `json:"pi"`
    DecodeInstance     string `json:"di"`
    IsPrefill          bool   `json:"isp"`
    PromptTokenLen     int    `json:"ptl"`
    DecodeTokenLen     int    `json:"dtl"`
    PredictPrefillTime float64 `json:"ppt"`
    PrefillStartTimeMs int64  `json:"pst"`
    TimeStamp          int64  `json:"ts"`
    GroupID            string `json:"-"`
    // LastModifiedTime is used for incremental merge during cache rebuild.
    // When rebuilding local cache from Redis, requests with larger LastModifiedTime
    // are considered newer and will overwrite older ones. This prevents local updates
    // from being overwritten by stale Redis data when async write hasn't completed.
    LastModifiedTime int64 `json:"lmt,omitempty"`
}
```

### 3.2 cache_manager.go

#### 3.2.1 添加 timeNow 函数引用

```go
const (
    defaultRefreshInterval = 100 * time.Millisecond
    syncChanBuffer         = 2048
    syncWriteChanTimeout   = 50 * time.Millisecond
    stopWaitTimeout        = 5 * time.Second
)

// timeNow returns current time in nanoseconds for version tracking
var timeNow = time.Now
```

#### 3.2.2 AddRequest - 设置版本号

```go
// update local cache
copyInfo := *info
copyInfo.LastModifiedTime = timeNow().UnixNano() // Set version timestamp for incremental merge
cache.requestMap.Store(info.ReqId, &copyInfo)
```

#### 3.2.3 UpdateRequestOnPrefillFinished - 设置版本号

```go
// Clear prefill instance for current request and find next head
nextHead := cm.getHeadReq(prefillIns, reqID)
req.IsPrefill = false
updatedCurrent := *req
updatedCurrent.LastModifiedTime = timeNow().UnixNano() // Set version timestamp for incremental merge
// Prepare update task
updates := []*RequestInfo{&updatedCurrent}

if nextHead != nil {
    nextHead.PrefillStartTimeMs = time.Now().UnixMilli()
    updatedNext := *nextHead
    updatedNext.LastModifiedTime = timeNow().UnixNano() // Set version timestamp for incremental merge
    updates = append(updates, &updatedNext)
}
```

#### 3.2.4 新增 getLocalRequests 方法

```go
// getLocalRequests returns a snapshot of all requests currently in local cache.
// This is used during incremental merge to preserve local updates that haven't
// been synced to Redis yet.
func (cm *CacheManager) getLocalRequests() map[string]*RequestInfo {
    localRequests := make(map[string]*RequestInfo)
    cache := cm.cache.holder.Load()
    if cache == nil {
        return localRequests
    }

    cache.requestMap.Range(func(key, value interface{}) bool {
        reqID, ok := key.(string)
        if !ok {
            return true
        }
        req, ok := value.(*RequestInfo)
        if !ok || req == nil {
            return true
        }
        // Store a copy to avoid concurrent modification issues
        reqCopy := *req
        localRequests[reqID] = &reqCopy
        return true
    })
    return localRequests
}
```

#### 3.2.5 新增 mergeRequests 函数

```go
// mergeRequests merges Redis data with local data using version timestamps.
// For each request ID, the version with larger LastModifiedTime wins.
// This ensures local updates that haven't been synced to Redis are preserved.
func mergeRequests(redisData, localData map[string]*RequestInfo) []*RequestInfo {
    result := make(map[string]*RequestInfo)

    // First, add all Redis data
    for reqID, req := range redisData {
        result[reqID] = req
    }

    // Then, overlay with local data (local data is newer if timestamp differs)
    for reqID, localReq := range localData {
        if existing, ok := result[reqID]; !ok {
            // Request only exists locally (not in Redis yet)
            result[reqID] = localReq
        } else if localReq.LastModifiedTime > existing.LastModifiedTime {
            // Local version is newer
            result[reqID] = localReq
        }
        // Otherwise, Redis version is newer or equal, keep it
    }

    // Convert to slice
    requests := make([]*RequestInfo, 0, len(result))
    for _, req := range result {
        requests = append(requests, req)
    }
    return requests
}
```

#### 3.2.6 修改 rebuildCache 方法

```go
// rebuildCache fetches data from remote db and rebuilds local cache
// with incremental merge to preserve local updates that haven't been synced yet.
func (cm *CacheManager) rebuildCache() error {
    start := time.Now()

    // Get all instance IDs from local cache metrics
    var instanceIDs []string
    cm.activeInstances.Range(func(key, value interface{}) bool {
        instanceID, ok := key.(string)
        if !ok {
            return true
        }
        instanceIDs = append(instanceIDs, instanceID)
        return true
    })

    // Use new instance-based format to fetch all requests
    instanceRequests, err := cm.remoteCache.FetchAllInstanceRequests(cm.modelName, instanceIDs)
    if err != nil {
        return fmt.Errorf("failed to fetch all instance requests for model %s: %w", cm.modelName, err)
    }

    // Merge all instance requests into a single map
    hashData := make(map[string]string)
    for _, requests := range instanceRequests {
        for reqID, jsonStr := range requests {
            hashData[reqID] = jsonStr
        }
    }

    // parse Redis data into RequestInfo list
    redisRequests, expiredRequests := parseRequests(hashData, cm.reqTtl)
    redisMap := make(map[string]*RequestInfo)
    for _, req := range redisRequests {
        redisMap[req.ReqId] = req
    }

    // Get local requests for incremental merge
    localRequests := cm.getLocalRequests()

    // Merge Redis data with local data, preferring newer version
    mergedRequests := mergeRequests(redisMap, localRequests)

    // rebuild cache state with merged requests
    cm.cache.swapInNewState(mergedRequests)
    log.Debug().Msgf("model %v rebuild metrics from cache cost %v, merged %d local + %d redis = %d total",
        cm.modelName, time.Since(start), len(localRequests), len(redisRequests), len(mergedRequests))
    // ... 后续代码不变 ...
}
```

## 四、效果分析

### 4.1 解决的问题

| 时间点 | 原方案 | 新方案 |
|--------|--------|--------|
| T0: AddRequest | 本地有数据，syncCh 异步写入 | 本地有数据 + 版本号，syncCh 异步写入 |
| T1: syncCh 还没处理 | - | - |
| T2: 定时器触发 rebuild | 从 Redis 读到旧数据 | 从 Redis 读 + 本地快照合并 |
| T3: swapInNewState | **本地新数据被覆盖** | **本地新数据被保留** |
| T4: syncCh 写入 Redis | - | - |

### 4.2 关键优势

1. **本地修改立即可见**：不需要等待 syncCh 处理
2. **数据丢失问题彻底解决**：每次 rebuild 都能保证本地数据是最新的
3. **向后兼容**：LastModifiedTime 是可选字段（`omitempty`），旧数据兼容

### 4.3 性能影响

1. **getLocalRequests()**：遍历本地所有请求并复制，约 O(n) 开销，n 为本地请求数
2. **mergeRequests()**：遍历两个 map，约 O(n+m) 开销
3. **总开销**：每次 rebuild 增加约 O(n+m) 时间，但避免了数据丢失问题

## 五、测试验证

### 5.1 单元测试

需要添加测试用例验证：
1. AddRequest 后版本号正确设置
2. UpdateRequestOnPrefillFinished 后版本号正确更新
3. mergeRequests 正确合并（本地更新优先）
4. mergeRequests 正确合并（Redis 更新优先）

### 5.2 集成测试

验证场景：
1. AddRequest 后立即 rebuild，本地数据被保留
2. 多个请求并发添加后 rebuild，数据完整
3. 本地删除 + Redis 未同步 + rebuild，数据正确

## 六、修改文件清单

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `internal/cachecenter/types.go` | 修改 | 添加 LastModifiedTime 字段 |
| `internal/cachecenter/cache_manager.go` | 修改 | 添加版本号设置、getLocalRequests、mergeRequests、修改 rebuildCache |

## 七、风险评估

### 7.1 低风险
- 版本号使用纳秒时间戳，理论上同一实例内单调递增
- 合并逻辑简单清晰，易于理解和维护

### 7.2 注意事项
- `timeNow` 是可注入的函数，便于单元测试
- `getLocalRequests` 会复制所有请求数据，有一定内存开销，但请求数量通常有限