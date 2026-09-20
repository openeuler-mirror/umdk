# SNC PathService 主成功场景测试设计

> 基于 `topo_data_2npu_1port.json` 和 `topo_data_4npu_8port.json` 两组测试工具，设计 planPath 主成功场景。

---

## 1. 全局假设与数据修正

### 1.1 2npu_1port 路由前缀修正

JSON 中 L1SW0 路由前缀与 NPU 端口 CNA 经 `cnaToTargetAddr()` 后的结果不匹配：

| L1SW 路由(JSON) | 应修正为 | 对应的 NPU 端口 CNA | cnaToTargetAddr |
|---|---|---|---|
| `170.170.170.17/32` | `170.170.170.18/32` | NPU1 `400GE 0/0/1` → `170.170.170.18` | `170.170.170.18` |
| `221.221.221.68/32` | `221.221.221.66/32` | NPU2 `400GE 0/1/1` → `221.221.221.66` | `221.221.221.66` |

否则 `routePhase` 中 LPM 查找因 `/32` 精确匹配失败，抛出 `ROUTE_NOT_REACHABLE`。

### 1.2 4npu_8port 路由前缀修正

仅 L1SW0 的路由前缀与所连端口的 CNA 匹配（NPU2 port0/0/0 的 CNA `221.221.221.68` = 路由前缀），L1SW1/2/3 的路由前缀不匹配各自所连端口的 CNA。若需在所有 L1SW 上工作，修正如下：

| L1SW | 端口 | 连 NPU 端口 | 该端口 CNA | cnaToTargetAddr | 应修正路由前缀 |
|---|---|---|---|---|---|
| l1sw1 | 1/0/2 | npu2 0/0/1 | 221.221.221.66 | 221.221.221.66 | `221.221.221.66/32` |
| l1sw1 | 1/0/4 | npu3 0/0/1 | 238.238.238.86 | 238.238.238.86 | `238.238.238.86/32` |
| l1sw1 | 1/0/6 | npu4 0/0/1 | 255.255.255.103 | 255.255.255.103 | `255.255.255.103/32` |
| l1sw2 | 1/0/2 | npu2 0/0/2 | 221.221.221.69 | 221.221.221.69 | `221.221.221.69/32` |
| l1sw2 | 1/0/4 | npu3 0/0/2 | 238.238.238.87 | 238.238.238.87 | `238.238.238.87/32` |
| l1sw2 | 1/0/6 | npu4 0/0/2 | 255.255.255.104 | 255.255.255.104 | `255.255.255.104/32` |
| l1sw3 | 1/0/2 | npu2 0/0/3 | 221.221.221.70 | 221.221.221.70 | `221.221.221.70/32` |
| l1sw3 | 1/0/4 | npu3 0/0/3 | 238.238.238.88 | 238.238.238.88 | `238.238.238.88/32` |
| l1sw3 | 1/0/6 | npu4 0/0/3 | 255.255.255.105 | 255.255.255.105 | `255.255.255.105/32` |

本文后续的测试用例假定上述修正已应用，否则仅 L1SW0 相关场景可通过。

---

## 2. 测试工具 1：2npu_1port

### 2.1 拓扑结构

```
rack1#os0#npu1:400GE 0/0/1  ←→  rack1#l1sw0:400GE 1/0/1  ←→  rack1#os0#npu2:400GE 0/1/1
```

### 2.2 主成功场景

#### 用例 2.2.1：多跳路径 npu1 → l1sw0 → npu2

**输入：**

```json
{
  "superNodeName": "A5-superPod-1",
  "srcDevice": "rack1#os0#npu1",
  "destDevice": "rack1#os0#npu2",
  "srcPort": "400GE 0/0/1",
  "destPort": "400GE 0/1/1",
  "interDevices": {
    "rack1#l1sw0": "400GE 1/0/2"
  }
}
```

**处理追踪：**

| Step | 操作 | 结果 |
|---|---|---|
| 0 | 查 SuperNode | `A5-superPod-1` 找到 |
| 0 | 查 src/dest Device | superNode.getNpuDevices() 中 npu1 / npu2 找到，均为 NPU |
| 1 | 查 srcPort | `400GE 0/0/1` → `npu1.findNpuPort()` → CNA=`170.170.170.18`, EID=`AAAAAA12000000000000000000000002` |
| 1 | 端口直连 | remoteDevice=`rack1#l1sw0`, remotePort=`400GE 1/0/1` |
| 2 | 查 destPort | `400GE 0/1/1` → `npu2.findNpuPort()` → CNA=`221.221.221.66`, EID=`DDDDDD42000000000000000000000002` |
| 2 | 端口直连 | remoteDevice=`rack1#l1sw0`, remotePort=`400GE 1/0/2` |
| 3 | interDevices 非空 | 进入多跳逻辑 |
| 5 | 多跳路径还原 | hops=[NPU1, L1SW0, NPU2] |
| 6 | 正向 routePhase | 中间跳 L1SW0, target=`cnaToTargetAddr("221.221.221.66")`=`"221.221.221.66"` |
| 6 | L1SW0 路由查找 | 前缀 `221.221.221.66/32`(修正后) → 匹配, outPort=400GE 1/0/2 |
| 7 | 反向 routePhase | 中间跳 L1SW0, target=`cnaToTargetAddr("170.170.170.18")`=`"170.170.170.18"` |
| 7 | L1SW0 路由查找 | 前缀 `170.170.170.18/32`(修正后) → 匹配, outPort=400GE 1/0/1 |
| 9-10 | 构建结果 | SUCCESS |

**期望输出：**

```json
{
  "status": "SUCCESS",
  "srcEid": "AAAAAA12000000000000000000000002",
  "dstEid": "DDDDDD42000000000000000000000002",
  "path": {
    "hops": [
      { "deviceName": "rack1#os0#npu1", "inPort": null, "outPort": "400GE 0/0/1", "deviceType": "NPU", "multiPath": false },
      { "deviceName": "rack1#l1sw0",   "inPort": "400GE 1/0/1", "outPort": "400GE 1/0/2", "deviceType": "SW",  "multiPath": false },
      { "deviceName": "rack1#os0#npu2", "inPort": "400GE 0/1/1", "outPort": null,       "deviceType": "NPU", "multiPath": false }
    ]
  }
}
```

**断言要点：**
- `result.status == PlanStatus.SUCCESS`
- `result.srcEid == "AAAAAA12000000000000000000000002"`
- `result.dstEid == "DDDDDD42000000000000000000000002"`
- `result.path.hops.size() == 3`
- `hops[0].deviceName == "rack1#os0#npu1"`, `hops[0].inPort == null`, `hops[0].outPort == "400GE 0/0/1"`
- `hops[1].deviceName == "rack1#l1sw0"`, `hops[1].inPort == "400GE 1/0/1"`, `hops[1].outPort == "400GE 1/0/2"`
- `hops[2].deviceName == "rack1#os0#npu2"`, `hops[2].inPort == "400GE 0/1/1"`, `hops[2].outPort == null`

---

## 3. 测试工具 2：4npu_8port

### 3.1 拓扑结构

```
4 NPU (npu1~npu4) + 4 L1SW (l1sw0~l1sw3) + 1 L2SW (lc#0)
每 NPU 8 端口，分 4 组连 4 个 L1SW（每 L1SW 2 口）
每 L1SW 8 端口，分 4 组连 4 个 NPU + 4 口连 L2SW
```

详细连线关系见 `topo_4npu_8port_连线关系.md`。

### 3.2 主成功场景

#### 用例 3.2.1：npu1 → l1sw0 → npu2（port 0/0/0）

这是最直接的路径：npu1 和 npu2 各自用 port0 连 l1sw0，路由前缀精确匹配。

**输入：**

```json
{
  "superNodeName": "A5-superPod-2",
  "srcDevice": "rack1#os0#npu1",
  "destDevice": "rack1#os0#npu2",
  "srcPort": "400GE 0/0/0",
  "destPort": "400GE 0/0/0",
  "interDevices": {
    "rack1#l1sw0": "400GE 1/0/2"
  }
}
```

**处理追踪：**

| Step | 操作 | 结果 |
|---|---|---|
| 0 | 查 SuperNode | `A5-superPod-2` 找到 |
| 0 | 查 src/dest Device | `superNode.getNpuDevices()`中 npu1 / npu2 找到 |
| 1 | 查 srcPort | `npu1.findNpuPort("400GE 0/0/0")` → CNA=`170.170.170.17`, EID=`AAAAAA12000000000000000000000001`, remoteDevice=`rack1#l1sw0`, remotePort=`400GE 1/0/0` |
| 2 | 查 destPort | `npu2.findNpuPort("400GE 0/0/0")` → CNA=`221.221.221.68`, EID=`DDDDDD42000000000000000000000001`, remoteDevice=`rack1#l1sw0`, remotePort=`400GE 1/0/2` |
| 3 | interDevices 非空 | 进入多跳逻辑 |
| 5 | 多跳路径还原 | hops=[NPU1, L1SW0, NPU2] |
| 6 | 正向 routePhase | target=`cnaToTargetAddr("221.221.221.68")`=`"221.221.221.68"` |
| 6 | L1SW0 路由查找 | `221.221.221.68/32` → 1/0/2 → 匹配 outPort=`400GE 1/0/2` |
| 7 | 反向 routePhase | target=`cnaToTargetAddr("170.170.170.17")`=`"170.170.170.17"` |
| 7 | L1SW0 路由查找 | `170.170.170.17/32` → 1/0/0 → 匹配 outPort=`400GE 1/0/0` |
| 9-10 | 构建结果 | SUCCESS |

**期望输出：**

```json
{
  "status": "SUCCESS",
  "srcEid": "AAAAAA12000000000000000000000001",
  "dstEid": "DDDDDD42000000000000000000000001",
  "path": {
    "hops": [
      { "deviceName": "rack1#os0#npu1", "inPort": null, "outPort": "400GE 0/0/0", "deviceType": "NPU", "multiPath": false },
      { "deviceName": "rack1#l1sw0",   "inPort": "400GE 1/0/0", "outPort": "400GE 1/0/2", "deviceType": "SW",  "multiPath": false },
      { "deviceName": "rack1#os0#npu2", "inPort": "400GE 0/0/0", "outPort": null,       "deviceType": "NPU", "multiPath": false }
    ]
  }
}
```

**断言要点：**
- `result.status == PlanStatus.SUCCESS`
- `result.srcEid == "AAAAAA12000000000000000000000001"`
- `result.dstEid == "DDDDDD42000000000000000000000001"`
- `result.path.hops.size() == 3`
- `hops[0].deviceName == "rack1#os0#npu1"`, `hops[0].outPort == "400GE 0/0/0"`
- `hops[1].deviceName == "rack1#l1sw0"`, `hops[1].inPort == "400GE 1/0/0"`, `hops[1].outPort == "400GE 1/0/2"`
- `hops[2].deviceName == "rack1#os0#npu2"`, `hops[2].inPort == "400GE 0/0/0"`

#### 用例 3.2.2：npu1 → l1sw1 → npu3（port 0/0/1）

需修正路由前缀后使用（见 1.2 节 L1SW1 路由修正）。

**输入：**

```json
{
  "superNodeName": "A5-superPod-2",
  "srcDevice": "rack1#os0#npu1",
  "destDevice": "rack1#os0#npu3",
  "srcPort": "400GE 0/0/1",
  "destPort": "400GE 0/0/1",
  "interDevices": {
    "rack1#l1sw1": "400GE 1/0/4"
  }
}
```

**处理追踪：**

| Step | 结果 |
|---|---|
| srcPort | `npu1.findNpuPort("400GE 0/0/1")` → CNA=`170.170.170.18`, EID=`AAAAAA12000000000000000000000002`, remote=`l1sw1:1/0/0` |
| destPort | `npu3.findNpuPort("400GE 0/0/1")` → CNA=`238.238.238.86`, EID=`EEEEEE55000000000000000000000002`, remote=`l1sw1:1/0/4` |
| 正向 routePhase | target=`cnaToTargetAddr("238.238.238.86")`=`"238.238.238.86"` → L1SW1 路由 `238.238.238.86/32`(修正后) → outPort=`400GE 1/0/4` |
| 反向 routePhase | target=`cnaToTargetAddr("170.170.170.18")`=`"170.170.170.18"` → L1SW1 路由 `170.170.170.18/32`(修正后) → outPort=`400GE 1/0/0` |

**期望输出：**

```json
{
  "status": "SUCCESS",
  "srcEid": "AAAAAA12000000000000000000000002",
  "dstEid": "EEEEEE55000000000000000000000002",
  "path": {
    "hops": [
      { "deviceName": "rack1#os0#npu1", "inPort": null, "outPort": "400GE 0/0/1", "deviceType": "NPU", "multiPath": false },
      { "deviceName": "rack1#l1sw1",   "inPort": "400GE 1/0/0", "outPort": "400GE 1/0/4", "deviceType": "SW",  "multiPath": false },
      { "deviceName": "rack1#os0#npu3", "inPort": "400GE 0/0/1", "outPort": null,       "deviceType": "NPU", "multiPath": false }
    ]
  }
}
```

---

## 4. 主成功场景：覆盖规划（planPathsCoverage / planPathsCoverageEx）

### 4.1 planPathsCoverage — 4npu_8port 主成功场景

**前置条件：** `setSuperNode(topo_4npu_8port)` 已调用，状态为 DATAREADY。

**输入（CoveragePathsRequest）：**

```json
{
  "superNodeName": "A5-superPod-2",
  "coverageRequirement": "MIN_COVERAGE"
}
```

**处理追踪：**

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | PathService.planPathsCoverage | 构造 CoveragePlanEngine(superNode, hashFunc, ...) |
| 2 | engine.findCoverage(MIN_COVERAGE) | 收集 L1SW↔L2SW 出端口覆盖域 |
| 3 | 枚举 EID 对 | 跨机框 + 同机框全部 src×dst NPU 端口组合 |
| 4 | 对每个 EID 对追踪 4 跳正反向路径 | 使用 H3a/H3b、H5a/H5b 选口；NPU 末跳出端口取 get(0) |
| 5 | 贪心选择 | 挑选能覆盖最多未命中 L1SW↔L2SW 端口的 EID 对 |
| 6 | 终止 | 全部覆盖域端口 coverCount >= 1（MIN_COVERAGE） |
| 7 | 统计 | totalStats = { totalLinks, coveredLinks=totalLinks, coverageRate=1.0, ... } |
| 8 | 组装结果 | scope=L1_L2，layerStats=null |

**期望输出（CoveragePathsResult）：**

```json
{
  "scope": "L1_L2",
  "status": "SUCCESS",
  "eidPairs": [
    { "srcEid": "AAAAAA12...", "dstEid": "DDDDDD42...", "coveredLinks": [...4 条...], "type": null },
    ...
  ],
  "coverageLinks": [
    { "deviceName": "rack1#l1sw0", "chipIndex": 0, "outPortName": "400GE 1/0/8", ..., "coverCount": 1, "layer": null, "deviceType": null },
    ...
  ],
  "totalStats": { "totalLinks": N, "coveredLinks": N, "coverageRate": 1.0, "redundantLinks": ..., "eidPairCount": M, "eidUniformity": ... },
  "layerStats": null
}
```

**断言要点：**
- `result.status == PlanStatus.SUCCESS`
- `result.scope == CoverageLinkScope.L1_L2`
- `result.layerStats == null`
- `result.coverageLinks` 内所有 `layer == null`、`deviceType == null`
- `result.eidPairs` 内所有 `type == null`
- 每个 `CoveredEidPair.coveredLinks.size() == 4`（2 正向 + 2 反向）
- `totalStats.coverageRate == 1.0`
- `totalStats.coveredLinks == totalStats.totalLinks`

### 4.2 planPathsCoverageEx — 4npu_8port 主成功场景

**前置条件：** 同 4.1；拓扑输入 NPU 端口需含 `jettyId` 字段。

**输入（CoveragePathsRequest）：**

```json
{
  "superNodeName": "A5-superPod-2",
  "coverageRequirement": "MIN_COVERAGE"
}
```

**处理追踪（两阶段）：**

| 阶段 | 步骤 | 操作 | 结果 |
|---|---|---|---|
| 阶段1 | 1 | engine.findCoverageEx | 收集 NPU↔L1SW↔L2SW 全部覆盖域 |
| 阶段1 | 2 | 枚举跨机框 EID 对 | src/dst 在不同机框 |
| 阶段1 | 3 | 追踪 4 跳正反向路径 | 使用 H1/H2、H3a/H3b、H4、H5a/H5b 选口 |
| 阶段1 | 4 | 贪心选择 CROSS_L2 EID 对 | 覆盖 L1SW↔L2SW 缺口 |
| 阶段1 | 5 | 终止条件 | L1_L2 层全部端口 coverCount >= 1 |
| 阶段2 | 6 | 筛选 NPU_L1 缺口 | layer == NPU_L1 && coverCount < required |
| 阶段2 | 7 | 枚举同机框 EID 对 | src/dst 在同一机框 |
| 阶段2 | 8 | 追踪 2 跳正反向路径 | 使用 H6、H7a/H7b 选口 |
| 阶段2 | 9 | 贪心补齐 LOCAL_L1 EID 对 | 覆盖 NPU↔L1SW 缺口 |
| 合并 | 10 | 统计 | totalStats + layerStats=[NPU_L1, L1_L2] |
| 合并 | 11 | 组装结果 | scope=NPU_L1_L2 |

**期望输出（CoveragePathsResult）：**

```json
{
  "scope": "NPU_L1_L2",
  "status": "SUCCESS",
  "eidPairs": [
    { ..., "type": "CROSS_L2", "coveredLinks": [...8 条...（4 正向 + 4 反向）...] },
    { ..., "type": "LOCAL_L1", "coveredLinks": [...4 条...（2 正向 + 2 反向）...] },
    ...
  ],
  "coverageLinks": [
    { ..., "layer": "NPU_L1", "deviceType": "NPU", ... },
    { ..., "layer": "NPU_L1", "deviceType": "SW", ... },
    { ..., "layer": "L1_L2",  "deviceType": "SW", ... },
    ...
  ],
  "totalStats": { ..., "coverageRate": 1.0 },
  "layerStats": [
    { "layer": "NPU_L1", "stats": { ..., "coverageRate": 1.0 } },
    { "layer": "L1_L2",   "stats": { ..., "coverageRate": 1.0 } }
  ]
}
```

**断言要点：**
- `result.scope == CoverageLinkScope.NPU_L1_L2`
- `result.layerStats.size() == 2`，含 NPU_L1 与 L1_L2 两层
- `result.coverageLinks[*].layer ∈ {NPU_L1, L1_L2}`
- `result.coverageLinks[*].deviceType ∈ {"NPU", "SW"}`
- `eidPairs[*].type ∈ {CROSS_L2, LOCAL_L1}`
- CROSS_L2 的 `coveredLinks.size() == 8`（4 正向 + 4 反向）
- LOCAL_L1 的 `coveredLinks.size() == 4`（2 正向 + 2 反向）
- `totalStats.coverageRate == 1.0`
- `layerStats[0].stats.coverageRate == 1.0`（NPU_L1 全覆盖）
- `layerStats[1].stats.coverageRate == 1.0`（L1_L2 全覆盖）

### 4.3 planPathsCoverageEx — jettyId 缺失回落场景

**前置条件：** 拓扑输入未携带 `jettyId` 字段（模拟旧拓扑）。

**处理追踪：**

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | CoveragePlanEngine.jettyIdOf(port) | jettyId 为 null → 回落 `32 + port.id` |
| 2 | 累加诊断计数 | `exJettyFallback++` |
| 3 | 继续两阶段覆盖规划 | 使用回落的 jettyId 调用 `HashUtils.nativeHashDstCnaJetty` |

**断言要点：**
- `result.status == SUCCESS`（仍可完成选路）
- `engine.getExDiagnostics().jettyIdFallback > 0`
- 其他诊断计数均为 0

### 4.4 planPathsCoverage — COVERAGE_INCOMPLETE 场景

**前置条件：** 拓扑中部分 L1SW 路由表缺失或不完整，导致无法覆盖到某些 L1SW↔L2SW 端口。

**期望输出：**

```json
{
  "scope": "L1_L2",
  "status": "COVERAGE_INCOMPLETE",
  "errorMessage": "coverage incomplete: 6/8 covered, missing 2 links",
  "eidPairs": [...],
  "coverageLinks": [..., { ..., "coverCount": 0 }, { ..., "coverCount": 0 }],
  "totalStats": { "coverageRate": 0.75, ... }
}
```

**断言要点：**
- `result.status == PlanStatus.COVERAGE_INCOMPLETE`
- `result.totalStats.coverageRate < 1.0`
- 仍返回 `eidPairs` 与 `coverageLinks`（部分覆盖结果，由调用方决定接受或重试）

---

## 5. 主成功场景：路由计算与实例化（routeCalculate + makeRoutes + getNodeRoute）

### 5.1 routeCalculate — 首次调用

**前置条件：** `init()` 已完成，状态为 READY（无需 SuperNode 已下发）。

**输入：** 无参数。

**处理追踪：**

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | synchronized 进入 | routeCalculated == false，继续 |
| 2 | TopoTemplateService.parseTemplateFile | 加载 128_npu_rack.json + 128_npu_inter_rack.json |
| 3 | RouteMspService.routeMsp | BFS 计算每个转发节点到其他节点的最短路径 |
| 4 | RouteInstantiationService.buildXpodRoutes | 生成模板路由表 routes |
| 5 | routeCalculated = true | 后续重复调用直接返回 |

**断言要点：**
- 方法正常返回，无异常
- 第二次调用同样无异常（幂等），内部 `routeCalculated == true` 跳过实际计算

### 5.2 makeRoutes — 实例化路由表

**前置条件：** `routeCalculate()` 已调用；`setSuperNode(superNode)` 已调用。

**输入：** SuperNode（已下发）。

**处理追踪：**

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | 检查 routeCalculated | true，继续 |
| 2 | RouteInstantiationService.instantiateXpodRoute | 遍历 NPU/L1SW/L2SW 设备 |
| 3 | NPU 实例化 | 按 chassis/slot/ubpu/die 标签匹配模板 |
| 4 | L1SW 实例化 | 按 chassis/index 标签匹配模板 |
| 5 | L2SW 实例化 | 按 index/chip 标签匹配模板，端口索引重映射 |
| 6 | deepCopyRoutingEntry | 深拷贝避免外部修改影响内部 |
| 7 | instantiationRouteMap.put | key="deviceName#chipIndex" |

**期望输出：** `Map<String, Map<String, RoutingEntry>>`

**断言要点：**
- 返回的 Map 不为空
- Map 中包含 SuperNode 中每个设备的每个 chip 一条记录
- 每条 `RoutingEntry` 与 `instantiationRouteMap` 内部对象**不相等**（深拷贝验证）
- 修改返回的 Map 不影响再次调用 `getNodeRoute` 的结果

### 5.3 getNodeRoute — 查询单设备路由

**前置条件：** `makeRoutes(superNode)` 已调用。

**输入：**

```java
getNodeRoute("rack1#os0#npu1", 0)
```

**处理追踪：**

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | 查找 instantiationRouteMap | key="rack1#os0#npu1#0" |
| 2 | 返回对应的 Map<String, RoutingEntry> | 该 chip 的路由前缀 → RoutingEntry |

**断言要点：**
- 返回的 Map 包含多个路由前缀
- 每个 RoutingEntry.prefix 非 null
- 每个 RoutingEntry.outPortInfos 至少包含一个出端口
- 返回值与 `makeRoutes` 返回的对应子 Map 内容相等（深拷贝但内容相同）

### 5.4 错误场景：未调用 routeCalculate 直接 makeRoutes

**前置条件：** 未调用 `routeCalculate()`。

**调用：** `makeRoutes(superNode)`

**期望：** 抛出 `IllegalStateException`，错误消息包含 "routeCalculate" 或 "not calculated"。

### 5.5 错误场景：未调用 makeRoutes 直接 getNodeRoute

**前置条件：** 未调用 `makeRoutes(superNode)`。

**调用：** `getNodeRoute("rack1#os0#npu1", 0)`

**期望：** 抛出 `IllegalArgumentException`（key 不存在）或 `IllegalStateException`。

---

## 6. 主成功场景：链路事件与路由收敛（notifyLinkEvent）

### 6.1 链路 down 事件 — 单跳收敛

**前置条件：** `makeRoutes(superNode)` 已完成；拓扑中 `rack1#l1sw0:400GE 1/0/2` 是 `rack1#os0#npu2` 上行链路。

**输入（LinkEvent）：**

```json
{
  "deviceName": "rack1#l1sw0",
  "portName": "400GE 1/0/2",
  "eventType": "down",
  "eventTime": 1716230400000
}
```

**处理追踪：**

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | LinkEventService.handleLinkEvent | 定位 l1sw0 的 chip 0 包含 port 1/0/2 |
| 2 | PortEntity.setLinkStatus | port.linkStatus = LINK_DOWN, port.updateAt = 1716230400000 |
| 3 | RouteConvergeService.converge | 遍历 "rack1#l1sw0#0" 路由表 |
| 4 | 定位包含 1/0/2 的 RoutingEntry | 找到，对应 prefix "221.221.221.68/32" |
| 5 | OutPortInfo.setFlag | convergedFlag \|= FLAG_PASSIVE_CONVERRGED |
| 6 | RoutingEntry.refreshReachable | 该 entry 仅有此一个出端口 → reachable = false |
| 7 | BFS 传播 | reachable 变化（true→false） |
| 8 | 通过 port 1/0/0 的 remoteDevice 找到 npu1 | 在 npu1 chip 0 路由表查 prefix "221.221.221.68/32" |
| 9 | npu1 对应 OutPortInfo.setFlag | 标记 1/0/0 为 PASSIVE_CONVERGED |
| 10 | npu1 该 entry refreshReachable | 若 npu1 有多个出端口且其余有效 → reachable = true（无变化），BFS 终止 |

**断言要点：**
- 方法正常返回，无异常
- 调用 `getNodeRoute("rack1#l1sw0", 0)` 返回的路由表中，prefix "221.221.221.68/32" 的 RoutingEntry：
  - `reachable == false`
  - `outPortInfos["400GE 1/0/2"].isConverged() == true`
  - `outPortInfos["400GE 1/0/2"].getConvergedFlag() & FLAG_PASSIVE_CONVERRGED != 0`

### 6.2 链路 up 事件 — 清除 PASSIVE_CONVERGED

**前置条件：** 6.1 已执行，路由已收敛。

**输入（LinkEvent）：**

```json
{
  "deviceName": "rack1#l1sw0",
  "portName": "400GE 1/0/2",
  "eventType": "up",
  "eventTime": 1716230500000
}
```

**处理追踪：**

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | PortEntity.setLinkStatus | port.linkStatus = LINK_UP, port.updateAt = 1716230500000 |
| 2 | RouteConvergeService.converge | 遍历路由表 |
| 3 | OutPortInfo.clearFlag | convergedFlag &= ~FLAG_PASSIVE_CONVERRGED |
| 4 | RoutingEntry.refreshReachable | reachable = true（true→false→true，再次变化） |
| 5 | BFS 传播 | 同 6.1 步骤 7~10，对端 npu1 同样清除 PASSIVE_CONVERGED |

**断言要点：**
- 调用 `getNodeRoute("rack1#l1sw0", 0)` 返回的 RoutingEntry：
  - `reachable == true`
  - `outPortInfos["400GE 1/0/2"].isConverged() == false`
  - `outPortInfos["400GE 1/0/2"].getConvergedFlag() == 0`

### 6.3 重复 down 事件 — 幂等性

**前置条件：** 6.1 已执行。

**输入：** 同 6.1（再次发送 down 事件）。

**断言要点：**
- 方法正常返回，无异常
- 路由表状态不变（FLAG_PASSIVE_CONVERRGED 已置位，幂等）
- BFS 不传播（reachable 未变化）

### 6.4 错误场景：设备或端口不存在

**输入：**

```json
{ "deviceName": "rack1#l1sw99", "portName": "400GE 1/0/0", "eventType": "down", "eventTime": 1716230400000 }
```

**期望：** 抛出 `IllegalStateException`，错误消息包含 "device" 或 "port" 不存在。

### 6.5 错误场景：eventType 非法

**输入：**

```json
{ "deviceName": "rack1#l1sw0", "portName": "400GE 1/0/2", "eventType": "freeze", "eventTime": 1716230400000 }
```

**期望：** 抛出 `IllegalArgumentException`，错误消息包含 "eventType"。

---

## 7. 数据验证清单

需确认数据满足以下约束：

### 7.1 路由一致性

对每对 `(L1SW, NPU端口)` 组合：

```
cnaToTargetAddr(NPU端口.CNA) ∈ L1SW.routingTables[].prefix.dstAddress
```

即：NPU 端口的 CNA 经过 `cnaToTargetAddr` 变换后，必须在所连 L1SW 的路由表中有匹配的前缀。

### 7.2 jettyId 取值一致性（planPathsCoverageEx）

对每个 NPU 端口：

```
NPU端口.jettyId ∈ [32, 1023]   或   NPU端口.jettyId 为 null（触发回落）
```

缺失或越界时，`CoveragePlanEngine.jettyIdOf` 回落 `32 + port.id`，并累加诊断计数 `exJettyFallback`。

### 7.3 覆盖域完整性（planPathsCoverage/Ex）

```
CoveragePathsResult.totalStats.coveredLinks == CoveragePathsResult.totalStats.totalLinks
（当 status == SUCCESS 时；COVERAGE_INCOMPLETE 时 coveredLinks < totalLinks）
```

### 7.4 路由收敛一致性（notifyLinkEvent）

链路 down 后：

```
对应 OutPortInfo.convergedFlag & FLAG_PASSIVE_CONVERRGED != 0
RoutingEntry.reachable == false（若该 entry 仅此一个出端口）
```

链路 up 后：

```
对应 OutPortInfo.convergedFlag & FLAG_PASSIVE_CONVERRGED == 0
RoutingEntry.reachable == true
```

---

## 8. 覆盖率标注

| 测试用例 | 覆盖 flow | 覆盖 RoutePhase 方向 |
|---|---|---|
| 2.2.1 多跳 npu1→npu2 via l1sw0 | 多跳 SUCCESS | 正向 + 反向 |
| 2.2.1 反向 npu2→npu1 via l1sw0 | 多跳 SUCCESS（反转路径） | 正向 + 反向（PathServiceTest 覆盖） |
| 3.2.1 npu1→npu2 via l1sw0 (port0) | 多跳 SUCCESS + L1SW0 路由 | 正向 + 反向 |
| 3.2.2 npu1→npu3 via l1sw1 (port1) | 多跳 SUCCESS + L1SW1 路由 | 正向 + 反向 |
| 4npu_8port 全量遍历（6 对 × 8 端口） | 多跳 SUCCESS × 96 | 正向 + 反向 × 96 |
| 4.1 planPathsCoverage L1↔L2 覆盖 | 覆盖规划 SUCCESS + 统计 | 正向 + 反向 |
| 4.2 planPathsCoverageEx NPU↔L1↔L2 两阶段 | 覆盖规划 SUCCESS + 分层统计 + jettyId hash | 正向 + 反向 |
| 4.3 planPathsCoverageEx jettyId 缺失回落 | 诊断计数 jettyIdFallback > 0 + SUCCESS | - |
| 4.4 planPathsCoverage COVERAGE_INCOMPLETE | 部分覆盖 | - |
| 5.1 routeCalculate 幂等 | 路由模板计算 + 第二次幂等 | - |
| 5.2 makeRoutes 实例化 | 模板实例化 + 深拷贝 | - |
| 5.3 getNodeRoute 查询 | HashMap 查询 | - |
| 5.4 makeRoutes 未调用 routeCalculate 错误 | IllegalStateException | - |
| 5.5 getNodeRoute 未调用 makeRoutes 错误 | IllegalArgumentException/IllegalStateException | - |
| 6.1 链路 down 收敛 | OutPortInfo.setFlag + refreshReachable + BFS 传播 | - |
| 6.2 链路 up 清除 | OutPortInfo.clearFlag + refreshReachable + BFS 传播 | - |
| 6.3 重复 down 幂等 | 位运算幂等 + BFS 不传播 | - |
| 6.4 设备/端口不存在错误 | IllegalStateException | - |
| 6.5 eventType 非法错误 | IllegalArgumentException | - |

---
