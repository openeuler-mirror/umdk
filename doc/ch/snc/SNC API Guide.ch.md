# SNC 模块接口文档

## 1. 概述

SNC（SuperNode Network Controller）模块提供 SuperNode 拓扑管理、路径规划等功能。对外暴露统一的 `SNCService` 接口，内部采用分层架构：Service → Engine → Store。

---

## 2. 核心接口 — `SNCService`

包路径：`com.huawei.umdk.snc.SNCService`

### 2.1 生命周期管理

| 方法 | 参数 | 返回值 | 描述 | 异常说明 |
|------|------|--------|------|---------|
| `init` | `SNCConfig config` | `void` | 初始化 SNC 服务，创建 Store、Engine、Service 实例，状态迁移至 READY | 可在任何状态调用；`config` 为 `null` 时 **日志默认 INFO**；重复调用会**重建所有内部实例**，旧 Store 数据丢失 |
| `uninit` | 无 | `void` | 反初始化，清空所有 Store，状态迁移至 UNINIT | 可在任何状态调用（包括从未 `init` 的状态）；重复调用安全无副作用；`uninit` 后除 `init` 外**所有方法抛 SNCStateException** |

### 2.1a init 参数说明

`SNCConfig.logLevel` 控制 `SNCServiceImpl` 的日志级别（通过 `LOG.setLevel()` 生效）：

| 调用方式 | 日志行为 |
|---------|---------|
| `init(new SNCConfig())` | `logLevel=INFO`（默认），输出 `INFO` 日志 |
| `init(new SNCConfig(Level.WARNING))` | 仅输出 `WARNING` 及以上日志，`INFO` 被 Logger 原生过滤 |
| `init(null)` | config 为 null → 默认 `INFO` |

### 2.2 SuperNode 拓扑管理

| 方法 | 参数 | 返回值 | 描述 | 异常说明 |
|------|------|--------|------|---------|
| `setSuperNode` | `SuperNode superNode` | `void` | 导入（**按 name 覆盖**）SuperNode 拓扑，标记 superNodeLoaded，更新数据就绪状态；同 name 的旧数据被覆盖，不同 name 的 SuperNode 共存不受影响 | INIT/UNINIT → `SNCStateException`；参数 null/name空/devices空 → `IllegalArgumentException`；**子字段（deviceName/forwardingChips/routingTable 等）不校验**，缺失时静默存储，后续 planPath 返回对应错误码 |
| `addNpuDevices` | `String superNodeName, List<NpuDevice> devices` | `void` | 向已有 SuperNode 添加 NPU 设备；若 SuperNode 不存在则**抛 IllegalStateException** | INIT/UNINIT → `SNCStateException`；null参数 → `IllegalArgumentException` |
| `addSwDevices` | `String superNodeName, List<SwDevice> devices` | `void` | 向已有 SuperNode 添加 SW 设备；若 SuperNode 不存在则**抛 IllegalStateException** | INIT/UNINIT → `SNCStateException`；null参数 → `IllegalArgumentException` |
| `removeDevices` | `String superNodeName, List<String> deviceNames` | `void` | 从 SuperNode 的 npuDevices 和 swDevices 中移除设备；不存在则**静默无操作** | INIT/UNINIT → `SNCStateException`；null参数 → `IllegalArgumentException` |
| `addRoutingEntries` | `String superNodeName, String deviceName, Integer chipIndex, List<RoutingEntry> entries` | `void` | 添加路由条目到指定芯片的路由表；路由表不存在则**抛 IllegalStateException** | INIT/UNINIT → `SNCStateException`；null参数 → `IllegalArgumentException` |
| `removeRoutingEntries` | `String superNodeName, String deviceName, Integer chipIndex, List<RoutePrefix> prefixes` | `void` | 按前缀从路由表移除路由条目；不存在则**静默无操作** | INIT/UNINIT → `SNCStateException`；null参数 → `IllegalArgumentException` |
| `getSuperNode` | `String name` | `SuperNode` | 按名称查询 SuperNode | INIT/UNINIT → `SNCStateException`；不存在返回 `null`（非异常） |
| `removeSuperNode` | `String name` | `void` | 按名称删除 SuperNode | INIT/UNINIT → `SNCStateException` |

### 2.3 路径规划

| 方法 | 参数 | 返回值 | 描述 | 异常说明 |
|------|------|--------|------|---------|
| `planPath` | `PathPlanRequest request` | `PathPlanResult` | 规划源到目的的传输路径 | 非 DATAREADY 状态 → `SNCStateException`（消息格式："SNC is not in DATAREADY state, current state: \<STATE\>"，**不同于**其他方法的 checkNotUninit 拦截消息） |
| | | | | request 为 null 或 superNodeName/srcDevice/destDevice/srcPort/destPort 任一为 null/空 → `IllegalArgumentException` |
| | | | | **interDevices 字段可选**（可为 null/空，表示直连场景） |
| | | | | 业务失败时不抛异常，返回 `PathPlanResult.status` 非 SUCCESS，详见下方 `PlanStatus` 映射表 |
| | | | | **路由查找机制**：planPath 内部路由查找以目的端口的 CNA（`destCna`）作为查找目标，直接与路由前缀做 LPM 匹配。|

### 2.3a 覆盖规划

| 方法 | 参数 | 返回值 | 描述 | 异常说明 |
|------|------|--------|------|---------|
| `planPathsCoverage` | `CoveragePathsRequest request` | `CoveragePathsResult` | **框间覆盖规划**：给定超节点拓扑（含路由表），挑选一组 EID 对使其正反向 hash 选路结果遍历 **L1SW↔L2SW** 出端口集合 | 非 DATAREADY 状态 → `SNCStateException`（与 `planPath` 同形） |
| | | | | request 为 null → `IllegalArgumentException` |
| | | | | `superNodeName` 为 null/空 或 SuperNode 不存在 → 返回 `PlanStatus.TOPO_NOT_FOUND`（不抛异常） |
| | | | | 覆盖未达 100% 时返回 `PlanStatus.COVERAGE_INCOMPLETE`，`errorMessage` 携带覆盖率明细 |
| | | | | **结果 `scope = L1_L2`**，每个 EID 对固定 4 条覆盖链路（2 正向 + 2 反向） |
| | | | | **覆盖域**：仅 L1SW→L2SW 与 L2SW→L1SW 的 ECMP 出端口 |
| `planPathsCoverageEx` | `CoveragePathsRequest request` | `CoveragePathsResult` | **扩展覆盖规划（含 NPU↔L1SW）**：在 `planPathsCoverage` 覆盖域基础上增加 **NPU↔L1SW** 出端口覆盖，NPU→L1SW 出端口由 **`(DstCNA, jettyId)` 二元组 CRC-8 hash** 选路，**被选中 NPU 端口的 CNA 作为下游 SCNA**，ACK 方向以**源 NPU 端口的 jettyId** 选路（与正向同一 jettyId） | 非 DATAREADY 状态 → `SNCStateException`（与 `planPath` 同形） |
| | | | | request 为 null → `IllegalArgumentException` |
| | | | | `superNodeName` 为 null/空 或 SuperNode 不存在 → 返回 `PlanStatus.TOPO_NOT_FOUND`（不抛异常） |
| | | | | 覆盖未达 100% 时返回 `PlanStatus.COVERAGE_INCOMPLETE`，`errorMessage` 追加分层覆盖率明细（如 `[NPU_L1: 98.4% 1008/1024; L1_L2: 95.3% 1008/1056]`） |
| | | | | **结果 `scope = NPU_L1_L2`**，框间 EID 对 8 条覆盖链路（4 正向 + 4 反向），框内 EID 对 4 条（2 正向 + 2 反向） |
| | | | | **两阶段流程**：阶段 1 枚举跨机框 EID 对做框间覆盖（`type = CROSS_L2`），阶段 2 对框间未覆盖的 NPU↔L1SW 出端口用同机框 EID 对补齐（`type = LOCAL_L1`），最后合并统计 |
| | | | | **jettyId 取值**：`[32, 1023]`，每个 NPU 物理端口一个；拓扑缺失时回落 `32 + portId` 并累加诊断计数 `jettyIdFallback` |
| | | | | **复用配置**：`hashFunc` / `fixedDataUdpPort` / `fixedAckUdpPort` / `hashTuple` / `dieHashFunctionSelect`，不新增配置项 |

#### 2.3a.1 `planPathsCoverage` 与 `planPathsCoverageEx` 对照

| 维度 | `planPathsCoverage` | `planPathsCoverageEx` |
|:---|:---|:---|
| 覆盖链路域 | L1SW↔L2SW | NPU↔L1SW ＋ L1SW↔L2SW |
| NPU→L1SW 出端口选择 | 由候选固定（物理连接），不参与 hash | NPU 路由 LPM + **`(DstCNA, jettyId)` CRC-8 hash** 选择 |
| L1SW→NPU 末跳出端口 | `get(0)` 确定性取首个 | **hash** 选择（L1SW 路由到目的 NPU 的出端口集合） |
| 每个 EID 对链路数 | 4（2 正向 + 2 反向） | 框间 8 / 框内 4 |
| 路径类型 `type` | `null` | `CROSS_L2`（框间）/ `LOCAL_L1`（框内） |
| 分层统计 `layerStats` | `null` | `NPU_L1` + `L1_L2` 两个分层 |
| `coverageLinks[*].layer` | `null` | `NPU_L1` / `L1_L2` |
| `coverageLinks[*].deviceType` | `null` | `"NPU"` / `"SW"` |
| ACK jettyId | 无（末跳 `get(0)`） | **源 NPU 端口 jettyId**（与正向同一） |
| 原生 hash 符号 | `ubswitch_Hash_ecmp` | `ubswitch_Hash_ecmp` ＋ **`ubswitch_Hash_dieEcmp`**（CRC-8/ATM） |
| 失败诊断 | `fwdFail1..12` / `revFailA..H` | 追加 `npuRouteFail` / `npuPortFail` / `jettyIdFallback` / `l1Fail` / `l2Fail` / `dstL1Fail` / `revNpuFail` / `revDstL1Fail` / `revL2Fail` / `revSrcL1Fail`（`CoveragePlanEngine.getExDiagnostics()`） |

#### 2.3a.2 覆盖规划请求与状态

**`CoveragePathsRequest`** 复用同一 DTO，两个接口签名区别仅在于方法名（不通过请求字段区分覆盖域）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `superNodeName` | `String` | SuperNode 名称（必填） |
| `coverageRequirement` | `CoverageRequirement` | 覆盖要求枚举；`null` 时按 `MIN_COVERAGE` 处理 |

**`CoverageRequirement` 枚举：**

| 值 | 含义 | 每条链路最小覆盖次数 |
|:---|:---|:---:|
| `MIN_COVERAGE` | 最小覆盖，每条链路至少被 1 个 EID 对覆盖 | 1 |
| `REDUNDANT` | 冗余覆盖，每条链路至少被 2 个**互不相交**的 EID 对覆盖（`runGreedyCoverageDualDisjoint`） | 2 |

**覆盖规划 `PlanStatus` 取值：**

| 状态 | 码值 | 触发条件 |
|------|------|---------|
| `SUCCESS` | 0 | 全部链路 `coverCount ≥ required`（全覆盖） |
| `COVERAGE_INCOMPLETE` | 1011 | 存在链路 `coverCount < required`；`errorMessage` 携带覆盖率明细 |
| `TOPO_NOT_FOUND` | 1012 | `superNodeName` 为空或 SuperNode 不存在 |

### 2.3b 链路事件与路由管理

| 方法 | 参数 | 返回值 | 描述 | 异常说明 |
|------|------|--------|------|---------|
| `notifyLinkEvent` | `SuperNode supernode, LinkEvent event` | `void` | 通知链路 up/down 事件，更新端口 `linkStatus` 与 `updateAt`，并触发 **BFS 路由收敛**（`RouteConvergeService.converge`）在互联转发节点间传播可达性变化 | INIT/UNINIT → `SNCStateException`（走 `checkNotUninit`） |
| | | | | `supernode` 为 null → `IllegalArgumentException` |
| | | | | `event` 为 null → `IllegalArgumentException` |
| | | | | `event.deviceName` / `event.portName` 为 null/空 → `IllegalArgumentException` |
| | | | | `event.eventType` 非 `"up"`/`"down"` → `IllegalArgumentException` |
| | | | | 设备或端口在拓扑中不存在 → `IllegalStateException` |
| | | | | **路由收敛算法**：定位事件端口所属 chip，刷新该 chip 路由表中以该端口为出端口的 `OutPortInfo.convergedFlag`（down=置 PASSIVE，up=清 PASSIVE）并调用 `RoutingEntry.refreshReachable()`；reachable 变化的前缀通过 chip 其他 up 端口向对端转发节点传播，迭代直到无 reachable 变化（BFS）。同一设备不同 forwardingChip 转发隔离，收敛只在端口所属 chip 路由表内传播 |
| | | | | **作用对象**：`SncService` 持有的 `instantiationRouteMap`（由 `makeRoutes` 填充），收敛结果影响后续 `getNodeRoute` 查询 |
| `routeCalculate` | 无 | `void` | **同步方法**（`synchronized`）：基于内置拓扑模板（`128_npu_rack.json`、`128_npu_inter_rack.json`）计算并实例化路由模板，填充 `routes`。**幂等**：已计算过则直接返回 | INIT/UNINIT → `SNCStateException`（走 `checkNotUninit`） |
| | | | | 计算流程：`TopoTemplateService.parseTemplateFile` 解析模板 → `RouteMspService.routeMsp` 按最短路径策略生成模板路由 → `RouteInstantiationService.instantiateXpodRoute` 按机框实例化 |
| | | | | **必须在 `makeRoutes` 之前调用**，否则 `makeRoutes` 抛 `IllegalStateException("calculate routeCalculate first")` |
| | | | | **不依赖 SuperNode 已下发**：可在 `init` 后任意时刻（非 INIT/UNINIT）调用 |
| `makeRoutes` | `SuperNode superNode` | `Map<String, Map<String, RoutingEntry>>` | 基于已计算的路由模板，为 SuperNode 中的 NPU/L1SW/L2SW 设备生成实例化路由表，存入 `instantiationRouteMap` 并返回副本 | INIT/UNINIT → `SNCStateException`（走 `checkNotUninit`） |
| | | | | `routeCalculate` 未调用 → `IllegalStateException("calculate routeCalculate first")` |
| | | | | `superNode` 为 null → `IllegalArgumentException` |
| | | | | **返回值 key**：`"deviceName#chipIndex"`（由 `RouteInstantiationService.buildRouteTableKey` 构建）；value 为该 chip 的路由前缀 → `RoutingEntry` 映射 |
| | | | | **实例化规则**：NPU 按 `chassis/slot/ubpu/die` 标签匹配模板；L1SW 按 `chassis/index` 匹配；L2SW 按 `index/chip` 匹配，4 框实例化时 L2SW 的出端口索引/名称按框间拓扑重映射 |
| | | | | **深拷贝**：`RouteInstantiationService.deepCopyRoutingEntry` 保证内部 `instantiationRouteMap` 与返回值互不影响 |
| `getNodeRoute` | `String deviceName, int chipIndex` | `Map<String, RoutingEntry>` | 查询单个设备单芯片的实例化路由表（从 `instantiationRouteMap` 读取） | INIT/UNINIT → `SNCStateException`（走 `checkNotUninit`） |
| | | | | `deviceName` 为 null → `IllegalArgumentException` |
| | | | | key `"deviceName#chipIndex"` 在 `instantiationRouteMap` 中不存在 → `IllegalArgumentException("not found route for " + key)` |
| | | | | **典型用途**：路由收敛（`notifyLinkEvent`）后查询收敛后的可达性状态 |
| `routeMSP` (static) | 无 | `Map<String, Map<String, RouteTable>>` | 工具方法：解析内置拓扑模板并生成路由模板（不写入 `routes`），返回 `xpodType → (nodeLabel → RouteTable)` | 无状态校验（静态方法） |

---

## 3. 状态机

```
          init()                       uninit()
    INIT ──────────▶ READY ──(setSuperNode 已完成)──▶ DATAREADY
     │                                │                                 │
     │                                │ 增量操作 (add/remove/get/…)       │ planPath (可多次并发)
     │                                │ setSuperNode                     │ planPathsCoverage / planPathsCoverageEx
     │                                │ routeCalculate                   │ setSuperNode (可更新)
     │                                │ makeRoutes                       │ 增量操作 (add/remove/get/…)
     │                                │ getNodeRoute                     │ notifyLinkEvent
     │                                │ notifyLinkEvent                  │ routeCalculate (幂等)
     │                                │ uninit()                         │ makeRoutes / getNodeRoute / notifyLinkEvent
     │                                │                                 │ uninit()
     └──── uninit() ───▶ UNINIT ◀───────────────────────────────────────┘
```

| 状态 | 说明 | 允许的操作 |
|:-----|:-----|:----------|
| `INIT` | 初始状态（未初始化） | init()、uninit() |
| `READY` | 就绪状态（已初始化，数据未就绪） | setSuperNode；所有增量操作（addNpuDevices、addSwDevices、removeDevices、addRoutingEntries、removeRoutingEntries）；所有查询操作（getSuperNode）；removeSuperNode；routeCalculate；makeRoutes（需先 routeCalculate）；getNodeRoute（需先 makeRoutes）；notifyLinkEvent；uninit |
| `DATAREADY` | 数据就绪状态（拓扑已下发） | 同 READY，追加 planPath / planPathsCoverage / planPathsCoverageEx |
| `UNINIT` | 已去初始化 | （无，调用任何操作均抛 SNCStateException） |

**状态转换规则：**
- `init()`: INIT → READY（非幂等，重复 init 重建全部内部对象）
- `uninit()`: INIT / READY / DATAREADY → UNINIT（INIT 状态调用仅清空状态标记，无副作用）
- `setSuperNode()`: READY → DATAREADY（拓扑下发后自动迁移）
- `setSuperNode()`: DATAREADY → DATAREADY（数据就绪态可继续更新数据）
- `routeCalculate()`: READY/DATAREADY 内部迁移不变，仅设置 `routeCalculated = true`（幂等，重复调用直接返回）
- `planPath()` / `planPathsCoverage()` / `planPathsCoverageEx()`: 仅在 **DATAREADY** 状态下可用，非 DATAREADY 时抛 `SNCStateException`，消息为 `"SNC is not in DATAREADY state, current state: <STATE>"`（**注意**：这三个方法不走 `checkNotUninit`，自有状态判断，消息格式与其他方法不同）
- `notifyLinkEvent()` / `routeCalculate()` / `makeRoutes()` / `getNodeRoute()`: 走 `checkNotUninit`，READY/DATAREADY 均可调用（INIT/UNINIT 抛 `"SNC is in INIT state"` / `"SNC is in UNINIT state"`）

---

## 3a. 数据导入校验规则

### 3a.1 setSuperNode 校验层级

| 层级 | 字段 | 校验规则 | 非法时行为 |
|------|------|---------|-----------|
| L0 | `superNode` 本身 | non-null | `IllegalArgumentException` |
| L1 | `superNode.name` | non-null, non-empty | `IllegalArgumentException` |
| L1 | `superNode.npuDevices` + `superNode.swDevices` | 至少一个非空 | `IllegalArgumentException` |
| L2 | `npuDevices`/`swDevices` 中每个 `NpuDevice`/`SwDevice` (key/value) | **不校验** | 空 Map→通过，null value→存入后可能导致 NPE |
| L3 | `DeviceEntity.deviceName` | **不校验** | 可为 null/空，存入后按 null 名称索引 |
| L3 | `DeviceEntity.deviceType` | **不校验** | 可为 null，`planPath` 中类型判断通过 `getNpuDevices()` 仅查 NPU，SW 设备不会混入 |
| L3 | `DeviceEntity.forwardingChips` | **不校验** | 可为 null/空，存入后该设备无可转发芯片和端口 |
| L4 | `ForwardingChip.chipIndex` | **不校验** | 可为 null，路由表按 null chipIndex 索引 |
| L4 | `ForwardingChip.ports` | **不校验** | 可为 null/空，`findNpuPort` 遍历时返回 null |
| L4 | `ForwardingChip.routingTable` | **不校验** | 可为 null，则路由表不入索引，`addRoutingEntries` 抛 IllegalStateException |
| L5 | `PortEntity.portName` | **不校验** | null → 端口以 null 名称存入，无法通过名称查找 |
| L5 | `NpuPortEntity.eid` | **不校验** | `planPath` 中检测到 null → `SRC/DST_INFO_ERR` |
| L5 | `NpuPortEntity.cna` | **不校验** | `planPath` 中检测到 null → `SRC/DST_INFO_ERR` |
| L5 | `PortEntity.remoteDevice/remotePort` | **不校验** | `resolveDirectPath` 验证连接时错配 → `TOPO_CONNECTION_ERROR` |
| L5 | `RoutingEntry.prefix` | **不校验** | `addRoutingEntries` 中 entry.prefix null → `IllegalArgumentException`（Service 层会检） |
| L5 | `OutPortInfo` 各字段 | **不校验** | 存入后路由查找时可能产生 NPE |

### 3a.2 增量操作校验层级

与导入同理，增量操作（`addNpuDevices`、`addSwDevices` 等）仅校验自身入参，**嵌套对象字段不做校验**：

```java
addNpuDevices("sn1", Arrays.asList(
    new NpuDevice()   // deviceName=null, deviceType=null, forwardingChips=null
    // 可以通过校验并存入 → 后续操作 NPE
));
```

完整校验边界原则：

| 校验范围 | 校验内容 | 不校验范围 |
|---------|---------|-----------|
| 方法入参非 null | `devices != null` | 设备内部字段（deviceName, forwardingChips...） |
| 集合内元素非 null | 列表中每个 `device != null` | 端口字段（eid, cna, remoteDevice...） |
| 标识符非空字符串 | `superNodeName != ""` | 路由表字段（prefix, outPortInfos...） |

---

## 3b. 通用异常行为

所有方法（除 `init` 外）在错误状态调用时抛出 `SNCStateException`：

> ⚠️ **planPath / planPathsCoverage / planPathsCoverageEx 例外**：这三个方法不走 `checkNotUninit` 拦截，自有 `state != DATAREADY` 判断，统一抛 `"SNC is not in DATAREADY state, current state: <STATE>"`（INIT/READY/UNINIT 同形）。其余方法（`notifyLinkEvent` / `routeCalculate` / `makeRoutes` / `getNodeRoute` 等）走 `checkNotUninit`，消息为 `"SNC is in INIT state"` 或 `"SNC is in UNINIT state"`。

| 当前状态 | 调用 `init` | 调用 `uninit` | 调用其他方法 |
|----------|------------|--------------|-------------|
| `INIT` | 正常执行 → READY | 正常执行 → UNINIT | 抛 `SNCStateException("SNC is in INIT state")` |
| `READY` | 正常执行（重新初始化） | 正常执行 → UNINIT | 正常执行（`planPath`/`planPathsCoverage`/`planPathsCoverageEx` 除外，这三个要求 DATAREADY） |
| `DATAREADY` | 正常执行（重新初始化） | 正常执行 → UNINIT | 正常执行 |
| `UNINIT` | 正常执行 → READY | 正常执行 | 抛 `SNCStateException("SNC is in UNINIT state")` |

### 3b.2 参数校验异常

**有校验的方法**（setSuperNode、addNpuDevices、addSwDevices、removeDevices、addRoutingEntries、removeRoutingEntries、planPath、planPathsCoverage、planPathsCoverageEx、notifyLinkEvent、makeRoutes、getNodeRoute、getSuperNode、removeSuperNode）：

| 检查项 | 条件 | 异常 |
|--------|------|------|
| null 参数 | 任意非空入参为 null | `IllegalArgumentException` |
| empty 集合/字符串 | List/Map/String 为 empty | `IllegalArgumentException` |
| null/empty String | superNodeName、deviceName 等 | `IllegalArgumentException` |

**仅 init 不校验参数：**

| 方法 | 传入 null 的行为 |
|------|-----------------|
| `init(null)` | config 未使用，正常运行（进入 READY） |

### 3b.3 查询返回值约定

| 方法 | 存在返回值 | 不存在 |
|------|-----------|--------|
| `getSuperNode(name)` | SuperNode 对象 | `null`（非异常） |

---

## 3c. 调用时序异常场景

### 3c.1 先增量操作，后 setSuperNode

```java
// 错误时序：先增量添加再导入
sncService.addNpuDevices("sn1", devices);    // ① SuperNode 不存在 → IllegalStateException
sncService.addRoutingEntries("sn1", ...);    // ② 路由表不存在 → IllegalStateException
sncService.setSuperNode(completeSN);         // ③ 正常导入
```

| 调用顺序 | 行为 | 后果 |
|---------|------|------|
| `addNpuDevices` → `setSuperNode` | addNpuDevices 要求 SuperNode 已存在，不会隐式创建 | `IllegalStateException` |
| `addRoutingEntries` → `setSuperNode` | addRoutingEntries 要求路由表已存在 | `IllegalStateException` |

### 3c.2 未导入拓扑就增量操作

| 操作 | 条件 | 行为 | 结果 |
|------|------|------|------|
| `addNpuDevices("nonExistent", ...)` | 该 SuperNode 不存在 | **抛 IllegalStateException** | 明确提示 |
| `addSwDevices("nonExistent", ...)` | 该 SuperNode 不存在 | **抛 IllegalStateException** | 明确提示 |
| `removeDevices("nonExistent", ...)` | 该 SuperNode 不存在 | **静默无操作** | 数据未被删除，也无异常 |
| `addRoutingEntries("nonExistent", ...)` | 该路由表不存在 | **抛 IllegalStateException** | 明确提示 |
| `removeRoutingEntries("nonExistent", ...)` | 该路由表不存在 | **静默无操作** | 同上 |
| `removeSuperNode("nonExistent")` | 该 SuperNode 不存在 | **静默无操作** | Map.remove null → 无影响 |

### 3c.3 只做增量操作，不调 setSuperNode

```java
sncService.init(config);
sncService.addNpuDevices("sn1", devices);       // 抛 IllegalStateException（SuperNode 不存在）
// 无法跳过 setSuperNode 直接增量操作
```

仅 `setSuperNode()` 会设置 `superNodeLoaded` 标志。全部增量操作**不设置**该标志 → 状态永远不会进入 DATAREADY → `planPath` 始终失败。

### 3c.4 重复导入

| 操作 | 行为 |
|------|------|
| `setSuperNode(SN1)` → `setSuperNode(SN2)` | **同 name**：第二次覆盖第一次（`Map.put` 语义），SN1 旧数据丢失；**不同 name**：两者共存互不影响 |
| `init()` → `init()` | 每次创建新的 Store/Engine/Service 实例，旧实例被丢弃 |
| `init()` → `uninit()` → `init()` | 正常：先清理，后重新初始化 |

### 3c.5 进入 DATAREADY 后删除数据，状态会回退

```java
setSuperNode(sn);                            // superNodeLoaded=true → DATAREADY
removeSuperNode("sn1");                       // 数据已删，superNodeLoaded = getSuperNode("sn1") != null → false
planPath(req);                              // 状态检查失败 → SNCStateException（状态已回退到 READY）
```

`updateDataReadyState()` 在 `superNodeLoaded` 变为 false 时，会将状态从 DATAREADY 回退到 READY。因此删除数据后**状态会回退**，后续 `planPath` 调用会抛出 `SNCStateException`。

### 3c.6 批量操作校验失败（原子性）

```java
// 列表中前两个 device 正常，第三个为 null
addNpuDevices("sn1", Arrays.asList(d1, d2, null, d3));
```

| 步骤 | 行为 |
|------|------|
| 预校验阶段 | 逐元素校验合法性 |
| null | Service 层校验出 null → 抛出 `IllegalArgumentException`，**预校验中止** |
| d1、d2、d3 | **全部未提交**（预校验失败时 Store 无任何变更） |

批量操作采用**预校验+全提交（两阶段）**设计：阶段1 先遍历全部元素做合法性校验，发现非法立即抛出异常（此时 Store 尚未被修改）；阶段2 全部校验通过后才遍历列表执行 Store 操作。保证原子性——**要么全成功（校验通过 + 全部提交），要么全失败（校验失败抛异常 + Store 无变更）**。

### 3c.7 init 异常场景

| 场景 | 行为 | 后果 |
|------|------|------|
| `init(null)` | config 未使用，正常运行 | 无异常，正常进入 READY |
| `init()` 连续调用两次 | 第二次重建所有 Store/Engine/Service | 第一次加载的数据完全丢失（无合并），状态重置为 READY |
| `init()` 时字段状态 | 创建新实例，重置 `superNodeLoaded=false` | 之前状态完全清空 |
| `init()` → 之后立即调其他方法 | 正常执行，状态为 READY | 仅 `planPath` 被阻止（需 DATAREADY） |

### 3c.8 uninit 异常场景

| 场景 | 行为 | 后果 |
|------|------|------|
| `uninit()` 在 `init()` 之前调用 | Store 字段为 null，但 `uninit` 有 null 检查 | 安全无操作，状态 → UNINIT |
| `uninit()` 连续调用两次 | 第二次时 Store 已空，`clear()` 安全无副作用 | 状态保持 UNINIT |
| `uninit()` → 调非 init 方法 | `checkNotUninit()` 检测到 UNINIT | 抛 `SNCStateException("SNC is in UNINIT state")` |
| `uninit()` → `init()` → 正常操作 | 重建 Store，重新进入 READY | 正常工作 |

### 3c.9 planPath 异常场景

| 场景 | 行为 | 结果 |
|------|------|------|
| `planPath` 时状态为 INIT | `SncService.planPath` 自有状态判断（不走 checkNotUninit） | `SNCStateException("SNC is not in DATAREADY state, current state: INIT")` |
| `planPath` 时状态为 READY | 同上 | `SNCStateException("SNC is not in DATAREADY state, current state: READY")` |
| `planPath` 时状态为 UNINIT | 同上 | `SNCStateException("SNC is not in DATAREADY state, current state: UNINIT")` |
| `planPath(request)` 中 srcDevice 不存在于 SuperNode | PathService.planPath lookup 返回 null | `TOPO_INCOMPLETE` |
| `planPath(request)` 中 destDevice 不存在 | 同上 | `TOPO_INCOMPLETE` |
| `planPath(request)` 中 srcDevice/destDevice 为交换机（非 NPU） | PathService.planPath 两层判断：设备存在于 swDevices 但 deviceType ≠ NPU | `SRC_AND_DST_MUST_BE_NPU(3002)` |
| `planPath(request)` 中 srcPort 在设备上不存在 | NpuDevice.findNpuPort 返回 null | `SRC_INFO_ERR` |
| `planPath(request)` 中 destPort 在设备上不存在 | 同上 | `DST_INFO_ERR` |
| `planPath` 直连场景两端 remote 不匹配 | PathService 验证失败 | `TOPO_CONNECTION_ERROR` |
| `planPath` 多跳场景中间连接不一致 | PathEngine.resolveMultiHopPath 抛出异常 | `TOPO_CONNECTION_NOT_FOUND` |
| `planPath` 路由不可达（中间设备最长前缀匹配未命中或无出端口） | PathService.routePhase 抛 `PathPlanException(ROUTE_NOT_REACHABLE)` | `ROUTE_NOT_REACHABLE(1010)` |
| `planPath` 直连场景经 init 重置后未重设拓扑 | 状态为 READY | `SNCStateException`（不会进入 planPath 逻辑） |

### 3c.10 planPathsCoverage / planPathsCoverageEx 异常场景

| 场景 | 行为 | 结果 |
|------|------|------|
| 状态非 DATAREADY | `SncService` 自有状态判断（不走 checkNotUninit） | `SNCStateException("SNC is not in DATAREADY state, current state: <STATE>")` |
| `request == null` | `SncService` 直接拦截 | `IllegalArgumentException("CoveragePathsRequest must not be null")` |
| `request.superNodeName` 为 null/空 | `PathService.planPathsCoverageInternal` 返回带 errorMessage 的 result | `PlanStatus.TOPO_NOT_FOUND`（不抛异常） |
| `superNodeName` 在 store 中不存在 | 同上 | `PlanStatus.TOPO_NOT_FOUND` |
| 全部链路 `coverCount ≥ required` | `buildResult` 标记 `fullCoverage = true` | `PlanStatus.SUCCESS` |
| 存在链路 `coverCount < required` | `buildResult` 标记 `fullCoverage = false`，`errorMessage` 携带覆盖率明细；`planPathsCoverageEx` 追加分层明细 | `PlanStatus.COVERAGE_INCOMPLETE` |
| `planPathsCoverageEx` 中拓扑无 NPU 设备 | `collectNpuCandidates` 返回空 | `emptyResult()`（`totalLinks=0`，`SUCCESS`） |
| `planPathsCoverageEx` 中拓扑无 L2SW | 阶段 1 无跨机框候选 → 跳过；阶段 2 用框内 EID 对覆盖 NPU↔L1SW | `SUCCESS`，`eidPairs[*].type = LOCAL_L1`，`layerStats[L1_L2].totalLinks = 0` |
| NPU 路由 LPM 未命中（`dst.cna` 无路由） | `traceForwardPathEx` 中 `selectNpuEgress` 返回 null，`exFailNpuRoute++` | 该 EID 对不可用，`continue` 跳过（不改变接口返回） |
| NPU 路由出端口中无 L1SW 向端口 | `exFailNpuPort++` | 同上 |
| `jettyId` 缺失或越界 | `jettyIdOf` 回落 `32 + portId`，`exJettyFallback++` | 选路继续，不抛异常；诊断计数可见于 `CoveragePlanEngine.getExDiagnostics()` |
| L1SW→L2SW 路由 LPM 未命中 | `exFailL1++` | 该 EID 对不可用 |
| L2SW→L1SW 路由 LPM 未命中 | `exFailL2++` | 同上 |
| 目的 L1SW→NPU 路由 LPM 未命中 | `exFailDstL1++` | 同上 |
| 反向 NPU 选路失败（含源端口 jettyId 解析失败） | `exFailRevNpu++` | 反向路径不可用，该 EID 对 `continue` 跳过 |
| 反向目的 L1SW 失败 | `exFailRevDstL1++` | 同上 |
| 反向 L2SW 失败 | `exFailRevL2++` | 同上 |
| 反向源 L1SW 失败 | `exFailRevSrcL1++` | 同上 |
| 全场无可用 EID 对 | `selectedPairs` 为空，`coveredCount = 0` | `COVERAGE_INCOMPLETE`，`errorMessage` 形如 `物理遍历覆盖率未达100%: 0.00% (0/N 出端口已覆盖) [NPU_L1: 0.00% 0/M; L1_L2: 0.00% 0/K]` |

### 3c.11 notifyLinkEvent 异常场景

| 场景 | 行为 | 结果 |
|------|------|------|
| 状态为 INIT/UNINIT | `checkNotUninit` 拦截 | `SNCStateException("SNC is in INIT state")` 或 `("SNC is in UNINIT state")` |
| `supernode == null` | `SncService` 拦截 | `IllegalArgumentException("supernode must not be null")` |
| `event == null` | `SncService` 拦截 | `IllegalArgumentException("event must not be null")` |
| `event.deviceName` 为 null/空 | `LinkEventService` 拦截 | `IllegalArgumentException("deviceName must not be null or empty")` |
| `event.portName` 为 null/空 | `LinkEventService` 拦截 | `IllegalArgumentException("portName must not be null or empty")` |
| `event.eventType` 非 `"up"`/`"down"` | `LinkEventService` 拦截 | `IllegalArgumentException("invalid eventType: {X}, expected: up|down")` |
| 设备在拓扑中不存在 | `LinkEventService` 查不到设备 | `IllegalStateException("Device not found: <deviceName>")` |
| 端口在设备上不存在 | `findPortByName` 返回 null | `IllegalStateException("Port not found: <portName> in device <deviceName>")` |
| 事件端口无路由变化 | `processLocalChip` 返回空集 | 直接 return，不传播（日志 `"converge finished: ... no reachable change on start"`） |
| `instantiationRouteMap` 为空（未调 `makeRoutes`） | `RouteConvergeService.converge` 中 `routeMap.get(...)` 返回 null，`updateOutPortOnChip` 返回空集 | 端口状态仍被更新（`port.setLinkStatus/setUpdateAt`），但无路由收敛传播 |
| 对端 chip 不存在 | `findChipByPort` 返回 null | 跳过该对端（日志 warning，不入队） |
| 对端端口链路状态为 down | `propagateToPeers` 跳过 down 端口 | 不向该对端传播（避免 down 端口传递可达性） |

### 3c.12 routeCalculate 异常场景

| 场景 | 行为 | 结果 |
|------|------|------|
| 状态为 INIT/UNINIT | `checkNotUninit` 拦截 | `SNCStateException` |
| 拓扑模板文件不存在 | `TopoTemplateService.parseTemplateFile` 抛异常 | 异常向上传播 |
| 拓扑 `label.names["type"]` 为 null | `calculateDefaultTemplateRoute` 抛 `IllegalArgumentException("find invalid xpod type")` | 异常向上传播 |
| 重复调用 | `routeCalculated == true` 直接 return | 日志 `"route has calculated"`，幂等无副作用 |
| 调用后立即 `uninit` 再 `init` | `init` 重建实例，`routeCalculated` 重置为 false | 需重新调用 `routeCalculate` |

### 3c.13 makeRoutes 异常场景

| 场景 | 行为 | 结果 |
|------|------|------|
| 状态为 INIT/UNINIT | `checkNotUninit` 拦截 | `SNCStateException` |
| `routeCalculate` 未调用 | `routeCalculated == false` | `IllegalStateException("calculate routeCalculate first")` |
| `superNode == null` | `SncService` 拦截 | `IllegalArgumentException("superNode is null")` |
| NPU 设备无 forwardingChips | `makeNpuRoutes` 抛 `IllegalArgumentException("npu device <X> has no forwarding chips")` | 异常向上传播 |
| L1SW/L2SW 设备无 forwardingChips | `makeL1SwRoutes`/`makeL2SwRoutes` 抛 `IllegalArgumentException` | 异常向上传播 |
| 模板中找不到设备对应的路由 label | `makeNpuRoutes`/`makeL1SwRoutes`/`makeL2SwRoutes` 日志 error 后 `continue` | 该芯片路由缺失，不放入 `instantiationRouteMap`；其他设备正常处理 |
| `rack` 格式无法解析数字 | `extractRackNumber` 抛 `IllegalArgumentException("invalid rack format: <X>")` | 异常向上传播 |

### 3c.14 getNodeRoute 异常场景

| 场景 | 行为 | 结果 |
|------|------|------|
| 状态为 INIT/UNINIT | `checkNotUninit` 拦截 | `SNCStateException` |
| `deviceName == null` | `SncService` 拦截 | `IllegalArgumentException("device info is null")` |
| key `"deviceName#chipIndex"` 不在 `instantiationRouteMap` 中 | `SncService` 抛异常 | `IllegalArgumentException("not found route for <key>")` |
| `makeRoutes` 未调用（`instantiationRouteMap` 为空） | 同上 | 同上 |

---

## 4. DTO 定义

### `PathPlanRequest`

| 字段 | 类型 | 说明 |
|------|------|------|
| `superNodeName` | `String` | SuperNode 名称 |
| `srcPort` | `String` | 源端口名 |
| `destPort` | `String` | 目的端口名 |
| `srcDevice` | `String` | 源设备名 |
| `destDevice` | `String` | 目的设备名 |
| `interDevices` | `LinkedHashMap<String, String>` | 中间设备映射（deviceName → connectionPort） |

### `PathPlanResult`

| 字段 | 类型 | 说明 |
|------|------|------|
| `srcEid` | `String` | 源 EID |
| `dstEid` | `String` | 目的 EID |
| `path` | `PathInfo` | 路径信息 |
| `status` | `PlanStatus` | 规划结果状态 |
| `errorMessage` | `String` | 错误消息 |
| `ackUdpSrcPort` | `int` | ACK UDP 源端口 |
| `dataUdpSrcPort` | `int` | 数据 UDP 源端口 |
| `spray` | `boolean` | 是否喷雾 |

### `PlanStatus` 枚举

| 名称 | 码值 | 消息 | 触发条件 |
|------|------|------|---------|
| `SUCCESS` | 0 | success | 路径规划成功 / 覆盖规划全覆盖 |
| `SRC_INFO_ERR` | 1003 | src info error | 源端口不存在/EID 或 CNA 为 null/格式错误 |
| `DST_INFO_ERR` | 1004 | dst info error | 目的端口不存在/EID 或 CNA 为 null/格式错误 |
| `TOPO_INCOMPLETE` | 1007 | topo incomplete | srcDevice 或 destDevice 在 SuperNode 中不存在 |
| `TOPO_CONNECTION_ERROR` | 1008 | topo connection error | 直连拓扑中 src 和 dest 端口 remoteDevice/remotePort 不匹配 |
| `TOPO_CONNECTION_NOT_FOUND` | 1009 | topo connection not found | 多跳拓扑中某跳间连接不一致 |
| `ROUTE_NOT_REACHABLE` | 1010 | route not reachable | 中间设备路由不可达 |
| `COVERAGE_INCOMPLETE` | 1011 | coverage incomplete | 覆盖规划未达 100%（`planPathsCoverage` / `planPathsCoverageEx`） |
| `TOPO_NOT_FOUND` | 1012 | topo not found | 请求的 SuperNode 名称在 store 中不存在 |
| `SRC_AND_DST_MUST_BE_NPU` | 3002 | src and dst must be npu | srcDevice 或 destDevice 类型不是 NPU |
| `UPI_MISMATCH` | 3003 | upi mismatch | 源和目的端口都有 UPI 但不相等 |

### `PathInfo`

| 字段 | 类型 | 说明 |
|------|------|------|
| `hops` | `List<HopInfo>` | 跳列表 |

### `HopInfo`

| 字段 | 类型 | 说明 |
|------|------|------|
| `deviceName` | `String` | 设备名称 |
| `inPort` | `String` | 入端口 |
| `outPort` | `String` | 出端口 |
| `multiPath` | `boolean` | 是否多路径 |
| `deviceType` | `String` | 设备类型 |

### `CoveragePathsRequest`

`planPathsCoverage` 与 `planPathsCoverageEx` 共用同一请求 DTO，覆盖域由方法名决定（不在请求中加 `scope` 字段）。

| 字段 | 类型 | 说明 |
|------|------|------|
| `superNodeName` | `String` | SuperNode 名称（必填） |
| `coverageRequirement` | `CoverageRequirement` | 覆盖要求枚举；`null` 时按 `MIN_COVERAGE` 处理 |

### `CoverageRequirement` 枚举

| 值 | 说明 |
|:---|:---|
| `MIN_COVERAGE` | 最小覆盖，每条链路至少被 1 个 EID 对覆盖 |
| `REDUNDANT` | 冗余覆盖，每条链路至少被 2 个互不相交的 EID 对覆盖 |

### `CoveragePathsResult`

| 字段 | 类型 | 说明 |
|------|------|------|
| `status` | `PlanStatus` | `SUCCESS` / `COVERAGE_INCOMPLETE` / `TOPO_NOT_FOUND` |
| `errorMessage` | `String` | 未全覆盖时携带覆盖率明细；`planPathsCoverageEx` 追加分层明细，例如：`物理遍历覆盖率未达100%: 96.88% (2016/2080 出端口已覆盖) [NPU_L1: 98.4% 1008/1024; L1_L2: 95.3% 1008/1056]` |
| `eidPairs` | `List<CoveredEidPair>` | 选出的 EID 对列表（含每个对的覆盖链路） |
| `coverageLinks` | `List<CoverageLink>` | 全量出端口及其 `coverCount` / `coveredPairs` / `layer` / `deviceType` |
| `stats` | `CoverageStats` | 合计统计（口径与 `planPathsCoverage` 一致） |
| `scope` | `CoverageLinkScope` | 本次覆盖所用链路域；`planPathsCoverage` 固定为 `L1_L2`，`planPathsCoverageEx` 为 `NPU_L1_L2` |
| `layerStats` | `Map<CoverageLinkLayer, CoverageLayerStats>` | 分层统计；仅 `planPathsCoverageEx` 设置，`planPathsCoverage` 保持 `null` |

### `CoverageLinkScope` 枚举

| 值 | 说明 |
|:---|:---|
| `L1_L2` | 仅 L1SW↔L2SW 出端口（`planPathsCoverage` 的域） |
| `NPU_L1_L2` | NPU↔L1SW ＋ L1SW↔L2SW 出端口（`planPathsCoverageEx` 的域） |

### `CoverageLinkLayer` 枚举

链路分层，用于把出端口归入 NPU↔L1SW 或 L1SW↔L2SW。方向不在此枚举中表达，由链路两端设备类型推导（设备为 NPU 即 NPU→L1SW；设备为 L1SW 且对端为 NPU 即 L1SW→NPU）。

| 值 | 说明 |
|:---|:---|
| `NPU_L1` | NPU↔L1SW（NPU 上连出端口 / L1SW 的 NPU 向出端口） |
| `L1_L2` | L1SW↔L2SW |

### `CoveragePathType` 枚举

EID 对的路径类型标识（`CoveredEidPair.type`），按 NPU/L1/L2 层级命名，不依赖物理 chassis 概念。

| 值 | 说明 | 每 EID 对链路数 |
|:---|:---|:---:|
| `CROSS_L2` | 框间路径：`NPU → L1SW → L2SW → L1SW → NPU` | 8（4 正向 + 4 反向） |
| `LOCAL_L1` | 框内路径：`NPU → L1SW → NPU`（同一机框，不经 L2SW） | 4（2 正向 + 2 反向） |

### `CoverageLayerStats`

单个分层（`CoverageLinkLayer`）的覆盖率统计，字段语义对齐 `CoverageStats`。

| 字段 | 类型 | 计算 |
|------|------|------|
| `totalLinks` | `Integer` | 该层在 `linkMap` 中的链路数 |
| `coveredCount` | `Integer` | 该层 `coverCount > 0` 的链路数 |
| `coverageRate` | `Double` | `totalLinks > 0 ? coveredCount / totalLinks : 0` |
| `minRepeatCount` | `Integer` | 该层已覆盖链路 `coverCount` 的最小值；无已覆盖链路时为 0 |
| `maxRepeatCount` | `Integer` | 该层已覆盖链路 `coverCount` 的最大值；无已覆盖链路时为 0 |
| `avgRepeatCount` | `Double` | 该层已覆盖链路 `ΣcoverCount / coveredCount`；`coveredCount == 0` 时为 0 |
| `repeatRate` | `Double` | `(ΣcoverCount - coveredCount) / totalLinks` |

### `CoverageStats`

合计统计（覆盖全部 layer），字段语义与 `CoverageLayerStats` 一致，额外含 EID 均匀度字段。

| 字段 | 类型 | 说明 |
|------|------|------|
| `totalLinks` | `Integer` | 总出端口数 |
| `coveredCount` | `Integer` | 已覆盖出端口数 |
| `coverageRate` | `Double` | `coveredCount / totalLinks` |
| `minRepeatCount` | `Integer` | 单链路最小覆盖次数 |
| `maxRepeatCount` | `Integer` | 单链路最大覆盖次数 |
| `avgRepeatCount` | `Double` | 单链路平均覆盖次数 |
| `repeatRate` | `Double` | `(ΣcoverCount - coveredCount) / totalLinks` |
| `uniqueEidCount` | `Integer` | 唯一 EID 数 |
| `totalEidAppearances` | `Integer` | EID 总出现次数 |
| `eidRepeatRate` | `Double` | EID 重复率 |
| `eidMinRepeat` / `eidMaxRepeat` / `eidAvgRepeat` | `Integer`/`Integer`/`Double` | EID 重复次数统计 |
| `srcEidMinRepeat` / `srcEidMaxRepeat` / `srcEidAvgRepeat` | `Integer`/`Integer`/`Double` | 源 EID 重复次数统计 |
| `dstEidMinRepeat` / `dstEidMaxRepeat` / `dstEidAvgRepeat` | `Integer`/`Integer`/`Double` | 目的 EID 重复次数统计 |
| `npuUsageByChassis` | `Map<String, Integer>` | 按机框统计的 NPU 使用次数 |

### `CoveredEidPair`

| 字段 | 类型 | 说明 |
|------|------|------|
| `srcEid` | `String` | 源 EID |
| `dstEid` | `String` | 目的 EID |
| `srcCna` | `String` | 源 CNA |
| `dstCna` | `String` | 目的 CNA |
| `srcDevice` | `String` | 源设备名 |
| `srcPort` | `String` | 源端口名（端点身份，**不约束**报文物理出口；真实出口由 `(DstCNA, jettyId)` hash 决定，见 `coveredLinks[0].outPort`） |
| `destDevice` | `String` | 目的设备名 |
| `destPort` | `String` | 目的端口名（端点身份） |
| `coveredLinks` | `List<CoverageLink>` | 覆盖链路列表；`planPathsCoverage` 固定 4 条（下标 0..3 = 正 2 + 反 2），`planPathsCoverageEx` 框间 8 条 / 框内 4 条 |
| `type` | `CoveragePathType` | 路径类型；`planPathsCoverage` 为 `null`，`planPathsCoverageEx` 为 `CROSS_L2` / `LOCAL_L1` |

**`planPathsCoverageEx` 框间 EID 对 `coveredLinks` 顺序约定（8 条）：**

| 下标 | 方向 | 设备（出端口） | 对端 | layer |
|:---:|:---|:---|:---|:---|
| 0 | 正向 | 源 NPU | 源 L1SW | `NPU_L1` |
| 1 | 正向 | 源 L1SW | L2SW | `L1_L2` |
| 2 | 正向 | L2SW | 目的 L1SW | `L1_L2` |
| 3 | 正向 | 目的 L1SW | 目的 NPU | `NPU_L1` |
| 4 | 反向 | 目的 NPU | 目的 L1SW | `NPU_L1` |
| 5 | 反向 | 目的 L1SW | L2SW | `L1_L2` |
| 6 | 反向 | L2SW | 源 L1SW | `L1_L2` |
| 7 | 反向 | 源 L1SW | 源 NPU | `NPU_L1` |

**`planPathsCoverageEx` 框内 EID 对 `coveredLinks` 顺序约定（4 条）：**

| 下标 | 方向 | 设备（出端口） | 对端 | layer |
|:---:|:---|:---|:---|:---|
| 0 | 正向 | 源 NPU | L1SW | `NPU_L1` |
| 1 | 正向 | L1SW | 目的 NPU | `NPU_L1` |
| 2 | 反向 | 目的 NPU | L1SW | `NPU_L1` |
| 3 | 反向 | L1SW | 源 NPU | `NPU_L1` |

### `CoverageLink`

| 字段 | 类型 | 说明 |
|------|------|------|
| `switchDevice` | `String` | 出端口所属设备名（**语义扩展**：既可能是 SW，也可能是 NPU） |
| `chipIndex` | `Integer` | 转发芯片索引 |
| `outPort` | `String` | 出端口名 |
| `remoteSwitch` | `String` | 对端设备名 |
| `remotePort` | `String` | 对端端口名 |
| `outPortIndex` | `Integer` | 出端口在 ECMP 成员集中的下标 |
| `totalOutPorts` | `Integer` | ECMP 成员集大小 |
| `coveredPairs` | `List<CoveredEidPairRef>` | 覆盖该出端口的 EID 对引用列表 |
| `coverCount` | `Integer` | 被覆盖次数 |
| `deviceType` | `String` | 出端口所属设备类型，取值 `"NPU"` / `"SW"`（由 `DeviceType.name()` 转换，dto 层不依赖 entity 包）；`planPathsCoverage` 不设置（`null`） |
| `layer` | `CoverageLinkLayer` | 链路分层（`NPU_L1` / `L1_L2`）；`planPathsCoverage` 不设置（`null`） |

> **架构约束：** `dto` 层不可依赖 `entity` 包。`deviceType` 采用 `String` 而非 `DeviceType`，由 Service 层从 `DeviceType.name()` 转换，与 `HopInfo.deviceType` 的既有做法一致。
>
> **兼容说明：** `switchDevice` 字段名保留（避免破坏 JSON 契约与既有解析），语义由"交换机设备名"放宽为"出端口所属设备名"。

### `CoveredEidPairRef`

| 字段 | 类型 | 说明 |
|------|------|------|
| `srcEid` | `String` | 源 EID |
| `dstEid` | `String` | 目的 EID |

### `LinkEvent`

| 字段 | 类型 | 说明 |
|------|------|------|
| `deviceName` | `String` | 链路所在设备名（必填） |
| `portName` | `String` | 链路端口名（必填） |
| `eventType` | `String` | 事件类型，取值 `"up"` / `"down"`（对应常量 `LinkEvent.LINK_STATUS_UP` / `LINK_STATUS_DOWN`） |
| `eventTime` | `Long` | 事件时间戳（写入 `PortEntity.updateAt`） |

---

## 5. 异常定义

| 异常类 | 父类 | 说明 |
|--------|------|------|
| `SNCException` | `RuntimeException` | 基类异常 |
| `SNCStateException` | `SNCException` | SNC 状态错误 |
| `SuperNodeNotFoundException` | `SNCException` | SuperNode 或设备未找到 |
| `PathPlanException` | `SNCException` | 路径规划失败（含 `PlanStatus status`） |

---

## 6. Service 内部接口

### `SuperNodeService`

| 方法 | 参数 | 返回值 |
|------|------|--------|
| `importSuperNode` | `SuperNode` | `void` |
| `addNpuDevices` | `String, List<NpuDevice>` | `void` |
| `addSwDevices` | `String, List<SwDevice>` | `void` |
| `removeDevices` | `String, List<String>` | `void` |
| `addRoutingEntries` | `String, String, Integer, List<RoutingEntry>` | `void` |
| `removeRoutingEntries` | `String, String, Integer, List<RoutePrefix>` | `void` |
| `getSuperNode` | `String` | `SuperNode` |
| `removeSuperNode` | `String` | `void` |

### `PathService`

| 方法 | 参数 | 返回值 |
|------|------|--------|
| `planPath` | `PathPlanRequest` | `PathPlanResult` |
| `planPathsCoverage` | `CoveragePathsRequest` | `CoveragePathsResult` |
| `planPathsCoverageEx` | `CoveragePathsRequest` | `CoveragePathsResult` |

### `LinkEventService`

| 方法 | 参数 | 返回值 |
|------|------|--------|
| `notifyLinkEvent` | `SuperNode supernode, LinkEvent event` | `void` |

> `LinkEventService` 仅更新端口 `linkStatus` 与 `updateAt`；路由收敛由 `RouteConvergeService.converge` 在 `SncService.notifyLinkEvent` 中显式调用。

### `RouteConvergeService`

| 方法 | 参数 | 返回值 |
|------|------|--------|
| `converge` | `Map<String, Map<String, RoutingEntry>> instantiationRouteMap, SuperNode supernode, LinkEvent event` | `void` |

> BFS 路由收敛算法。**作用对象**为 `SncService.instantiationRouteMap`（由 `makeRoutes` 填充），收敛结果影响后续 `getNodeRoute` 查询。

### `RouteInstantiationService`

| 方法 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `instantiateXpodRoute` (static) | `Map<String, SncTopology>, Map<String, Map<String, RouteTable>>, Map<String, RouteTable>` | `void` | 按机框实例化模板路由到 `routes` |
| `makeNpuRoutes` | `NpuDevice, Map<String, RouteTable>, Map<String, Map<String, RoutingEntry>>` | `void` | 为单台 NPU 设备生成实例化路由 |
| `makeSwRoutes` | `SwDevice, Map<String, RouteTable>, Map<String, Map<String, RoutingEntry>>` | `void` | 为单台 SW 设备生成实例化路由（按 L1/L2 分发） |
| `buildRouteTableKey` (static) | `String deviceName, int chipIndex` | `String` | 构造 key：`"deviceName#chipIndex"` |
| `deepCopyRoutingEntry` (static) | `Map<String, Map<String, RoutingEntry>>` | 同类型 | 深拷贝（保证内部 `instantiationRouteMap` 与返回值互不影响） |

### `RouteMspService`

| 方法 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `routeMsp` (static) | `SncTopology` | `Map<String, RouteTable>` | 按最短路径策略生成单节点模板路由 |

### `TopoTemplateService`

| 方法 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `parseTemplateFile` (static) | `String filePath` | `SncTopology` | 解析内置拓扑模板 JSON |

---

## 7. Engine 内部接口

| Engine | 方法 | 参数 | 返回值 |
|--------|------|------|--------|
| `PathEngine` | `resolveDirectPath` | `NpuDevice, NpuPortEntity, NpuDevice, NpuPortEntity` | `InternalPathInfo` |
| `PathEngine` | `resolveMultiHopPath` | `NpuDevice, NpuPortEntity, NpuDevice, NpuPortEntity, Map, Map` | `InternalPathInfo` |
| `PathEngine` | `reverseHops` | `List<InternalPathHop>` | `List<InternalPathHop>` |
| `PathEngine` | `findPortByName` | `DeviceEntity, String` | `PortEntity` |
| `PathEngine` | `findPortByConnection` | `DeviceEntity` | `PortEntity` |
| `RouteLookupEngine` | `lookup` | `String, Map, List<Integer>` | `RoutingEntry` |
| `CoveragePlanEngine` | `findCoverage` | `SuperNode, int, int, CoverageRequirement` | `CoverageSearchResult` |
| `CoveragePlanEngine` | `findCoverageEx` | `SuperNode, int dataUdpSrcPort, int ackUdpSrcPort, CoverageRequirement` | `CoverageSearchResult`（含 `layerTotalLinks` / `layerCoveredCount`） |
| `CoveragePlanEngine` | `getExDiagnostics` | 无 | `Map<String, Integer>`（含 `npuRouteFail` / `npuPortFail` / `jettyIdFallback` / `l1Fail` / `l2Fail` / `dstL1Fail` / `revNpuFail` / `revDstL1Fail` / `revL2Fail` / `revSrcL1Fail`） |

**`CoveragePlanEngine` 构造参数：**

| 参数 | 类型 | 来源 | 说明 |
|------|------|------|------|
| `superNodeStore` | `SuperNodeStore` | `SncService.init` | 拓扑存储 |
| `hashFunc` | `int` | `SNCConfig.getHashFunc()` | hash 函数选择器（1=FNV-1a，其他=简单累加） |
| `fixedDataUdpPort` | `int` | `SNCConfig.getFixedDataUdpPort()` | 数据流固定 UDP 源端口 |
| `fixedAckUdpPort` | `int` | `SNCConfig.getFixedAckUdpPort()` | ACK 流固定 UDP 源端口 |
| `hashTuple` | `HashTuple` | `SNCConfig.getHashTuple()` | hash 元组宽度（TWO/FIVE） |
| `dieHashFunctionSelect` | `int` | `SNCConfig.getDieHashFunctionSelect()` | NPU→L1SW CRC-8 hash 函数选择器（0/1） |

---

## 8. Store 内部接口

| Store | 方法 |
|-------|------|
| `SuperNodeStore` | `init, clear, replace, removeSuperNode, getSuperNode, getRoutingTable, addNpuDevice, addSwDevice, removeDevice, addRoutingEntry, removeRoutingEntry` |

---

## 9. 覆盖规划算法概要

### 9.1 hash 使用点

`CoveragePlanEngine.nativePortIdx(scna, dcna, sport, dport, ecmpCnt)` 统一封装 L1SW↔L2SW 和 L1SW→NPU 的 hash（复用 `ubswitch_Hash_ecmp`）；NPU→L1SW 使用独立的 `HashUtils.nativeHashDstCnaJetty(dstCna, jettyId, ecmpCnt, hashFunc)`（`ubswitch_Hash_dieEcmp`，CRC-8/ATM）。

**`planPathsCoverage` hash 点位（4 处，均为 `nativePortIdx`）：**

| 序号 | 位置 | 方向 | scna / dcna | sport / dport | 成员集 |
|:---:|:---|:---|:---|:---|:---|
| H1 | `traceForwardPath` | L1SW→L2SW | `src.cna` / `dst.cna` | `dataUdpSrcPort` / `ackUdpSrcPort` | L1SW 路由出端口中 remote 为 L2SW 的集合 |
| H2 | `traceForwardPath` | L2SW→L1SW | `src.cna` / `dst.cna` | `dataUdpSrcPort` / `ackUdpSrcPort` | L2SW 入端口所属 chip 上通往 `dst.remoteL1sw` 的端口集合 |
| H3 | `traceReversePath` | L1SW→L2SW（反） | `dst.cna` / `src.cna` | `ackUdpSrcPort` / `dataUdpSrcPort` | 目的 L1SW 路由出端口中 remote 为 L2SW 的集合 |
| H4 | `traceReversePath` | L2SW→L1SW（反） | `dst.cna` / `src.cna` | `ackUdpSrcPort` / `dataUdpSrcPort` | 反向 L2SW 入端口所属 chip 上通往 `src.remoteL1sw` 的端口集合 |

**`planPathsCoverageEx` 新增 hash 点位（H5/H6 用 `nativeHashDstCnaJetty` 与 `nativePortIdx`）：**

| 序号 | 位置 | 方向 | hash 输入 | 成员集 | 原生符号 |
|:---:|:---|:---|:---|:---|:---|
| H5 | `traceForwardPathEx` | NPU→L1SW（正） | **`(DstCNA=dst.cna, jettyId=源端口 jettyId)`** | NPU 路由 LPM 命中条目中 remote 为 L1SW 的出端口 | `ubswitch_Hash_dieEcmp` |
| H6 | `traceForwardPathEx` | L1SW→NPU（正，末跳） | `nativePortIdx(scna, dst.cna, data, ack, M.size())`，scna = H5 选中端口 CNA | 目的 L1SW 路由 LPM 命中条目中 remote = `dst.deviceName` 的出端口 | `ubswitch_Hash_ecmp` |
| H7a | `traceReversePathEx` | NPU→L1SW（反） | **`(DstCNA=src.cna, jettyId=源端口 jettyId)`**（与正向同一 jettyId） | 目的 NPU 路由 LPM 命中条目中 remote 为 L1SW 的出端口 | `ubswitch_Hash_dieEcmp` |
| H7d | `traceReversePathEx` | L1SW→NPU（反，末跳） | `nativePortIdx(scnaRev, src.cna, ack, data, M.size())` | 源 L1SW 路由 LPM 命中条目中 remote = `src.deviceName` 的出端口 | `ubswitch_Hash_ecmp` |

### 9.2 SCNA 链接

`planPathsCoverageEx` 中，**被选中 NPU 端口的 CNA 作为 SCNA** 供后续 L1SW→L2SW、L2SW→L1SW、L1SW→NPU 的 hash 选口使用。ACK 方向同理：H7a 选中端口的 CNA 作为反向 SCNA（`scnaRev`），驱动反向 L1SW/L2SW 选口。

### 9.3 两阶段覆盖（`planPathsCoverageEx`）

1. **阶段 1（框间 CROSS_L2）**：枚举跨机框 EID 对，追踪 4 跳正/反向路径（`traceForwardPathEx` / `traceReversePathEx`），贪心选出覆盖 L1SW↔L2SW 的 EID 对；
2. **阶段 2（框内 LOCAL_L1）**：在阶段 1 结果中筛出 `layer == NPU_L1 && coverCount < required` 的出端口作为缺口集合，枚举同机框 EID 对并追踪 2 跳正/反向路径（`traceIntraForwardPathEx` / `traceIntraReversePathEx`），以缺口集合为目标再贪心选对；
3. **合并统计**：阶段 1 + 阶段 2 的 EID 对合并后，在完整链路域上重算覆盖率/重复率等统计。

> 某些拓扑下阶段 2 可能产出 0 对（框间已覆盖全部 NPU↔L1SW 出端口），这是正常结果；单机框（或跨机框路径不可用）时则全部由框内覆盖。

### 9.4 路由范围扩展与接收语义（`planPathsCoverageEx`）

**接收语义（关键前提）**：目的 CNA 属于某 NPU 设备，该 NPU 就能接收该报文，即使报文到达的端口并不是该 CNA 自己对应的物理端口。因此路由/选口的约束从"CNA ↔ 端口一一对应"放宽为"CNA 所属 NPU 设备可达"。

| 位置 | `planPathsCoverage` 口径 | `planPathsCoverageEx` 口径 |
|:---|:---|:---|
| L1SW 路由 | 仅为"物理相连端口"的 CNA 建 /32 路由 | 对有端口的每个 NPU，为其每个 CNA 建 /32 路由，出端口 = 该 L1SW 到该 NPU 的全部端口（由测试夹具 `CoverageRouteAugmentor.augmentL1swNpuRouting` 增强） |
| L2SW→L1SW 选口 | 固定用 `dst.remoteL1sw` | 任意"能到达目的 NPU 设备的 L1SW"（`PrecomputedTopo.npuL1Peers` + `l2PortsTowardsL1Peers`） |
| L1SW→NPU 选口 | 路由仅 1 个出端口（无 ECMP），`get(0)` | 该 L1SW 到目的 NPU 的全部端口（≥2 → hash 可选），`l1PortsTowardsDevice` + `nativePortIdx` |

### 9.5 EID 与出端口的关系

- `srcPort / srcCna / srcEid` 标识的是**端点身份**（哪台设备的哪个逻辑端口发起/接收该流），**不约束**报文的物理出口；
- 源 NPU 收到报文后，按 **CRC8 `(DstCNA, jettyId)`** 在自己的上连端口（对目的所经 L1SW 的全部端口）中选择真实出口；**被选中端口的 CNA 才是后续 L1/L2 选口使用的 SCNA**；
- 因此 `CoveredEidPair.srcPort`（选定的端点身份）与 `coveredLinks[0].outPort`（真实出口）**可以不同**，这是设计上的有意行为；
- ACK 方向同理：`destPort` 是 ACK 的发送端点身份，真实出口由 `(srcCna, 源端口 jettyId)` 决定（jettyId 取自源 NPU 端口，与正向同一）。

### 9.6 jettyId 取值与原生库

| 项 | 说明 |
|:---|:---|
| jettyId 取值范围 | `[32, 1023]`，每个 NPU 物理端口一个；入口校验越界抛 `IllegalArgumentException`（`HashUtils.JETTY_ID_MIN/MAX`、`isValidJettyId`） |
| topo 输入字段 | 超节点 JSON `jettyId`（`TestDataLoader`）；模板 JSON `jetty_id`（`128_npu_rack.json`）+ `PortLoader`/`SncPort`；`FullRackTopologyGenerator` 用固定分配 `JETTY_ID_BASE + portIndex`（32..39，每次生成完全一致）；缺失时回落 `32 + portId` 并计入 `jettyIdFallback` |
| 原生库 `ubswitch_Hash_ecmp` | L1SW↔L2SW 选口、L1SW→NPU 选口；Java 入口 `HashUtils.nativeHash(...)` / `nativePortIdx(...)` |
| 原生库 `ubswitch_Hash_dieEcmp` | **NPU→L1SW 选口（CRC-8/ATM）**；Java 入口 `HashUtils.nativeHashDstCnaJetty(dstCna, jettyId, ecmpCnt, hashFunc)`；字节流 = `DstCNA` 的 ASCII + `jettyId` 低字节 + `jettyId` 高字节；`ecmpCnt == 0` 返回原始 CRC（0..255），`ecmpCnt > 0` 返回 `CRC % ecmpCnt` |
| Java fallback | `UbSwitchHash`（纯 Java 实现两个哈希算法），原生库加载失败时自动回退，结果与原生库完全一致 |
