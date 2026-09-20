# SNC (Supernode Network Controller) 设计文档

> 本文档定义 SNC 模块的类设计，包含领域模型、计算模型、北向数据结构、北向接口、路径规划算法及路径规划详细流程。

---

## 目录

1. [概述](#1-概述)
2. [北向机制](#2-北向机制)
3. [文件目录设计](#3-文件目录设计)
4. [数据结构定义（领域模型 Entity）](#4-数据结构定义)
5. [纯内部数据结构（计算模型）](#5-纯内部数据结构)
6. [北向数据结构（DTO）](#6-北向数据结构dto)
   - [6.1 PathPlanRequest（路径规划请求）](#61-pathplanrequest路径规划请求)
   - [6.2 PathPlanResult（路径规划响应）](#62-pathplanresult路径规划响应)
   - [6.3 覆盖规划 DTO](#63-覆盖规划-dto)
   - [6.4 北向数据结构与内部数据结构的关系](#64-北向数据结构与内部数据结构的关系)
7. [北向接口](#7-北向接口)
   - [7.1 接口概述](#71-接口概述)
   - [7.2 SNCService 接口定义](#72-sncservice-接口定义)
   - [7.3 调用时序](#73-调用时序)
   - [7.4 状态机](#74-状态机)
   - [7.5 错误处理](#75-错误处理)
   - [7.6 参数校验规则](#76-参数校验规则)
   - [7.7 接口实现映射](#77-接口实现映射)
   - [7.8 错误调用顺序说明](#78-错误调用顺序说明)
   - [7.9 SuperNodeStore（拓扑存储）](#79-supernodestore拓扑存储)
8. [算法](#8-算法)
   - [8.1 索引掩码匹配（Indexed Mask Match）](#81-算法描述)
   - [8.2 RouteLookupEngine](#82-引擎接口)
   - [8.3 覆盖规划算法（CoveragePlanEngine）](#83-覆盖规划算法coverageplanengine)
   - [8.4 路由收敛算法（RouteConvergeService）](#84-路由收敛算法routeconvergeservice)
   - [8.5 路由 MSP 计算与实例化算法](#85-路由-msp-计算与实例化算法)
   - [8.6 HashUtils（hash 封装）](#86-hashutilshash-封装)
   - [8.7 覆盖规划关键设计决策](#87-覆盖规划关键设计决策)
9. [路径规划详细流程](#9-路径规划详细流程)

---

## 1. 概述

### 1.1 业务背景

SNC（Supernode Network Controller）是一个超级节点控制器，负责网络拓扑、路由信息的管理，并提供路径规划、覆盖规划、链路事件路由收敛功能，返回通信覆盖当前路径时所需参数。

### 1.2 核心功能需求

| 功能模块         | 说明                           | 优先级 |
|:----------------:|:-------------------------------|:------:|
| 初始化/去初始化   | SNC服务的启动与停止             | P0     |
| SuperNode数据管理     | 网络拓扑结构下发、查询与删除     | P1     |
| 路径规划   | 基于EID对的路径规划     | P2     |
| 覆盖规划 | 给定拓扑挑选一组 EID 对使其 hash 选路遍历覆盖域出端口；支持 L1↔L2 与 NPU↔L1↔L2 两种覆盖域 | P2 |
| 链路事件通知 | 接收链路 up/down 事件，触发 BFS 路由收敛刷新 OutPortInfo.convergedFlag 与 RoutingEntry.reachable | P2 |
| 路由模板计算与实例化 | 基于内置拓扑模板计算 MSP 路由并按 SuperNode 机框实例化，供 getNodeRoute / notifyLinkEvent 使用 | P2 |

---

## 2. 北向机制

### 2.1 北向概述

**北向数据流向：**
```
┌──────────────────────────────────────────────────┐
│         上层编排器/管理系统        │ (北向调用方) │
│   - 拓扑数据录入（包含路由信息）    │             │
│   - 路径规划请求                 │             │
└──────────────┬───────────────────────────────────┘
               │ API 调用
┌──────────────▼──────────────────────────────────┐
│        SNC 模块 (本模块)         │             │
│   - 数据持久化与索引              │             │
│   - 路径规划与路径还原           │             │
└──────────────┬──────────────────────────────────┘
               │ 南向采集/注入（当前阶段不进行开发）
┌──────────────▼──────────────────────────────────┐
│      设备层 (NPU/L1SW/L2SW)      │             │
│   - 拓扑连接关系                 │             │
│   - 路由表                      │             │
│   - 端口信息                    │             │
└──────────────────────────────────────────────────┘
```

### 2.2 交互模式

- **配置类操作（拓扑下发）：** 同步调用，调用方下发完整数据快照。
- **查询类操作（路径规划）：** 同步调用，请求-响应模式，调用方发送 PathPlanRequest，SNC 返回 PathPlanResult。
- **覆盖规划：** 同步调用，请求-响应模式，调用方发送 CoveragePathsRequest，SNC 返回 CoveragePathsResult（含 EID 对、覆盖链路、覆盖率统计）。
- **链路事件通知：** 同步调用，调用方发送 LinkEvent，SNC 内部更新端口状态并触发 BFS 路由收敛，返回 void。
- **路由计算/实例化/查询：** 同步调用；`routeCalculate` 幂等可重复；`makeRoutes` 基于已计算的模板路由为 SuperNode 生成实例化路由表；`getNodeRoute` 从实例化结果中查询。
- **初始化/去初始化：** 同步调用，SNC 启动时从北向加载数据或接收全量同步；去初始化时清理内存数据。

### 2.3 数据一致性保证

- 拓扑数据（包含路由信息）以全量快照方式下发，SNC 不维护增量变更日志。
- 所有数据使用内存 HashMap 索引，保证 O(1) 查找效率。
- 路径规划基于内存中的数据实时计算，不依赖外部存储。
- 链路事件（up/down）实时更新 `PortEntity.linkStatus` 与 `updateAt`，并通过 BFS 路由收敛刷新 `OutPortInfo.convergedFlag` 与 `RoutingEntry.reachable`，保证后续 `getNodeRoute` 查询反映最新拓扑状态。
- `instantiationRouteMap`（由 `makeRoutes` 填充）与 SuperNode 拓扑数据解耦；`setSuperNode` 全量替换不影响 `instantiationRouteMap`，需重新调用 `makeRoutes` 同步。
- `routeCalculate` 幂等：已计算过则直接返回，避免重复解析模板与 MSP 计算。

### 2.4 内部调用链

#### 2.4.1 planPath 调用链

```
SNCService.planPath(PathPlanRequest)
└→ PathService.planPath(request)
   ├→ superNode.getNpuDevices().get(srcDevice/destDevice)              // Step 0: NPU 设备查找
   ├→ srcNpuDevice.findNpuPort() + destNpuDevice.findNpuPort()         // Step 1~2: 端口查找
   ├→ PathEngine.resolveDirectPath/resolveMultiHopPath(InternalPathInfo) // Step 3~5: 路径还原
   ├→ superNode.getAllDevices() + RouteLookupEngine.lookup()           // Step 6~8: 路径规划
   └→ 组装 dto.PathPlanResult                                           // Step 9~10: 输出构造
```

#### 2.4.2 planPathsCoverage / planPathsCoverageEx 调用链

```
SNCService.planPathsCoverage(req) / planPathsCoverageEx(req)
└→ PathService.planPathsCoverage / planPathsCoverageEx(req)
   ├→ SuperNodeStore.get(superNodeName)                                // 拓扑查找
   ├→ CoveragePlanEngine.findCoverage / findCoverageEx(superNode, requirement)
   │   ├→ 构造覆盖域 OutPortInfo 集合（L1↔L2 或 NPU↔L1↔L2）
   │   ├→ 枚举候选 EID 对（src/dst NPU 端口组合）
   │   ├→ 对每个 EID 对追踪正反向路径（planPathsCoverageEx 调用 HashUtils.nativeHashDstCnaJetty）
   │   ├→ 贪心选择覆盖未命中端口的 EID 对
   │   └→ 累加统计（覆盖率 / 重复率 / EID 均匀度 / 分层统计）
   └→ 组装 dto.CoveragePathsResult
```

#### 2.4.3 notifyLinkEvent 调用链

```
SNCService.notifyLinkEvent(superNode, LinkEvent)
└→ LinkEventService.handleLinkEvent(superNode, event)
   ├→ 定位 deviceName + portName 对应的 PortEntity
   ├→ port.setLinkStatus(LINK_UP/LINK_DOWN) + port.setUpdateAt(eventTime)
   ├→ RouteConvergeService.converge(superNode, deviceName, chipIndex, portName, isDown)
   │   ├→ 遍历 chip 路由表，定位包含该端口的 RoutingEntry
   │   ├→ OutPortInfo.setFlag(FLAG_PASSIVE_CONVERRGED) [down] / clearFlag(FLAG_PASSIVE_CONVERRGED) [up]
   │   ├→ RoutingEntry.refreshReachable() → 记录 reachable 变化的前缀
   │   └→ BFS 传播：通过 PortEntity.remoteDevice/remotePort 定位对端转发节点
   │       └→ 在远端 chip 路由表中查询变化前缀 → 刷新入接口对应 OutPortInfo 的 convergedFlag → refreshReachable
   └→ （无返回值；收敛结果存入 instantiationRouteMap）
```

#### 2.4.4 routeCalculate / makeRoutes / getNodeRoute 调用链

```
SNCService.routeCalculate()
└→ synchronized { 已计算则直接返回 }
   ├→ TopoTemplateService.parseTemplateFile("128_npu_rack.json")
   ├→ TopoTemplateService.parseTemplateFile("128_npu_inter_rack.json")
   ├→ RouteMspService.routeMsp(topoTemplate)                  // BFS 最短路径 + 路径策略
   └→ routes = RouteInstantiationService.buildXpodRoutes(template) // 模板路由表（未实例化）

SNCService.makeRoutes(superNode)
└→ RouteInstantiationService.instantiateXpodRoute(routes, superNode)
   ├→ 遍历 NPU 设备：按 chassis/slot/ubpu/die 标签匹配模板
   ├→ 遍历 L1SW 设备：按 chassis/index 标签匹配模板
   ├→ 遍历 L2SW 设备：按 index/chip 标签匹配模板（4 框实例化时端口重映射）
   ├→ deepCopyRoutingEntry(...)                                // 深拷贝避免外部修改影响内部
   └→ instantiationRouteMap.put("deviceName#chipIndex", routingEntryMap)
       返回 instantiationRouteMap 的副本

SNCService.getNodeRoute(deviceName, chipIndex)
└→ instantiationRouteMap.get("deviceName#chipIndex")          // 直接 HashMap 查找
```

---

## 3. 文件目录设计

### 3.1 设计原则

采用 **DDD 分层包结构**，将领域模型（§4）、计算模型（§5）、API 契约 DTO（§6）分离到独立 package，避免北向调用方直接依赖内部领域模型，同时保证字段语义的精确对应。

### 3.2 包结构总览

```
com.huawei.umdk.snc
├── SNCService.java                    # 北向接口定义（§7.2）
├── SNCServiceImpl.java                # 北向接口实现（委托入口）
│
├── config/
│   └── SNCConfig.java                 # SNC 配置（日志策略、索引策略等）
│
├── entity/                            # §4 领域模型 + §5 内部计算模型
│   ├── SuperNode.java                  # 拓扑数据顶层容器（§4.1）含 npuDevices + swDevices + getAllDevices()
│   ├── DeviceEntity.java              # 设备抽象基类（含 getForwardingChips() 抽象方法）
│   ├── MgmtInfo.java                  # 管理信息（ip、port、user、password）
│   ├── NpuDevice.java                 # NPU 设备（含 forwardingChips 精确类型 + findNpuPort()）
│   ├── SwDevice.java                  # 交换设备（含 forwardingChips 精确类型）
│   ├── DeviceType.java                # 设备类型枚举（NPU/SW）
│   ├── SwitchLevel.java               # 交换机层级枚举（L1/L2）
│   ├── ForwardingChip.java            # 转发芯片抽象基类（含 getPorts() 抽象方法）
│   ├── NpuForwardingChip.java         # NPU 转发芯片（含 ports 精确类型 + getNpuPorts()）
│   ├── SwForwardingChip.java          # 交换转发芯片（含 ports 精确类型 + getSwPorts()）
│   ├── PortEntity.java                # 端口抽象基类（含 linkStatus、updateAt 字段，供 LinkEventService 更新）
│   ├── NpuPortEntity.java             # NPU 端口（§4.5.1，含 jettyId 字段供 planPathsCoverageEx 使用）
│   ├── SwPortEntity.java              # 交换端口（§4.5.2）
│   ├── LogicPortEntity.java           # 逻辑端口（§4.6）
│   ├── LinkEvent.java                 # 链路事件（deviceName + portName + eventType + eventTime，供 notifyLinkEvent）
│   ├── RoutingTable.java              # 路由表（§4.7）
│   ├── RoutingEntry.java              # 路由条目（§4.9，含 reachable 状态，供路由收敛 refreshReachable）
│   ├── RoutePrefix.java               # 路由前缀结构体（§4.8）
│   ├── RoutingTableKey.java           # 路由表联合键（superNodeName + deviceName + chipIndex，§4.7.1）
│   ├── OutPortInfo.java               # 出端口信息（§4.9.1，含 convergedFlag 标志位：down=置 PASSIVE，up=清 PASSIVE）
│   ├── InternalPathInfo.java          # §5.1 内部路径信息（引擎计算上下文）
│   ├── InternalPathHop.java           # §5.1 内部路径跳
│   └── RouteSelectionRecord.java      # §5.2 内部选路记录
│
├── dto/                               # §6 北向 API DTO（与领域模型解耦）
│   ├── PathPlanRequest.java           # 路径规划请求（§6.1）
│   ├── PathPlanResult.java            # 路径规划响应 + PlanStatus 枚举（§6.2）
│   ├── PathInfo.java                  # 路径信息（§6.2.1）
│   ├── HopInfo.java                   # 跳信息（§6.2.2）
│   ├── CoveragePathsRequest.java      # 覆盖规划请求（superNodeName + coverageRequirement，复用于 planPathsCoverage/Ex）
│   ├── CoveragePathsResult.java       # 覆盖规划响应（含 scope、layerStats 分层统计）
│   ├── CoverageStats.java             # 覆盖合计统计（含 EID 均匀度字段）
│   ├── CoverageLayerStats.java        # 分层统计（NPU_L1 / L1_L2 各一份）
│   ├── CoverageLink.java              # 覆盖链路（含 deviceType、layer 字段）
│   ├── CoverageLinkScope.java         # 覆盖域枚举（L1_L2 / NPU_L1_L2）
│   ├── CoverageLinkLayer.java         # 链路分层枚举（NPU_L1 / L1_L2）
│   ├── CoveragePathType.java          # 路径类型枚举（CROSS_L2 / LOCAL_L1）
│   ├── CoverageRequirement.java       # 覆盖要求枚举（MIN_COVERAGE / REDUNDANT）
│   ├── CoveredEidPair.java            # 覆盖的 EID 对（含 type 字段）
│   └── CoveredEidPairRef.java         # EID 对引用（srcEid + dstEid）
│
├── service/                           # 业务逻辑层（编排）
│   ├── SuperNodeService.java               # 拓扑数据管理
│   ├── PathService.java               # 路径规划编排 + 覆盖规划编排（planPath / planPathsCoverage / planPathsCoverageEx）
│   └── LinkEventService.java          # 链路事件处理（更新 port.linkStatus/updateAt）
│
├── route/                             # 路由计算与收敛子模块（由 SncService 编排）
│   ├── model/                         # 路由模型
│   │   ├── RouteTable.java            #   模板路由表（Prefix → RouteEntry）
│   │   ├── RouteEntry.java            #   模板路由条目（含 NhpSet + shortest/secondShortest/other 分类）
│   │   ├── Inbound.java               #   入接口（inPortId + parentNodeId + cost + outIfSet）
│   │   ├── NextHopPort.java           #   下一跳端口（outPortId + outPortName + cost + pathType）
│   │   └── OriginNode.java            #   MSP 搜索节点（layer + inboundMap）
│   ├── service/                       # 路由服务
│   │   ├── RouteMspService.java       #   模板路由 MSP 计算（BFS 最短路径 + 路径策略）
│   │   ├── RouteInstantiationService.java # 模板路由实例化（按机框扩展 + NPU/L1SW/L2SW 分发 + buildRouteTableKey + deepCopyRoutingEntry）
│   │   └── RouteConvergeService.java  #   路由收敛（BFS 在互联转发节点间传播 reachable 变化）
│   └── topo/                          # 拓扑模板
│       └── template/
│           ├── model/                 # 模板模型（SncTopology、SncNode、SncPort、Label、Address、Prefix、Bitmap、PolicyPath、PolicyPrefix、AddrType）
│           ├── loader/                # 模板加载器（TemplateLoader、NodeLoader、PortLoader、PrefixLoader、PolicyLoader、PathPolicyLoader、LogicalPortLoader、PermitOrDenyPolicy、PrefixPolicyLoader、PortFwdPolicyLoader、PathPolicyItemsLoader、Deserializers）
│           └── service/               # 模板服务（TopoTemplateService.parseTemplateFile）
│
├── store/                             # 数据存储层（HashMap 索引）
│   └── SuperNodeStore.java                 # 拓扑索引（superNodeName→SuperNode / routingTableMap）
│
├── engine/                            # 算法引擎层
│   ├── PathEngine.java                # 路径还原引擎（Step 3~5）
│   ├── RouteLookupEngine.java         # 路径规划引擎 / 索引掩码匹配（Step 6~8，§8）
│   └── CoveragePlanEngine.java        # 覆盖规划引擎（findCoverage / findCoverageEx + 两阶段覆盖 + 分层统计 + getExDiagnostics）
│
├── exception/                         # 异常定义（§7.5.2）
│   ├── SNCException.java              # 基础异常
│   ├── SNCStateException.java         # 状态异常
│   ├── SuperNodeNotFoundException.java     # 拓扑数据未找到
│   └── PathPlanException.java         # 路径规划失败（内含 PlanStatus）
│
└── util/                              # 工具类
    ├── AddressUtils.java              # CNA 掩码计算、地址格式校验
    ├── HashUtils.java                 # hash 封装（nativeHash + nativeHashDstCnaJetty + JETTY_ID_MIN/MAX + isValidJettyId）
    ├── UbSwitchHash.java              # 纯 Java hash fallback（与两个 C 文件逻辑一一对应）
    └── DllLoader.java                 # JNA 原生库搜索与加载（jar 同级目录、classpath 提取等）
```

### 3.3 依赖关系

```
                    ┌──────────┐
                    │   dto    │ （§6 北向 API DTO，无内部依赖，纯数据结构）
                    └────▲─────┘
                         │使用
                    ┌────┴─────┐
                    │ service  │ （编排层：SuperNodeService / PathService / LinkEventService）
                    └─┬──┬──┬─┘
                      │  │  │
            ┌─────────┘  │  └─────────┘
            │            │            │
       ┌────────┐  ┌─────────┐  ┌────────┐
       │ store  │  │ engine  │  │ entity │
       │ (索引)  │  │ (算法)   │  │ (模型)  │
       └───┬────┘  └────┬────┘  └────────┘
           │            │
           │     ┌──────┴───────┐
           │     │              │
           │  ┌──┴─────┐  ┌─────┴──────┐
           │  │ route  │  │   util     │
           │  │ (模板/ │  │ (HashUtils │
           │  │ 收敛)  │  │  /AddressUtils│
           │  └──┬─────┘  └────────────┘
           │     │
           └─────┴──────┘
                 │查询/写入
           ┌────────┐
           │ entity │ （§4 领域模型 + §5 计算模型，store/engine/service/route 共同依赖）
           └────────┘
```

| 层 | 可依赖 | 不可依赖 | 说明 |
|:---|:-------|:--------|:-----|
| `dto` | - | entity / service / store / engine / route / util | API 契约层，独立于内部实现 |
| `entity` | util | dto / service / store / engine / route | 纯数据结构层 |
| `store` | entity / util | dto / service / engine / route | 索引存储，直接操作领域模型 |
| `engine` | entity / util | dto / service / store / route | 算法引擎，读 entity 输出 §5 计算模型 |
| `route` | entity / util | dto / service / store / engine | 路由 MSP 计算、实例化、收敛、模板解析 |
| `service` | entity / dto / store / engine / route / util | - | 编排层，完成 DTO 与领域模型映射 |
| `exception` | dto.PathPlanResult.PlanStatus | - | 异常可引用错误码枚举（PlanStatus 定义在 §6.2 PathPlanResult 内部） |
| `util` | - | entity / dto / service / store / engine / route | 纯工具类（HashUtils、UbSwitchHash、DllLoader、AddressUtils） |

### 3.4 接口层与内部层转换映射

`SNCServiceImpl` 位于 package 根，负责将 `dto` 与内部 `entity`/`service` 连接。

```
SNCServiceImpl
    │
    ├── init(SNCConfig)
    │     └→ SuperNodeStore.init()
    │     └→ 仅操作 config 和 store，不涉及 dto
    │
    ├── setSuperNode(SuperNode)          // entity.SuperNode（§4.1 领域模型）
    │     └→ SuperNodeService.importSuperNode(superNode)
    │              └→ SuperNodeStore.replace(superNode)
    │
    ├── planPath(PathPlanRequest)      // dto.PathPlanRequest（§6.1 DTO）
    │     └→ PathService.planPath(request)
    │              ├→ superNode.getNpuDevices().get(srcDevice/destDevice)  // Step 0: NPU 设备查找
    │              ├→ srcNpuDevice.findNpuPort() + destNpuDevice.findNpuPort() // Step 1~2: 端口查找（直接使用 NpuForwardingChip.getNpuPorts()，无需 instanceof/cast）
    │              ├→ PathEngine.resolveDirectPath/resolveMultiHopPath(→ InternalPathInfo) // Step 3~5: 路径还原
    │              │    签名: (NpuDevice, NpuPortEntity, NpuDevice, NpuPortEntity, ...)
    │              ├→ superNode.getAllDevices() + RouteLookupEngine.lookup() // Step 6~8: 路径规划
    │              └→ 组装 dto.PathPlanResult                       // Step 9~10: 输出构造（§6.2 DTO）
    │
    └── uninit()
            └→ SuperNodeStore.clear()
```

> `setSuperNode` 的入参直接使用 `entity.SuperNode`（领域模型），因为它们来自 JSON 反序列化的原始结构，与拓扑文件 1:1 对应，无需额外 DTO 包装。`planPath` 的入参/出参使用 `dto.PathPlanRequest` / `dto.PathPlanResult`，因为它们面向北向调用方，需要稳定的 API 契约。

---

## 4. 数据结构定义

> **Lombok 说明：** 本章所有 Java 代码中的 getter/setter、equals/hashCode、toString 均由 Lombok 注解（`@Getter`、`@Setter`、`@NoArgsConstructor`、`@EqualsAndHashCode`、`@ToString`）自动生成，不再手写。代码清单中仅保留字段声明、自定义构造器和覆盖方法。**注意：** 抽象类 `DeviceEntity`（§4.3）和 `ForwardingChip`（§4.4）不再使用 `@AllArgsConstructor`（改为自定义 protected 构造器），其子类 `NpuDevice`、`SwDevice`、`NpuForwardingChip`、`SwForwardingChip` 也不再使用 `@AllArgsConstructor`（改为自定义 public 构造器）。Lombok 依赖已加入 `pom.xml`（scope=provided），通过 `maven-compiler-plugin` 注解处理器编译。

---

### 4.1 SuperNode（拓扑数据 — 顶层结构）

```java
public class SuperNode {
    /** 超节点名称，如 "A5-superPod-1" -- 必填字段 */
    private String name;

    /** 拓扑数据版本号，如 "1.0" -- 必填字段 */
    private String version;

    /** NPU 设备 Map -- key 为 deviceName（设备唯一标识），value 为 NpuDevice */
    private Map<String, NpuDevice> npuDevices;

    /** SW 设备 Map -- key 为 deviceName（设备唯一标识），value 为 SwDevice */
    private Map<String, SwDevice> swDevices;

    /**
     * 返回不可修改的 npuDevices 视图
     */
    public Map<String, NpuDevice> getNpuDevices() {
        return npuDevices == null ? null : Collections.unmodifiableMap(npuDevices);
    }

    /**
     * 返回不可修改的 swDevices 视图
     */
    public Map<String, SwDevice> getSwDevices() {
        return swDevices == null ? null : Collections.unmodifiableMap(swDevices);
    }

    /**
     * 合并 npuDevices 和 swDevices 为统一的 DeviceEntity 视图
     * 用于内部统一查找（如 PathService.routePhase 遍历所有设备）
     */
    public Map<String, DeviceEntity> getAllDevices() {
        Map<String, DeviceEntity> all = new HashMap<>();
        if (npuDevices != null) {
            all.putAll(npuDevices);
        }
        if (swDevices != null) {
            all.putAll(swDevices);
        }
        return all.isEmpty() ? Collections.emptyMap() : Collections.unmodifiableMap(all);
    }
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| name | String | 超节点名称，如 "A5-superPod-1" -- 必填字段 |
| version | String | 拓扑数据版本号，如 "1.0" -- 必填字段 |
| npuDevices | Map\<String, NpuDevice\> | NPU 设备 Map，key为deviceName，value为NpuDevice |
| swDevices | Map\<String, SwDevice\> | SW 设备 Map，key为deviceName，value为SwDevice |

**对应 JSON 示例：**
```json
{
    "name": "A5-superPod-1",
    "version": "1.0",
    "devices": { ... }
}
```

**Key说明：**
- `SuperNode` 是从 `superNode_data_*.json` 文件反序列化后的顶层数据结构。一个 `superNode_data_*.json` 文件对应一个超节点（如 "A5-superPod-1"）。
- `name` 字段同时作为 `SuperNodeStore` 中 `Map<String, SuperNode>` 的 key（见 §7.9），外部可下发多个超节点的拓扑数据，各自以 `name`（superNodeName）区分存储。
- `devices` 在 JSON 中仍为单一 Map（key=deviceName），由反序列化器根据 `deviceType` 字段拆分为 `npuDevices` 和 `swDevices`。
- `getAllDevices()` 合并两个 Map 提供统一的 `Map<String, DeviceEntity>` 视图，用于内部遍历查找（如路径规划中的设备查询）。

---

### 4.2 MgmtInfo（管理信息）

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class MgmtInfo {
    /** 管理IP地址 -- 必填字段 */
    private String ip;

    /** 管理端口号 -- 必填字段 */
    private Integer port;

    /** 管理用户名 -- 必填字段 */
    private String username;

    /** 管理密码 -- 必填字段 */
    private String password;
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| ip | String | 管理IP地址 -- 必填字段 |
| port | Integer | 管理端口号，如 8443 -- 必填字段 |
| username | String | 管理用户名 -- 必填字段 |
| password | String | 管理密码 -- 必填字段 |

**对应 JSON 示例：**
```json
"mgmtInfo": {
    "ip": "198.168.0.1",
    "port": 8443,
    "username": "admin",
    "password": "xxx"
}
```

**说明：**
- `MgmtInfo` 存储设备的远程管理连接信息，所有设备类型（NPU、SW）均包含此信息。
- JSON 中 NPU 设备使用 `"userName"`（驼峰命名），SW 设备使用 `"username"`（全小写）。`MgmtInfo` 统一用 `username` 字段反序列化，需要在 JSON 反序列化时兼容两种命名风格（如配置 `@JsonAlias("userName")`）。

---

### 4.3 DeviceEntity（设备实体 — 抽象类）

```java
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EqualsAndHashCode
@ToString
public abstract class DeviceEntity {
    /** 设备唯一标识，格式：rack#os#npu 或 rack#l1sw0 或 lc#0 -- 必填字段 */
    private String deviceName;

    /** 设备类型 -- 必填字段 */
    private DeviceType deviceType;

    /** 设备管理信息 -- 必填字段 */
    private MgmtInfo mgmtInfo;

    /** 所属Rack */
    private String rack;

    /** 抽象方法：获取转发芯片Map（多态迭代用），返回通配类型 Map<Integer, ? extends ForwardingChip>。
     *  <p>各子类持有精确类型的 forwardingChips 字段（NpuDevice→Map<Integer, NpuForwardingChip>，
     *  SwDevice→Map<Integer, SwForwardingChip>），通过此抽象方法对外提供统一遍历视图，
     *  供 PathEngine/SuperNodeStore/PathService 等跨类型多态迭代。
     *  <p>子类同时提供类型特定的 getter（如 getNpuForwardingChips/getSwForwardingChips），
     *  返回精确类型的不可修改视图，消除 instanceof/cast。 */
    public abstract Map<Integer, ? extends ForwardingChip> getForwardingChips();

    /** 全参数构造（不含 forwardingChips，该字段由各子类持有） */
    protected DeviceEntity(String deviceName, DeviceType deviceType, MgmtInfo mgmtInfo, String rack) {
        this.deviceName = deviceName;
        this.deviceType = deviceType;
        this.mgmtInfo = mgmtInfo;
        this.rack = rack;
    }
}
```

**字段来源对照表：**

| 类设计字段 | JSON 字段 | 设备类型 | 说明 |
|:-----------|:----------|:---------|:-----|
| deviceName | deviceName | NPU & SW | 设备唯一标识 |
| deviceType | deviceType | NPU & SW | 设备类型，反序列化时推导 |
| mgmtInfo | mgmtInfo | NPU & SW | 管理信息（§4.2） |
| rack | rack | NPU & SW | 所属机框 |

**抽象方法说明：**

| 方法 | 返回类型 | 说明 |
|:-----|:---------|:-----|
| getForwardingChips() | Map\<Integer, ? extends ForwardingChip\> | 抽象方法，供多态迭代。子类实现返回各自精确类型的 forwardingChips 字段 |

**Key说明：**
- `getForwardingChips()`：抽象方法，返回 `Map<Integer, ? extends ForwardingChip>` 通配类型。PathEngine、SuperNodeStore、PathService 等跨设备类型遍历时通过此方法统一访问转发芯片，无需 instanceof/cast。
- 各子类持有精确类型的 `forwardingChips` 字段（NpuDevice→`Map<Integer, NpuForwardingChip>`，SwDevice→`Map<Integer, SwForwardingChip>`），并提供类型特定的 getter（`getNpuForwardingChips`/`getSwForwardingChips`），返回精确类型的不可修改视图，消除 instanceof/cast。
- `DeviceEntity` 为抽象类，具体设备类型由 `NpuDevice`、`SwDevice` 派生实现。

#### 4.3.1 设备类型枚举

```java
public enum DeviceType {
    NPU,   // NPU设备
    SW     // 交换设备（L1SW或L2SW，由SwitchLevel区分）
}
```

设备类型说明：

| 类型 | 说明     | 典型场景           | 对应派生类    |
|:-----|:---------|:-------------------|:---------------|
| NPU  | 计算节点 | AI 训练/推理节点    | NpuDevice      |
| SW   | 交换设备 | L1SW框内交换 / L2SW跨框交换 | SwDevice       |

**SwitchLevel（交换机层级枚举）：**

```java
public enum SwitchLevel {
    L1,   // L1SW — 框内交换
    L2    // L2SW — 跨框交换
}
```

#### 4.3.2 NpuDevice（NPU设备）

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class NpuDevice extends DeviceEntity {
    /** OS名称 -- 仅NPU设备有，如 "os0" */
    private String osName;

    /** OS IP地址 -- 仅NPU设备有，如 "172.168.0.1" */
    private String osIp;

    /** 板卡ID -- 仅NPU设备有 */
    private Integer boardId;

    /** 模组ID -- 仅NPU设备有 */
    private Integer moduleId;

    /** 板卡索引（在机框中的位置编号）-- 仅NPU设备有 */
    private Integer boardIndex;

    /** 转发芯片列表 -- 精确类型，Map的key为chipIndex（芯片编号） */
    private Map<Integer, NpuForwardingChip> forwardingChips;

    @Override
    public DeviceType getDeviceType() {
        return DeviceType.NPU;
    }

    @Override
    public Map<Integer, ? extends ForwardingChip> getForwardingChips() {
        return forwardingChips;
    }

    /** 类型特定的转发芯片 getter -- 返回不可修改的精确类型视图，消除 instanceof/cast */
    public Map<Integer, NpuForwardingChip> getNpuForwardingChips() {
        return forwardingChips == null ? null : Collections.unmodifiableMap(forwardingChips);
    }

    /**
     * 全参数构造
     * <p>先调用 super(deviceName, DeviceType.NPU, mgmtInfo, rack) 初始化基类字段，
     * 再设置 NPU 特有字段和 forwardingChips。
     */
    public NpuDevice(String deviceName, MgmtInfo mgmtInfo, String rack,
                     Map<Integer, NpuForwardingChip> forwardingChips,
                     String osName, String osIp, Integer boardId, Integer moduleId, Integer boardIndex) {
        super(deviceName, DeviceType.NPU, mgmtInfo, rack);
        this.forwardingChips = forwardingChips;
        this.osName = osName;
        this.osIp = osIp;
        this.boardId = boardId;
        this.moduleId = moduleId;
        this.boardIndex = boardIndex;
    }

    /**
     * 查找 NPU 端口 -- 直接使用 forwardingChips（NpuForwardingChip 精确类型）
     * <p>无需 instanceof NpuPortEntity + cast，通过 getNpuPorts() 直接获取 NpuPortEntity。
     */
    public NpuPortEntity findNpuPort(String portName) {
        if (forwardingChips != null) {
            for (NpuForwardingChip chip : forwardingChips.values()) {
                NpuPortEntity port = chip.getNpuPorts().get(portName);
                if (port != null) {
                    return port;
                }
            }
        }
        return null;
    }
}
```

| 字段 | JSON字段 | 说明 |
|:-----|:---------|:-----|
| osName | osName | OS名称，如 `"os0"` |
| osIp | osIp | OS IP地址，如 `"172.168.0.1"` |
| boardId | boardId | 板卡ID |
| moduleId | moduleId | 模组ID（原 `osZone`、`moduleidx` 字段废弃，以 `boardId` + `moduleId` 联合替代） |
| boardIndex | boardIndex | 板卡索引（在机框中的位置编号） |
| forwardingChips | forwardingChip | NPU 转发芯片，精确类型 `Map<Integer, NpuForwardingChip>`。JSON 为单对象，反序列化后转为 Map |

**方法说明：**

| 方法 | 返回类型 | 说明 |
|:-----|:---------|:-----|
| getForwardingChips() | Map\<Integer, ? extends ForwardingChip\> | 覆盖抽象方法，返回 forwardingChips（满足多态迭代契约） |
| getNpuForwardingChips() | Map\<Integer, NpuForwardingChip\> | 类型特定 getter，返回不可修改的精确类型视图 |
| findNpuPort(String) | NpuPortEntity | 简化实现：直接使用 forwardingChips 遍历 NpuForwardingChip，调用 chip.getNpuPorts().get(portName)，无需 instanceof/cast |

#### 4.3.3 SwDevice（交换设备）

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class SwDevice extends DeviceEntity {
    /** 交换机层级 -- L1（框内交换）或 L2（跨框交换） */
    private SwitchLevel switchLevel;

    /** 交换机在Rack中的索引（序号）-- 仅SW设备有 */
    private Integer index;

    /** 转发芯片列表 -- 精确类型，Map的key为chipIndex（芯片编号） */
    private Map<Integer, SwForwardingChip> forwardingChips;

    @Override
    public DeviceType getDeviceType() {
        return DeviceType.SW;
    }

    @Override
    public Map<Integer, ? extends ForwardingChip> getForwardingChips() {
        return forwardingChips;
    }

    /** 类型特定的转发芯片 getter -- 返回不可修改的精确类型视图，消除 instanceof/cast */
    public Map<Integer, SwForwardingChip> getSwForwardingChips() {
        return forwardingChips == null ? null : Collections.unmodifiableMap(forwardingChips);
    }

    /**
     * 全参数构造
     * <p>先调用 super(deviceName, DeviceType.SW, mgmtInfo, rack) 初始化基类字段，
     * 再设置 SW 特有字段和 forwardingChips。
     */
    public SwDevice(String deviceName, MgmtInfo mgmtInfo, String rack,
                    Map<Integer, SwForwardingChip> forwardingChips,
                    SwitchLevel switchLevel, Integer index) {
        super(deviceName, DeviceType.SW, mgmtInfo, rack);
        this.forwardingChips = forwardingChips;
        this.switchLevel = switchLevel;
        this.index = index;
    }
}
```

| 字段 | JSON字段 | 说明 |
|:-----|:---------|:-----|
| switchLevel | level | 交换机层级，L1=框内交换 / L2=跨框交换 |
| index | index | 交换机在Rack中的索引（序号） |
| forwardingChips | forwardingChip | SW 转发芯片，精确类型 `Map<Integer, SwForwardingChip>`。JSON 为单对象，反序列化后转为 Map |

**方法说明：**

| 方法 | 返回类型 | 说明 |
|:-----|:---------|:-----|
| getForwardingChips() | Map\<Integer, ? extends ForwardingChip\> | 覆盖抽象方法，返回 forwardingChips（满足多态迭代契约） |
| getSwForwardingChips() | Map\<Integer, SwForwardingChip\> | 类型特定 getter，返回不可修改的精确类型视图 |

---

### 4.4 ForwardingChip（转发芯片 — 抽象类）

```java
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EqualsAndHashCode
@ToString
public abstract class ForwardingChip {
    /** 芯片编号，设备内唯一 -- 必填字段 */
    private Integer chipIndex;

    /** 路由表 -- 由 SuperNodeStore.replace() 在索引时从顶层 JSON 提取并填充，ForwardingChip 本身不负责反序列化此字段 */
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    private RoutingTable routingTable;

    /** 抽象方法：获取端口Map（多态迭代用），返回通配类型 Map<String, ? extends PortEntity>。
     *  <p>各子类持有精确类型的 ports 字段（NpuForwardingChip→Map<String, NpuPortEntity>，
     *  SwForwardingChip→Map<String, SwPortEntity>），通过此抽象方法对外提供统一遍历视图，
     *  供 PathEngine/SuperNodeStore/PathService 等跨类型多态迭代。
     *  <p>子类同时提供类型特定的 getter（如 getNpuPorts/getSwPorts），
     *  返回精确类型的不可修改视图，消除 instanceof/cast。 */
    public abstract Map<String, ? extends PortEntity> getPorts();

    /** 最小构造：仅 chipIndex（无端口、无路由表），由子类 NpuForwardingChip/SwForwardingChip 使用 */
    protected ForwardingChip(Integer chipIndex) {
        this.chipIndex = chipIndex;
    }
}
```

**Key说明：**
- `ForwardingChip`：以 `chipIndex` 作为 key，在各子类的 `forwardingChips` 这个 Map 中 O(1) 查找。
- `getPorts()`：抽象方法，返回 `Map<String, ? extends PortEntity>` 通配类型。PathEngine、SuperNodeStore、PathService 等跨芯片类型遍历时通过此方法统一访问端口，无需 instanceof/cast。
- 各子类持有精确类型的 `ports` 字段（NpuForwardingChip→`Map<String, NpuPortEntity>`，SwForwardingChip→`Map<String, SwPortEntity>`），并提供类型特定的 getter（`getNpuPorts`/`getSwPorts`），返回精确类型的不可修改视图，消除 instanceof/cast。
- `ForwardingChip` 为抽象类，具体芯片类型由 `NpuForwardingChip`、`SwForwardingChip` 派生实现。
- `routingTable`：由 SuperNodeStore 索引时从输入 JSON 的设备级别提取并注入，ForwardingChip 的类定义持有该引用以便遍历访问，但 routingTable 的实际存储以 RoutingTableKey→RoutingTable 的全局索引为准（见 §7.9）。

#### 4.4.1 NpuForwardingChip（NPU转发芯片）

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class NpuForwardingChip extends ForwardingChip {
    /** 端口Map -- 精确类型，Map的key为portName，支持O(1)查找和遍历 */
    private Map<String, NpuPortEntity> ports;

    /** 逻辑端口Map（聚合端口） -- 仅NPU芯片有，key为portName，支持O(1)查找 */
    private Map<String, LogicPortEntity> logicPorts;

    /** 最小构造：仅 chipIndex */
    public NpuForwardingChip(Integer chipIndex) {
        super(chipIndex);
    }

    /** 芯片+端口构造 */
    public NpuForwardingChip(Integer chipIndex, Map<String, NpuPortEntity> ports) {
        super(chipIndex);
        this.ports = ports;
    }

    @Override
    public Map<String, ? extends PortEntity> getPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }

    /** 类型特定的端口 getter -- 返回不可修改的精确类型视图，消除 instanceof/cast */
    public Map<String, NpuPortEntity> getNpuPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }
}
```

**说明：**
- `ports`：精确类型 `Map<String, NpuPortEntity>`，Map 的 key 为 `portName`（端口名称），支持 O(1) 查找和遍历。
- `getNpuPorts()`：类型特定 getter，返回不可修改的 `Map<String, NpuPortEntity>` 视图。NpuDevice.findNpuPort() 直接调用 `chip.getNpuPorts().get(portName)`，无需 instanceof NpuPortEntity + cast。
- `getPorts()`：覆盖抽象方法，返回 `Map<String, ? extends PortEntity>` 通配类型，供跨芯片类型多态迭代。
- `logicPorts`：Map 的 key 为 `portName`（逻辑端口名称），支持 O(1) 查找，与其他 Map 结构保持一致。
- NPU 转发芯片独有逻辑端口，交换转发芯片无逻辑端口。

#### 4.4.2 SwForwardingChip（交换转发芯片）

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class SwForwardingChip extends ForwardingChip {
    /** 端口Map -- 精确类型，Map的key为portName，支持O(1)查找和遍历 */
    private Map<String, SwPortEntity> ports;

    /** 最小构造：仅 chipIndex */
    public SwForwardingChip(Integer chipIndex) {
        super(chipIndex);
    }

    /** 芯片+端口构造 */
    public SwForwardingChip(Integer chipIndex, Map<String, SwPortEntity> ports) {
        super(chipIndex);
        this.ports = ports;
    }

    @Override
    public Map<String, ? extends PortEntity> getPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }

    /** 类型特定的端口 getter -- 返回不可修改的精确类型视图，消除 instanceof/cast */
    public Map<String, SwPortEntity> getSwPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }
}
```

**说明：**
- `ports`：精确类型 `Map<String, SwPortEntity>`，Map 的 key 为 `portName`（端口名称），支持 O(1) 查找和遍历。
- `getSwPorts()`：类型特定 getter，返回不可修改的 `Map<String, SwPortEntity>` 视图，消除 instanceof/cast。
- `getPorts()`：覆盖抽象方法，返回 `Map<String, ? extends PortEntity>` 通配类型，供跨芯片类型多态迭代。

**通用说明：**
- 每个设备可以有一个或多个转发芯片，每个芯片独立管理自身的端口。
- `chipIndex` 在设备内唯一，标识芯片编号。
- 路由表数据独立于superNode，通过 `superNodeName + deviceName + chipIndex` 联合定位（见 RoutingTableKey §4.7.1）。

---

### 4.5 PortEntity（端口实体 — 抽象类）

```java
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EqualsAndHashCode
@ToString
public abstract class PortEntity {
    /** 端口名称，如 "400GE 0/0/1" -- 必填字段 */
    private String portName;

    /** 端口ID */
    private Integer id;

    /** 所属芯片编号 */
    private Integer chipIndex;

    /** 连接的设备 -- 必填字段 */
    private String remoteDevice;

    /** 连接的端口 -- 必填字段 */
    private String remotePort;

    /** 关联的CNA -- 32 bit（IP格式）-- 必填字段 */
    private String cna;

    protected PortEntity(String portName, Integer id, Integer chipIndex,
                         String remoteDevice, String remotePort, String cna) {
        this.portName = portName;
        this.id = id;
        this.chipIndex = chipIndex;
        this.remoteDevice = remoteDevice;
        this.remotePort = remotePort;
        this.cna = cna;
    }
}
```

**字段约束：**
- `cna`：32 bit CNA 地址，字符串格式（如 "0.1.2.3"）。**NPU 端口的 cna 为必填；交换设备（SW）端口的 cna 为可选，可为 null**（见 §4.5.2）。
- `remoteDevice` / `remotePort`：描述物理连接的对端设备和端口，用于路径还原。
- `PortEntity` 为抽象类，具体端口类型由 `NpuPortEntity`、`SwPortEntity` 派生实现。端口存储于各子类转发芯片的精确类型 `ports` 字段中（NpuForwardingChip.ports 为 `Map<String, NpuPortEntity>`，SwForwardingChip.ports 为 `Map<String, SwPortEntity>`），通过 `getPorts()` 抽象方法提供统一多态访问（§4.4）。

#### 4.5.1 NpuPortEntity（NPU端口）

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class NpuPortEntity extends PortEntity {
    /** 关联的EID -- 128 bit -- 仅NPU端口有 */
    private String eid;

    /** UPI -- 32 bit -- 必填字段 */
    private String upi;

    /** jettyId -- NPU→L1SW 选路 hash 的二元组 (DstCNA, jettyId) 中 jettyId 字段；
     *  取值范围 [32, 1023]，每个 NPU 物理端口一个；用于 planPathsCoverageEx
     *  （§4.5.1.a jettyId）。缺失或越界时 CoveragePlanEngine.jettyIdOf 回落
     *  HashUtils.JETTY_ID_MIN + portId（= 32 + portId），并累加诊断计数 exJettyFallback */
    private Integer jettyId;

    public NpuPortEntity(String portName, Integer id, Integer chipIndex,
                         String remoteDevice, String remotePort, String cna,
                         String eid, String upi) {
        super(portName, id, chipIndex, remoteDevice, remotePort, cna);
        this.eid = eid;
        this.upi = upi;
    }

    /** 含 jettyId 的扩展构造器（planPathsCoverageEx 用） */
    public NpuPortEntity(String portName, Integer id, Integer chipIndex,
                         String remoteDevice, String remotePort, String cna,
                         String eid, String upi, Integer jettyId) {
        super(portName, id, chipIndex, remoteDevice, remotePort, cna);
        this.eid = eid;
        this.upi = upi;
        this.jettyId = jettyId;
    }
}
```

**字段约束：**
- `eid`：128 bit EID 标识，字符串格式。仅 NPU 端口携带 EID 信息。
- `upi`：UPI 标识，仅 NPU 端口携带，用于源/目的 UPI 一致性校验（`planPath` §9 Step 0）。
- `jettyId`：NPU→L1SW 选路 hash 的物理端口标识，取值范围 **`[32, 1023]`**（`HashUtils.JETTY_ID_MIN = 32`，`HashUtils.JETTY_ID_MAX = 1023`），每个 NPU 物理端口一个。仅 `planPathsCoverageEx` 使用（作为 `(DstCNA, jettyId)` 二元组的 jettyId 字段，见 §8 路径规划算法）；`planPath` 与 `planPathsCoverage` 不使用。拓扑输入缺失或越界时由 `CoveragePlanEngine.jettyIdOf` 回落 `32 + portId` 并累加 `exJettyFallback` 诊断计数。
- NpuPortEntity 存储于 `NpuForwardingChip.ports`（`Map<String, NpuPortEntity>`，§4.4.1），通过 `getNpuPorts()` 直接获取精确类型，无需 instanceof/cast。

##### 4.5.1.a jettyId 取值规则（planPathsCoverageEx）

| 项 | 说明 |
|:---|:---|
| 取值范围 | `[32, 1023]`，由 `HashUtils.JETTY_ID_MIN` / `HashUtils.JETTY_ID_MAX` 定义；越界由 `HashUtils.isValidJettyId` 校验，抛 `IllegalArgumentException` |
| topo 输入字段 | 超节点 JSON `jettyId`（由 `TestDataLoader` 解析）；模板 JSON `jetty_id`（`128_npu_rack.json`，由 `PortLoader`/`SncPort` 承载）；`FullRackTopologyGenerator` 用固定分配 `JETTY_ID_BASE + portIndex`（32..39，每次生成完全一致，由 `FullRackTopologyJettyIdTest` 钉死） |
| 缺失回落 | jettyId 为 null 或越界时，`CoveragePlanEngine.jettyIdOf(port)` 回落 `HashUtils.JETTY_ID_MIN + (port.id == null ? 0 : port.id)`，并累加诊断计数 `exJettyFallback`，保证旧拓扑输入（未携带 jettyId）仍可完成选路 |
| hash 使用 | `HashUtils.nativeHashDstCnaJetty(dstCna, jettyId, ecmpCnt, hashFunc)` 调用原生库 `ubswitch_Hash_dieEcmp`（CRC-8/ATM），见 §8 路径规划算法 |
| ACK 方向 | ACK 方向 NPU 选口仍使用**源 NPU 端口的 jettyId**（与正向同一 jettyId），而非目的 NPU 端口的 jettyId；DstCNA 为源 CNA |

#### 4.5.2 SwPortEntity（交换端口）

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class SwPortEntity extends PortEntity {
    public SwPortEntity(String portName, Integer id, Integer chipIndex,
                        String remoteDevice, String remotePort, String cna) {
        super(portName, id, chipIndex, remoteDevice, remotePort, cna);
    }
}
```

**字段约束：**
- 交换设备的端口无 CNA/EID/UPI 概念，`cna` 字段在交换端口场景下为**可选**（可为 null），不参与路径规划中的 CNA 匹配。
- `remoteDevice` / `remotePort` 为交换端口的核心字段，用于多跳拓扑路径还原。
- SwPortEntity 存储于 `SwForwardingChip.ports`（`Map<String, SwPortEntity>`，§4.4.2），通过 `getSwPorts()` 直接获取精确类型，无需 instanceof/cast。

#### 4.5.3 LinkEvent（链路事件实体）

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class LinkEvent {
    /** 链路所属设备名 -- 必填，对应 SuperNode 的 npuDevices/swDevices key */
    private String deviceName;

    /** 端口名 -- 必填，对应 ForwardingChip.ports key */
    private String portName;

    /** 事件类型："up" / "down" -- 必填，大小写敏感；其他值抛 IllegalArgumentException */
    private String eventType;

    /** 事件时间戳（毫秒，epoch） -- 必填；用于更新 PortEntity.updateAt */
    private long eventTime;
}
```

**字段约束：**
- `eventType` 仅接受 `"up"` 或 `"down"`，其他值抛 `IllegalArgumentException`。
- `eventTime` 用于更新 `PortEntity.updateAt`（用于后续审计 / 路由收敛快照）。
- `deviceName` + `portName` 必须能在 SuperNode 拓扑中定位到具体的 `PortEntity`；找不到时抛 `IllegalStateException`。
- 处理流程见 §7.2 `notifyLinkEvent` 方法说明与 §8 路由收敛算法。

---

### 4.6 LogicPortEntity（逻辑端口实体）

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class LogicPortEntity {
    /** 逻辑端口名称，如 "port_group1" -- 必填字段 */
    private String portName;

    /** 关联的CNA -- 32 bit（IP格式） */
    private String cna;

    /** 关联的EID -- 128 bit */
    private String eid;

    /** 包含的物理端口列表 -- 必填字段 */
    private List<String> ports;
}
```

**说明：**
- 逻辑端口是物理端口的聚合。
- `ports` 中存储的是各物理端口的 `portName`。

---

### 4.7 RoutingTable（路由表）

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutingTable {
    /** 所属设备 */
    private String deviceName;

    /** 所属转发芯片索引 */
    private Integer chipIndex;

    /** 路由条目Map -- Map的key为RoutePrefix对象，查找时按已知掩码构造key做O(1)命中（§4.8） */
    private Map<RoutePrefix, RoutingEntry> routes;

    /** 该路由表中存在的掩码长度列表（去重后从大到小排序），在replace/增量更新时由引擎维护。
     *  <p>例如外部输入32和20两种掩码 → [32, 20]；查找时仅用这两种掩码去匹配，无需遍历全表。 */
    private List<Integer> maskLengths;
}
```

**Key说明：**
- `RoutingTable`：路由表独立存储于 `SuperNodeStore.routingTableMap` 中，以 `RoutingTableKey`（`superNodeName + deviceName + chipIndex`）为 key（`Map<RoutingTableKey, RoutingTable>`，§4.7.1），支持全局 O(1) 定位。多个超节点下 deviceName 可能重复，通过 superNodeName 区分。`RoutingTable` 不作为 HashMap key 使用，`equals()`/`hashCode()` 由 Lombok `@EqualsAndHashCode` 生成（全部字段参与，与 `RoutePrefix` §4.8 一致）。
- `chipIndex`：对应 ForwardingChip.chipIndex，标识该路由表所属的转发芯片。
- `routes`：Map 的 key 为 `RoutePrefix` 对象（包含 dstAddress 和 maskLength）。路径规划时不再遍历全表，而是先取 `maskLengths` 列表中最长的掩码，将 `targetAddr` 按该掩码做按位与得到 `networkAddr`，再以 `(networkAddr, maskLen)` 构造 `RoutePrefix` 作为 HashMap key 做 O(1) 命中（见 §4.8）。
- `maskLengths`：路由表中实际存在的掩码长度列表（去重后按从大到小排序）。例如外部只输入了掩码 32 的明细路由和掩码 20 的框级路由，则 `maskLengths = [32, 20]`。该列表在 `SuperNodeStore.replace()` 或增量更新时由引擎自动提取维护。查找时仅按此列表中的掩码逐级尝试，无需遍历全表。

**路由表存储流程：**
- 先构造 `RoutePrefix` 对象（包含网络地址 + 掩码长度，如 `192.168.1.0/24`）。
- 创建 `RoutingEntry` 对象（包含下一跳、出接口等信息）。
- 以 `RoutePrefix` 为 key、`RoutingEntry` 为 value 存入 HashMap。
- `RoutePrefix` 的 `equals()` 和 `hashCode()` 由 Lombok `@EqualsAndHashCode` 生成（参见 §4.8）。
- 引擎同时提取当前路由表中所有 `RoutePrefix.maskLength` 的去重值，降序排列后写入 `maskLengths` 字段。

**增量更新时 maskLengths 的维护规则：**
- `addRoutingEntry()`：新增路由的 maskLength 若不在现有 maskLengths 列表中，则插入并按降序重排。
- `removeRoutingEntry()`：删除路由后，检查该 maskLength 在 routes Map 中是否还有其他路由条目——若无，则从 maskLengths 中移除该掩码。
- 全量替换 `replace()` 时：重新从 routes 中提取所有 maskLength 去重降序生成新列表。

**对应 JSON 示例（在 SuperNode JSON 中路由表的位置）：**
```json
{
  "name": "A5-superPod-1",
  "version": "1.0",
  "devices": {
    "rack1#os0#npu1": {
      "deviceName": "rack1#os0#npu1",
      "deviceType": "NPU",
      "forwardingChip": {
        "0": {
          "chipIndex": 0,
          "routingTable": {
            "routes": [
              {
                "prefix": { "dstAddress": "170.170.170.0", "maskLength": 24 },
                "outPortInfos": {
                  "400GE 0/0/1": {
                    "portName": "400GE 0/0/1",
                    "nextHop": "170.170.0.1",
                    "preference": 60,
                    "tag": 0,
                    "protocol": "STATIC"
                  }
                }
              },
              {
                "prefix": { "dstAddress": "0.0.0.0", "maskLength": 0 },
                "outPortInfos": {
                  "400GE 0/0/2": {
                    "portName": "400GE 0/0/2",
                    "nextHop": "0.0.0.1",
                    "preference": 60,
                    "tag": 0,
                    "protocol": "STATIC"
                  }
                }
              }
            ]
          },
          "ports": { ... }
        }
      }
    }
  }
}
```
> **说明：** 输入 JSON 文件（`superNode_data_*.json`）中 `routingTables` 数据位于设备级别（§4.1 SuperNode.devices 下每个设备对象中），与 `forwardingChip` 平级而非嵌套。`SuperNodeStore.replace()` 在处理过程中遍历 devices→chips，将每个芯片对应的 `RoutingTable` 提取并存入 `routingTableMap`（`Map<RoutingTableKey, RoutingTable>`，见 §7.9），同时将引用注入 `ForwardingChip.routingTable`。后续路径规划查找路由表不再依赖 JSON 中的嵌套结构，统一通过 `routingTableMap` 全局 O(1) 定位。

---

#### 4.7.1 RoutingTableKey（路由表联合键）

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutingTableKey {
    /** 超节点名称（superNodeName），如 "A5-superPod-1" -- 必填字段，对应 SuperNode.name */
    private String superNodeName;

    /** 设备唯一标识，格式：rack#os#npu 或 rack#l1sw0 或 lc#0 -- 必填字段 */
    private String deviceName;

    /** 所属芯片编号（对应 ForwardingChip.chipIndex，§4.4） */
    private Integer chipIndex;
}
```

**设计说明：**
- 路由表归属于某个超节点（superNodeName），不同超节点下 deviceName 可能重复，仅用 `deviceName + chipIndex` 无法全局唯一定位路由表。
- `RoutingTableKey` 三元素联合唯一标识一份路由表，用于 `SuperNodeStore.routingTableMap` 的 Map key。
- `routingTableMap` 类型为 `Map<RoutingTableKey, RoutingTable>`，详见 §7.9 SuperNodeStore 定义。

**HashMap Key 约束：**
- `equals()` 和 `hashCode()` 由 Lombok `@EqualsAndHashCode` 自动生成（三个字段参与），保证 HashMap 查找正确性。此做法与 `RoutePrefix`（§4.8）一致。

**查找流程：**
```
PathService 获取 superNodeName（来自当前查询上下文）
    + deviceName（来自 InternalPathHop）
    + chipIndex（来自 ForwardingChip.chipIndex）
    → 构造 RoutingTableKey(superNodeName, deviceName, chipIndex)
    → routingTableMap.get(key) → RoutingTable
    → 按 maskLengths 列表（从大到小）逐级 O(1) 查找：
        1. 取当前最长掩码 maskLen
        2. targetAddr 按 maskLen 按位与 → networkAddr
        3. 构造 RoutePrefix(networkAddr, maskLen) → routes.get(prefix)  O(1) 命中
        4. 命中则返回 RoutingEntry；未命中则尝试下一级掩码
    → 全部未命中则尝试默认路由 0.0.0.0/0
    （索引掩码匹配算法详见 §8，无需遍历全表）
```

---

### 4.8 RoutePrefix（路由前缀结构体）

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutePrefix {
    /** 目的地址（已掩码后的网络地址，如 "170.170.170.0"），必填字段 */
    private String dstAddress;

    /** 掩码长度(0-32)，必填字段 */
    private Integer maskLength;

    public String toPrefixString() {
        return dstAddress + "/" + maskLength;
    }
}
```

**说明：**
RoutePrefix 作为路由条目在 `RoutingTable.routes` Map 中的 key。`equals()`/`hashCode()` 由 Lombok `@EqualsAndHashCode` 自动生成（基于 `dstAddress` + `maskLength` 两字段）。查找时不再遍历全表，而是使用 RoutingTable 内部记录的 `maskLengths` 列表（见 §4.7），该列表示路由表中实际存在的所有掩码长度，去重后从大到小排序。

取目的地址，记为变量 destAddr。
例：目的地址是 170.170.170.17。

查找过程如下：
1. 从 `maskLengths` 中取出当前最长（即第一个）掩码 maskLen。
   例：路由表 maskLengths = [24, 16]，先取 maskLen=24。
2. 调用 `AddressUtils.applyMask(destAddr, maskLen)` 将 destAddr 与 maskLen 做按位与运算，得到 networkAddr。
   例：AddressUtils.applyMask("170.170.170.17", 24) → "170.170.170.0"。
3. 构造 `RoutePrefix(networkAddr, maskLen)` 作为 key，在 `RoutingTable.routes` 中做 O(1) 查找。
   例：构造 RoutePrefix{dstAddress="170.170.170.0", maskLen=24} → routes.get(prefix)。
4. 若命中 → 直接返回对应的 `RoutingEntry`（无需继续遍历，因为 maskLen 已是当前最长）。
5. 若未命中 → 取 maskLengths 中的下一个掩码（16），重复步骤 2~4。
   例：未命中 /24，尝试 /16：applyMask("170.170.170.17", 16) → "170.170.0.0" → 构造 RoutePrefix{"170.170.0.0", 16} → routes.get(prefix) → 命中 ✅。
6. 若所有已知掩码均未命中 → 尝试默认路由（0.0.0.0/0，若 maskLengths 未包含 0）。
   例：若 maskLengths = [24, 16] 均不命中，且存在 maskLen=0 的默认路由 → 命中默认路由。

**复杂度：**
- 查找次数 = `maskLengths.size()`，即外部路由输入中的掩码种类数。典型场景仅 2~3 种，每次做到 O(1) HashMap 命中。整体复杂度 O(m)，m = 掩码种类数（通常 ≤ 5）。
- 相比遍历全表 O(n)（n = 路由条目数，典型值几十到几百），**查找效率大幅提升**。
- 掩码种类数 m 独立于路由条目数 n，不会因路由表膨胀而退化。

**说明：**
- `maskLengths` 由引擎在路由表全量替换或增量更新时自动提取并排序（见 §4.7）。
- `dstAddress` 已由数据完整性约束保证是掩码后的网络地址，构造 key 时无需额外掩码运算。

---

### 4.9 RoutingEntry（路由条目实体）

路由条目，表示一条路由表记录。

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutingEntry {
    /** 目标前缀结构体 -- 包含目的地址(dstAddress)和掩码长度(maskLength) */
    private RoutePrefix prefix;

    /** 出端口信息Map -- 支持多出端口（ECMP），Map的key为portName，必填字段；
     *  内部使用 LinkedHashMap 维护插入顺序，setOutPortInfos 会拷贝入参到 LinkedHashMap */
    private Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();

    /** 路由可达性：表示 outPortInfos 中是否存在 convergedFlag==0 的有效出端口；
     *  默认 true；由 refreshReachable() 在链路事件收敛时刷新（§8 路由收敛算法） */
    private boolean reachable = true;

    public RoutingEntry(RoutePrefix prefix, Map<String, OutPortInfo> outPortInfos, boolean reachable) {
        this.prefix = prefix;
        this.reachable = reachable;
        this.outPortInfos = new LinkedHashMap<>();
        if (outPortInfos != null) {
            this.outPortInfos.putAll(outPortInfos);
        }
    }

    /** 遍历 outPortInfos，若存在任一 convergedFlag==0 的端口则 reachable=true，否则 false */
    public void refreshReachable();

    /** 深拷贝：拷贝 prefix、outPortInfos（含每个 OutPortInfo 实例）与 reachable */
    public static RoutingEntry copy(RoutingEntry src);
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| prefix | RoutePrefix | 目标前缀结构体，包含目的地址和掩码长度 |
| outPortInfos | Map\<String, OutPortInfo\> | 出端口信息Map，key为portName，支持多出端口（ECMP），必填字段；内部 LinkedHashMap 维护顺序 |
| reachable | boolean | 路由可达性。默认 true；链路事件收敛时由 `refreshReachable()` 刷新：只要有一个出端口 `convergedFlag==0`（有效）则 true，否则 false |

**说明：**
- `RoutingEntry` 存储在 `RoutingTable.routes` 中，以 `RoutePrefix` 对象为 key。
- 路径规划时，将 CNA 补齐为 32 bit 的 `targetAddr`（见 §4.8.1），从 `RoutingTable.maskLengths` 中取已知掩码，按从长到短逐级构造 key 做 O(1) 查找（§8）。
- 例如 `1.1.1.0/24` 和 `1.1.1.0/20` 是不同的路由，因为掩码不同导致 `RoutePrefix` 不同。
- `reachable` 字段在 `notifyLinkEvent`（§7.2）触发的 BFS 路由收敛流程中被刷新，影响后续 `getNodeRoute` 查询返回的路由表状态。
- `RoutingEntry.copy(src)` 用于 `RouteInstantiationService.deepCopyRoutingEntry`，保证 `makeRoutes` 返回的实例化路由表与内部 `instantiationRouteMap` 互不影响。

#### 4.9.1 OutPortInfo（出端口信息）

出端口信息，一个路由条目可包含多个，支持 ECMP。

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class OutPortInfo {
    /** 链路 down 收敛被动标志：链路事件 down 时设置 */
    public static final int FLAG_PASSIVE_CONVERRGED = 1 << 0;

    /** 主动收敛标志：用于路由策略二维维护 */
    public static final int FLAG_ACTIVE_CONVERRGED = 1 << 1;

    private String portName;         // 出接口名称 -- 必填字段
    private String nextHop;          // 下一跳IP
    private Integer preference;      // 路由优先级(1-255,默认60)
    private Integer tag;             // 路由标签
    private String protocol;         // 路由协议类型
    private int convergedFlag;       // 收敛标志位，按位组合 FLAG_PASSIVE_CONVERRGED / FLAG_ACTIVE_CONVERRGED

    /** 判断该出端口是否处于收敛状态（不再参与转发） */
    public boolean isConverged() { return convergedFlag != 0; }

    /** 在 convergedFlag 上置位指定 flag（不影响其他位） */
    public void setFlag(int flag) { this.convergedFlag |= flag; }

    /** 在 convergedFlag 上清零指定 flag（不影响其他位） */
    public void clearFlag(int flag) { this.convergedFlag &= ~flag; }
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| portName | String | 出接口名称 -- 必填字段 |
| nextHop | String | 下一跳IP |
| preference | Integer | 路由优先级(1-255,默认60) |
| tag | Integer | 路由标签 |
| protocol | String | 路由协议类型 |
| convergedFlag | int | 收敛标志位（按位组合）：`FLAG_PASSIVE_CONVERRGED`（链路 down 时置位）、`FLAG_ACTIVE_CONVERRGED`（路由策略主动收敛时置位）。`isConverged()` 返回 `convergedFlag != 0`，表示该出端口不参与转发 |

**收敛标志位使用规则：**
- 链路 down 事件：`notifyLinkEvent` → `LinkEventService` 定位端口所属 chip 路由表 → 找到包含该端口的 `RoutingEntry` → `OutPortInfo.setFlag(FLAG_PASSIVE_CONVERRGED)` → `RoutingEntry.refreshReachable()`。
- 链路 up 事件：`OutPortInfo.clearFlag(FLAG_PASSIVE_CONVERRGED)` → `RoutingEntry.refreshReachable()`。
- 路由策略主动收敛：`OutPortInfo.setFlag(FLAG_ACTIVE_CONVERRGED)` / `clearFlag(FLAG_ACTIVE_CONVERRGED)`。
- `RoutingEntry.refreshReachable()` 遍历 `outPortInfos`，只要存在一个 `convergedFlag == 0` 的端口，`reachable = true`，否则 `false`。

**说明：**
- 掩码长度已迁移至 `RoutePrefix` 结构体，`OutPortInfo` 不再包含 `maskLength` 字段。
- 上述字段统一封装在 `OutPortInfo`，作为 `RoutingEntry.outPortInfos` Map 的 value；Map 的 key 为 `portName`，支持 O(1) 查找和遍历，覆盖 ECMP 场景。


## 5 纯内部数据结构

### 5.1 InternalPathInfo（内部路径信息）

> **设计依据：** 参照 §9.3 阶段2 Step 5 — 多跳路径还原流程。

#### 5.1.1 InternalPathHop（内部路径跳）

单跳的内部表示，包含拓扑还原所需的全部连接和地址信息。

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class InternalPathHop {
    /** 当前设备ID -- 必填字段 */
    private String deviceName;

    /** 设备类型 */
    private DeviceType deviceType;

    /** 入端口名称 -- 源节点为 null */
    private String inPort;

    /** 出端口名称 -- 目的节点为 null */
    private String outPort;

    /** 当前端口关联的 CNA（32 bit）。正向路径取 outPort 的 cna，反向路径取 inPort 的 cna（正向的 outPort 即反向的 inPort） */
    private String cna;

    /** 当前端口关联的 EID（128 bit）。正向路径取 outPort 的 eid，反向路径取 inPort 的 eid */
    private String eid;

    /** 该端口连接的对端设备ID -- 用于拓扑连接校验 */
    private String remoteDevice;

    /** 该端口连接的对端端口名称 -- 用于拓扑连接校验 */
    private String remotePort;

    /** 所属 Rack */
    private String rack;

    /** 跳序号（从 0 开始，源节点为 0） */
    private int hopIndex;
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| deviceName | String | 当前设备ID -- 必填字段 |
| deviceType | DeviceType | 设备类型（NPU / SW） |
| inPort | String | 入端口名称 -- 源节点为 null |
| outPort | String | 出端口名称 -- 目的节点为 null |
| cna | String | 当前端口关联的 CNA（32 bit），来自 PortEntity.cna。NPU 端口为 NpuPortEntity.cna（必填），交换端口为 SwPortEntity.cna（可选，可为 null）。正向路径取出端口 cna，反向路径取入端口 cna（正向的出端口即反向的入端口） |
| eid | String | 当前端口关联的 EID（128 bit），仅NPU端口有（来自 NpuPortEntity.eid），交换端口为 null。正向路径取出端口 eid，反向路径取入端口 eid |
| remoteDevice | String | 该端口连接的对端设备ID，用于拓扑连接校验 |
| remotePort | String | 该端口连接的对端端口名称，用于拓扑连接校验 |
| rack | String | 所属 Rack |
| hopIndex | int | 跳序号（从 0 开始，源节点为 0） |

**字段约束：**
- 源节点（hopIndex=0）：`inPort=null`，`outPort` 为源设备出端口，`cna`/`eid` 取自源端口。
- 目的节点（hopIndex 最大）：`outPort=null`，`inPort` 取自上一跳的 `remotePort`。
- 中间节点：`inPort` 为上一跳 `remotePort`（对端端口），`outPort` 取自 `interDevices` 指定的出端口。

**与外部 HopInfo 的对应关系：**

| 内部 InternalPathHop | 外部 HopInfo | 说明 |
|:---------------------|:-------------|:-----|
| deviceName | deviceName | 直接映射 |
| deviceType | deviceType | 直接映射 |
| inPort | inPort | 直接映射 |
| outPort | outPort | 直接映射 |
| cna | - | 仅内部使用，不对外暴露 |
| eid | - | 仅内部使用，不对外暴露 |
| remoteDevice | - | 内部拓扑校验用 |
| remotePort | - | 内部拓扑校验用 |
| rack | - | 仅内部使用 |
| hopIndex | - | hopIndex=0 即源节点，hopIndex 最大即目的节点 |

#### 5.1.2 InternalPathInfo（内部路径信息）

封装完整的内部路径，在 Step 5 构建并在后续 Step 6~8 中消费。

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class InternalPathInfo {
    /** 路径逐跳列表 */
    private List<InternalPathHop> hops;

    /** 源 EID */
    private String sourceEid;

    /** 目的 EID */
    private String destEid;

    /** 源 CNA */
    private String sourceCna;

    /** 目的 CNA */
    private String destCna;

    /** 总跳数（应等于 hops.size()） */
    private int hopCount;
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| hops | List\<InternalPathHop\> | 路径逐跳列表，每跳包含拓扑还原所需的完整信息 |
| sourceEid | String | 源 EID，来自 Step 1 |
| destEid | String | 目的 EID，来自 Step 2 |
| sourceCna | String | 源 CNA，来自 Step 1 |
| destCna | String | 目的 CNA，来自 Step 2 |
| hopCount | int | 总跳数 |

**数据流说明：**
```
Step 5 (多跳路径还原):
    Input:  PathPlanRequest (srcDevice, srcPort, destDevice, destPort, interDevices)
    Output: InternalPathInfo (按拓扑一致性校验逐跳填充)
    
Step 6~8 (路径规划循环):
    Input:  InternalPathInfo (从 Stage 2 构建)
    Process: 遍历 InternalPathInfo.hops，对每个中间设备执行路径规划
    Output: RouteSelectionRecord 列表 (从 Step 9 产生)
    
Step 10 (填充 PathPlanResult):
    Input:  InternalPathInfo.hops
    Output: PathPlanResult.paths (转换为外部 HopInfo 列表)
```

---

### 5.2 RouteSelectionRecord（内部选路记录）

> **设计依据：** 参照 §9.4 阶段3 Step 9 — 出端口判断与选路记录。

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RouteSelectionRecord {
    /** 执行选路的设备ID */
    private String deviceName;

    /** 匹配的路由前缀（32 bit，已补齐） */
    private String prefix;

    /** 所有候选出接口列表（需同时记录选中与未选中的出接口） */
    private List<CandidateOutPort> candidateOutPorts;

    /** 源 CNA（二元组之 SCNA） */
    private String scna;

    /** 目的 CNA（二元组之 DCNA） */
    private String dcna;

    /** Hash 信息 — 用于 ECMP 负载均衡计算。
     *  <p>hash 算法输入为三元组：源 CNA（SCNA，32 bit）、目的 CNA（DCNA，32 bit）、
     *  源 UDP 端口号（8 bit，由 Step 9 计算填入）。
     *  输出为整数 hash 值，对候选出端口数取模后得到选中的出端口索引。
     *  <p>hash 函数可打桩（stub），测试时注入特定实现保证特定三元组输出指定 hash 值。 */
    private String hashInfo;

    /** 方向标识 */
    private Direction direction;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @EqualsAndHashCode
    @ToString
    public static class CandidateOutPort {
        /** 出接口名称，取自 OutPortInfo.portName */
        private String portName;

        /** 下一跳IP */
        private String nextHop;

        /** 是否为选中的出接口（ECMP 选路结果）。使用 boolean 原始类型，默认 false，避免 null 语义歧义 */
        private boolean selected;
    }

    /** 方向枚举 */
    public enum Direction {
        FORWARD,  // 正向：源地址 = CNA1
        REVERSE   // 反向：源地址 = CNA2
    }
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| deviceName | String | 执行选路的设备ID |
| prefix | String | 匹配的路由前缀（32 bit） |
| candidateOutPorts | List\<CandidateOutPort\> | 所有候选出接口列表，同时记录选中与未选中的出接口 |
| scna | String | 源 CNA（32 bit），二元组之 SCNA |
| dcna | String | 目的 CNA（32 bit），二元组之 DCNA |
| hashInfo | String | Hash 信息 — 用于 ECMP 负载均衡（三元组 hash key：SCNA + DCNA + srcUdpPort） |
| direction | Direction | 方向：FORWARD（源=CNA1）或 REVERSE（源=CNA2） |

**CandidateOutPort 子结构：**

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| portName | String | 出接口名称，取自 OutPortInfo.portName |
| nextHop | String | 下一跳IP，取自 OutPortInfo.nextHop |
| selected | boolean | 是否为选中的出接口：`true`=ECMP 选路命中，`false`=未选中。原始类型，默认 `false`，无需判空 |

**选路记录字段来源说明：**

| 字段 | 来源 | 对应 Step 9 伪代码中的项 |
|:-----|:-----|:--------------------------|
| prefix | 路径规划结果 RoutingEntry.prefix | `路由信息（prefix）` |
| candidateOutPorts[].portName | OutPortInfo.portName | `路由信息（portName）` |
| candidateOutPorts[].nextHop | OutPortInfo.nextHop | 下一跳信息 |
| candidateOutPorts[].selected | ECMP hash 选路结果 | 是否被选中 |
| scna / dcna | Step 1 / Step 2 提取的 CNA1 / CNA2 | `二元组信息（SCNA, DCNA）` |
| hashInfo | ECMP hash 算法输入（三元组：SCNA、DCNA、srcUdpPort） | `hash 信息` |
| direction | 正向查 CNA1→CNA2，反向查 CNA2→CNA1 | `方向 flag` |

**记录规则：**
- 出端口数量 == 1：不记录 `RouteSelectionRecord`，直接进入下一跳。
- 出端口数量 > 1：记录一条 `RouteSelectionRecord`，其中 `candidateOutPorts` 包含所有候选出接口（ECMP 所有路径），与 `interDevices` 指定出端口一致的标记为 `selected=true`（目标端口），其余为 `false`。进入下一跳。SNC 通过 `HopInfo.multiPath=true` 与 `PathPlanResult.spray=true` 通知调用方该路径包含 ECMP 多路径，由调用方自行决定逐流策略；不再返回 MULTI_PATH_NOT_SUPPORTED 错误码。

**消费关系：**
```
§9.4.4 Step 9 (记录):
    对每个存在 ECMP 的中间设备 → 生成 RouteSelectionRecord
    → candidateOutPorts 记录所有候选出接口 + 选中标记
    
§9.5 Step 9 (UDP 端口计算):
    遍历 RouteSelectionRecord 列表
    → 基于 hashInfo + scna/dcna 计算 8-bit src_udp_port / dst_udp_port
    → 填入 PathPlanResult.ackUdpSrcPort / dataUdpSrcPort
```

---

## 6 北向数据结构（DTO）

> 本章定义 SNC 对外暴露的北向 API 数据结构。内部数据结构的详细定义参见 [§4. 数据结构定义](#4-数据结构定义)。

---

### 6.1 PathPlanRequest（路径规划请求）

北向路径规划请求，由调用方提交，指定源/目的设备及端口和中间路径约束。

```java
public class PathPlanRequest {
    /** 超节点名称（superNodeName），对应 SuperNode.name（§4.1），用于在多超节点场景下定位目标超节点 -- 必填字段 */
    private String superNodeName;

    /** 源端口名称 -- 必填字段 */
    private String srcPort;

    /** 目的端口名称 -- 必填字段 */
    private String destPort;

    /** 源设备ID -- 必填字段 */
    private String srcDevice;

    /** 目的设备ID -- 必填字段 */
    private String destDevice;

    /** 中间设备及出端口Map，key=deviceName，value=portName。存在中间设备场景时为必填，不填则默认直连 */
    private Map<String, String> interDevices;
}
```

**字段说明：**

| 字段 | 类型 | 必填 | 说明 |
|:-----|:-----|:-----|:-----|
| srcPort | String | 是 | 源物理端口名称，如 `"400GE 0/0/1"` |
| destPort | String | 是 | 目的物理端口名称，如 `"400GE 0/1/1"` |
| srcDevice | String | 是 | 源设备 deviceName，如 `"rack1#os0#npu1"` |
| destDevice | String | 是 | 目的设备 deviceName，如 `"rack1#os0#npu2"` |
| interDevices | Map\<String,String\> | 否 | 中间设备及对应的出端口，key=deviceName，value=portName。为空时引擎自动寻路。**注意：** "自动寻路"算法当前版本 V1 暂未实现，`interDevices` 为空时仅处理直连场景 Step 6，不支持自动发现多跳路径。多跳场景必须通过 `interDevices` 显式指定中间设备及出端口。 |

**字段与 SuperNode 的对应关系：**

| PathPlanRequest 字段 | 对应 SuperNode 中的字段 | 说明 |
|:---------------------|:-----------------------|:-----|
| srcDevice / destDevice | `SuperNode.devices` 的 key（deviceName） | 直接对应，见 §4.1 |
| srcPort / destPort | 各子类转发芯片的 `ports` key（portName），通过 `getPorts()` 抽象方法访问 | 见 §4.4、§4.5 |
| interDevices key | `SuperNode.devices` 的 key（deviceName） | 见 §4.3 |
| interDevices value | `PortEntity.portName` | 中间设备上的出端口名称，见 §4.5 |

---

### 6.2 PathPlanResult（路径规划响应）

北向路径规划响应，返回路径规划结果。

```java
public class PathPlanResult {
    /** 源EID -- 128 bit */
    private String sourceEid;

    /** 目的EID -- 128 bit */
    private String destEid;

    /** 路径详情 */
    private PathInfo path;

    /** 查询状态 */
    private PlanStatus status;

    /** 失败原因（如果查询失败） */
    private String errorMessage;

    /** Ack UDP 源端口 -- 8 bit，用于硬件卸载 */
    private Integer ackUdpSrcPort;

    /** Data UDP 源端口 -- 8 bit，用于硬件卸载 */
    private Integer dataUdpSrcPort;

    /** Spray 使能 -- 是否启用多路径喷洒 */
    private Boolean spray;

    /** ========== 查询状态枚举 ========== */
    public enum PlanStatus {
        SUCCESS(0, "success"),
        SRC_INFO_ERR(1003, "src info error"),
        DST_INFO_ERR(1004, "dst info error"),
        TOPO_INCOMPLETE(1007, "topo incomplete"),
        TOPO_CONNECTION_ERROR(1008, "topo connection error"),
        TOPO_CONNECTION_NOT_FOUND(1009, "topo connection not found"),
        ROUTE_NOT_REACHABLE(1010, "route not reachable"),
        TOPO_NOT_FOUND(1012, "topo not found"),
        SRC_AND_DST_MUST_BE_NPU(3002, "src and dst must be npu"),
        UPI_MISMATCH(3003, "upi mismatch");

        private final int code;
        private final String message;

        PlanStatus(int code, String message) {
            this.code = code;
            this.message = message;
        }

        public int getCode() { return code; }
        public String getMessage() { return message; }
    }
}
```

**字段说明：**

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| sourceEid | String | 源 EID（128 bit），来自源 NPU 端口，参见 §4.5.1 NpuPortEntity.eid |
| destEid | String | 目的 EID（128 bit），来自目的 NPU 端口，参见 §4.5.1 NpuPortEntity.eid |
| path | PathInfo | 路径详情，包含逐跳信息 |
| status | PlanStatus | 查询状态，0=成功，非0=失败（错误码见上表） |
| errorMessage | String | 失败原因描述，status 非 SUCCESS 时填写 |
| ackUdpSrcPort | Integer | Ack UDP 源端口（8 bit），由 Step 9 计算，用于硬件卸载 |
| dataUdpSrcPort | Integer | Data UDP 源端口（8 bit），由 Step 9 计算，用于硬件卸载 |
| spray | Boolean | Spray 使能标识，true=启用多路径喷洒 |

---

#### 6.2.1 PathInfo（路径信息）

```java
public class PathInfo {
    /** 逐跳列表 -- 从源到目的依次排列 */
    private List<HopInfo> hops;
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| hops | List\<HopInfo\> | 逐跳列表，hops[0] 为源节点，hops[last] 为目的节点 |

---

#### 6.2.2 HopInfo（跳信息）

```java
public class HopInfo {
    /** 设备ID -- 必填字段 */
    private String deviceName;

    /** 入端口 -- 目的节点和中间节点一定有，源节点为 null */
    private String inPort;

    /** 出端口 -- 源节点和中间节点一定有，目的节点为 null */
    private String outPort;

    /** 多路径使能 -- 该跳是否支持 ECMP 逐流 */
    private Boolean multiPath;

    /** 设备类型 -- "NPU" 或 "SW"（使用字符串常量，避免 dto 层直接依赖 entity.DeviceType 枚举）。
     *  <p>可能值：{@code "NPU"}（计算节点）、{@code "SW"}（交换设备）。
     *  <p>由 service 层通过 {@code DeviceType.name()} 转换填充。 */
    private String deviceType;
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| deviceName | String | 设备唯一标识，对应 `DeviceEntity.deviceName`（§4.3） |
| inPort | String | 入端口名称，源节点为 null |
| outPort | String | 出端口名称，目的节点为 null |
| multiPath | Boolean | 该跳是否支持多路径（ECMP 逐流） |
| deviceType | String | 设备类型（`"NPU"` / `"SW"`），使用字符串常量，由 service 层从 `DeviceType.name()` 转换（§4.3.1）。**设计原因：** dto 层不可依赖 entity 包（§3.3 分层约束），故使用 String 类型避免跨层引用枚举 |

> **架构约束：** §3.3 明确 dto 层不可依赖 entity 包。`DeviceType` 是 entity 包中的枚举，HopInfo（dto 包）使用 `String deviceType` 而非 `DeviceType`，service 层负责 `DeviceType.name()` 到 `String` 转换。

**字段约束：**
- 源节点（hops[0]）：`inPort=null`，`outPort` 为源设备出端口。
- 目的节点（hops[last]）：`outPort=null`，`inPort` 为最后一跳入端口。
- 中间节点：`inPort` 和 `outPort` 均非空。

**与 SuperNode 内部数据结构的对应关系：**

| HopInfo 字段 | 对应内部字段 | 来源 |
|:-------------|:-------------|:-----|
| deviceName | DeviceEntity.deviceName | §4.3 |
| inPort / outPort | PortEntity.portName | §4.5 |
| deviceType | DeviceType 枚举 | §4.3.1 |
| multiPath | 由路径规划结果推导（ECMP 场景） | §4.9 RoutingEntry.outPortInfos.size() > 1 |

---

### 6.3 覆盖规划 DTO

#### 6.3.1 CoveragePathsRequest（覆盖规划请求）

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoveragePathsRequest {
    /** 超节点名称 -- 必填，对应 SuperNode.name（§4.1） */
    private String superNodeName;

    /** 覆盖要求；null 时按 MIN_COVERAGE（§6.3.6 CoverageRequirement） */
    private CoverageRequirement coverageRequirement;
}
```

> planPathsCoverage 与 planPathsCoverageEx 共用本 DTO，覆盖域差异由方法名决定，不由 request 字段控制。

#### 6.3.2 CoveragePathsResult（覆盖规划响应）

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoveragePathsResult {
    /** 覆盖域：L1_L2（planPathsCoverage）/ NPU_L1_L2（planPathsCoverageEx） */
    private CoverageLinkScope scope;

    /** 状态：SUCCESS / COVERAGE_INCOMPLETE / TOPO_NOT_FOUND */
    private PathPlanResult.PlanStatus status;

    /** 错误消息；status=SUCCESS 时为 null */
    private String errorMessage;

    /** 选出的 EID 对列表 */
    private List<CoveredEidPair> eidPairs;

    /** 所有覆盖链路（去重后），按 layer 分组排列 */
    private List<CoverageLink> coverageLinks;

    /** 合计统计（覆盖域全集） */
    private CoverageStats totalStats;

    /** 分层统计；planPathsCoverage 返回 null，planPathsCoverageEx 返回 NPU_L1 + L1_L2 两层 */
    private List<CoverageLayerStats> layerStats;
}
```

**字段约束：**
- `scope`：SUCCESS 时必填，TOPO_NOT_FOUND 时可为 null。
- `eidPairs`：SUCCESS / COVERAGE_INCOMPLETE 时必填（可能为部分覆盖结果）；TOPO_NOT_FOUND 时为空列表。
- `coverageLinks[*].layer`：planPathsCoverage 为 null；planPathsCoverageEx ∈ {NPU_L1, L1_L2}。
- `coverageLinks[*].deviceType`：planPathsCoverage 为 null；planPathsCoverageEx ∈ {"NPU", "SW"}。
- `eidPairs[*].type`：planPathsCoverage 为 null；planPathsCoverageEx ∈ {CROSS_L2, LOCAL_L1}。

#### 6.3.3 CoverageLinkScope（覆盖域枚举）

```java
public enum CoverageLinkScope {
    /** planPathsCoverage：仅覆盖 L1SW↔L2SW 出端口 */
    L1_L2,
    /** planPathsCoverageEx：覆盖 NPU↔L1SW↔L2SW 出端口（含 jettyId hash 选路） */
    NPU_L1_L2
}
```

#### 6.3.4 CoverageLinkLayer（链路分层枚举）

```java
public enum CoverageLinkLayer {
    /** NPU↔L1SW 链路层（仅 planPathsCoverageEx 使用） */
    NPU_L1,
    /** L1SW↔L2SW 链路层 */
    L1_L2
}
```

#### 6.3.5 CoveragePathType（路径类型枚举）

```java
public enum CoveragePathType {
    /** 跨机框：源/目的 NPU 在不同机框，4 跳路径 NPU→L1SW→L2SW→L1SW→NPU */
    CROSS_L2,
    /** 同机框：源/目的 NPU 在同一机框，2 跳路径 NPU→L1SW→NPU */
    LOCAL_L1
}
```

#### 6.3.6 CoverageRequirement（覆盖要求枚举）

```java
public enum CoverageRequirement {
    /** 最低覆盖：每个出端口至少被 1 个 EID 对覆盖（coverCount >= 1） */
    MIN_COVERAGE,
    /** 冗余覆盖：每个出端口至少被 2 个 EID 对覆盖（coverCount >= 2） */
    REDUNDANT
}
```

#### 6.3.7 CoverageStats（覆盖合计统计）

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoverageStats {
    /** 当前覆盖域出端口总数 */
    private int totalLinks;
    /** 已被覆盖的出端口数 */
    private int coveredLinks;
    /** 覆盖率 = coveredLinks / totalLinks */
    private double coverageRate;
    /** 被覆盖 ≥ 2 次的出端口数 */
    private int redundantLinks;
    /** 重复率 = redundantLinks / totalLinks */
    private double redundantRate;
    /** EID 对总数 */
    private int eidPairCount;
    /** EID 均匀度：每个出端口被覆盖次数的标准差，越低越均匀 */
    private double eidUniformity;
}
```

#### 6.3.8 CoverageLayerStats（分层统计）

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoverageLayerStats {
    /** 所属分层 */
    private CoverageLinkLayer layer;
    /** 该层的统计（结构与 CoverageStats 相同） */
    private CoverageStats stats;
}
```

> planPathsCoverage 返回 `layerStats = null`；planPathsCoverageEx 返回 `[NPU_L1 层统计, L1_L2 层统计]`。

#### 6.3.9 CoverageLink（覆盖链路）

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoverageLink {
    /** 链路所属设备名 */
    private String deviceName;
    /** 链路所属芯片编号 */
    private int chipIndex;
    /** 出端口名称 */
    private String outPortName;
    /** 出端口 ID */
    private int outPortId;
    /** 对端设备名（PortEntity.remoteDevice） */
    private String remoteDevice;
    /** 对端端口名（PortEntity.remotePort） */
    private String remotePort;
    /** 被覆盖次数（被几个 EID 对命中） */
    private int coverCount;
    /** 链路分层；planPathsCoverage 为 null，planPathsCoverageEx ∈ {NPU_L1, L1_L2} */
    private CoverageLinkLayer layer;
    /** 设备类型；planPathsCoverage 为 null，planPathsCoverageEx ∈ {"NPU", "SW"} */
    private String deviceType;
}
```

#### 6.3.10 CoveredEidPair（覆盖的 EID 对）

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoveredEidPair {
    /** 源 EID（128 bit 字符串） */
    private String srcEid;
    /** 目的 EID（128 bit 字符串） */
    private String dstEid;
    /** 该 EID 对覆盖的链路列表（按 layer 分组排列，正反向合并） */
    private List<CoverageLink> coveredLinks;
    /** 路径类型；planPathsCoverage 为 null，planPathsCoverageEx ∈ {CROSS_L2, LOCAL_L1} */
    private CoveragePathType type;
}
```

> `coveredLinks` 内链路顺序：正向路径按源→目的顺序，反向路径按目的→源顺序追加；同 EID 对的 4 条（planPathsCoverage）或 4/8 条（planPathsCoverageEx）覆盖链路在 list 中连续存放。

#### 6.3.11 CoveredEidPairRef（EID 对引用）

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoveredEidPairRef {
    /** 源 EID */
    private String srcEid;
    /** 目的 EID */
    private String dstEid;
}
```

> 用作 CoveragePlanEngine 内部候选 EID 对枚举的轻量引用，避免在搜索阶段提前构造完整 CoveredEidPair。

#### 6.3.12 LinkEvent（链路事件）

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class LinkEvent {
    /** 链路所属设备名 -- 必填 */
    private String deviceName;
    /** 端口名 -- 必填 */
    private String portName;
    /** 事件类型："up" / "down" -- 必填，大小写敏感 */
    private String eventType;
    /** 事件时间戳（毫秒，epoch） -- 必填 */
    private long eventTime;
}
```

---

### 6.4 北向数据结构与内部数据结构的关系

```
┌──────────────────────────────────────────────────┐
│ 北向 API（§6）                                   │
│   PathPlanRequest    PathPlanResult              │
│       │                     ▲                    │
│       │   ┌─────────────────┘                    │
│       │   │                                      │
│ ┌──────────────────────────────────────────┐     │
│ │ SNC 引擎（路径规划 + 路径规划）           │     │
│ │  内部数据结构: InternalPathInfo（§5.1）   │     │
│ └──────────────────────────────────────────┘     │
│       │                     ▲                    │
│       │                     │                    │
│ ┌──────────────────────────────────────────┐     │
│ │ 拓扑数据层（§4）                          │     │
│ │  SuperNode / DeviceEntity / ForwardingChip │     │
│ │           / PortEntity / RoutingTable     │     │
│ │  （抽象类通过 getForwardingChips/getPorts │     │
│ │   提供多态迭代，子类持有精确类型字段）     │     │
│ └──────────────────────────────────────────┘     │
└──────────────────────────────────────────────────┘
```

**数据流说明：**
1. 调用方构造 `PathPlanRequest`（§6.1），指定 src/dest 设备及端口。
2. 引擎从 `SuperNode`（§4.1）中查找对应 `DeviceEntity`（§4.3），提取端口 CNA/EID。
3. 引擎构建内部 `InternalPathInfo`（§5.1），执行逐跳拓扑校验和路径规划。
4. 引擎将内部结果转换为 `PathPlanResult`（§6.2），返回给调用方。

---

## 7 北向接口

### 7.1 接口概述

SNC 模块对外暴露统一的北向接口 `SNCService`，位于包 `com.huawei.umdk.snc`。调用方（上层编排器/管理系统）通过该接口完成**初始化、数据下发、路径规划、覆盖规划、链路事件与路由管理、去初始化**六个阶段的操作。

```
北向接口 (SNCService)
    │
    ├── init(SNCConfig) → void                   // 初始化
    │
    ├── setSuperNode(SuperNode) → void             // 拓扑全量下发
    ├── addNpuDevices(String, List<NpuDevice>) → void    // 拓扑增量：批量添加 NPU 设备
    ├── addSwDevices(String, List<SwDevice>) → void         // 拓扑增量：批量添加 SW 设备
    ├── removeDevices(String, List<String>) → void              // 拓扑增量：批量移除设备
    ├── addRoutingEntries(String, String, Integer, List<RoutingEntry>) → void  // 拓扑增量：批量添加/更新路由条目
    ├── removeRoutingEntries(String, String, Integer, List<RoutePrefix>) → void  // 拓扑增量：批量删除路由条目
    ├── getSuperNode(String) → SuperNode           // 拓扑数据查询
    ├── removeSuperNode(String) → void             // 拓扑数据删除
    │
    ├── planPath(PathPlanRequest) → PathPlanResult     // 路径规划（单路径）
    ├── planPathsCoverage(CoveragePathsRequest) → CoveragePathsResult       // 覆盖规划（L1↔L2）
    ├── planPathsCoverageEx(CoveragePathsRequest) → CoveragePathsResult     // 覆盖规划扩展（NPU↔L1↔L2）
    │
    ├── notifyLinkEvent(SuperNode, LinkEvent) → void                     // 链路 up/down 通知 + BFS 路由收敛
    ├── routeCalculate() → void                                          // 路由模板计算（幂等，先于 makeRoutes）
    ├── makeRoutes(SuperNode) → Map<String, Map<String, RoutingEntry>>   // 路由实例化
    ├── getNodeRoute(String, int) → Map<String, RoutingEntry>            // 查询单设备单芯片路由表
    │
    └── uninit() → void                                // 去初始化
```

> **数据结构引用：** 接口涉及的 `PathPlanRequest`、`PathPlanResult`、`PathInfo`、`HopInfo`、`PlanStatus`、`CoveragePathsRequest`、`CoveragePathsResult`、`CoverageLink`、`CoverageLinkScope`、`CoverageLinkLayer`、`CoveragePathType`、`CoverageRequirement`、`CoverageStats`、`CoverageLayerStats`、`CoveredEidPair`、`CoveredEidPairRef`、`LinkEvent` 等北向数据结构完整定义见 [§6 北向数据结构](#6-北向数据结构dto)。

---

### 7.2 SNCService 接口定义

```java
package com.huawei.umdk.snc;

import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.entity.*;
import com.huawei.umdk.snc.dto.*;
import com.huawei.umdk.snc.config.SNCConfig;

/**
 * SNC 主服务接口 —— 北向调用入口
 *
 * <h3>调用顺序约束</h3>
 * <pre>{@code
 *   sncService.init(config);                    // 1. 初始化
 *   sncService.setSuperNode(superNode);           // 2. 下发拓扑数据（可多次调用更新）
 *   sncService.addNpuDevices("A5-superPod-1", List.of(npuDevice));  // 3. 增量：批量添加 NPU 设备
 *   sncService.addSwDevices("A5-superPod-1", List.of(swDevice));    // 4. 增量：批量添加 SW 设备
 *   sncService.removeDevices("A5-superPod-1", List.of("rack1#os0#npu1")); // 5. 增量：批量移除设备
 *   sncService.addRoutingEntries("A5-superPod-1", "rack1#os0#npu1", 0, List.of(entry)); // 6. 增量：批量添加路由
 *   sncService.planPath(request);               // 7. 路径规划（可多次并发调用）
 *   sncService.planPathsCoverage(req);          // 7a. 覆盖规划（L1↔L2）
 *   sncService.planPathsCoverageEx(req);        // 7b. 覆盖规划（NPU↔L1↔L2，含 jettyId）
 *   sncService.routeCalculate();                // 7c. 路由模板计算（幂等，必须先于 makeRoutes）
 *   sncService.makeRoutes(superNode);           // 7d. 实例化路由表（填充 instantiationRouteMap）
 *   sncService.getNodeRoute("rack1#os0#npu1", 0); // 7e. 查询单设备单芯片路由表
 *   sncService.notifyLinkEvent(superNode, event); // 7f. 通知链路 up/down（触发 BFS 路由收敛）
 *   SuperNode td = sncService.getSuperNode("A5-superPod-1");   // 8. 拓扑数据查询
 *   sncService.removeSuperNode("A5-superPod-1");              // 9. 拓扑数据删除
 *   sncService.uninit();                       // 10. 去初始化
 * }</pre>
 *
 * <h3>状态约束</h3>
 * - 未 init() 调用其他接口：抛出 SNCStateException
 * - uninit() 后再次调用其他接口：抛出 SNCStateException
 * - 重复 init()：幂等处理或抛出 SNCStateException
 * - planPath / planPathsCoverage / planPathsCoverageEx：要求状态为 DATAREADY
 * - notifyLinkEvent / routeCalculate / makeRoutes / getNodeRoute：要求状态非 INIT/UNINIT（READY / DATAREADY 均可）
 *
 * @see PathPlanRequest
 * @see PathPlanResult
 * @see CoveragePathsRequest
 * @see CoveragePathsResult
 * @see LinkEvent
 * @see SuperNode
 */
public interface SNCService {

    // ============ 生命周期管理 ============

    /**
     * 初始化 SNC 服务
     *
     * 加载配置，初始化内部 HashMap（拓扑索引）。
     *
     * @param config SNC 配置（日志策略、索引策略等），可为 null（使用默认配置）
     * @throws SNCStateException 状态异常（重复初始化等）
     */
    void init(SNCConfig config);

    /**
     * 去初始化 SNC 服务
     *
     * 清空所有内存数据（拓扑 Map），释放资源。
     *
     * @throws SNCStateException 状态异常（未初始化等）
     */
    void uninit();

    // ============ 数据下发 ============

    /**
     * 下发拓扑数据（全量替换）
     *
     * 将 SuperNode 解析并索引到内存 HashMap 中。
     * - 使用全量替换（replace）策略：新数据覆盖旧数据。
     * - 可多次调用，每次调用全量替换同一 name 拓扑的全部数据。
     *
     * @param superNode 拓扑数据，来自 superNode_data_*.json 反序列化（§4.1）
     * @throws IllegalArgumentException superNode 为 null 或必填字段缺失
     * @throws SNCStateException SNC 未初始化
     */
    void setSuperNode(SuperNode superNode);

    // ============ 增量更新 - 拓扑 ============

    /**
     * 增量批量添加 NPU 设备
     *
     * 向指定超节点的 npuDevices 中批量添加 NPU 设备（覆盖已有），同时索引路由表。
     * SuperNode 必须已通过 setSuperNode 导入，否则抛 IllegalStateException。
     *
     * @param superNodeName 超节点名称（对应 SuperNode.name，§4.1）
     * @param devices NPU 设备列表（§4.3.2），每个元素非 null
     * @throws IllegalArgumentException superNodeName 或 devices 为 null/空
     * @throws IllegalStateException SuperNode 不存在
     * @throws SNCStateException SNC 未初始化
     */
    void addNpuDevices(String superNodeName, List<NpuDevice> devices);

    /**
     * 增量批量添加 SW 设备
     *
     * 向指定超节点的 swDevices 中批量添加 SW 设备（覆盖已有），同时索引路由表。
     * SuperNode 必须已通过 setSuperNode 导入，否则抛 IllegalStateException。
     *
     * @param superNodeName 超节点名称（对应 SuperNode.name，§4.1）
     * @param devices SW 设备列表（§4.3.3），每个元素非 null
     * @throws IllegalArgumentException superNodeName 或 devices 为 null/空
     * @throws IllegalStateException SuperNode 不存在
     * @throws SNCStateException SNC 未初始化
     */
    void addSwDevices(String superNodeName, List<SwDevice> devices);

    /**
     * 增量批量移除设备
     *
     * 从指定超节点的拓扑数据中批量移除设备，同时清空其在 routingTableMap 中的路由表索引。
     *
     * @param superNodeName 超节点名称（对应 SuperNode.name，§4.1）
     * @param deviceNames 设备唯一标识列表，每个元素非 null/空
     * @throws IllegalArgumentException superNodeName 或 deviceNames 为 null/空
     * @throws SNCStateException SNC 未初始化
     */
    void removeDevices(String superNodeName, List<String> deviceNames);

    /**
     * 增量批量添加/更新路由条目
     *
     * 在指定设备的指定芯片路由表中批量添加或更新路由条目。
     * 每条路由的 prefix 从 RoutingEntry.prefix 字段中提取。
     *
     * @param superNodeName 超节点名称
     * @param deviceName 设备唯一标识
     * @param chipIndex 芯片编号
     * @param entries 路由条目列表（§4.9），每个 entry 及其 prefix 非 null
     * @throws IllegalArgumentException 任一参数为 null，或路由表不存在
     * @throws SNCStateException SNC 未初始化
     */
    void addRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                           List<RoutingEntry> entries);

    /**
     * 增量批量删除路由条目
     *
     * 从指定设备的指定芯片路由表中批量删除路由条目。
     *
     * @param superNodeName 超节点名称
     * @param deviceName 设备唯一标识
     * @param chipIndex 芯片编号
     * @param prefixes 路由前缀列表（§4.8），每个元素非 null
     * @throws IllegalArgumentException 任一参数为 null，或路由表不存在
     * @throws SNCStateException SNC 未初始化
     */
    void removeRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                              List<RoutePrefix> prefixes);

    // ============ 数据查询 ============

    /**
     * 查询拓扑数据
     *
     * 根据 superNodeName 从 SuperNodeStore 中获取对应的 SuperNode 对象。
     *
     * @param superNodeName 超节点名称（对应 SuperNode.name，§4.1）
     * @return SuperNode 对象，若指定 superNodeName 的拓扑数据不存在则返回 null
     * @throws IllegalArgumentException superNodeName 为 null 或空字符串
     * @throws SNCStateException SNC 未初始化
     */
    SuperNode getSuperNode(String superNodeName);

    /**
     * 删除拓扑数据
     *
     * 根据 superNodeName 从 SuperNodeStore 中移除对应的拓扑数据（包括拓扑一级索引及其关联的路由表数据）。
     *
     * @param superNodeName 超节点名称（对应 SuperNode.name，§4.1）
     * @throws IllegalArgumentException superNodeName 为 null 或空字符串
     * @throws SNCStateException SNC 未初始化
     */
    void removeSuperNode(String superNodeName);

    // ============ 路径规划 ============

    /**
     * 路径规划（同步请求-响应模式）
     *
     * 基于源/目的设备及端口信息，执行路径规划与路径规划，返回完整的通信路径参数。
     * 内部执行 Step 0 ~ Step 10 流程。
     *
     * <table>
     *   <tr><th>阶段</th><th>步骤</th><th>说明</th></tr>
     *   <tr><td>阶段1</td><td>Step 0~2</td><td>设备判断与源/目的信息查找 §9.2</td></tr>
     *   <tr><td>阶段2</td><td>Step 3~5</td><td>路径还原（直连/多跳）§9.3</td></tr>
     *   <tr><td>阶段3</td><td>Step 6~8</td><td>路径规划循环（正向/反向）§9.4</td></tr>
     *   <tr><td>阶段4</td><td>Step 9~10</td><td>构造输出（UDP端口计算+PathPlanResult 填充）§9.5</td></tr>
     * </table>
     *
     * <h3>前置条件</h3>
     * - init() 已完成
     * - setSuperNode() 已调用（拓扑数据存在）
     *
     * <h3>并发保证</h3>
     * 本方法为只读操作（不修改内存数据），支持多线程并发调用。
     *
     * @param request 路径规划请求（§6.1）
     * @return PathPlanResult 路径规划结果，status=SUCCESS 时 path 有效（§6.2）
     * @throws IllegalArgumentException request 或必填字段为 null
     * @throws SNCStateException SNC 未初始化
     */
    PathPlanResult planPath(PathPlanRequest request);

    // ============ 覆盖规划 ============

    /**
     * 覆盖规划（框间 L1SW↔L2SW）
     *
     * 给定超节点拓扑（含路由表），挑选一组 EID 对（src/dst NPU 端口），使其正反向 hash 选路
     * 结果遍历 L1SW↔L2SW 出端口集合，输出 EID 对 → 覆盖链路映射与覆盖率/重复率/EID 均匀度统计。
     *
     * <h3>覆盖域</h3>
     * <ul>
     *   <li>L1SW→L2SW：L1SW 路由出端口中 remoteDevice ∈ L2SW 集合的全部出端口（含单端口路由）；</li>
     *   <li>L2SW→L1SW：L2SW 路由出端口中 remoteDevice 为 L1SW 的 ECMP 出端口（非默认路由且出端口数 &gt; 1）。</li>
     * </ul>
     *
     * <p>NPU↔L1SW 出端口不在此覆盖域内，NPU 出端口由候选物理绑定固定，末跳出端口取 get(0)。
     *
     * <h3>结果特征</h3>
     * <ul>
     *   <li>{@code scope = L1_L2}；</li>
     *   <li>每个 EID 对固定 4 条覆盖链路（2 正向 + 2 反向）；</li>
     *   <li>{@code eidPairs[*].type = null}；{@code layerStats = null}；{@code coverageLinks[*].layer = null}。</li>
     * </ul>
     *
     * @param request 覆盖规划请求（§6.x），{@code superNodeName} 必填；{@code coverageRequirement} 为 null 时按 MIN_COVERAGE
     * @return 覆盖规划结果；状态为 SUCCESS / COVERAGE_INCOMPLETE / TOPO_NOT_FOUND
     * @throws SNCStateException 当前状态不是 DATAREADY
     * @throws IllegalArgumentException request 为 null
     */
    CoveragePathsResult planPathsCoverage(CoveragePathsRequest request);

    /**
     * 覆盖规划（扩展版：含 NPU↔L1SW）
     *
     * 在 {@link #planPathsCoverage} 覆盖域基础上增加 NPU↔L1SW 出端口覆盖：
     * <ul>
     *   <li>NPU→L1SW 出端口由 {@code (DstCNA, jettyId)} 二元组 CRC-8 hash 选路（NPU 路由 LPM 命中条目的 L1SW 向出端口为 ECMP 成员集）；</li>
     *   <li>被选中 NPU 端口的 CNA 作为下游 SCNA，参与 L1SW→L2SW、L2SW→L1SW、L1SW→NPU 的 hash 选口；</li>
     *   <li>L1SW→NPU 末跳出端口按 hash 选择（不再取 get(0)）；</li>
     *   <li>ACK 方向以源 NPU 端口的 jettyId 选路（与正向同一 jettyId），DstCNA 为源 CNA。</li>
     * </ul>
     *
     * <h3>两阶段流程</h3>
     * <ol>
     *   <li>阶段 1（框间 CROSS_L2）：枚举跨机框 EID 对，追踪 4 跳正/反向路径，贪心选出覆盖 L1SW↔L2SW 的 EID 对；</li>
     *   <li>阶段 2（框内 LOCAL_L1）：在阶段 1 结果中筛出 {@code layer == NPU_L1 && coverCount < required} 的缺口，枚举同机框 EID 对并追踪 2 跳正/反向路径补齐；</li>
     *   <li>合并统计：阶段 1 + 阶段 2 的 EID 对合并后，在完整链路域上重算覆盖率/重复率等统计。</li>
     * </ol>
     *
     * <h3>结果特征</h3>
     * <ul>
     *   <li>{@code scope = NPU_L1_L2}；</li>
     *   <li>框间 EID 对 8 条覆盖链路（4 正向 + 4 反向，{@code type = CROSS_L2}）；</li>
     *   <li>框内 EID 对 4 条覆盖链路（2 正向 + 2 反向，{@code type = LOCAL_L1}）；</li>
     *   <li>{@code layerStats} 含 NPU_L1 / L1_L2 两个分层；{@code coverageLinks[*].layer ∈ {NPU_L1, L1_L2}}；{@code coverageLinks[*].deviceType ∈ {"NPU", "SW"}}。</li>
     * </ul>
     *
     * <h3>jettyId 取值</h3>
     * <p>取值范围 {@code [32, 1023]}，每个 NPU 物理端口一个；拓扑缺失时回落 {@code 32 + portId} 并累加诊断计数 {@code jettyIdFallback}。
     *
     * @param request 覆盖规划请求（与 {@link #planPathsCoverage} 复用同一 DTO，覆盖域由方法名决定）
     * @return 覆盖规划结果（含 scope 与 layerStats 分层统计）
     * @throws SNCStateException 当前状态不是 DATAREADY
     * @throws IllegalArgumentException request 为 null
     * @see CoverageLinkScope#NPU_L1_L2
     * @see CoverageLinkLayer
     * @see CoveragePathType
     */
    CoveragePathsResult planPathsCoverageEx(CoveragePathsRequest request);

    // ============ 链路事件与路由管理 ============

    /**
     * 通知链路 up/down 事件
     *
     * 更新端口 {@code linkStatus} 与 {@code updateAt}（由 {@link LinkEventService} 处理），
     * 并触发 BFS 路由收敛（由 {@link RouteConvergeService#converge} 处理）：在互联转发节点间
     * 传播可达性变化，刷新 {@code OutPortInfo.convergedFlag}（down=置 PASSIVE，up=清 PASSIVE）
     * 与 {@code RoutingEntry.reachable}。
     *
     * <h3>收敛算法</h3>
     * <ol>
     *   <li>定位事件端口所属 chip C，遍历 "device#C" 路由表中以该端口为出端口的 RoutingEntry，刷新命中的 OutPortInfo.convergedFlag；</li>
     *   <li>调用 {@link RoutingEntry#refreshReachable()} 刷新可达性，记录 reachable 变化的路由前缀；</li>
     *   <li>若 reachable 发生变化，则遍历 chip C 上其他 up 端口，通过 PortEntity.remoteDevice/remotePort 定位对端转发节点的入接口；</li>
     *   <li>在远端转发节点上定位入接口所属 chip C'，在 "peerDevice#C'" 路由表中查询变化前缀，刷新出端口为入接口的 OutPortInfo 状态并刷新 reachable；</li>
     *   <li>迭代直到没有转发节点的路由 reachable 变化需要传播（BFS）。</li>
     * </ol>
     *
     * <p>同一设备不同 forwardingChip 转发隔离，收敛只在端口所属 chip 路由表内传播。
     * 作用对象为 SNCService 持有的 {@code instantiationRouteMap}（由 {@link #makeRoutes} 填充），
     * 收敛结果影响后续 {@link #getNodeRoute} 查询。
     *
     * @param supernode 链路事件所属的超节点
     * @param event 链路事件（deviceName + portName + eventType + eventTime）
     * @throws IllegalArgumentException supernode/event 为 null，或 event 必填字段为 null/空，或 eventType 非 "up"/"down"
     * @throws IllegalStateException 设备或端口在拓扑中不存在
     * @throws SNCStateException SNC 处于 INIT/UNINIT 状态
     */
    void notifyLinkEvent(SuperNode supernode, LinkEvent event);

    /**
     * 路由计算（基于内置拓扑模板）
     *
     * 同步方法（synchronized）：解析内置拓扑模板（{@code 128_npu_rack.json}、{@code 128_npu_inter_rack.json}），
     * 调用 {@link RouteMspService#routeMsp} 按最短路径策略生成模板路由，
     * 再调用 {@link RouteInstantiationService#instantiateXpodRoute} 按机框实例化，填充 {@code routes}。
     *
     * <h3>幂等性</h3>
     * <p>已计算过则直接返回（{@code routeCalculated == true}），重复调用安全无副作用。
     *
     * <h3>调用顺序</h3>
     * <p>必须在 {@link #makeRoutes} 之前调用，否则 {@code makeRoutes} 抛 {@link IllegalStateException}。
     * 不依赖 SuperNode 已下发：可在 init 后任意时刻（非 INIT/UNINIT）调用。
     *
     * @throws SNCStateException SNC 处于 INIT/UNINIT 状态
     */
    void routeCalculate();

    /**
     * 路由实例化（基于已计算的路由模板为 SuperNode 生成实例化路由表）
     *
     * 遍历 SuperNode 中的 NPU/L1SW/L2SW 设备，按设备类型与机框/索引匹配模板路由标签，
     * 由 {@link RouteInstantiationService} 转换为 {@code Map<String, RoutingEntry>}（key = 路由前缀 IP），
     * 存入 {@code instantiationRouteMap}（key = {@code "deviceName#chipIndex"}）并返回副本。
     *
     * <h3>实例化规则</h3>
     * <ul>
     *   <li>NPU：按 {@code chassis/slot/ubpu/die} 标签匹配模板；</li>
     *   <li>L1SW：按 {@code chassis/index} 标签匹配；</li>
     *   <li>L2SW：按 {@code index/chip} 标签匹配，4 框实例化时 L2SW 的出端口索引/名称按框间拓扑重映射。</li>
     * </ul>
     *
     * <p>深拷贝保证内部 {@code instantiationRouteMap} 与返回值互不影响
     * （{@link RouteInstantiationService#deepCopyRoutingEntry}）。
     *
     * @param superNode 已下发的超节点拓扑
     * @return 实例化路由表（key = "deviceName#chipIndex"，value = 该 chip 的路由前缀 → RoutingEntry 映射）
     * @throws IllegalArgumentException superNode 为 null，或设备无 forwardingChips
     * @throws IllegalStateException {@link #routeCalculate} 未调用
     * @throws SNCStateException SNC 处于 INIT/UNINIT 状态
     */
    Map<String, Map<String, RoutingEntry>> makeRoutes(SuperNode superNode);

    /**
     * 查询单设备单芯片的实例化路由表
     *
     * 从 {@code instantiationRouteMap} 中读取指定设备指定芯片的路由表。
     * 典型用途：路由收敛（{@link #notifyLinkEvent}）后查询收敛后的可达性状态。
     *
     * @param deviceName 设备唯一标识
     * @param chipIndex 芯片编号
     * @return 该芯片的路由前缀 → RoutingEntry 映射
     * @throws IllegalArgumentException deviceName 为 null，或 key 不存在
     * @throws SNCStateException SNC 处于 INIT/UNINIT 状态
     */
    Map<String, RoutingEntry> getNodeRoute(String deviceName, int chipIndex);
}
```

**方法汇总表：**

| 方法 | 入参 | 出参 | 类型 | 线程安全 | 说明 |
|:-----|:-----|:-----|:-----|:--------|:-----|
| init | SNCConfig | void | 同步 | 否（初始化阶段） | 加载配置，初始化内存结构 |
| uninit | - | void | 同步 | 否（清理阶段） | 清空数据，释放资源 |
| setSuperNode | SuperNode | void | 同步 | 否（写操作需串行） | 全量替换拓扑数据 |
| addNpuDevices | String, List\<NpuDevice\> | void | 同步 | 否（写操作需串行） | 增量批量添加 NPU 设备 |
| addSwDevices | String, List\<SwDevice\> | void | 同步 | 否（写操作需串行） | 增量批量添加 SW 设备 |
| removeDevices | String, List\<String\> | void | 同步 | 否（写操作需串行） | 增量批量移除设备 |
| addRoutingEntries | String, String, Integer, List\<RoutingEntry\> | void | 同步 | 否（写操作需串行） | 增量批量添加/更新路由条目 |
| removeRoutingEntries | String, String, Integer, List\<RoutePrefix\> | void | 同步 | 否（写操作需串行） | 增量批量删除路由条目 |
| getSuperNode | String | SuperNode | 同步 | 是（只读，可并发） | 根据 superNodeName 查询拓扑数据 |
| removeSuperNode | String | void | 同步 | 否（写操作需串行） | 根据 superNodeName 删除拓扑数据及关联路由表 |
| planPath | PathPlanRequest | PathPlanResult | 同步 | 是（只读，可并发） | 单路径规划 |
| planPathsCoverage | CoveragePathsRequest | CoveragePathsResult | 同步 | 否（内部枚举 EID 对，建议串行） | 覆盖规划（L1↔L2 出端口域） |
| planPathsCoverageEx | CoveragePathsRequest | CoveragePathsResult | 同步 | 否（两阶段枚举 EID 对，建议串行） | 覆盖规划扩展（NPU↔L1↔L2，含 jettyId hash） |
| notifyLinkEvent | SuperNode, LinkEvent | void | 同步 | 否（修改端口状态 + 触发 BFS 路由收敛，需串行） | 通知链路 up/down 事件，刷新 OutPortInfo.convergedFlag 与 RoutingEntry.reachable |
| routeCalculate | - | void | 同步 | 否（synchronized，幂等） | 解析内置拓扑模板，计算 MSP 模板路由；必须在 makeRoutes 之前 |
| makeRoutes | SuperNode | Map\<String, Map\<String, RoutingEntry\>\> | 同步 | 否（填充 instantiationRouteMap，需串行） | 按机框实例化模板路由；依赖 routeCalculate 已完成 |
| getNodeRoute | String, int | Map\<String, RoutingEntry\> | 同步 | 是（只读，可并发） | 从 instantiationRouteMap 查询单设备单芯片路由表 |

---

### 7.3 调用时序

```
北向调用方                                          SNCService
   │                                                   │
   │── init(config) ──────────────────────────────────▶│  阶段1: 初始化
   │◀── void ────────────────────────────────────────│
   │                                                   │
   │── setSuperNode(superNode) ─────────────────────────▶│  阶段2: 拓扑下发
   │◀── void ────────────────────────────────────────│
   │                                                   │
│── planPath(request1) ────────────────────────────▶│  阶段3a: 路径规划
│◀── PathPlanResult { status=0, path=... } ───────│ (可多次并发)
│                                                   │
│── planPath(request2) ────────────────────────────▶│
│◀── PathPlanResult { status=1010, ... } ─────────│
│                                                   │
│── planPathsCoverage(req) ────────────────────────▶│  阶段3b: 覆盖规划（L1↔L2）
│◀── CoveragePathsResult { scope=L1_L2, ... } ────│
│                                                   │
│── planPathsCoverageEx(req) ──────────────────────▶│  阶段3c: 覆盖规划扩展（NPU↔L1↔L2）
│◀── CoveragePathsResult { scope=NPU_L1_L2, ... } ─│
│                                                   │
│── routeCalculate() ──────────────────────────────▶│  阶段3d-1: 路由模板计算（幂等）
│◀── void ────────────────────────────────────────│  解析 128_npu_rack.json + 128_npu_inter_rack.json
│                                                   │
│── makeRoutes(superNode) ─────────────────────────▶│  阶段3d-2: 路由实例化
│◀── Map<dev#chip, Map<prefix, RoutingEntry>> ────│  填充 instantiationRouteMap
│                                                   │
│── getNodeRoute("rack1#os0#npu1", 0) ──────────────▶│  阶段3d-3: 查询单设备路由
│◀── Map<prefix, RoutingEntry> ───────────────────│
│                                                   │
│── notifyLinkEvent(superNode, event) ──────────────▶│  阶段3e: 链路事件通知
│◀── void ────────────────────────────────────────│  触发 BFS 路由收敛
│                                                   │
│── getSuperNode("A5-superPod-1") ──────────────────▶│  阶段4: 数据查询
│◀── SuperNode { name="A5-superPod-1", ... } ──────│
│                                                   │
│── removeSuperNode("A5-superPod-1") ───────────────▶│  阶段5: 数据删除
│◀── void ────────────────────────────────────────│
│                                                   │
│── uninit() ──────────────────────────────────────▶│  阶段6: 去初始化
│◀── void ────────────────────────────────────────│
   │                                                   │
```

> **说明：**
> - setSuperNode 必须在 planPath / planPathsCoverage / planPathsCoverageEx 之前完成（状态迁至 DATAREADY）。
> - routeCalculate 必须在 makeRoutes 之前调用（幂等，可重复安全调用）；makeRoutes 完成后才能用 getNodeRoute 查询。
> - notifyLinkEvent 依赖 makeRoutes 已填充的 instantiationRouteMap 做路由收敛。
> - planPathsCoverage / planPathsCoverageEx 的覆盖域差异见 §7.2 方法说明。

---

### 7.4 状态机

SNC 服务内部维护以下生命周期状态：

```
         init()                          uninit()
  INIT ──────────▶ READY ──(setSuperNode 已完成)──▶ DATAREADY
   │                                │                                 │
   │                                │ 增量操作 (add/remove/get/…)       │ planPath (可多次并发)
   │                                │ setSuperNode                     │ planPathsCoverage / planPathsCoverageEx
   │                                │ routeCalculate                   │ setSuperNode (可更新)
   │                                │ makeRoutes                       │ 增量操作 (add/remove/get/…)
   │                                │ getNodeRoute                     │ routeCalculate / makeRoutes / getNodeRoute
   │                                │ notifyLinkEvent                  │ notifyLinkEvent
   │                                │ uninit()                         │ uninit()
   │                                │                                 │
   └──── uninit() ───▶ UNINIT ◀───────────────────────────────────────┘
```

| 状态 | 说明 | 允许的操作 |
|:-----|:-----|:----------|
| INIT | 初始状态（未初始化） | init()、uninit() |
| READY | 就绪状态（已初始化，数据未就绪） | setSuperNode；所有增量操作（addNpuDevices、addSwDevices、removeDevices、addRoutingEntries、removeRoutingEntries）；所有查询操作（getSuperNode）；removeSuperNode；routeCalculate、makeRoutes、getNodeRoute、notifyLinkEvent；uninit |
| DATAREADY | 数据就绪状态（拓扑已下发） | 同 READY，追加 planPath、planPathsCoverage、planPathsCoverageEx |
| UNINIT | 已去初始化 | （无，调用任何操作均抛 SNCStateException） |

**状态转换规则：**
- `init()`: INIT → READY（非幂等，重复 init 重建全部内部对象）
- `uninit()`: INIT / READY / DATAREADY → UNINIT（INIT 状态调用仅清空状态标记，无副作用）
- `setSuperNode()`: READY → DATAREADY（拓扑下发后自动迁移）
- `setSuperNode()`: DATAREADY → DATAREADY（数据就绪态可继续更新数据）
- `planPath()` / `planPathsCoverage()` / `planPathsCoverageEx()`: 仅在 **DATAREADY** 状态下可用，未到 DATAREADY 时返回 SNCStateException
- `routeCalculate()` / `makeRoutes()` / `getNodeRoute()` / `notifyLinkEvent()`: **READY / DATAREADY** 均可，仅要求 SNC 已 init（非 INIT/UNINIT）；不依赖 SuperNode 已下发（routeCalculate 不读取 SuperNode；makeRoutes 需传入 SuperNode 参数）

---

### 7.5 错误处理

#### 7.5.1 返回状态码

所有路径规划的错误码通过 `PathPlanResult.status`（`PlanStatus` 枚举）返回：

| 错误码 | 枚举常量 | 说明 | 触发阶段 |
|:------:|:--------|:-----|:--------|
| 0 | `SUCCESS` | 成功 | - |
| 1003 | `SRC_INFO_ERR` | 源信息缺失或错误 | Step 1 |
| 1004 | `DST_INFO_ERR` | 目的信息缺失或错误 | Step 2 |
| 1007 | `TOPO_INCOMPLETE` | 拓扑不完整（设备在超节点 devices 中找不到） | Step 0 / Step 3~5 |
| 1008 | `TOPO_CONNECTION_ERROR` | 拓扑连接错误（直连验证失败） | Step 4 |
| 1009 | `TOPO_CONNECTION_NOT_FOUND` | 未找到拓扑连接（多跳路径还原失败） | Step 5 |
| 1010 | `ROUTE_NOT_REACHABLE` | 路由不可达（索引掩码匹配未命中或路由条目无出端口） | Step 8 |
| 1011 | `COVERAGE_INCOMPLETE` | 覆盖规划未完成：枚举完候选 EID 对仍未达到 `coverageRequirement` 所要求的最低覆盖率（仅 `planPathsCoverage` / `planPathsCoverageEx` 返回；返回时 result 仍含已选 EID 对与统计，由调用方决定是否接受） | planPathsCoverage / planPathsCoverageEx |
| 1012 | `TOPO_NOT_FOUND` | 拓扑数据未找到（superNodeName 为空或对应的 SuperNode 不存在）；同时用于 `planPathsCoverage` / `planPathsCoverageEx` / `notifyLinkEvent` 中 SuperNode 缺失场景 | Step 0 / 覆盖规划 / 链路事件 |
| 3002 | `SRC_AND_DST_MUST_BE_NPU` | 源和目的必须为 NPU | Step 0 |
| 3003 | `UPI_MISMATCH` | 源和目的端口 UPI 不一致 | Step 0 |

> **完整枚举定义：** [§6.2 PathPlanResult.PlanStatus](#62-pathplanresult路径规划响应)。完整枚举值与 `com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus` 一一对应。

**错误码编码规则：**
- `0`：成功
- `1xxx`：路径规划阶段错误（设备/端口/路由/拓扑相关）
- `3xxx`：参数校验错误

**各层处理原则：**

| 层级     | 处理策略                                                       |
|:---------|:---------------------------------------------------------------|
| 北向接口 | 捕获所有异常，转换为统一的错误响应（错误码 + 错误消息）         |
| service  | 不吞异常，向上抛出带有明确错误码的 PathPlanException            |
| engine   | 抛出具体异常（路径不可达、路由未找到等），不处理业务逻辑         |
| store    | 数据不存在时返回 null 或 Optional，由 service 层判断并转换异常   |

**北向错误响应格式：**

所有北向接口在发生异常时，应返回如下结构：

```json
{
    "code": 1001,
    "message": "源EID未找到",
    "detail": "deviceName=rack1#os#npu1 not found in superNode"
}
```


**参数校验：**

- **必填字段校验：** 入参中的必填字段（如 deviceName、srcPort 等）在 service 层入口处统一校验，为 null 或空字符串时立即返回参数错误。
- **格式校验：** deviceName 格式、EID 长度（128 bit）、CNA 范围（32 bit）等由 `util` 包中的工具类校验。
- **业务规则校验：** 设备类型必须为 NPU 等业务规则在 engine 层校验。

#### 7.5.2 异常体系

```
SNCException (基础异常)
├── SNCStateException        // 状态异常（未初始化、已去初始化、重复初始化）
├── SuperNodeNotFoundException    // 拓扑数据未找到
└── PathPlanException        // 路径规划失败（内含 PlanStatus 错误码和描述）
```

| 异常类 | 使用场景 | 处理方式 |
|:-------|:--------|:--------|
| `SNCStateException` | 非法调用顺序（未 init 就 planPath、uninit 后再次调用等） | 直接抛出，北向调用方捕获并处理 |
| `IllegalArgumentException` | 入参为 null、必填字段缺失 | 入口校验，直接抛出 |
| `SuperNodeNotFoundException` | `setSuperNode` 未调用或拓扑数据不完整（含 superNodeName 不存在和设备找不到） | service 层转换为错误码 1012/1001/1002/1007 |
| `PathPlanException` | planPath 执行过程中任何业务失败 | 内含 PlanStatus，北向接口转换为 PathPlanResult |

#### 7.5.3 错误传播链

```
北向调用方
    ↑ 通过 PathPlanResult.status 获取错误码，.errorMessage 获取描述
北向接口层 (SNCServiceImpl)
    ↑ 捕获 SNCException，转换为 PathPlanResult { status=错误码, errorMessage=描述 }
Service 层
    ↑ 根据 null / 校验失败抛出对应异常
Engine / Store 层
    ↑ 返回 null / 抛出底层异常
```

---

### 7.6 参数校验规则

北向接口入口处（`SNCServiceImpl`）统一进行参数校验。

| 校验项 | 校验内容 | 违规处理 |
|:-------|:--------|:--------|
| `superNode` 非 null | `setSuperNode(SuperNode)` 入参 | 抛出 `IllegalArgumentException` |
| `superNode.name` 非空 | 超节点名称必填（§4.1） | 抛出 `IllegalArgumentException` |
| `superNode.devices` 非空 | 设备 Map 必填（§4.1） | 抛出 `IllegalArgumentException` |
| `request` 非 null | `planPath(PathPlanRequest)` 入参 | 抛出 `IllegalArgumentException` |
| `request.superNodeName` 非空 | 超节点名称必填（§6.1），用于多超节点场景定位 | 抛出 `IllegalArgumentException` |
| `request.srcDevice` 非空 | 源设备必填（§6.1） | 抛出 `IllegalArgumentException` |
| `request.destDevice` 非空 | 目的设备必填（§6.1） | 抛出 `IllegalArgumentException` |
| `request.srcPort` 非空 | 源端口必填（§6.1） | 抛出 `IllegalArgumentException` |
| `request.destPort` 非空 | 目的端口必填（§6.1） | 抛出 `IllegalArgumentException` |
| `superNodeName` 非空 | `getSuperNode(String)` / `removeSuperNode(String)` 入参 | 抛出 `IllegalArgumentException` |
| deviceName 格式 | `rack#os#npu` 或 `rack#l1sw0` 格式 | engine 层校验，返回错误码 1003/1004 |

> **业务规则校验**（设备类型必须为 NPU、EID/CNA 完整性等）在 engine 层进行，不在入口处校验。

---

### 7.7 接口实现映射

`SNCServiceImpl` 实现类将接口方法委托给内部组件：

```
SNCServiceImpl
    │
    ├── init(SNCConfig)
    │     └→ SuperNodeStore.init()  // 初始化 HashMap
    │
    ├── setSuperNode(SuperNode)
    │     └→ SuperNodeService.importSuperNode(superNode)
    │              └→ SuperNodeStore.replace(superNode)  // 全量替换拓扑索引
    │
    ├── addNpuDevices(String, List<NpuDevice>)
    │     └→ SuperNodeService.addNpuDevices(superNodeName, devices)     // 循环调用 store.addNpuDevice()
    │              └→ SuperNodeStore.addNpuDevice(superNodeName, device)  // 增量添加 NPU 设备及路由表索引
    │
    ├── addSwDevices(String, List<SwDevice>)
    │     └→ SuperNodeService.addSwDevices(superNodeName, devices)     // 循环调用 store.addSwDevice()
    │              └→ SuperNodeStore.addSwDevice(superNodeName, device)  // 增量添加 SW 设备及路由表索引
    │
    ├── removeDevices(String, List<String>)
    │     └→ SuperNodeService.removeDevices(superNodeName, deviceNames)       // 循环调用 store.removeDevice()
    │              └→ SuperNodeStore.removeDevice(superNodeName, deviceName)  // 从 npuDevices/swDevices 中移除设备及路由表索引
    │
    ├── addRoutingEntries(String, String, Integer, List<RoutingEntry>)
    │     └→ SuperNodeService.addRoutingEntries(superNodeName, deviceName, chipIndex, entries) // 循环调用 store.addRoutingEntry()
    │              └→ SuperNodeStore.addRoutingEntry(superNodeName, deviceName, chipIndex, prefix, entry)  // 增量添加/更新路由（单条）
    │
    ├── removeRoutingEntries(String, String, Integer, List<RoutePrefix>)
    │     └→ SuperNodeService.removeRoutingEntries(superNodeName, deviceName, chipIndex, prefixes) // 循环调用 store.removeRoutingEntry()
    │              └→ SuperNodeStore.removeRoutingEntry(superNodeName, deviceName, chipIndex, prefix)  // 增量删除路由（单条）
    │
    ├── getSuperNode(String)
    │     └→ SuperNodeStore.getSuperNode(superNodeName)        // 查询拓扑数据
    │
    ├── removeSuperNode(String)
    │     └→ SuperNodeStore.removeSuperNode(superNodeName)     // 删除拓扑数据及关联路由表
    │
    ├── planPath(PathPlanRequest)
    │     └→ PathService.planPath(request)
    │              ├→ PathEngine.resolvePath()      // 路径还原 (Step 3~5)
    │              ├→ RouteLookupEngine.lookup()    // 路径规划 (Step 6~8)
    │              └→ 组装 PathPlanResult            // 输出构造 (Step 9~10)
    │
    ├── planPathsCoverage(CoveragePathsRequest)
    │     └→ PathService.planPathsCoverage(request)
    │              ├→ SuperNodeStore.getSuperNode(superNodeName)   // 拓扑查找
    │              ├→ new CoveragePlanEngine(superNode, hashFunc, ...)  // 构造引擎
    │              ├→ engine.findCoverage(requirement)             // L1↔L2 覆盖
    │              └→ 组装 CoveragePathsResult { scope=L1_L2, ... }
    │
    ├── planPathsCoverageEx(CoveragePathsRequest)
    │     └→ PathService.planPathsCoverageEx(request)
    │              ├→ SuperNodeStore.getSuperNode(superNodeName)
    │              ├→ new CoveragePlanEngine(superNode, hashFunc, dieHashFuncSelect, ...)
    │              ├→ engine.findCoverageEx(requirement)          // 两阶段：CROSS_L2 + LOCAL_L1
    │              └→ 组装 CoveragePathsResult { scope=NPU_L1_L2, layerStats=[...], ... }
    │
    ├── notifyLinkEvent(SuperNode, LinkEvent)
    │     └→ LinkEventService.handleLinkEvent(superNode, event)
    │              ├→ port.setLinkStatus(LINK_UP/LINK_DOWN) + port.setUpdateAt(eventTime)
    │              └→ RouteConvergeService.converge(superNode, deviceName, chipIndex, portName, isDown)
    │                       ├→ OutPortInfo.setFlag/clearFlag(FLAG_PASSIVE_CONVERRGED)
    │                       ├→ RoutingEntry.refreshReachable()
    │                       └→ BFS 传播到对端转发节点
    │
    ├── routeCalculate()
    │     └→ synchronized { if (routeCalculated) return; }
    │              ├→ TopoTemplateService.parseTemplateFile("128_npu_rack.json")
    │              ├→ TopoTemplateService.parseTemplateFile("128_npu_inter_rack.json")
    │              ├→ RouteMspService.routeMsp(topoTemplate)             // BFS 最短路径
    │              ├→ RouteInstantiationService.buildXpodRoutes(template) // 模板路由表
    │              └→ routeCalculated = true
    │
    ├── makeRoutes(SuperNode)
    │     └→ if (!routeCalculated) throw IllegalStateException
    │     └→ RouteInstantiationService.instantiateXpodRoute(routes, superNode)
    │              ├→ 遍历 NPU/L1SW/L2SW 设备按标签匹配模板
    │              ├→ deepCopyRoutingEntry(...)                         // 深拷贝
    │              └→ instantiationRouteMap.put("deviceName#chipIndex", routingEntryMap)
    │                  返回 instantiationRouteMap 的副本
    │
    ├── getNodeRoute(String, int)
    │     └→ instantiationRouteMap.get("deviceName#chipIndex")          // 直接 HashMap 查找
    │
    └── uninit()
            └→ SuperNodeStore.clear()  // 清空数据
```

### 7.8 错误调用顺序说明

以下调用序列是非法的，SNC 应返回错误：

| 非法序列                              | 错误原因                          | 建议处理            |
|:--------------------------------------|:----------------------------------|:--------------------|
| 未 `init()` 直接调用其他接口            | 内部数据结构未初始化               | 抛出 SNCStateException   |
| `uninit()` 后再次调用其他接口          | 已去初始化，内存数据已清空         | 抛出 SNCStateException   |
| 未下发拓扑数据直接调用 `planPath()` / `planPathsCoverage()` / `planPathsCoverageEx()` | 状态未到 DATAREADY | 抛出 SNCStateException |
| 重复 `init()` 不调用 `uninit()`       | 状态机重复初始化                   | 幂等处理或抛异常     |
| 未调用 `routeCalculate()` 直接调用 `makeRoutes()` | 模板路由未计算，无法实例化 | 抛出 IllegalStateException |
| 未调用 `makeRoutes()` 直接调用 `getNodeRoute()` / `notifyLinkEvent()` | instantiationRouteMap 为空 | 抛出 IllegalStateException / 返回 key 不存在 |
| `notifyLinkEvent()` 的 `deviceName` + `portName` 在拓扑中找不到 | 设备或端口不存在 | 抛出 IllegalStateException |
| `notifyLinkEvent()` 的 `eventType` 非 "up"/"down" | 参数非法 | 抛出 IllegalArgumentException |

---

### 7.9 SuperNodeStore（拓扑存储）

拓扑数据的核心存储层，维护超节点→拓扑数据的一级索引及路由表的全局索引。

```java
public class SuperNodeStore {
    /** 拓扑数据一级索引 -- Map的key为SuperNode.name（superNodeName，§4.1），支持多超节点场景 */
    private Map<String, SuperNode> superNodeMap;

    /** 路由表全局索引 -- Map的key为RoutingTableKey（superNodeName + deviceName + chipIndex，§4.7.1） */
    private Map<RoutingTableKey, RoutingTable> routingTableMap;

    // ========== 生命周期方法 ==========

    /**
     * 初始化存储
     * <p>创建空的 HashMap 实例，供后续 replace 填充数据。
     */
    public void init() {
        this.superNodeMap = new HashMap<>();
        this.routingTableMap = new HashMap<>();
    }

    /**
     * 全量替换拓扑数据
     * <p>解析 SuperNode（§4.1）并将以下数据写入索引：
     * <ol>
     *   <li>以 superNode.name 为 key，将 SuperNode 对象存入 superNodeMap</li>
     *   <li>清除 routingTableMap 中归属于该 superNodeName 的所有旧路由表条目</li>
     *   <li>遍历 superNode 所有设备（通过 getAllDevices()），将各芯片的 RoutingTable 提取到 routingTableMap：
     *       <br>key = 构造 RoutingTableKey(superNode.name, device.deviceName, chip.chipIndex)
     *       <br>value = 该芯片的 RoutingTable 对象</li>
     * </ol>
     *
     * @param superNode 拓扑数据（§4.1），要求 name 非空，npuDevices 或 swDevices 至少一个非空
     */
    public void replace(SuperNode superNode) {
        String name = superNode.getName();
        superNodeMap.put(name, superNode);

        routingTableMap.entrySet().removeIf(e -> e.getKey().getSuperNodeName().equals(name));

        Map<String, DeviceEntity> allDevices = superNode.getMutableAllDevices();
        if (allDevices != null) {
            for (DeviceEntity device : allDevices.values()) {
                indexRoutingTable(name, device);
            }
        }
    }

    private void indexRoutingTable(String superNodeName, DeviceEntity device) {
        if (device.getForwardingChips() != null) {
            for (ForwardingChip chip : device.getForwardingChips().values()) {
                if (chip.getRoutingTable() != null) {
                    RoutingTable rt = chip.getRoutingTable();
                    if (rt.getRoutes() != null) {
                        updateMaskLengths(rt);
                    }
                    RoutingTableKey key = new RoutingTableKey(
                        superNodeName, device.getDeviceName(), chip.getChipIndex());
                    routingTableMap.put(key, rt);
                }
            }
        }
    }

    /**
     * 清空所有存储数据
     * <p>调用 superNodeMap.clear() 和 routingTableMap.clear()，释放内存。
     */
    public void clear() {
        if (superNodeMap != null) {
            superNodeMap.clear();
        }
        if (routingTableMap != null) {
            routingTableMap.clear();
        }
    }

    /**
     * 删除指定超节点的拓扑数据及关联路由表
     *
     * <p>从 superNodeMap 中移除指定 superNodeName 对应的 SuperNode，并清除 routingTableMap 中
     * 所有归属于该 superNodeName 的路由表条目。
     *
     * @param superNodeName 超节点名称（§4.1 SuperNode.name）
     */
    public void removeSuperNode(String superNodeName) {
        superNodeMap.remove(superNodeName);
        // 移除 routingTableMap 中所有 superNodeName 匹配的条目
        routingTableMap.keySet().removeIf(key -> superNodeName.equals(key.getSuperNodeName()));
    }

    // ========== 查询方法 ==========

    /**
     * 根据 superNodeName 获取拓扑数据
     *
     * @param superNodeName 超节点名称（§4.1 SuperNode.name）
     * @return SuperNode 对象，不存在返回 null
     */
    public SuperNode getSuperNode(String superNodeName) {
        return superNodeMap.get(superNodeName);
    }

    /**
     * 根据联合键获取路由表
     *
     * @param key RoutingTableKey（superNodeName + deviceName + chipIndex，§4.7.1）
     * @return RoutingTable 对象，不存在返回 null
     */
    public RoutingTable getRoutingTable(RoutingTableKey key) {
        return routingTableMap.get(key);
    }
}
```

**设计说明：**

| 特性 | 说明 |
|:-----|:-----|
| 一级索引 `superNodeMap` | 以 `superNodeName` 为 key，O(1) 定位超节点，支持多超节点共存 |
| 路由表索引 `routingTableMap` | 以 `RoutingTableKey`（superNodeName + deviceName + chipIndex）为 key，全局 O(1) 查找任意设备芯片的路由表 |
| `replace()` 策略 | 全量替换：先清除旧路由表索引，再重新索引全部设备。通过 `getMutableAllDevices()` 统一遍历 npuDevices 和 swDevices |
| `clear()` 策略 | 调用 Map.clear() 清空内存，不保留任何数据 |
| 路由表提取 | `replace()` 通过 `indexRoutingTable()` 私有方法遍历设备→芯片层级（通过 `device.getForwardingChips()` 抽象方法遍历所有转发芯片），提取 RoutingTable 并更新 maskLengths。输入 JSON 中 routingTables 位于设备级别，由反序列化器注入到 ForwardingChip.routingTable |
| `addNpuDevice()` | 增量添加 NPU 设备到 `npuDevices` Map，同时调用 `indexRoutingTable()` 索引其路由表。若 `npuDevices` 为 null 则自动创建新 HashMap |
| `addSwDevice()` | 增量添加 SW 设备到 `swDevices` Map，同时调用 `indexRoutingTable()` 索引其路由表。若 `swDevices` 为 null 则自动创建新 HashMap |
| `removeDevice()` | 从 `npuDevices` 和 `swDevices` 两个 Map 中同时尝试移除指定 deviceName，并清除 routingTableMap 中对应的路由表条目 |

**查询流程示例：**
```
// Step 0: 定位超节点
SuperNode superNode = superNodeStore.getSuperNode(request.getSuperNodeName());

// Step 8: 查找路由表
RoutingTableKey rtKey = new RoutingTableKey(superNodeName, deviceName, chipIndex);
RoutingTable rt = superNodeStore.getRoutingTable(rtKey);
```

---

## 8 算法

### 8.1 算法描述

基于预索引掩码的逐级最长前缀匹配算法。内部记录外部路由输入中的掩码长度（如 32 对应明细路由、20 对应框级路由），查找时仅用这些已知掩码逐级尝试，通过 HashMap O(1) 命中直接定位。

**设计说明：** 本算法与 §4.7/§4.8 保持一致——`RoutingTable` 内部维护 `maskLengths` 列表（去重、降序），查找时按该列表从最长掩码向最短掩码逐级构造 key 做 HashMap O(1) 查询，无需遍历全表。

**输入：** `targetAddr`（32 bit）；`RoutingTable`（包含 `routes` Map 和 `maskLengths` 列表）。

**前置条件：**
- `RoutingTable.maskLengths` 已由引擎在路由表构建/更新时维护完毕，保证包含当前路由表中所有 `RoutePrefix.maskLength` 的去重降序值。

**查找步骤：**
1. 从 `RoutingTable.maskLengths` 中取出当前最长（即第一个）掩码 `maskLen`（掩码列表已从大到小排序）
2. 调用 `AddressUtils.applyMask(targetAddr, maskLen)` 将 `targetAddr` 按 `maskLen` 做按位与运算，得到 `networkAddr`
3. 构造 `RoutePrefix(networkAddr, maskLen)` 作为 key，在 `RoutingTable.routes` Map 中执行 `get(key)` —— **O(1) 命中**
4. 若命中 → 返回对应的 `RoutingEntry`（由于 maskLen 已是当前最长，当前命中的即为本表的最长匹配项）
5. 若未命中 → 取 `maskLengths` 中的下一个掩码，重复步骤 2~4
6. 若所有已知掩码均未命中 → 尝试默认路由（`0.0.0.0/0`）——若 `maskLengths` 中尚不包含 0，则取 `maskLen=0` 构造 `RoutePrefix("0.0.0.0", 0)` 做最后一次 O(1) 查找；若已包含 0 则已在循环中覆盖，无需重复
7. 若默认路由也未命中 → 返回未找到路由（报错）

**算法示例：**
```
路由表 entries：
├── {dstAddress="170.170.170.0", maskLen=24} → eth0
├── {dstAddress="170.170.0.0",   maskLen=16} → eth1
└── {dstAddress="0.0.0.0",       maskLen=0}  → wan

路由表 maskLengths（引擎自动提取）：[24, 16, 0]

查找目标 targetAddr = 170.170.170.17 (32 bit)

第1轮：取 maskLen=24（最长）
   applyMask("170.170.170.17", 24) → "170.170.170.0"
   构造 RoutePrefix("170.170.170.0", 24) → routes.get(prefix) → 命中 eth0 ✅
   直接返回，无需继续尝试后续掩码。

匹配项: A(maskLen=24) → 返回 eth0 ✅
```

**边界示例（未命中最长，命中次长）：**
```
查找目标 targetAddr = 170.170.171.17 (32 bit)

第1轮：取 maskLen=24
   applyMask("170.170.171.17", 24) → "170.170.171.0"
   RoutePrefix("170.170.171.0", 24) → routes.get → 未命中 ❌

第2轮：取 maskLen=16
   applyMask("170.170.171.17", 16) → "170.170.0.0"
   RoutePrefix("170.170.0.0", 16) → routes.get → 命中 eth1 ✅
   返回。
```

**复杂度：**
- 查找次数 = `maskLengths.size()`，即路由表中实际存在的去重掩码种类数 m。典型场景 m = 2~3（如只有 /32 的明细路由和 /20 的框级路由）
- 每轮查询 O(1) HashMap get。整体复杂度 **O(m)**，m = 掩码种类数（通常 ≤ 5）
- 相比遍历全表 O(n)（n = 路由条目数，可达几百条），**查找效率显著提升且不随路由表规模增长而退化**

### 8.2 引擎接口

> **对应 3.2 包结构中的 `engine/RouteLookupEngine.java`**

```java
package com.huawei.umdk.snc.engine;

import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import java.util.List;
import java.util.Map;

/**
 * 路径规划引擎 —— 索引掩码匹配（Indexed Mask Match）
 *
 * <h3>职责</h3>
 * 接收 32 bit targetAddr 和一张路由表（含 maskLengths 列表），执行 §8.1 所述的
 * 按已知掩码逐级 O(1) 查找算法，返回最长匹配的 RoutingEntry。
 *
 * <h3>调用方</h3>
 * PathService → RouteLookupEngine，对应 §9.4 阶段3 Step 8。
 */
public class RouteLookupEngine {

    /**
     * 索引掩码匹配查找
     *
     * <p>从 maskLengths（已降序）中取当前最长掩码，将 targetAddr 按该掩码按位与得到 networkAddr，
     * 构造 RoutePrefix(networkAddr, maskLen) 在 routes 中做 O(1) 查找。
     * 命中即返回；未命中则尝试下一个掩码。
     *
     * @param targetAddr  32 bit 目标地址
     * @param routes      路由表 Map，key 为 RoutePrefix（包含 dstAddress + maskLength），value 为 RoutingEntry
     * @param maskLengths 路由表中实际存在的掩码长度列表（去重后从大到小排序），由引擎在路由表构建时维护
     * @return 最长匹配的 RoutingEntry；若无匹配则返回 null（调用方自行处理默认路由/报错逻辑）
     */
    public RoutingEntry lookup(String targetAddr, Map<RoutePrefix, RoutingEntry> routes,
                               List<Integer> maskLengths) {
        // 实现详见 §8.1 算法步骤 1~7
    }
}
```

### 8.3 覆盖规划算法（CoveragePlanEngine）

> **对应 3.2 包结构中的 `engine/CoveragePlanEngine.java`**（约 2882 行）

#### 8.3.1 算法概述

给定超节点拓扑（含路由表）与覆盖要求（MIN_COVERAGE / REDUNDANT），从 NPU 端口 EID 笛卡尔积中贪心选择一组 EID 对，使其正反向 hash 选路路径遍历覆盖域内全部出端口。`planPathsCoverage` 与 `planPathsCoverageEx` 共用同一引擎，差异仅在覆盖域是否包含 NPU↔L1SW：

| 方法 | 引擎入口 | 覆盖域 | hash 使用点 |
|:-----|:---------|:-------|:-----------|
| planPathsCoverage | findCoverage | L1SW↔L2SW（4 跳路径中 2 段：L1SW→L2SW、L2SW→L1SW） | H3a/H3b、H5a/H5b |
| planPathsCoverageEx | findCoverageEx | NPU↔L1SW↔L2SW（4 跳路径全部 4 段 + 框内 2 跳路径） | H1/H2、H3a/H3b、H4、H5a/H5b、H6、H7a/H7b |

#### 8.3.2 hash 使用点

| ID | 位置 | 输入 | hash 函数 | 输出口 |
|:---|:-----|:-----|:---------|:-------|
| H1 | NPU→L1SW（正向） | `(DstCNA, jettyId)` | `ubswitch_Hash_dieEcmp`（CRC-8/ATM） | NPU 路由 LPM 命中条目的 L1SW 向 ECMP 出端口 |
| H2 | NPU→L1SW（ACK） | `(源CNA, 源端口jettyId)` | `ubswitch_Hash_dieEcmp` | 同 H1，但 jettyId 用源 NPU 端口 |
| H3a | L1SW→L2SW（正向） | `(DstCNA, ...)` | `ubswitch_Hash_ecmp` | L1SW 路由 LPM 命中条目的 L2SW 向出端口 |
| H3b | L1SW→L2SW（ACK） | 同 H3a，方向反 | `ubswitch_Hash_ecmp` | - |
| H4 | L1SW→NPU（正向，扩展版） | `(DstCNA, ...)` | `ubswitch_Hash_ecmp` | L1SW 路由 LPM 命中条目的 NPU 向出端口（不再 get(0)） |
| H5a | L2SW→L1SW（正向） | `(DstCNA, ...)` | `ubswitch_Hash_ecmp` | L2SW 路由 LPM 命中条目的 L1SW 向 ECMP 出端口 |
| H5b | L2SW→L1SW（ACK） | 同 H5a | `ubswitch_Hash_ecmp` | - |
| H6 | L1SW→L2SW（框内 ACK） | `(源CNA, ...)` | `ubswitch_Hash_ecmp` | - |
| H7a/H7b | L1SW→NPU（框内正/反） | `(DstCNA/源CNA, ...)` | `ubswitch_Hash_ecmp` | - |

> 说明：planPathsCoverage 不使用 H1/H2/H4/H6/H7（仅 L1↔L2 覆盖域），末跳出端口取 get(0)。

#### 8.3.3 SCNA 链接

`planPathsCoverageEx` 在阶段 1 枚举框间 EID 对时，被选中 NPU 端口的 CNA（源 CNA）将作为下游 L1SW/L2SW/L1SW 路由查找的 DstCNA（即 SCNA），决定下游各跳的 hash 选口。即：源 NPU 端口 CNA → 影响 L1SW→L2SW、L2SW→L1SW、L1SW→NPU 的出端口选择。同一 EID 对的正向 DstCNA 与反向 DstCNA 不同（反向用源 CNA），导致正反向路径不必重合，从而覆盖更多链路。

#### 8.3.4 两阶段覆盖（planPathsCoverageEx）

**阶段 1（框间 CROSS_L2）：**
1. 枚举跨机框 EID 对（src 在机框 A，dst 在机框 B）；
2. 对每个 EID 对追踪 4 跳正反向路径（NPU→L1SW→L2SW→L1SW→NPU），使用 H1~H5b hash 选口；
3. 贪心选择：每次挑选能覆盖最多未命中 L1SW↔L2SW 链路的 EID 对；
4. 直到全部 L1SW↔L2SW 出端口 coverCount >= required（MIN_COVERAGE=1，REDUNDANT=2）或候选 EID 对耗尽。

**阶段 2（框内 LOCAL_L1）：**
1. 在阶段 1 结果中筛出 `layer == NPU_L1 && coverCount < required` 的缺口链路；
2. 枚举同机框 EID 对（src 与 dst 在同一机框）；
3. 对每个 EID 对追踪 2 跳正反向路径（NPU→L1SW→NPU），使用 H6/H7a/H7b hash 选口；
4. 贪心补齐 NPU↔L1SW 未覆盖链路。

**合并统计：** 阶段 1 + 阶段 2 EID 对合并后，在完整链路域上重算覆盖率 / 重复率 / EID 均匀度 / 分层统计（NPU_L1 / L1_L2）。

#### 8.3.5 EID 与 outport 关系

| NPU 端口字段 | 用途 | 影响范围 |
|:---|:---|:---|
| eid | EID 对的 srcEid/dstEid，作为 planPath 的输入参数 | 决定 EID 对集合 |
| cna | 作为下游 hash 的 DstCNA / 反向的源 CNA（SCNA） | 决定 H3a~H7b 的 outport 选择 |
| jettyId | 仅 planPathsCoverageEx：NPU→L1SW 选路 hash 二元组的 jettyId 字段 | 决定 H1/H2 的 outport 选择 |

#### 8.3.6 路由 scope 扩展（planPathsCoverageEx）

NPU 路由 LPM 命中条目的出端口集合，在 planPathsCoverage 中仅取 `get(0)` 作为末跳出端口；在 planPathsCoverageEx 中作为 ECMP 成员集，由 H1/H2 hash 选择其中一个。L1SW→NPU 同理：planPathsCoverage 取 get(0)，planPathsCoverageEx 由 H4 hash 选择。

#### 8.3.7 引擎接口

```java
package com.huawei.umdk.snc.engine;

public class CoveragePlanEngine {

    /** JETTY_ID_MIN/MAX 与 HashUtils 一致；用于校验 jettyId 取值 */
    public static final int JETTY_ID_MIN = HashUtils.JETTY_ID_MIN;
    public static final int JETTY_ID_MAX = HashUtils.JETTY_ID_MAX;

    /**
     * 构造覆盖规划引擎
     *
     * @param superNode       超节点拓扑（含路由表）
     * @param hashFunc        hash 函数选择（HashUtils.HASH_FUNC_CRC8_ATM 等）
     * @param dieHashFuncSelect planPathsCoverageEx 用的 NPU→L1SW die hash 函数选择
     * @param fixedDataUdpPort 固定数据 UDP 端口（路径规划用）
     * @param fixedAckUdpPort  固定 ACK UDP 端口（路径规划用）
     * @param hashTuple        hash 元组配置
     */
    public CoveragePlanEngine(SuperNode superNode, int hashFunc, int dieHashFuncSelect,
                              int fixedDataUdpPort, int fixedAckUdpPort, int hashTuple);

    /** planPathsCoverage 入口：仅覆盖 L1SW↔L2SW */
    public CoveragePathsResult findCoverage(CoverageRequirement requirement);

    /** planPathsCoverageEx 入口：覆盖 NPU↔L1SW↔L2SW，两阶段流程 */
    public CoveragePathsResult findCoverageEx(CoverageRequirement requirement);

    /** 获取 jettyId；缺失或越界时回落 32 + portId 并累加 exJettyFallback */
    private int jettyIdOf(NpuPortEntity port);

    /** 获取扩展版诊断计数（planPathsCoverageEx 用） */
    public ExDiagnostics getExDiagnostics();
}
```

**`ExDiagnostics` 字段：**

| 字段 | 说明 |
|:---|:---|
| npuRouteFail | NPU 路由 LPM 未命中次数 |
| npuPortFail | NPU 端口查找失败次数 |
| jettyIdFallback | jettyId 缺失或越界回落次数 |
| l1Fail | L1SW 路由查找/选口失败次数 |
| l2Fail | L2SW 路由查找/选口失败次数 |
| dstL1Fail | 目的 L1SW 查找失败次数 |
| revNpuFail | 反向 NPU 选口失败次数 |
| revDstL1Fail | 反向目的 L1SW 失败次数 |
| revL2Fail | 反向 L2SW 失败次数 |
| revSrcL1Fail | 反向源 L1SW 失败次数 |

> 诊断计数用于测试与生产环境的故障定位；正常 SUCCESS 结果中所有计数应为 0 或仅 jettyIdFallback 非 0（旧拓扑输入场景）。

### 8.4 路由收敛算法（RouteConvergeService）

> **对应 3.2 包结构中的 `route/service/RouteConvergeService.java`**

#### 8.4.1 算法概述

链路 up/down 事件触发后，BFS 在互联转发节点间传播可达性变化：从事件端口所属 chip 出发，定位受影响的路由前缀，沿对端转发链路传播到下游 chip 路由表，刷新对应 OutPortInfo.convergedFlag 与 RoutingEntry.reachable。

#### 8.4.2 收敛步骤

1. **定位事件端口**：在 SuperNode 中按 `deviceName` 找到 DeviceEntity，遍历其 forwardingChips，找到包含 `portName` 的 chip C。
2. **刷新本地 chip 路由表**：遍历 `"deviceName#C"` 路由表中所有 RoutingEntry，对每个 entry.outPortInfos 中 portName == eventPortName 的 OutPortInfo：
   - down 事件：`setFlag(FLAG_PASSIVE_CONVERRGED)`
   - up 事件：`clearFlag(FLAG_PASSIVE_CONVERRGED)`
3. **刷新 reachable**：对步骤 2 中修改过的 RoutingEntry 调用 `refreshReachable()`，记录 reachable 变化（true→false 或 false→true）的前缀集合 `changedPrefixes`。
4. **BFS 传播**：若 `changedPrefixes` 非空：
   - 遍历 chip C 上其他 `linkStatus == up` 的端口 P；
   - 通过 `P.remoteDevice` / `P.remotePort` 定位对端转发节点 N 的入接口 P'；
   - 在 N 上找到 P' 所属的 chip C'；
   - 在 `"N#C'"` 路由表中查询 `changedPrefixes` 中的前缀；
   - 对命中前缀的 RoutingEntry，定位 outPortInfos 中 portName == P'.portName 的 OutPortInfo，setFlag/clearFlag `FLAG_PASSIVE_CONVERRGED`（与事件方向一致），refreshReachable；
   - 若 N 上的 reachable 也发生变化，将 N 加入 BFS 队列继续传播。
5. **终止条件**：BFS 队列为空（没有更多 reachable 变化需要传播）。

#### 8.4.3 关键约束

- 转发隔离：同一设备不同 forwardingChip 的路由表独立，收敛只在端口所属 chip 路由表内传播。
- 作用对象：SNCService 持有的 `instantiationRouteMap`（由 `makeRoutes` 填充）；不修改 SuperNode 拓扑数据本身的 `routingTableMap`。
- ECMP 处理：若一个 RoutingEntry 有多个出端口，down 事件只标记命中的那个出端口；reachable 由所有出端口的 convergedFlag 共同决定（任一 == 0 即 reachable=true）。
- 幂等性：重复发送同一 down 事件不会重复置位（位运算幂等）。

### 8.5 路由 MSP 计算与实例化算法

#### 8.5.1 RouteMspService（模板路由 MSP 计算）

> **对应 `route/service/RouteMspService.java`**

基于拓扑模板（`128_npu_rack.json`、`128_npu_inter_rack.json`），使用 BFS 计算每个转发节点到其他节点的最短路径，按路径策略（shortest / secondShortest / other）生成模板路由表 `RouteTable`（`Prefix → RouteEntry`，每个 RouteEntry 含 NhpSet + 路径分类）。

**BFS 最短路径策略：**
- 每跳 cost = 1，BFS 队列保证首次到达即为最短；
- shortest：最短路径的下一跳出端口集合；
- secondShortest：次短路径（比最短多 1 跳）的下一跳出端口集合；
- other：其他更长路径的出端口，用于 ECMP 多路径场景。

#### 8.5.2 RouteInstantiationService（模板路由实例化）

> **对应 `route/service/RouteInstantiationService.java`**

按 SuperNode 的实际机框/槽位/索引将模板路由表实例化为 `Map<String, RoutingEntry>`（key = 路由前缀 IP），存入 `instantiationRouteMap`（key = `"deviceName#chipIndex"`）。

**实例化规则：**
- NPU：按 `chassis/slot/ubpu/die` 标签匹配模板节点；每个 NPU 设备生成一份路由表副本。
- L1SW：按 `chassis/index` 标签匹配；L1SW 路由表的出端口名称按实际端口重映射。
- L2SW：按 `index/chip` 标签匹配；4 框实例化时 L2SW 的出端口索引/名称按框间拓扑重映射。
- 深拷贝：`deepCopyRoutingEntry` 保证 `instantiationRouteMap` 与返回值互不影响。

#### 8.5.3 TopoTemplateService（模板解析）

> **对应 `route/topo/template/service/TopoTemplateService.java`**

解析内置拓扑模板 JSON 文件，构建 `SncTopology` 模型（含 SncNode、SncPort、Label、Address、Prefix、Bitmap、PolicyPath、PolicyPrefix 等）。由 `TemplateLoader`、`NodeLoader`、`PortLoader`、`PrefixLoader` 等加载器协作完成反序列化。

### 8.6 HashUtils（hash 封装）

> **对应 `util/HashUtils.java`、`util/UbSwitchHash.java`、`util/DllLoader.java`**

#### 8.6.1 双 JNA 绑定

HashUtils 通过 JNA 加载两个原生库接口：

| 接口 | 原生函数 | 算法 | 用途 |
|:-----|:---------|:-----|:-----|
| `UbSwitchEcmpLibrary` | `ubswitch_Hash_ecmp` | ECMP hash（与 `ubswitch_hash.c` 对应） | L1SW/L2SW 选路（H3~H7） |
| `UbSwitchDieLibrary` | `ubswitch_Hash_dieEcmp` | CRC-8/ATM hash（与 `ubswitch_dieHash.c` 对应） | NPU→L1SW 选路（H1/H2，二元组 `(DstCNA, jettyId)`） |

**JNA 加载流程：**
1. `DllLoader` 按 jar 同级目录、classpath 提取等顺序搜索原生库文件；
2. `Native.load("ubswitch_hash", UbSwitchEcmpLibrary.class)` 加载 ECMP 库；
3. `Native.load("ubswitch_dieHash", UbSwitchDieLibrary.class)` 加载 die 库；
4. 任一加载失败时回落到 `UbSwitchHash`（纯 Java 实现，与两个 C 文件逻辑一一对应）。

#### 8.6.2 Java fallback（UbSwitchHash）

`UbSwitchHash` 提供 `hashEcmp` 与 `hashDieEcmp` 两个静态方法，逻辑与原生库完全一致，用于：
- 测试环境无原生库时；
- JNA 加载失败时自动回落；
- 双路径一致性测试验证（同时调用 native 与 Java 实现对比结果）。

#### 8.6.3 关键 API

```java
public class HashUtils {
    public static final int JETTY_ID_MIN = 32;
    public static final int JETTY_ID_MAX = 1023;

    /** ECMP hash（L1SW/L2SW 选路） */
    public static int nativeHash(String dstCna, int ecmpCnt, int hashFunc);

    /** die hash（NPU→L1SW 选路，二元组 (DstCNA, jettyId)） */
    public static int nativeHashDstCnaJetty(String dstCna, int jettyId, int ecmpCnt, int hashFunc);

    /** 校验 jettyId 取值范围 [32, 1023] */
    public static boolean isValidJettyId(int jettyId);
}
```

### 8.7 覆盖规划关键设计决策

> 本节合并自原《SNC NPU-L1 Coverage Path Planning Design》文档的 §12 开放问题与 §13 实施补充说明，记录 2026-09-13 落地的设计决策。

#### 8.7.1 接口命名（Q1）

| 决策 | 选项 | 最终采用 |
|:---|:---|:---|
| 扩展接口命名 | `planPathsCoverageEx` / `planPathsCoverageWithNpuL1` / `planPathsFullCoverage` | **`planPathsCoverageEx`**（精简、保留原接口名前缀） |

#### 8.7.2 SCNA 语义（Q2）

| 决策 | 选项 | 最终采用 |
|:---|:---|:---|
| NPU 出端口 hash 使用的 SCNA | 流的源 CNA / NPU 端口级 CNA | **流的源 CNA**（沿用既有约定；若硬件实现按出端口 CNA 参与 hash，需按实际行为调整） |

#### 8.7.3 REDUNDANT 覆盖粒度（Q3）

| 决策 | 选项 | 最终采用 |
|:---|:---|:---|
| REDUNDANT 的 "≥2" 应用粒度 | 按层统一配置 / 按子层精细配置 | **按层统一配置**（NPU_L1 全部 ≥ 2，L1_L2 全部 ≥ 2）；如有更细粒度需求可分层配置 |

#### 8.7.4 CoverageLinkScope 取值（Q4）

| 决策 | 选项 | 最终采用 |
|:---|:---|:---|
| 是否支持仅 NPU↔L1（不含 L1↔L2） | 加 `NPU_L1` 枚举值 / 不加 | **不加**（当前仅 `L1_L2` / `NPU_L1_L2`；如需可后续扩展） |

#### 8.7.5 诊断计数实例化（Q5）

| 决策 | 选项 | 最终采用 |
|:---|:---|:---|
| 失败计数器是 `static` 还是实例字段 | `static`（全局共享）/ 实例字段（每次构造独立） | **实例字段**（`CoveragePlanEngine.ExDiagnostics`，每次构造引擎时重置；并发安全） |

#### 8.7.6 CoverageLink 字段命名（Q6）

| 决策 | 选项 | 最终采用 |
|:---|:---|:---|
| `CoverageLink.switchDevice` 是否改名为 `deviceName` | 改名 / 保留原名 | **改名为 `deviceName`**（与其他 DTO 字段命名一致；JSON 契约同步更新） |

#### 8.7.7 路由范围扩展与接收语义

**接收语义（关键前提）：** 目的 CNA 属于某 NPU 设备，该 NPU 就能接收该报文，即使报文到达的端口并不是该 CNA 自己对应的物理端口。因此路由/选口的约束从 "CNA ↔ 端口一一对应" 放宽为 "**CNA 所属 NPU 设备可达**"。

| 位置 | 旧口径 | 扩展后口径 |
|:---|:---|:---|
| L1SW 路由 | 仅为"物理相连端口"的 CNA 建 /32 路由 | 对**有端口的每个 NPU**，为其**每个 CNA** 建 /32 路由，出端口 = 该 L1SW 到该 NPU 的**全部**端口 |
| L2SW→L1SW 选口 | 固定用 `dst.remoteL1sw`（目的端口所在的 L1SW） | 任意"能到达目的 NPU 设备的 L1SW" |
| L1SW→NPU 选口 | 路由仅 1 个出端口（无 ECMP） | 该 L1SW 到目的 NPU 的全部端口（≥2 → hash 可选） |

**副作用（正向）：** L1SW→NPU 与 L2SW→L1SW 两跳的 ECMP 成员集不再退化，覆盖规划可以真正"踩"到这些出端口，NPU↔L1SW 层覆盖率可达 100%。

#### 8.7.8 EID 与出端口的关系

- `srcPort` / `srcCna` / `srcEid` 标识的是**端点身份**（哪台设备的哪个逻辑端口发起/接收该流），**不约束**报文的物理出口；
- 源 NPU 收到报文后，按 **CRC8 `(DstCNA, jettyId)`** 在自己的上连端口（对目的所经 L1SW 的全部端口）中选择真实出口；**被选中端口的 CNA 才是后续 L1/L2 选口使用的 SCNA**；
- 因此 `CoveredEidPair.srcPort`（选定的端点身份）与 `coveredLinks[0].outPort`（真实出口）**可以不同**，这是设计上的有意行为；
- ACK 方向同理：`destPort` 是 ACK 的发送端点身份，真实出口由 `(srcCna, 源端口 jettyId)` 决定（jettyId 取自源 NPU 端口，与正向同一）。

#### 8.7.9 原生库 CRC8 算法细节

`ubswitch.c`（仓库根目录）导出符号：

```c
int ubswitch_Hash_dieEcmp(const char *dst_cna, int jetty_id, int ecmp_cnt);
/* CRC-8/ATM: poly 0x07, init 0x00, 无反转、无最终异或
   字节流 = DstCNA 的 ASCII（不含结尾 NUL）+ jettyId 低字节 + jettyId 高字节
   ecmp_cnt == 0 → 返回原始 CRC（0..255）；ecmp_cnt > 0 → CRC % ecmp_cnt */
```

| 用途 | 原生符号 | Java 入口 |
|:---|:---|:---|
| 框间 L1SW↔L2SW 选口、L1SW→NPU 选口 | `ubswitch_Hash_ecmp` | `HashUtils.nativeHash(...)` |
| **NPU→L1SW 选口（CRC8）** | **`ubswitch_Hash_dieEcmp`** | **`HashUtils.nativeHashDstCnaJetty(dstCna, jettyId, ecmpCnt, hashFunc)`** |

二进制构建：`build_ubswitch.ps1`（MinGW `gcc -O2 -shared` 生成 `libubswitch.dll`；`clang --target={x86_64,aarch64}-unknown-linux-gnu -fuse-ld=lld -nostdlib -shared` 生成两个 `.so`），产物落在 `umdk/src/snc/src/main/resources/`。CRC8 正确性由 `HashUtilsJettyTest.crc8MatchesReference` 用 Java 参考实现逐位比对（含 `ecmpCnt` 取模）。

#### 8.7.10 实测结果（2026-09-13 落地）

| 场景 | 接口 | status | 框间对数 | 框内对数 | NPU_L1 覆盖率 | L1_L2 覆盖率 | 报告 |
|:---|:---|:---|--:|--:|--:|--:|:---|
| **全机架 4 框**（148 设备） | `planPathsCoverageEx` | **SUCCESS** | **598** | 0 | **100.00% (2048/2048)** | **100.00% (2048/2048)** | `target/coverage-rack4-report.md`（耗时 ≈189s） |
| 2 机框子集 | `planPathsCoverage`（仅框间） | 见 `PlanPathsCoverageIntegrationTest` | — | — | — | — | 控制台输出（`CoverageMainSuccessTest`） |
| 单机框（无 L2SW） | `planPathsCoverageEx` | SUCCESS | 0 | 18 | 100% (64/64) | 0/0 | `target/coverage-intra-chassis-report.md` |

> 全机架 4 框 = `FullRackTopologyGenerator` 生成内容（128 NPU × 8 端口 + 16 L1SW + 4 L2SW），覆盖链路域 4096 条（NPU_L1 2048 = NPU→L1 1024 + L1→NPU 1024；L1_L2 2048 = L1→L2 1024 + L2→L1 1024），**全部 4096 条被 598 个框间 EID 对覆盖**，10 项引擎诊断计数全为 0、`jettyIdFallback` 为 0。

#### 8.7.11 测试约定（2026-09-13）

**2 机框场景只用于老接口 `planPathsCoverage` 的回归测试**（`PlanPathsCoverageIntegrationTest`、`CoverageMainSuccessTest`）；新接口 `planPathsCoverageEx` 的自动化测试全部基于 `FullRackTopologyGenerator` 生成的拓扑、裁剪为**单机框**子集：

- `PlanPathsCoverageExIntegrationTest`（北向 `SncService`，类比老接口集成测试）：MIN/REDUNDANT 覆盖率 + 状态机/空参/SuperNode 不存在/uninit 四类契约用例；
- `CoverageIntraChassisTest`（`PathService` 层）：框内 2 跳 + CRC8 选口 + SCNA 链接 + 分层统计 + 路由范围端到端校验，并产出框内覆盖率报告。
- `FullRackTopologyJettyIdTest`：`FullRackTopologyGenerator` 用固定分配 `JETTY_ID_BASE + portIndex`（32..39，每次生成完全一致）。

#### 8.7.12 框间流程示例（4 跳 + ACK）

> 示例数据取自 2 机框拓扑的规划输出。按 §8.7.11 的测试约定，2 机框场景只做老接口回归，因此本示例作为**流程走查**；新接口的自动化断言见 §8.7.13（单机框）。

拓扑：2 机框子集（8 NPU + 8 L1SW + 4 L2SW）。EID 对：`rack2#board1#npu1:400GUB 1/2/1` ↔ `rack1#board1#npu2:400GUB 1/4/1`。

| # | 方向 | 设备 | 出端口 | 对端 | 对端端口 | layer |
|--:|:---|:---|:---|:---|:---|:---|
| 0 | 正向 | rack2#board1#npu1 | 400GUB 1/2/1 | rack2#l1sw1 | 400GUB 1/0/1 | NPU_L1 |
| 1 | 正向 | rack2#l1sw1 | 400GUB 1/0/78 | l2sw1 | 400GUB 1/0/7:2 | L1_L2 |
| 2 | 正向 | l2sw1 | 400GUB 1/0/7:2 | rack1#l1sw1 | 400GUB 1/0/78 | L1_L2 |
| 3 | 正向 | rack1#l1sw1 | 400GUB 1/0/3 | rack1#board1#npu2 | 400GUB 1/4/1 | NPU_L1 |
| 4 | ACK | rack1#board1#npu2 | 400GUB 1/4/2 | rack1#l1sw1 | 400GUB 1/0/4 | NPU_L1 |
| 5 | ACK | rack1#l1sw1 | 400GUB 1/0/94 | l2sw1 | 400GUB 1/0/15:2 | L1_L2 |
| 6 | ACK | l2sw1 | 400GUB 1/0/47:2 | rack2#l1sw1 | 400GUB 1/0/94 | L1_L2 |
| 7 | ACK | rack2#l1sw1 | 400GUB 1/0/1 | rack2#board1#npu1 | 400GUB 1/2/1 | NPU_L1 |

**流程要点：**
1. 源 NPU 用 **CRC8 `(DstCNA, jettyId)`** 在"到目的所经 L1SW 的上连端口"里选出口（第 0 跳）；
2. 该选中端口的 **CNA 成为 SCNA**，参与 L1SW→L2SW（第 1 跳）与 L2SW→L1SW（第 2 跳）的选口；
3. 目的侧 L1SW 按 `DstCNA` 查表，在"到目的 NPU 的全部端口"里 hash 选出口（第 3 跳）；
4. ACK 方向（第 4~7 跳）：`DstCNA = 源 CNA`，**jettyId = 源 NPU 端口 jettyId**（与正向同一 jettyId）。

#### 8.7.13 框内流程示例（2 跳 + ACK，真实测试输出）

拓扑：单机框（rack1：4 NPU + 4 L1SW，无 L2SW）→ 阶段 1 无可用 EID 对，全部由阶段 2 覆盖。
EID 对：`rack1#board1#npu2:400GUB 1/4/1` ↔ `rack1#board1#npu1:400GUB 1/2/1`。

| # | 方向 | 设备 | 出端口 | 对端 | 对端端口 | layer |
|--:|:---|:---|:---|:---|:---|:---|
| 0 | 正向 | rack1#board1#npu2 | 400GUB 1/4/1 | rack1#l1sw1 | 400GUB 1/0/3 | NPU_L1 |
| 1 | 正向 | rack1#l1sw1 | 400GUB 1/0/2 | rack1#board1#npu1 | 400GUB 1/2/2 | NPU_L1 |
| 2 | ACK | rack1#board1#npu1 | 400GUB 1/2/1 | rack1#l1sw1 | 400GUB 1/0/1 | NPU_L1 |
| 3 | ACK | rack1#l1sw1 | 400GUB 1/0/4 | rack1#board1#npu2 | 400GUB 1/4/2 | NPU_L1 |

#### 8.7.14 关键不变量

| 编号 | 不变量 |
|:---:|:---|
| I1 | NPU↔L1 成员集只来自**路由表 LPM 命中条目**，不来自物理连接全量枚举（与硬件转发一致） |
| I2 | 成员集 `size == 1` 时 hash 退化为确定选路，与旧接口同场景结果一致 |
| I3 | `linkMap` key 仍为 `deviceName:outPortName`，无跨层冲突；同 key 去重取 `totalOutPorts` 较大者 |
| I4 | `L1_L2` 域下链路域、hash 点位、`CoveredPair` 链路数、统计全部与旧实现逐位一致 |
| I5 | `sum(layerStats[*].totalLinks) == stats.totalLinks`，`sum(layerStats[*].coveredCount) == stats.coveredCount` |
| I6 | 每个 EID 对的正向/反向覆盖链路数相等（CROSS_L2 各 4 条共 8 条；LOCAL_L1 各 2 条共 4 条），jettyId 在两方向相同（均取自源端口） |
| I7 | 贪心与统计逻辑不引入分层分支；分层只出现在 `collectBidirectionalLinks`（域名）与 `buildResult`（统计） |

#### 8.7.15 线程安全

- `CoveragePlanEngine` 本身为无状态对象，`hashFunc` / `fixedDataUdpPort` / `fixedAckUdpPort` / `hashTuple` 为 final 字段。
- `ExDiagnostics` 诊断计数器为**实例字段**（`CoveragePlanEngine` 的内部对象），每次构造引擎时重置；同一引擎实例并发调用不安全，但每次 `planPathsCoverage` / `planPathsCoverageEx` 调用都会构造新引擎，因此北向接口层面并发安全。
- `SncService.routeCalculate` / `makeRoutes` 通过 `synchronized` 保护 `routeCalculated` 标志与 `instantiationRouteMap` 写入；`getNodeRoute` 为只读，可并发；`notifyLinkEvent` 修改 `instantiationRouteMap` 需串行。
- `SuperNode` / `SuperNodeStore` 由调用方保证并发安全（既有约束不变）。

#### 8.7.16 配置兼容

| 配置 | 是否新增 | 说明 |
|:---|:---:|:---|
| `SNCConfig.hashFunc` | 否 | NPU 段 hash 复用同一函数选择器 |
| `SNCConfig.dieHashFunctionSelect` | 是 | NPU→L1SW die hash 函数选择（planPathsCoverageEx 用） |
| `SNCConfig.fixedDataUdpPort` / `fixedAckUdpPort` | 否 | NPU 段复用固定端口（四/五元组参与 hash 时生效） |
| `SNCConfig.hashTuple` | 否 | NPU 段复用同一元组宽度 |
| 新增 NPU 段开关 | **不加** | 是否启用由调用哪个接口决定（`planPathsCoverage` vs `planPathsCoverageEx`） |

---
## 9 路径规划详细流程

### 9.1 流程概述

路径规划以**二阶段循环（前向→反向）+ 直连短路**为整体控制结构，共 11 个步骤（Step 0 ~ Step 10）：

```
                                      阶段1
                                  ┌──────────────┐
                                  │ Step 0 ~ 2    │
                                  │ 设备判断/      │
                                  │ 节点判断       │
                                  └───────┬──────┘
                                          │
                              ┌───────────┴───────────┐
                              ▼                       ▼
                     ┌────────────────┐     ┌──────────────────┐
                     │ interDevices   │     │ interDevices     │
                     │ 为空 (直连)    │     │ 非空 (多跳)      │
                     └───────┬────────┘     └────────┬─────────┘
                             │ Step 4               │ Step 5
                             ▼                      ▼
                     ┌────────────────┐     ┌──────────────────┐
                     │ 直连路径验证    │     │ 多跳路径还原      │
                     │ (终端步，无路由) │     │ → InternalPathInfo│
                     └───────┬────────┘     └────────┬─────────┘
                             │ 成功返回               │
                             │ (码0)                 │
                             │                       ▼
                             │              ┌──────────────────┐
                             │              │ Step 6           │
                             │              │ 前向初始化        │
                             │              │ dst=dev2         │
                             │              └────────┬─────────┘
                             │                       ▼
                             │              ╔══════════════════╗
                             │              ║ 前向规划循环     ║
                             │              ║ Step 8→9 × n    ║
                             │              ╚══════╤═══════════╝
                             │                       ▼
                             │              ┌──────────────────┐
                             │              │ Step 10          │
                             │              │ dst==dev2?       │──→ Step 7 (反向)
                             │              │ 是 (前向完成)    │     dst=dev1
                             │              └──────────────────┘         │
                             │                                          ▼
                             │                                 ╔════════════════════╗
                             │                                 ║ 反向规划循环       ║
                             │                                 ║ Step 8→9 × n      ║
                             │                                 ╚══════╤═════════════╝
                             │                                          ▼
                             │                                 ┌──────────────────┐
                             │                                 │ Step 10          │
                             │                                 │ dst==dev1?       │──→ §9.5 (构造输出)
                             │                                 │ 是 (反向完成)    │
                             │                                 └──────────────────┘
                             │                                          │
                             │                                          ▼
                             │                                 ┌──────────────────┐
                             │                                 │ Step 9~10        │
                             │                                 │ UDP端口计算+输出 │
                             └─────────────────────────────────┴──────────────────┘
```

**二阶段循环说明：**

| 阶段 | 方向 | 目标地址 (targetAddr) | 目的设备 | 执行路径 |
|:-----|:-----|:----------------------|:---------|:---------|
| 前向 (Step 6) | dev1 → dev2 | CNA2 (= dev2 端口 IP) | dev2 | Step 6 → [8 → 9]^n → 10 |
| 反向 (Step 7) | dev2 → dev1 | CNA1 (= dev1 端口 IP) | dev1 | Step 7 → [8 → 9]^n → 10 → §9.5（构造输出） |

**直连短路说明：**
- Step 4 为**终端步骤**——直连路径验证通过后**直接返回成功**（码 0），跳过阶段3（路由规划 Step 6~8）和阶段4（构造输出 Step 9~10）。
- 直连场景两设备 NPU 端口直接相连，路径中不经过任何交换设备，因此**无需执行路由表查找**。通信路径由端口物理连接关系保证。

---

### 9.2 阶段1：设备判断与源目的信息查找（Step 0 ~ 2）

**Step 0 - superNodeName 定位与源和目的设备判断：**
1. **超节点定位：** 根据 `request.superNodeName`（§6.1）在 `SuperNodeStore.superNodeMap`（§7.9）中定位目标超节点的 `SuperNode`（§4.1）。
   - 若 `superNodeName` 为空或对应的 `SuperNode` 不存在 → 返回错误码 **1012**（`TOPO_NOT_FOUND`，§6.2 PlanStatus），流程终止。
2. **源和目的设备判断：** 在目标 `SuperNode.getNpuDevices()`（§4.1）中查找源设备 `dev1` 和目的设备 `dev2`。路径规划仅处理 NPU 设备，SW 设备不参与 src/dest 查找。
3. 若任一设备不存在 → 返回错误码 **1007**（`TOPO_INCOMPLETE`，§6.2 PlanStatus），流程终止。
   > **说明：** Step 0 中 `superNodeName` 不存在与设备在 `SuperNode.getNpuDevices()` 中找不到是两个不同层面的错误。`superNodeName` 不存在表示超节点数据未下发，返回 `TOPO_NOT_FOUND`(1012)；设备在已加载的超节点中找不到表示拓扑数据不完整，返回 `TOPO_INCOMPLETE`(1007)。错误码定义见 §6.2 PlanStatus。
4. 两个设备类型都必须为 `NPU`（`DeviceType.NPU`，§4.3.1）。
5. 若不是 NPU → 返回错误码 **3002**（`SRC_AND_DST_MUST_BE_NPU`，§6.2 PlanStatus）。
6. **UPI 一致性校验：** 校验源设备端口 `port1` 的 `upi`（§4.5.1 `NpuPortEntity.upi`，32 bit）与目的设备端口 `port2` 的 `upi` 是否一致。若不一致 → 返回错误码 **3003**（`UPI_MISMATCH`，§6.2 PlanStatus），流程终止。
7. 成功 → 记录当前 `superNodeName` 供后续 Step 使用，进入 Step 1。

**Step 1 - 查找源信息：**
查看并记录源设备 `dev1` 的以下信息：
- `EID1`（端口关联的 EID），来自 `NpuPortEntity.eid`（§4.5.1）
- `CNA1`（端口关联的 CNA），来自 `PortEntity.cna`（§4.5）
- `port1` 连接信息（`remoteDevice`、`remotePort`），来自 `PortEntity`（§4.5）

若任一信息缺失 → 返回错误码 **1003**（`SRC_INFO_ERR`，§6.2），流程终止。
成功 → 进入 Step 2。

**Step 2 - 查找目的信息：**
查看并记录目的设备 `dev2` 的以下信息：
- `EID2`（端口关联的 EID），来自 `NpuPortEntity.eid`（§4.5.1）
- `CNA2`（端口关联的 CNA），来自 `PortEntity.cna`（§4.5）
- `port2` 连接信息（`remoteDevice`、`remotePort`），来自 `PortEntity`（§4.5）

若任一信息缺失 → 返回错误码 **1004**（`DST_INFO_ERR`，§6.2），流程终止。
成功 → 进入 Step 3。

---

### 9.3 阶段2：路径还原（Step 3 ~ 5）

> **数据结构参见：** §4.3 DeviceEntity（含 getForwardingChips() 抽象方法）、§4.4 ForwardingChip（含 getPorts() 抽象方法）、§4.5 PortEntity、§5.1 InternalPathInfo/InternalPathHop、§6.1 PathPlanRequest

**Step 3 - 判断中间节点：**
检查 `request.interDevices`（§6.1）是否为空：
- 无中间节点 → 跳转到 Step 4（直连场景）。
  > **V1 行为说明：** 当前版本 V1 未实现自动寻路算法。`interDevices` 为空时，引擎仅处理直连场景：
  > - 先执行 Step 4 直连验证：若端口连接关系验证通过 → 返回直连结果（成功）。
  > - 若直连验证失败 → 返回错误码 **1008**（`TOPO_CONNECTION_ERROR`，§6.2），流程终止。引擎不会尝试自动发现多跳路径。
  > - 调用方需自行保证：若源和目的设备非直连，必须在 `interDevices` 中显式指定中间设备及出端口。
- 有中间节点 → 跳转到 Step 5（多跳场景，必须显式指定中间设备及出端口）。

**Step 4 - 直连路径验证（终端步骤）：**
验证双向连接关系：
- `port1.remoteDevice == dev2.deviceName` 且 `port1.remotePort == port2.portName`
- `port2.remoteDevice == dev1.deviceName` 且 `port2.remotePort == port1.portName`

若验证通过 → 按 `PathPlanResult` 构造返回结果（两跳路径，§6.2），**直接返回成功（码 0）**，不再执行阶段3和阶段4。

若验证失败 → 返回错误码 **1008**（`TOPO_CONNECTION_ERROR`，§6.2）。

> **直连短路语义：** Step 4 为终端步骤。直连场景的通信路径由端口物理连接关系保证，不依赖路由表（§4.7）转发，因此**不执行**阶段3（Step 6~8，路由规划）和阶段4（Step 9~10，UDP端口计算与输出构造）。这是设计上的有意行为。

**Step 5 - 多跳路径还原：**
使用 `request.interDevices` 和真实拓扑数据，构建完整的 `InternalPathInfo`（§5.1）。

**5.1 拓扑数据校验：**
依次遍历 `interDevices` 的每个 `{deviceName → outPort}` 条目，在 `SuperNode.devices` 中检查：
- 设备存在性：若 `superNode.devices.get(deviceName)` 返回 null → 返回错误码 **1007**（`TOPO_INCOMPLETE`），流程终止。
- 端口存在性：若该设备的任何转发芯片的 `ports` 中找不到 `outPort`（通过 `device.getForwardingChips()` 遍历所有芯片，再调用 `chip.getPorts()` 查找端口） → 返回错误码 **1007**（`TOPO_INCOMPLETE`），流程终止。

**5.2 路径构建：**
按顺序组装完整的 `InternalPathInfo.hops` 列表：

```
hops[0]   = dev1           (inPort=null, outPort=port1)
hops[1]   = interDevices[0] (inPort=port1.remotePort, outPort=interDevices[0].outPort)
hops[2]   = interDevices[1] (inPort=前一跳 remotePort, outPort=interDevices[1].outPort)
...
hops[n]   = interDevices[k] (inPort=前一跳 remotePort, outPort=interDevices[k].outPort)
hops[n+1] = dev2           (inPort=最后一跳 remotePort, outPort=null)
```

- **源节点（hops[0]）：** `inPort=null`，`outPort=request.srcPort`，`cna`/`eid` 取自源端口。
- **中间节点（hops[1] ~ hops[n]）：** `inPort` 取自上一跳的 `remotePort`，`outPort` 在 `interDevices` 中指定。
  - 对于 SW 设备：`cna` 可能为 null（SW 端口 cna 可选，§4.5.2），路由查找时需注意。
  - **连接校验：** 对每一跳执行 `currentHop.remoteDevice == nextHop.deviceName` 且 `currentHop.remotePort == nextHop.inPort`，保证路径连续。
- **目的节点（hops[n+1]）：** `outPort=null`，`inPort` 取自前一跳的 `remotePort`。

**5.3 连接关系验证：**
每一跳的 `remoteDevice` / `remotePort` 必须与下一跳的 `deviceName` / `inPort` 一致。若不一致 → 返回错误码 **1009**（`TOPO_CONNECTION_NOT_FOUND`，§6.2）。

> **实现说明：** 设备查找使用 `superNode.getAllDevices()` 返回的统一视图（合并 npuDevices + swDevices），通过 HashMap O(1) 定位；端口通过 `NpuDevice.findNpuPort()`（NPU 设备，直接使用 `NpuForwardingChip.getNpuPorts()`，无需 instanceof/cast）或遍历转发芯片的 `getPorts()` Map（SW 设备）进行查找（§4.4、§4.5）。端口所属芯片（`chipIndex`）在 Step 8 路由查找时通过遍历设备所有 `ForwardingChip`（通过 `device.getForwardingChips()`）自动覆盖，无需在 Step 5 额外记录。

---

### 9.4 阶段3：路径规划循环（Step 6 ~ 8）

> **数据结构参见：** §4.7 RoutingTable（含 maskLengths）、§4.8 RoutePrefix、§4.9 RoutingEntry/OutPortInfo、§5.2 RouteSelectionRecord、§8 索引掩码匹配算法

阶段3 的核心结构为一个**二阶段循环**，以 `currentPhase` 状态标识区分前向/反向：

```
前向 (Step 6)          反向 (Step 7)
     │                       │
     ▼                       ▼
┌─────────────────────────────────────┐
│ Step 8: 路径规划循环（中间设备逐一执行） │
│   for each intermediate device:     │
│     1. 遍历该设备所有 ForwardingChip │
│     2. 对每个芯片做索引掩码匹配 (targetAddr) │
│     3. 取所有芯片的最优结果               │
│     4. 验证路由出端口与拓扑连接一致性      │
│     5. 若 ECMP → 记录 RouteSelectionRecord │
│   循环结束后:                         │
│     若 FORWARD → 切换反向 (Step 7)    │
│     若 REVERSE → 进入构造输出 (§9.5) │
└─────────────────────────────────────┘
```

#### 9.4.1 前向阶段（Step 6 → 8）

**Step 6 - 前向路径规划初始设置：**
- 设置当前阶段标识 `currentPhase = FORWARD`
- 目的设备 = `dev2`，目的端口 = `port2`，目的地址 = `CNA2`（32 bit），源地址 = `CNA1`（32 bit）
- 进入 Step 8

#### 9.4.2 反向阶段（Step 7 → 8）

**Step 7 - 反向路径规划初始设置：**
- 设置当前阶段标识 `currentPhase = REVERSE`
- **路径反转：** 将当前 `InternalPathInfo.hops` 列表逆序排列（`Collections.reverse()`）

  | 属性 | 反转规则 |
  |:-----|:---------|
  | 元素顺序 | 原 hops[i] → 新 hops[n-1-i] |
  | inPort / outPort | 互换：原 inPort → 新 outPort，原 outPort → 新 inPort |
  | cna/eid | 正向取出端口 cna/eid，反转后取入端口 cna/eid（正向 outPort = 反向 inPort，语义一致） |
  | remoteDevice/remotePort | 指向前一 hop 的设备/端口，保持拓扑连接语义 |
  | hopIndex | 重新编号（0 ~ hops.size()-1） |

- 目的设备 = `dev1`，目的端口 = `port1`，目的地址 = `CNA1`（32 bit），源地址 = `CNA2`（32 bit）
- 进入 Step 8

#### 9.4.3 Step 8 - 路径规划循环（核心）

从当前 `InternalPathInfo.hops` 列表中**排除首尾节点**（首 = 当前源设备，尾 = 当前目的设备），对剩余中间设备依次执行路径规划。

> **首尾排除规则（与方向相关）：**
> - 前向阶段（FORWARD）：排除 hops[0]（dev1，源）和 hops[last]（dev2，目的）
> - 反向阶段（REVERSE）：排除 hops[0]（原 dev2，已逆序为路径的起点）和 hops[last]（原 dev1，已逆序为路径的终点）
> - 中间设备标准：**DeviceType == SW** 的交换设备。若反向阶段出现 NPU 设备（不合理路径），其端口无路由表（SW 端口无 CNA），算法在后续步骤会失败。

**对每个中间设备的处理流程：**

**① 地址确定：**
- `targetAddr` = 当前阶段的目的地址（前向 = `CNA2`，反向 = `CNA1`），32 bit CNA 地址。
- `prevHop` = 前一个 hop（已在循环中处理过的前一设备），用于 Step 8 ⑤ 的下一跳验证。

**② 跨芯片路由查找：**
路由表按芯片独立存储（§4.7），入端口所在的芯片不一定包含到达目的地的路由。因此需**遍历当前设备的所有 `ForwardingChip`**（通过 `device.getForwardingChips()` 抽象方法，§4.3），对每个芯片执行以下步骤：

```
for each (ForwardingChip chip in device.getForwardingChips().values()):
    1. 构造 RoutingTableKey(superNodeName, deviceName, chip.chipIndex)
       → 通过 superNodeStore.getRoutingTable(rtKey) 获取 RoutingTable
       → 若返回 null（该芯片无路由表），跳过此芯片，继续下一芯片

    2. 索引掩码匹配（§8.1）：
       maskLengths = routingTable.getMaskLengths()  // 已去重降序
       for each maskLen in maskLengths:
            netAddr = AddressUtils.applyMask(targetAddr, maskLen)
            prefix = RoutePrefix(netAddr, maskLen)
            entry = routingTable.routes.get(prefix)
            if entry != null:
                记录 (chipIndex, entry, maskLen) 为候选
                break  // 跳过该芯片的后续掩码（当前 maskLen 已是最长匹配）

    3. 芯片无路由表（getRoutingTable 返回 null）→ 跳过
```

遍历完成后，从所有芯片的候选结果中选择 `maskLen` 最大的 `RoutingEntry` 作为最终结果：
- **无任何芯片匹配成功 →** 当前设备无到达 `targetAddr` 的路由 → 返回错误码 **1010**（`ROUTE_NOT_REACHABLE`，§6.2）。

> **设计说明：**
> - 多芯片设备中，入端口和路由表可能不在同一芯片。例如：入端口在 chip 0，但路由表在 chip 1。遍历所有芯片确保跨芯片场景也能找到路由。
> - 同一芯片的 `maskLengths` 中存在多种掩码（如 [32, 20]），按从长到短逐级查找。
> - 若某芯片无路由表（`getRoutingTable` 返回 null），直接跳过——不报错，以有路由表的芯片结果为准。

**③ 路由出端口解析：**
找到的 `RoutingEntry` 中包含 `outPortInfos` Map（§4.9）：
- 若 `outPortInfos` 为空 → 无出端口 → 返回错误码 **1010**（`ROUTE_NOT_REACHABLE`）。
- `outPortInfos` 中每个 `OutPortInfo` 的 `portName` 为路由指向的出端口。

**④ 出端口与下一跳一致性校验：**
将路由匹配到的 `outPort`（或 ECMP 候选中的首个端口）与当前 hop 的 `outPort`（来自 `InternalPathHop.outPort`）进行比较：
- 路由的 `outPort` 必须能够连接到路径规划中的下一跳设备。即：`chip.getPorts().get(outPort).getRemoteDevice() == nextHop.deviceName`。
- 若不一致 → 返回错误码 **1010**（`ROUTE_NOT_REACHABLE`），表明路由表与拓扑连接不一致。

> **校验意义：** `interDevices` 指定了路径拓扑（哪个设备连接哪个设备），路由表指定了转发决策。两者必须一致——路由表指向的出端口应当连通到路径中的下一跳设备。此校验捕获路由配置错位问题。

**⑤ 结果汇总后进入 Step 9：**
将最终的 `RoutingEntry` 和当前设备信息传入 Step 9 做出端口判断。

> **下一跳关系：** 对于当前处理的中间设备 `currentHop`：
> - 前向阶段：`currentHop` 的下一个 hop 在路径中索引更大（更靠近目的设备）
> - 反向阶段：`currentHop` 的下一个 hop 在路径中索引更大（此时更靠近原 dev1，即反转后的目的）

如果当前循环已处理完所有中间设备 → 跳过 Step 9，进入 Step 10。

#### 9.4.4 Step 9 - 出端口判断与选路记录

对 Step 8 返回的 `RoutingEntry.outPortInfos` 做出端口判断：

| 条件 | 处理 |
|:-----|:-----|
| `outPortInfos.size() == 1` | 正常使用该出端口，进入下一跳 |
| `outPortInfos.size() > 1` | 创建一条 `RouteSelectionRecord`（§5.2），记录选路信息，进入下一跳；同时 `HopInfo.multiPath=true`、`PathPlanResult.spray=true` 标记该路径包含 ECMP 多路径，由调用方决定逐流策略 |

**RouteSelectionRecord 创建规则（ECMP 场景）：**

```
RouteSelectionRecord record = new RouteSelectionRecord();
record.setDeviceName(currentHop.deviceName);
record.setPrefix(matchedPrefix);                           // 匹配到的 RoutePrefix
record.setCandidateOutPorts(candidateList);                // 所有候选 OutPortInfo
record.setScna(CNA1);                                      // 源 CNA（不变）
record.setDcna(CNA2);                                      // 目的 CNA（不变）
record.setDirection(currentPhase == FORWARD ? Direction.FORWARD : Direction.REVERSE);
// hashInfo 记录三元组标识（SCNA:DCNA），供 §9.5 Step 9 hash 计算使用
record.setHashInfo(CNA1 + ":" + CNA2);
```

- `candidateOutPorts`：所有候选 `OutPortInfo` 都加入，其中与 `interDevices` 指定出端口一致的端口标记为 `selected=true`（即路径指定的目标端口），其余为 `false`。
- 该记录追加到 `RouteSelectionRecord` 列表末尾，供 §9.5 Step 9 使用。

> **框间多路径选路说明：** 当路径上存在多段 ECMP 时（如 L1SW0→L2SW 和 L2SW→L1SW1 均为多路径），本步骤仅记录候选出端口列表及路径指定的目标端口（`selected=true`）。hash 算法搜索满足所有 ECMP 段约束的 UDP 端口号的详细流程见 §9.5 Step 9。

#### 9.4.5 Step 10 - 方向切换判断

根据当前阶段标识 `currentPhase` 决定流程走向：

```
if currentPhase == FORWARD:
    // 前向阶段已完成所有中间设备的路由查找
    // 切换到反向阶段
    → 跳转到 Step 7（反向路径设置）

if currentPhase == REVERSE:
    // 反向阶段也已完成
    // 将路径恢复为正向顺序（再次反转）
    → 执行 path 反转（规则同 Step 7），恢复到正向顺序
    → 进入构造输出阶段（§9.5，Step 9~10）
```

---

### 9.5 阶段4：构造输出（Step 9 ~ 10）

> **数据结构参见：** §5.2 RouteSelectionRecord、§6.2 PathPlanResult/PathInfo/HopInfo

**Step 9 - UDP 端口计算（框间多路径场景）：**

当 `RouteSelectionRecord` 列表非空时，需要为正向和反向分别计算一个 8 bit 源 UDP 端口号（0~255），使 hash 算法在每段 ECMP 上都选中 `interDevices` 指定的路径。

> **位宽约束说明：** `dataUdpSrcPort` 和 `ackUdpSrcPort` 均严格限定为 8 bit（0~255），由硬件卸载寄存器位宽决定。所有涉及 UDP 端口搜索的算法均在此空间内进行。

> **背景：** 框间多路径场景下（如 NPU0↔L1SW0↔L2SW↔L1SW1↔NPU1），中间设备 L1SW0 和 L2SW 上的路由表可能同时存在多个出端口（ECMP）。同一个源 UDP 端口号必须同时满足所有 ECMP 段的 hash 选路约束，确保整个路径按照 `interDevices` 指定的端口连通。

**9.1 Hash 算法定义：**

```
选中端口索引 = hash(SCNA, DCNA, srcUdpPort) % candidateOutPorts.size()
```

- **输入三元组**：`SCNA`（源 CNA，32 bit）+ `DCNA`（目的 CNA，32 bit）+ `srcUdpPort`（源 UDP 端口号，8 bit）
- **输出**：整数 hash 值，对候选端口数取模后得到选中的出端口索引
- **可打桩（stub）**：hash 函数可在测试时注入桩实现，精确控制特定三元组的输出值，绕过多段耦合的搜索复杂度

**9.2 正向路径端口计算（dataUdpSrcPort）：**

正向路径的 UDP 源端口对应 `PathPlanResult.dataUdpSrcPort`，计算过程如下：

```
筛选: direction == FORWARD 的 RouteSelectionRecord 列表 L_fwd

对每个 record r ∈ L_fwd:
    N_r     = r.candidateOutPorts.size()         // 候选端口数
    idx_r   = r.candidateOutPorts中selected=true的索引  // 目标端口位置
    SCNA_r  = CNA1                                 // 源 CNA
    DCNA_r  = CNA2                                 // 目的 CNA

在 0~255 范围内遍历 port ∈ [0, 255]:
    若 ∀ r ∈ L_fwd: hash(SCNA_r, DCNA_r, port) % N_r == idx_r:
        dataUdpSrcPort = port
        break
```

- 条件满足：所有 FORWARD 方向的 ECMP 段都选中了目标端口 → 记录 `dataUdpSrcPort`
- 无解（0~255 范围内不存在满足所有约束的端口值）→ 返回错误码 **1**（`FAILED`）

**9.3 反向路径端口计算（ackUdpSrcPort）：**

反向路径的 UDP 源端口对应 `PathPlanResult.ackUdpSrcPort`，计算过程与正向类似但 SCNA/DCNA 互换：

```
筛选: direction == REVERSE 的 RouteSelectionRecord 列表 L_rev

对每个 record r ∈ L_rev:
    N_r     = r.candidateOutPorts.size()
    idx_r   = r.candidateOutPorts中selected=true的索引
    SCNA_r  = CNA2                                 // 反向：源 CNA = CNA2
    DCNA_r  = CNA1                                 // 反向：目的 CNA = CNA1

在 0~255 范围内遍历 port ∈ [0, 255]:
    若 ∀ r ∈ L_rev: hash(SCNA_r, DCNA_r, port) % N_r == idx_r:
        ackUdpSrcPort = port
        break
```

**9.4 正反向关系说明：**

| 属性 | 正向（dataUdpSrcPort） | 反向（ackUdpSrcPort） |
|:-----|:----------------------|:----------------------|
| Hash 输入 SCNA | CNA1（源端口 CNA） | CNA2（目的端口 CNA） |
| Hash 输入 DCNA | CNA2（目的端口 CNA） | CNA1（源端口 CNA） |
| 源 UDP 端口 | `dataUdpSrcPort`（8 bit） | `ackUdpSrcPort`（8 bit） |
| 对应结果字段 | `PathPlanResult.dataUdpSrcPort` | `PathPlanResult.ackUdpSrcPort` |

- 正反向路径经过的设备和出端口一致（由 `interDevices` 保证），但 hash 输入中的 SCNA/DCNA 互换，因此 `dataUdpSrcPort` 与 `ackUdpSrcPort` **独立计算**，取值可以不同。
- 当路径上仅有一段 ECMP 时，通常存在多个 UDP 端口值满足约束，搜索空间充裕。
- 当路径上存在多段 ECMP（如 L1SW0 和 L2SW 均存在多路径），同一个 UDP 端口必须同时满足多段约束，搜索空间缩小。由于 hash 为打桩实现，测试时可注入精确映射绕过多段耦合。

**9.5 无 ECMP 场景：**

若 `RouteSelectionRecord` 列表为空（路径上所有设备出端口均唯一），此步跳过，`dataUdpSrcPort` 和 `ackUdpSrcPort` 使用默认值或置空。

**9.6 RouteSelectionRecord 生命周期回顾：**

| 阶段 | 操作 | 记录方向 |
|:-----|:-----|:---------|
| 前向 (Step 6→8→9→10) | 正向路径的 ECMP 节点 → 追加记录 | FORWARD |
| 反向 (Step 7→8→9→10) | 反向路径的 ECMP 节点 → 追加记录 | REVERSE |
| §9.5 Step 9 | 按方向分组消费，独立计算 dataUdpSrcPort / ackUdpSrcPort | 两方向 |

**Step 10 - 填充 PathPlanResult：**
填入以下信息到 `PathPlanResult` 对象（§6.2）：
- `sourceEid` / `destEid`：EID 对信息（来自 Step 1/2）
- `path`：路径逐跳信息（`PathInfo` → `List<HopInfo>`），由 `InternalPathInfo.hops`（§5.1）转换为外部 `HopInfo`（§6.2.2）
- `ackUdpSrcPort` / `dataUdpSrcPort`：UDP 端口对信息（若 §9.5 Step 9 已计算）

返回成功（码 **0**），附带完整的 `PathPlanResult` 信息。

---

### 9.6 错误码与步骤映射

| 错误码 | 名称 | 触发步骤 | 说明 |
|:-------|:-----|:---------|:-----|
| 0 | SUCCESS | Step 4 / 10 | 成功（直连成功或完整路径规划成功） |
| 1003 | SRC_INFO_ERR | Step 1 | 源信息缺失 |
| 1004 | DST_INFO_ERR | Step 2 | 目的信息缺失 |
| 1007 | TOPO_INCOMPLETE | Step 0 / 5 | 拓扑不完整（设备在 SuperNode 中找不到） |
| 1008 | TOPO_CONNECTION_ERROR | Step 4 | 直连验证失败（端口连接关系不匹配） |
| 1009 | TOPO_CONNECTION_NOT_FOUND | Step 5 | 多跳路径还原失败（连接关系错误） |
| 1010 | ROUTE_NOT_REACHABLE | Step 8 | 路由不可达（无路由、无出端口或出端口与拓扑不一致） |
| 1011 | COVERAGE_INCOMPLETE | 覆盖规划阶段 | 覆盖规划未达 100%（仅 planPathsCoverage/planPathsCoverageEx） |
| 1012 | TOPO_NOT_FOUND | Step 0 | 超节点不存在 |
| 3002 | SRC_AND_DST_MUST_BE_NPU | Step 0 | 源和目的必须为 NPU 设备 |
| 3003 | UPI_MISMATCH | Step 0 | 源和目的端口 UPI 不一致 |

---

### 9.7 流程数据流总览

```
PathPlanRequest (§6.1)
    │ superNodeName, srcDevice, srcPort, destDevice, destPort, interDevices
    │
┌──────────────────────────────────────────────────────────────────────────┐
│ 阶段1 (Step 0~2): 设备判断与信息查找                                        │
│   SuperNode.getNpuDevices() → NpuDevice → NpuDevice.findNpuPort()        │
│   findNpuPort 使用 NpuForwardingChip.getNpuPorts()，无需 instanceof/cast │
│   提取: EID1, CNA1, EID2, CNA2, port1/port2 连接信息                     │
│   错误码: 3002, 3003, 1003, 1004, 1007, 1012                              │
└─────────────────────────┬────────────────────────────────────────────────┘
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
┌─────────────────────────┐  ┌──────────────────────────────────────────────┐
│ 阶段2: interDevices 为空  │  │ 阶段2: interDevices 非空                       │
│ Step 4: 直连验证 (终端)   │  │ Step 5: 多跳路径还原 → InternalPathInfo         │
│ 错误码: 1008              │  │   校验: 设备存在性, 端口存在性, 连接连续性      │
│ 成功: 直接返回 (码 0)     │  │   错误码: 1007, 1009                           │
└─────────────────────────┘  └─────────────────────┬────────────────────────┘
                                                    │
┌──────────────────────────────────────────────────────────────────────────┐
│ 阶段3 (Step 6→7→8→9→10): 路径规划循环 (前向 + 反向)                       │
│   Step 6: 前向设置 (target=CNA2, dst=dev2, phase=FORWARD)                  │
│   Step 7: 反向设置 (反转路径, target=CNA1, dst=dev1, phase=REVERSE)         │
│                                                                           │
│   Step 8 (对每个中间设备):                                                 │
│     ┌─────────────────────────────────────────────────────────────────┐  │
│     │ ① 遍历 device.getForwardingChips() 所有芯片                         │  │
│     │ ② 对每个芯片: RoutingTableKey → superNodeStore.getRoutingTable   │  │
│     │ ③ 索引掩码匹配: maskLengths[0..n] → RoutePrefix → O(1) 命中       │  │
│     │ ④ 跨芯片择优: 取 maskLen 最大的 RoutingEntry                      │  │
│     │ ⑤ 出端口与下一跳一致性校验                                         │  │
│     │ ⑥ 结果送入 Step 9                                                │  │
│     └─────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│   Step 9: 出端口判断                                                     │
│     1个出端口 → 正常进入下一跳                                            │
│     多个出端口 → 追加 RouteSelectionRecord + multiPath=true/spray=true     │
│                                                                           │
│   错误码: 1010                                                            │
└──────────────────────────────────────────┬───────────────────────────────┘
                                           │
┌──────────────────────────────────────────────────────────────────────────┐
│ 阶段4 (Step 9~10): 构造输出                                              │
│   Step 9: UDP 端口计算 (基于前向+反向 的 RouteSelectionRecord 列表)       │
│   Step 10: InternalPathInfo → PathPlanResult [§6.2]                     │
│   返回成功 (码 0)                                                        │
└──────────────────────────────────────────────────────────────────────────┘
```

---

---
