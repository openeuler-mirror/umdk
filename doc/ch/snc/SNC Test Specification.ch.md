# SNC 模块测试设计

## 1. 测试架构总览

### 1.1 分层策略

采用与开发分层对应的测试策略，使用真实实例（不 mock），通过构造参数注入依赖：

| 层 | 测试类型 | 策略 |
|:---|:---------|:-----|
| entity | 单元测试 | 纯数据类，覆盖构造/Getter/Setter/equals/hashCode/toString |
| dto | 单元测试 | 纯数据类，同 entity 层模式 |
| config | 单元测试 | 配置类，覆盖默认值/全参/Getter/Setter |
| exception | 单元测试 | 异常类，覆盖构造/错误码 |
| util | 单元测试 | 工具类，覆盖算法正确性（掩码/IP转换/CNA补齐） |
| store | 单元测试 | 内存存储，覆盖 init/replace/get/remove/clear |
| engine | 单元测试 | 算法引擎，覆盖 LPM/路径还原 |
| service | 单元测试 | 业务编排，store/engine 验证流程 |
| SNCServiceImpl | 集成测试 | 完整链路，结合 JSON 测试工具 |

### 1.2 测试包结构

```
src/test/java/com/huawei/umdk/snc/
├── SNCServiceIntegrationTest.java    # 集成测试（主入口）
├── TestDataLoader.java               # 测试数据加载工具
├── entity/                           # entity 层单元测试（22 classes，含 LinkEvent）
│   ├── DeviceEntityTest.java
│   ├── DeviceTypeTest.java
│   ├── ForwardingChipTest.java
│   ├── InternalPathHopTest.java
│   ├── InternalPathInfoTest.java
│   ├── LinkEventTest.java            # 新增：链路事件实体
│   ├── LogicPortEntityTest.java
│   ├── MgmtInfoTest.java
│   ├── NpuDeviceTest.java
│   ├── NpuForwardingChipTest.java
│   ├── NpuPortEntityTest.java        # 更新：含 jettyId 字段测试
│   ├── OutPortInfoTest.java          # 更新：含 convergedFlag/setFlag/clearFlag/isConverged 测试
│   ├── RoutePrefixTest.java
│   ├── RouteSelectionRecordTest.java
│   ├── RoutingEntryTest.java         # 更新：含 reachable 字段 + refreshReachable 测试
│   ├── RoutingTableKeyTest.java
│   ├── RoutingTableTest.java
│   ├── SwDeviceTest.java
│   ├── SwForwardingChipTest.java
│   ├── SwitchLevelTest.java
│   ├── SwPortEntityTest.java
│   └── SuperNodeTest.java
├── dto/                              # dto 层单元测试
│   ├── PathPlanRequestTest.java
│   ├── PathPlanResultTest.java       # 更新：含 COVERAGE_INCOMPLETE 状态
│   ├── PathInfoTest.java
│   ├── HopInfoTest.java
│   ├── CoveragePathsRequestTest.java          # 新增
│   ├── CoveragePathsResultTest.java           # 新增
│   ├── CoverageStatsTest.java                 # 新增
│   ├── CoverageLayerStatsTest.java            # 新增
│   ├── CoverageLinkTest.java                  # 新增
│   ├── CoverageLinkScopeTest.java             # 新增
│   ├── CoverageLinkLayerTest.java             # 新增
│   ├── CoveragePathTypeTest.java              # 新增
│   ├── CoverageRequirementTest.java           # 新增
│   ├── CoveredEidPairTest.java                # 新增
│   └── CoveredEidPairRefTest.java             # 新增
├── config/                           # config 层单元测试
│   └── SNCConfigTest.java
├── exception/                        # exception 层单元测试
│   ├── SNCExceptionTest.java
│   ├── SNCStateExceptionTest.java
│   ├── SuperNodeNotFoundExceptionTest.java
│   └── PathPlanExceptionTest.java
├── util/                             # util 层单元测试
│   ├── AddressUtilsTest.java
│   ├── HashUtilsTest.java                    # 新增：含 nativeHash/nativeHashDstCnaJetty/isValidJettyId
│   ├── UbSwitchHashTest.java                 # 新增：Java fallback 正确性
│   └── DllLoaderTest.java                    # 新增：JNA 搜索路径
├── store/                            # store 层单元测试
│   └── SuperNodeStoreTest.java
├── engine/                           # engine 层单元测试
│   ├── RouteLookupEngineTest.java
│   ├── PathEngineTest.java
│   └── CoveragePlanEngineTest.java           # 新增：findCoverage/findCoverageEx + 两阶段覆盖 + getExDiagnostics
├── route/                            # route 层单元测试（新增）
│   ├── model/
│   │   ├── RouteTableTest.java
│   │   ├── RouteEntryTest.java
│   │   ├── InboundTest.java
│   │   ├── NextHopPortTest.java
│   │   └── OriginNodeTest.java
│   ├── service/
│   │   ├── RouteMspServiceTest.java          # BFS 最短路径 + 路径策略
│   │   ├── RouteInstantiationServiceTest.java # 模板实例化 + deepCopyRoutingEntry
│   │   └── RouteConvergeServiceTest.java     # BFS 路由收敛 + setFlag/clearFlag/refreshReachable
│   └── topo/
│       └── template/
│           ├── model/TemplateModelTest.java   # SncTopology/SncNode/SncPort/Label 等
│           └── service/TopoTemplateServiceTest.java # 模板解析
└── service/                          # service 层单元测试
    ├── SuperNodeServiceTest.java
    ├── PathServiceTest.java                  # 更新：含 planPathsCoverage/planPathsCoverageEx
    └── LinkEventServiceTest.java             # 新增：handleLinkEvent + 触发收敛
```

---

## 2. 测试层次与用例统计

### 2.1 单元测试

| 层级 | 测试类 | 被测类 | 用例数 |
|------|--------|--------|--------|
| Service | `SuperNodeServiceTest` | `SuperNodeService` | 35 |
| Service | `PathServiceTest` | `PathService`（含 planPathsCoverage/Ex） | 95+ |
| Service | `LinkEventServiceTest` | `LinkEventService` | 25+ |
| Engine | `PathEngineTest` | `PathEngine` | 20 |
| Engine | `RouteLookupEngineTest` | `RouteLookupEngine` | 8 |
| Engine | `CoveragePlanEngineTest` | `CoveragePlanEngine`（findCoverage/Ex + 两阶段） | 80+ |
| Route | `RouteMspServiceTest` | `RouteMspService` | 20+ |
| Route | `RouteInstantiationServiceTest` | `RouteInstantiationService` | 25+ |
| Route | `RouteConvergeServiceTest` | `RouteConvergeService` | 30+ |
| Route | `TopoTemplateServiceTest` | `TopoTemplateService` | 12+ |
| Route | `TemplateModelTest` | SncTopology/SncNode/SncPort/Label 等 | 40+ |
| Route | `RouteTableTest`/`RouteEntryTest`/`InboundTest`/`NextHopPortTest`/`OriginNodeTest` | route.model 各类 | 35+ |
| Store | `SuperNodeStoreTest` | `SuperNodeStore` | 24 |
| Entity | 22 个测试文件（含 LinkEventTest） | 各 Entity 类 | ~170 |
| DTO | 15 个测试文件（含 11 个新增 DTO） | DTO 类 | 80+ |
| Exception | 4 个测试文件 | 异常类 | 18 |
| Config | `SNCConfigTest` | `SNCConfig` | 7 |
| Util | `AddressUtilsTest` + `HashUtilsTest` + `UbSwitchHashTest` + `DllLoaderTest` | AddressUtils + HashUtils + UbSwitchHash + DllLoader | 60+ |

### 2.2 集成测试

| 测试类 | 用例数 | 数据来源 |
|--------|--------|---------|
| `SNCServiceIntegrationTest` | 60+ | JSON 文件 (`topo_data_2npu_1port.json`, `topo_data_4npu_8port.json`, `topo_data_2box_16l2sw.json`) |
| `PlanPathsCoverageExIntegrationTest` | 30+ | 已落地（与 NPU-L1 设计同步落地） |
| `FullRackTopologyJettyIdTest` | 5+ | `FullRackTopologyGenerator` 固定 jettyId 分配（32..39） |

---

## 3. 各层测试设计

### 3.1 Entity 层

22 个 entity 类 + 1 个内部类，共 22 个测试文件，约 170 个测试用例。

| 类别 | 类名 | 测试文件 |
|:-----|:-----|:---------|
| 枚举 | DeviceType | DeviceTypeTest.java |
| 枚举 | SwitchLevel | SwitchLevelTest.java |
| 枚举 | RouteSelectionRecord.Direction | 内嵌在 RouteSelectionRecordTest.java |
| 抽象基类 | DeviceEntity | DeviceEntityTest.java |
| 抽象基类 | ForwardingChip | ForwardingChipTest.java |
| 领域类 | SuperNode | SuperNodeTest.java |
| 领域类 | MgmtInfo | MgmtInfoTest.java |
| 领域类 | NpuDevice | NpuDeviceTest.java |
| 领域类 | SwDevice | SwDeviceTest.java |
| 领域类 | NpuForwardingChip | NpuForwardingChipTest.java |
| 领域类 | SwForwardingChip | SwForwardingChipTest.java |
| 领域类 | NpuPortEntity | NpuPortEntityTest.java |
| 领域类 | SwPortEntity | SwPortEntityTest.java |
| 领域类 | LogicPortEntity | LogicPortEntityTest.java |
| 领域类 | LinkEvent | LinkEventTest.java |
| 领域类 | RoutingTable | RoutingTableTest.java |
| 领域类 | RoutingTableKey | RoutingTableKeyTest.java |
| 领域类 | RoutePrefix | RoutePrefixTest.java |
| 领域类 | RoutingEntry | RoutingEntryTest.java |
| 领域类 | OutPortInfo | OutPortInfoTest.java |
| 计算模型 | InternalPathInfo | InternalPathInfoTest.java |
| 计算模型 | InternalPathHop | InternalPathHopTest.java |
| 计算模型 | RouteSelectionRecord | RouteSelectionRecordTest.java |

**测试模式（Pattern）：** 每个实体类遵循统一的 7 步模板：
1. `testDefaultConstructor()` → 验证所有字段为 null/false
2. `testAllArgsConstructor()` → 验证全参构造字段赋值正确
3. `testSettersAndGetters()` → 验证 Setter/Getter 正确性
4. `testEquals()` → 等价性（相同对象相等、不同对象不等、非空性、自反性）
5. `testHashCode()` → hashCode 一致性
6. `testToString()` → toString 包含关键字段
7. 枚举：额外验证 `values()` 数组和 `valueOf()` 转换

**特化模式：**
- 抽象基类（ForwardingChip/DeviceEntity）：通过匿名子类测试父类方法
- `RoutePrefix`/`RoutingTableKey`（HashMap key 类）：额外覆盖 null 字段边界
- `SuperNode`：额外覆盖 `getNpuDevices`/`getSwDevices`/`getAllDevices` 合并逻辑
- `NpuDevice`：额外覆盖 `findNpuPort` 跨芯片搜索、null 芯片/null 端口边界
- `NpuPortEntity`：额外覆盖 `jettyId` 字段（含扩展构造器）；越界 jettyId 触发 `HashUtils.isValidJettyId` 抛 `IllegalArgumentException`
- `OutPortInfo`：额外覆盖 `convergedFlag` 位运算：`setFlag`/`clearFlag`/`isConverged`；FLAG_PASSIVE_CONVERRGED / FLAG_ACTIVE_CONVERRGED 位组合
- `RoutingEntry`：额外覆盖 `reachable` 字段；`refreshReachable()` 在 0/1/多 outPort 场景下的状态变化；`RoutingEntry.copy(src)` 深拷贝语义
- `LinkEvent`：额外覆盖 `eventType` 仅接受 "up"/"down"，其他值抛 `IllegalArgumentException`；全参构造 + Getter/Setter/equals/hashCode/toString

### 3.2 DTO 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| PathPlanRequest | 8+ | 构造/Getter/Setter/equals/hashCode/toString；`interDevices` 为 null 场景 |
| PathPlanResult | 12+ | 同上 + `PlanStatus` 枚举覆盖（11 个 status 值，含 COVERAGE_INCOMPLETE/TOPO_NOT_FOUND）+ 成功/失败构造；`spray` 字段 |
| PathInfo | 6+ | 构造/Getter/Setter/equals/hashCode/toString；`hops` 为 null 场景 |
| HopInfo | 8+ | 构造 + `multiPath`/`deviceType` 字段 + 源/目的/中间节点字段约束 |
| CoveragePathsRequest | 6+ | 构造 + `superNodeName`/`coverageRequirement`；null coverageRequirement 默认 MIN_COVERAGE |
| CoveragePathsResult | 15+ | 全字段构造 + `scope`/`status`/`eidPairs`/`coverageLinks`/`totalStats`/`layerStats`；layerStats 为 null（planPathsCoverage）与非 null（planPathsCoverageEx）两种 |
| CoverageStats | 10+ | 全字段 + 覆盖率/重复率计算字段 + eidUniformity |
| CoverageLayerStats | 6+ | 构造 + `layer` 枚举 + `stats` 嵌套 |
| CoverageLink | 10+ | 全字段 + `layer`/`deviceType` null 与非 null 场景 |
| CoverageLinkScope | 4+ | 枚举 values() + valueOf()：L1_L2 / NPU_L1_L2 |
| CoverageLinkLayer | 4+ | 枚举 values() + valueOf()：NPU_L1 / L1_L2 |
| CoveragePathType | 4+ | 枚举 values() + valueOf()：CROSS_L2 / LOCAL_L1 |
| CoverageRequirement | 4+ | 枚举 values() + valueOf()：MIN_COVERAGE / REDUNDANT |
| CoveredEidPair | 8+ | 全字段 + `coveredLinks` 列表 + `type` null 与非 null 场景 |
| CoveredEidPairRef | 6+ | 全字段 + `srcEid`/`dstEid` |

### 3.3 Config 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| SNCConfig | 7 | 默认构造（logLevel=INFO）、全参构造、Getter/Setter、equals/hashCode/toString |

### 3.4 Exception 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| SNCException | 4 | 消息构造、Cause 构造 |
| SNCStateException | 4 | 继承关系验证、构造 |
| SuperNodeNotFoundException | 4 | 继承关系验证 |
| PathPlanException | 6 | 错误码构造、Detail 构造、getStatus() |

### 3.5 Util 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| AddressUtils | 31 | `cnaToTargetAddr`、`applyMask`、`ipToInt`、`intToIp`、`isValidCna`、`isValidEid` |
| HashUtils | 18+ | `nativeHash`（ECMP）、`nativeHashDstCnaJetty`（die hash）、`JETTY_ID_MIN`/`JETTY_ID_MAX`、`isValidJettyId`（[32,1023] 范围内/外/null）；native 不可用时回落 UbSwitchHash |
| UbSwitchHash | 15+ | `hashEcmp` 与 `hashDieEcmp` 纯 Java 实现；与原生库双路径一致性测试（`hashEcmp` ↔ `ubswitch_Hash_ecmp`，`hashDieEcmp` ↔ `ubswitch_Hash_dieEcmp`） |
| DllLoader | 8+ | JNA 搜索路径：jar 同级目录、classpath 提取、temp 目录；找不到时返回 null |

### 3.6 Store 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| SuperNodeStore | 24 | init/replace/getSuperNodeData/getRoutingTable/removeSuperNode/clear；addNpuDevice/addSwDevice；多 superNodeName 共存；路由表提取；空设备/null 参数/beforeInit 操作 |

**SuperNodeStore 关键场景：**
1. **基础生命周期**：init → replace → get → clear
2. **路由表索引**：含 routingTable 的 ForwardingChip → replace 后 routingTableMap 正确索引
3. **多超节点共存**：不同 name 的 SuperNode 可独立查询
4. **删除**：removeSuperNode 清除 superNodeMap 和 routingTableMap 对应条目
5. **增量添加**：addNpuDevice/addSwDevice 分别向 npuDevices/swDevices 添加并索引路由表
6. **隐式 Map 创建**：addNpuDevice 时若 npuDevices 为 null 则自动创建新 HashMap

### 3.7 Engine 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| RouteLookupEngine | 8 | LPM 匹配/不匹配/默认路由/空路由/ECMP 多出口；maskLengths=[0] 无匹配 |
| PathEngine | 20 | 直连路径（NpuDevice/NpuPortEntity 重载）/多跳路径/跨芯片路由查找/路径反转/端口查找异常/null 芯片/半连接 |
| CoveragePlanEngine | 80+ | findCoverage（L1↔L2 域）；findCoverageEx（两阶段 CROSS_L2 + LOCAL_L1）；hash 使用点 H1~H7b；jettyIdOf 回落（缺失/越界/null port.id）；getExDiagnostics 全部 10 个诊断计数；MIN_COVERAGE / REDUNDANT 两种 coverageRequirement；COVERAGE_INCOMPLETE 与 SUCCESS 终止条件；EID 均匀度统计 |

**RouteLookupEngine LPM 核心算法：**

| 路由表 | targetAddr | 期望 |
|:-------|:-----------|:-----|
| {/24: eth0, /16: eth1, /0: wan} | "170.170.170.17" | eth0 (/24) |
| {/24: eth0, /16: eth1, /0: wan} | "171.170.170.17" | wan (/0) |
| {} | "1.2.3.4" | null |

**PathEngine 路径还原：**

| 场景 | 期望 |
|:-----|:-----|
| 2 个 NPU 端口直连 | InternalPathInfo.hops.size() == 2 |
| 1 个中间 L1SW | hops.size() == 3 |
| 中间设备不存在 | 抛出 SuperNodeNotFoundException |
| 跨芯片路由查找 | 返回最长前缀匹配条目 |

**CoveragePlanEngine 覆盖规划核心测试：**

| 测试类 | 场景 | 期望 |
|:-------|:-----|:-----|
| CoveragePlanEngineTest | findCoverage：4npu_8port + MIN_COVERAGE | SUCCESS，scope=L1_L2，layerStats=null，coverageRate=1.0 |
| CoveragePlanEngineTest | findCoverage：4npu_8port + REDUNDANT | SUCCESS，coverageRate=1.0，redundantLinks > 0 |
| CoveragePlanEngineTest | findCoverage：拓扑不完整 | COVERAGE_INCOMPLETE，coverageRate < 1.0 |
| CoveragePlanEngineTest | findCoverageEx：跨机框 + 同机框 + MIN_COVERAGE | SUCCESS，scope=NPU_L1_L2，layerStats=[NPU_L1, L1_L2]，两层 coverageRate=1.0 |
| CoveragePlanEngineTest | findCoverageEx：jettyId 缺失 | SUCCESS + exJettyFallback > 0 |
| CoveragePlanEngineTest | findCoverageEx：jettyId 越界（< 32 或 > 1023） | SUCCESS + exJettyFallback > 0（回落 32 + portId） |
| CoveragePlanEngineTest | findCoverageEx：CROSS_L2 EID 对 coveredLinks.size()==8 | 4 正向 + 4 反向 |
| CoveragePlanEngineTest | findCoverageEx：LOCAL_L1 EID 对 coveredLinks.size()==4 | 2 正向 + 2 反向 |
| CoveragePlanEngineTest | findCoverageEx：诊断计数全部为 0 | SUCCESS + 所有 exDiagnostics 字段为 0 |
| CoveragePlanEngineTest | findCoverageEx：NPU 路由 LPM 未命中 | npuRouteFail > 0 |
| CoveragePlanEngineTest | findCoverageEx：L1SW 路由查找失败 | l1Fail > 0 |
| CoveragePlanEngineTest | findCoverageEx：反向 NPU/L1SW/L2SW 失败 | revNpuFail / revDstL1Fail / revL2Fail / revSrcL1Fail > 0 |

### 3.8 Service 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| SuperNodeService | 35 | importSuperNode 校验、addNpuDevices/addSwDevices、getDevice、getRoutingTable、异常处理；空值/空串/空集合参数校验 |
| PathService | 95+ | 完整 planPath 流程（65）+ planPathsCoverage（15+）+ planPathsCoverageEx（15+）；各错误码分支、反射测试（null 字段）、routePhase 异常分支、NpuDevice.findNpuPort 边界；CoveragePlanEngine 构造参数注入；两阶段流程触发；scope/layerStats 验证 |
| LinkEventService | 25+ | handleLinkEvent 正常 down/up 流程；端口状态更新（linkStatus/updateAt）；触发 RouteConvergeService.converge；非法 eventType 抛 IllegalArgumentException；设备/端口不存在抛 IllegalStateException；SuperNode 为 null 抛 IllegalArgumentException |

**PathService 流程覆盖（对应设计文档 §9）：**

| Step | 场景 | 期望 PlanStatus |
|:-----|:-----|:----------------|
| 0 | superNodeName 不存在 | TOPO_NOT_FOUND (1012) |
| 0 | 设备不存在 | TOPO_INCOMPLETE (1007) |
| 1 | srcPort 不存在/CNA/EID 为空 | SRC_INFO_ERR (1003) |
| 2 | destPort 不存在/CNA/EID 为空 | DST_INFO_ERR (1004) |
| 4 | 直连验证失败 | TOPO_CONNECTION_ERROR (1008) |
| 5 | 多跳路径还原失败 | TOPO_CONNECTION_NOT_FOUND (1009) |
| 6-7 | 路由不可达 | ROUTE_NOT_REACHABLE (1010) |
| 9-10 | 成功 | SUCCESS (0) |

**PathService 覆盖规划测试（新增）：**

| 场景 | 期望 |
|:-----|:-----|
| planPathsCoverage：4npu_8port + MIN_COVERAGE | SUCCESS，scope=L1_L2 |
| planPathsCoverage：4npu_8port + REDUNDANT | SUCCESS，redundantLinks > 0 |
| planPathsCoverage：拓扑不完整 | COVERAGE_INCOMPLETE |
| planPathsCoverage：superNodeName 不存在 | TOPO_NOT_FOUND |
| planPathsCoverage：状态非 DATAREADY | SNCStateException |
| planPathsCoverage：request 为 null | IllegalArgumentException |
| planPathsCoverageEx：4npu_8port + jettyId + MIN_COVERAGE | SUCCESS，scope=NPU_L1_L2，layerStats=[NPU_L1, L1_L2] |
| planPathsCoverageEx：jettyId 缺失 | SUCCESS + exJettyFallback > 0 |
| planPathsCoverageEx：拓扑不完整 | COVERAGE_INCOMPLETE |
| planPathsCoverageEx：CROSS_L2 路径长度验证 | coveredLinks.size() == 8 |
| planPathsCoverageEx：LOCAL_L1 路径长度验证 | coveredLinks.size() == 4 |

**LinkEventService 测试场景：**

| 场景 | 期望 |
|:-----|:-----|
| handleLinkEvent：down 事件正常 | port.linkStatus = LINK_DOWN + port.updateAt 更新 + 触发 converge |
| handleLinkEvent：up 事件正常 | port.linkStatus = LINK_UP + port.updateAt 更新 + 触发 converge |
| handleLinkEvent：重复 down 事件 | 幂等，路由状态不变 |
| handleLinkEvent：eventType 非 up/down | IllegalArgumentException |
| handleLinkEvent：deviceName 不存在 | IllegalStateException |
| handleLinkEvent：portName 不存在 | IllegalStateException |
| handleLinkEvent：superNode 为 null | IllegalArgumentException |
| handleLinkEvent：event 为 null | IllegalArgumentException |
| handleLinkEvent：eventTime 为 0 或负数 | 允许（仅作 updateAt 写入，不校验范围） |

### 3.9 SNCServiceImpl

| 测试类别 | 测试用例数 | 关键测试点 |
|:---------|:----------|:-----------|
| 生命周期状态机 | 12+ | INIT→READY→DATAREADY→UNINIT 各状态转换；routeCalculate/makeRoutes/getNodeRoute/notifyLinkEvent 在 READY/DATAREADY 均可用；planPathsCoverage/Ex 仅 DATAREADY |
| 参数校验 | 20+ | 所有入参 null/空字符串检查；CoveragePathsRequest/LinkEvent 字段校验 |
| 异常处理 | 10+ | 未 init/uninit 后调用各方法；routeCalculate 未调用直接 makeRoutes 抛 IllegalStateException；makeRoutes 未调用直接 getNodeRoute 抛异常 |
| 完整链路 | 10+ | 从 init → setSuperNodeData → addNpuDevices → addSwDevices → planPath → planPathsCoverage → planPathsCoverageEx → routeCalculate → makeRoutes → getNodeRoute → notifyLinkEvent → uninit |
| 覆盖规划链路 | 8+ | planPathsCoverage/planPathsCoverageEx 完整流程；scope/layerStats/type 验证 |
| 路由计算链路 | 8+ | routeCalculate 幂等（两次调用）；makeRoutes 实例化；getNodeRoute 查询；notifyLinkEvent 收敛后 getNodeRoute 验证 reachable 变化 |

**状态机测试：**

| 测试场景 | 调用序列 | 期望结果 |
|:---------|:---------|:---------|
| 未 init 直接调用 setSuperNode | setSuperNode(...) | SNCStateException |
| init 后正常调用 | init → setSuperNode | 正常执行，状态进入 DATAREADY |
| uninit 后再次调用 | init → ... → uninit → getSuperNode | SNCStateException |
| 重复 init | init → init | 幂等，不抛异常 |
| READY 状态调用 planPath | init → planPath | SNCStateException（未到 DATAREADY） |
| READY 状态调用 routeCalculate | init → routeCalculate | 正常执行 |
| READY 状态调用 makeRoutes | init → makeRoutes | 抛 IllegalStateException（routeCalculate 未调用） |
| READY 状态调用 notifyLinkEvent | init → notifyLinkEvent | 抛 IllegalStateException（makeRoutes 未调用，instantiationRouteMap 为空） |
| DATAREADY 状态调用 planPathsCoverage | init → setSuperNode → planPathsCoverage | 正常执行 |
| DATAREADY 状态调用 planPathsCoverageEx | init → setSuperNode → planPathsCoverageEx | 正常执行 |

### 3.10 Route 层（新增）

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| RouteMspService | 20+ | BFS 最短路径计算；shortest/secondShortest/other 路径分类；模板路由表生成；单机框/跨机框拓扑；cost=1 一致性；不可达场景 |
| RouteInstantiationService | 25+ | instantiateXpodRoute 按机框扩展；NPU/L1SW/L2SW 标签匹配；4 框实例化时 L2SW 出端口重映射；buildRouteTableKey；deepCopyRoutingEntry 深拷贝语义（修改返回值不影响内部）；空 SuperNode / 无 forwardingChips 边界 |
| RouteConvergeService | 30+ | converge BFS 传播；FLAG_PASSIVE_CONVERRGED setFlag/clearFlag；refreshReachable 状态变化（true→false / false→true）；ECMP 多出端口仅标记命中的一个；同设备不同 chip 转发隔离；幂等性（重复 down 事件）；up 事件清除 PASSIVE 后 BFS 反向传播 |
| TopoTemplateService | 12+ | parseTemplateFile 解析 128_npu_rack.json + 128_npu_inter_rack.json；SncTopology 模型构建；NodeLoader/PortLoader/PrefixLoader 协作；模板文件不存在抛异常 |
| TemplateModel | 40+ | SncTopology/SncNode/SncPort/Label/Address/Prefix/Bitmap/PolicyPath/PolicyPrefix/AddrType 各类构造 + Getter/Setter/equals/hashCode/toString |
| RouteTable / RouteEntry / Inbound / NextHopPort / OriginNode | 35+ | route.model 各类构造 + 字段约束；RouteEntry 的 NhpSet + 路径分类；Inbound 的 inPortId/parentNode/cost/outIfSet；NextHopPort 的 pathType |

**RouteConvergeService 关键测试场景：**

| 场景 | 期望 |
|:-----|:-----|
| 单端口 down：单出端口 RoutingEntry | reachable=false + convergedFlag!=0 + BFS 传播到对端 |
| 单端口 down：ECMP 多出端口 RoutingEntry | 仅命中的 outPort setFlag，reachable=true（其他出端口仍有效），BFS 不传播 |
| 单端口 up：清除 PASSIVE | convergedFlag==0 + reachable=true + BFS 反向传播清除对端 |
| 重复 down 事件 | 幂等，状态不变 |
| 同设备不同 chip 收敛 | 转发隔离，仅 chip C 路由表受影响，chip C' 不受影响 |
| 跨多跳传播 | chip C → N → N' → N'' 链式 reachable 变化 |
| 作用对象验证 | 修改 instantiationRouteMap，不修改 SuperNode.routingTableMap |
| 设备不存在 | 抛 IllegalStateException |
| 端口不存在 | 抛 IllegalStateException |

---

## 4. 测试数据管理

### 4.1 JSON 测试数据

```
src/test/resources/
├── topo_data_2npu_1port.json     # 2 NPU + 1 L1 SW 拓扑（单端口）
├── topo_data_4npu_8port.json     # 4 NPU + 2 L1 SW 拓扑（多端口）
└── topo_data_2box_16l2sw.json    # 2 框 + 16 L2SW 拓扑（跨框路径）
```

### 4.2 TestDataLoader 工具类

`TestDataLoader` 负责从 JSON 文件解析为 Java 对象：
- `loadSuperNode(resourcePath)` — 解析拓扑 JSON 为 `SuperNode`（含 npuDevices、swDevices、芯片、端口、路由表）

### 4.3 2npu_1port 数据（最小验证）

- **NPU1**: 1 个端口 `400GE 0/0/1`, CNA=`170.170.170.18`, EID=`AAAAAA12000000000000000000000002`, UPI=`0A0A0A01`
- **NPU2**: 1 个端口 `400GE 0/1/1`, CNA=`221.221.221.66`, EID=`DDDDDD42000000000000000000000002`, UPI=`0A0A0A01`
- **L1SW0**: 2 个端口连 NPU1/NPU2
- **路由**: NPU1→目标221.221.221.68, L1SW 上有两条路由（170.170.170.17→NPU1侧, 221.221.221.68→NPU2侧）

### 4.4 4npu_8port 数据（全量验证）

- 4 个 NPU 各 8 个端口（共 32 个端口），每个端口有独立 CNA/EID
- 4 个 L1SW 各 8 个端口，无 L2SW
- 每个 NPU 的 8 个端口均分到 4 个 L1SW（每 L1SW 2 个端口）
- 路由表：每个 NPU 8 条路由到其他 NPU（ECMP 2 路），每个 L1SW 4 条路由到各 NPU（单路）

### 4.5 端口命名与编码规则

| 设备类型 | 端口格式 | 示例 |
|:---------|:---------|:-----|
| NPU | `400GE 0/{chipIndex}/{portIndex}` | `400GE 0/0/1` |
| L1SW | `400GE 1/{chipIndex}/{portIndex}` | `400GE 1/0/2` |

| NPU | EID 前缀 | CNA 范围 | UPI | jettyId 范围 |
|:----|:---------|:---------|:------------|:-------------|
| npu1 | AAAAAA | 170.170.170.x | 0A0A0A01 | [32, 1023]；FullRackTopologyGenerator 用 32..39 |
| npu2 | DDDDDD | 221.221.221.x | 0A0A0A01 | [32, 1023]；FullRackTopologyGenerator 用 32..39 |
| npu3 | EEEEEE | 238.238.238.x | 0A0A0A01 | [32, 1023]；FullRackTopologyGenerator 用 32..39 |
| npu4 | FFFFFF | 255.255.255.x | 0A0A0A01 | [32, 1023]；FullRackTopologyGenerator 用 32..39 |

**jettyId 测试数据来源：**
- 超节点 JSON `jettyId` 字段：由 `TestDataLoader` 解析；
- 模板 JSON `jetty_id` 字段：`128_npu_rack.json`，由 `PortLoader`/`SncPort` 承载；
- `FullRackTopologyGenerator` 固定分配 `JETTY_ID_BASE + portIndex`（32..39），由 `FullRackTopologyJettyIdTest` 钉死。

---

## 5. 测试工具与依赖

| 工具 | 版本 | 用途 |
|------|------|------|
| JUnit Jupiter | 5.9.2 | 测试框架 |
| JaCoCo | 0.8.12 | 覆盖率统计 |
| Maven Surefire | 3.2.2 | 测试执行 |
| Lombok | 1.18.36 | POJO 简化 |

---

## 6. 测试命名规范

- 测试类名：`{被测类}Test.java`
- 测试方法名：`{场景}_{预期结果}`（驼峰命名）
- 使用 `@DisplayName` 标注中文描述
- Entity/DTO 测试统一遵循 7 步模板：default → allArgs → setters → equalsEqual → equalsNotEqual → hashCode → toString
