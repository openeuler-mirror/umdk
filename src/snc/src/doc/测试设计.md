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
| engine | 单元测试 | 算法引擎，覆盖 LPM/ACL 校验/路径还原 |
| service | 单元测试 | 业务编排，store/engine 验证流程 |
| SNCServiceImpl | 集成测试 | 完整链路，结合 JSON 测试工具 |

### 1.2 测试包结构

```
src/test/java/com/huawei/umdk/snc/
├── SNCServiceIntegrationTest.java    # 集成测试（主入口）
├── TestDataLoader.java               # 测试数据加载工具
├── entity/                           # entity 层单元测试（25 classes）
│   ├── AclDataTest.java
│   ├── AclKeyTest.java
│   ├── DeviceEntityTest.java
│   ├── DeviceTypeTest.java
│   ├── ForwardingChipTest.java
│   ├── InternalPathHopTest.java
│   ├── InternalPathInfoTest.java
│   ├── LogicPortEntityTest.java
│   ├── MgmtInfoTest.java
│   ├── NpuDeviceTest.java
│   ├── NpuForwardingChipTest.java
│   ├── NpuPortEntityTest.java
│   ├── OutPortInfoTest.java
│   ├── RoutePrefixTest.java
│   ├── RouteSelectionRecordTest.java
│   ├── RoutingEntryTest.java
│   ├── RoutingTableKeyTest.java
│   ├── RoutingTableTest.java
│   ├── SwDeviceTest.java
│   ├── SwForwardingChipTest.java
│   ├── SwitchLevelTest.java
│   ├── SwPortEntityTest.java
│   ├── SuperNodeTest.java
│   ├── TpAclEntityTest.java
│   └── TransportTypeTest.java
├── dto/                              # dto 层单元测试
│   ├── PathPlanRequestTest.java
│   ├── PathPlanResultTest.java
│   ├── PathInfoTest.java
│   └── HopInfoTest.java
├── config/                           # config 层单元测试
│   └── SNCConfigTest.java
├── exception/                        # exception 层单元测试
│   ├── SNCExceptionTest.java
│   ├── SNCStateExceptionTest.java
│   ├── SuperNodeNotFoundExceptionTest.java
│   ├── AclNotFoundExceptionTest.java
│   └── PathPlanExceptionTest.java
├── util/                             # util 层单元测试
│   └── AddressUtilsTest.java
├── store/                            # store 层单元测试
│   ├── SuperNodeStoreTest.java
│   └── AclStoreTest.java
├── engine/                           # engine 层单元测试
│   ├── RouteLookupEngineTest.java
│   ├── AclCheckEngineTest.java
│   └── PathEngineTest.java
└── service/                          # service 层单元测试
    ├── SuperNodeServiceTest.java
    ├── AclServiceTest.java
    └── PathServiceTest.java
```

---

## 2. 测试层次与用例统计

### 2.1 单元测试

| 层级 | 测试类 | 被测类 | 用例数 |
|------|--------|--------|--------|
| Service | `SuperNodeServiceTest` | `SuperNodeService` | 35 |
| Service | `AclServiceTest` | `AclService` | 16 |
| Service | `PathServiceTest` | `PathService` | 65 |
| Engine | `PathEngineTest` | `PathEngine` | 20 |
| Engine | `RouteLookupEngineTest` | `RouteLookupEngine` | 8 |
| Engine | `AclCheckEngineTest` | `AclCheckEngine` | 7 |
| Store | `SuperNodeStoreTest` | `SuperNodeStore` | 24 |
| Store | `AclStoreTest` | `AclStore` | 10 |
| Entity | 25 个测试文件 | 各 Entity 类 | ~174 |
| DTO | 4 个测试文件 | DTO 类 | 29 |
| Exception | 5 个测试文件 | 异常类 | 22 |
| Config | `SNCConfigTest` | `SNCConfig` | 7 |
| Util | `AddressUtilsTest` | `AddressUtils` | 31 |

### 2.2 集成测试

| 测试类 | 用例数 | 数据来源 |
|--------|--------|---------|
| `SNCServiceIntegrationTest` | 28+ | JSON 文件 (`topo_data_2npu_1port.json`, `topo_data_4npu_8port.json`, `topo_data_2box_16l2sw.json`, `acl_data_2npu_1port.json`, `acl_data_4npu_8port.json`) |

---

## 3. 各层测试设计

### 3.1 Entity 层

26 个 entity 类 + 1 个内部类，共 25 个测试文件，约 174 个测试用例。

| 类别 | 类名 | 测试文件 |
|:-----|:-----|:---------|
| 枚举 | DeviceType | DeviceTypeTest.java |
| 枚举 | SwitchLevel | SwitchLevelTest.java |
| 枚举 | TransportType | TransportTypeTest.java |
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
| 领域类 | RoutingTable | RoutingTableTest.java |
| 领域类 | RoutingTableKey | RoutingTableKeyTest.java |
| 领域类 | RoutePrefix | RoutePrefixTest.java |
| 领域类 | RoutingEntry | RoutingEntryTest.java |
| 领域类 | OutPortInfo | OutPortInfoTest.java |
| 领域类 | AclData | AclDataTest.java |
| 领域类 | AclKey | AclKeyTest.java |
| 领域类 | TpAclEntity | TpAclEntityTest.java |
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
- `RoutePrefix`/`RoutingTableKey`/`AclKey`（HashMap key 类）：额外覆盖 null 字段边界
- `SuperNode`：额外覆盖 `getNpuDevices`/`getSwDevices`/`getAllDevices` 合并逻辑
- `NpuDevice`：额外覆盖 `findNpuPort` 跨芯片搜索、null 芯片/null 端口边界

### 3.2 DTO 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| PathPlanRequest | 8+ | 构造/Getter/Setter/equals/hashCode/toString；`interDevices` 为 null 场景 |
| PathPlanResult | 10+ | 同上 + `PlanStatus` 枚举覆盖（11 个 status 值）+ 成功/失败构造 |
| PathInfo | 6+ | 构造/Getter/Setter/equals/hashCode/toString；`hops` 为 null 场景 |
| HopInfo | 8+ | 构造 + `multiPath`/`deviceType` 字段 + 源/目的/中间节点字段约束 |

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
| AclNotFoundException | 4 | 继承关系验证 |
| PathPlanException | 6 | 错误码构造、Detail 构造、getStatus() |

### 3.5 Util 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| AddressUtils | 31 | `cnaToTargetAddr`、`applyMask`、`ipToInt`、`intToIp`、`isValidCna`、`isValidEid` |

### 3.6 Store 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| SuperNodeStore | 24 | init/replace/getSuperNodeData/getRoutingTable/removeSuperNode/clear；addNpuDevice/addSwDevice；多 superNodeName 共存；路由表提取；空设备/null 参数/beforeInit 操作 |
| AclStore | 10 | init/replace/getAclData/removeAclData/clear；空值/null 参数 |

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
| AclCheckEngine | 7 | 正向校验/反向校验/双向校验/CNA 不匹配/Key 不存在/forward 匹配但 dest 不匹配 |
| PathEngine | 20 | 直连路径（NpuDevice/NpuPortEntity 重载）/多跳路径/跨芯片路由查找/路径反转/端口查找异常/null 芯片/半连接 |

**RouteLookupEngine LPM 核心算法：**

| 路由表 | targetAddr | 期望 |
|:-------|:-----------|:-----|
| {/24: eth0, /16: eth1, /0: wan} | "170.170.170.17" | eth0 (/24) |
| {/24: eth0, /16: eth1, /0: wan} | "171.170.170.17" | wan (/0) |
| {} | "1.2.3.4" | null |

**AclCheckEngine 校验：**

| 场景 | 期望 |
|:-----|:-----|
| 完全匹配（EID + CNA 一致） | true |
| CNA 不匹配 | false |
| Key 不存在 | false |
| 双向校验 | 正反均通过才为 true |

**PathEngine 路径还原：**

| 场景 | 期望 |
|:-----|:-----|
| 2 个 NPU 端口直连 | InternalPathInfo.hops.size() == 2 |
| 1 个中间 L1SW | hops.size() == 3 |
| 中间设备不存在 | 抛出 SuperNodeNotFoundException |
| 跨芯片路由查找 | 返回最长前缀匹配条目 |

### 3.8 Service 层

| 类 | 测试用例数 | 关键测试点 |
|:---|:----------|:-----------|
| SuperNodeService | 35 | importSuperNode 校验、addNpuDevices/addSwDevices、getDevice、getRoutingTable、异常处理；空值/空串/空集合参数校验 |
| AclService | 16 | importAclData 校验、getAclData、异常处理；空值/空串/空集合参数校验 |
| PathService | 65 | 完整 planPath 流程（16 步骤）、各错误码分支、反射测试（null 字段）、routePhase 异常分支、NpuDevice.findNpuPort 边界 |

**PathService 流程覆盖（对应设计文档 §9）：**

| Step | 场景 | 期望 PlanStatus |
|:-----|:-----|:----------------|
| 0 | superNodeName 不存在 | TOPO_NOT_FOUND (1012) |
| 0 | 设备不存在 | TOPO_INCOMPLETE (1007) |
| 1 | srcPort 不存在/CNA/EID 为空 | SRC_INFO_ERR (1003) |
| 2 | destPort 不存在/CNA/EID 为空 | DST_INFO_ERR (1004) |
| 3 | ACL 数据不存在/CNA 不匹配 | ACL_CHECK_FAILED (1005) |
| 6 | 直连验证失败 | TOPO_CONNECTION_ERROR (1008) |
| 7 | 多跳路径还原失败 | TOPO_CONNECTION_NOT_FOUND (1009) |
| 10 | 路由不可达 | ROUTE_NOT_REACHABLE (1010) |
| 14 | 成功 | SUCCESS (0) |

### 3.9 SNCServiceImpl

| 测试类别 | 测试用例数 | 关键测试点 |
|:---------|:----------|:-----------|
| 生命周期状态机 | 8 | INIT→READY→DATAREADY→UNINIT 各状态转换 |
| 参数校验 | 16 | 所有入参 null/空字符串检查 |
| 异常处理 | 6 | 未 init/uninit 后调用各方法 |
| 完整链路 | 6 | 从 init → setSuperNodeData → setAclData → addNpuDevices → addSwDevices → planPath → uninit |

**状态机测试：**

| 测试场景 | 调用序列 | 期望结果 |
|:---------|:---------|:---------|
| 未 init 直接调用 setSuperNode | setSuperNode(...) | SNCStateException |
| init 后正常调用 | init → setSuperNode → setAclData | 正常执行 |
| uninit 后再次调用 | init → ... → uninit → getSuperNode | SNCStateException |
| 重复 init | init → init | 幂等，不抛异常 |

---

## 4. 测试数据管理

### 4.1 JSON 测试数据

```
src/test/resources/
├── topo_data_2npu_1port.json     # 2 NPU + 1 L1 SW 拓扑（单端口）
├── topo_data_4npu_8port.json     # 4 NPU + 2 L1 SW 拓扑（多端口）
├── topo_data_2box_16l2sw.json    # 2 框 + 16 L2SW 拓扑（跨框路径）
├── acl_data_2npu_1port.json      # 2npu 对应的 ACL 数据
└── acl_data_4npu_8port.json      # 4npu 对应的 ACL 数据
```

### 4.2 TestDataLoader 工具类

`TestDataLoader` 负责从 JSON 文件解析为 Java 对象：
- `loadSuperNode(resourcePath)` — 解析拓扑 JSON 为 `SuperNode`（含 npuDevices、swDevices、芯片、端口、路由表）
- `loadAclData(resourcePath, superNodeName)` — 解析 ACL JSON 为 `AclData`

### 4.3 2npu_1port 数据（最小验证）

- **NPU1**: 1 个端口 `400GE 0/0/1`, CNA=`170.170.170.18`, EID=`AAAAAA12000000000000000000000002`, UPI=`0A0A0A01`
- **NPU2**: 1 个端口 `400GE 0/1/1`, CNA=`221.221.221.66`, EID=`DDDDDD42000000000000000000000002`, UPI=`0A0A0A01`
- **L1SW0**: 2 个端口连 NPU1/NPU2
- **路由**: NPU1→目标221.221.221.68, L1SW 上有两条路由（170.170.170.17→NPU1侧, 221.221.221.68→NPU2侧）
- **ACL**: 两条双向规则（AAAAAA11...↔DDDDDD44...）

### 4.4 4npu_8port 数据（全量验证）

- 4 个 NPU 各 8 个端口（共 32 个端口），每个端口有独立 CNA/EID
- 4 个 L1SW 各 8 个端口，无 L2SW
- 每个 NPU 的 8 个端口均分到 4 个 L1SW（每 L1SW 2 个端口）
- 路由表：每个 NPU 8 条路由到其他 NPU（ECMP 2 路），每个 L1SW 4 条路由到各 NPU（单路）
- ACL：6 对 NPU × 8 端口 × 2 方向 = 96 条双向规则

### 4.5 端口命名与编码规则

| 设备类型 | 端口格式 | 示例 |
|:---------|:---------|:-----|
| NPU | `400GE 0/{chipIndex}/{portIndex}` | `400GE 0/0/1` |
| L1SW | `400GE 1/{chipIndex}/{portIndex}` | `400GE 1/0/2` |

| NPU | EID 前缀 | CNA 范围 | UPI |
|:----|:---------|:---------|:------------|
| npu1 | AAAAAA | 170.170.170.x | 0A0A0A01 |
| npu2 | DDDDDD | 221.221.221.x | 0A0A0A01 |
| npu3 | EEEEEE | 238.238.238.x | 0A0A0A01 |
| npu4 | FFFFFF | 255.255.255.x | 0A0A0A01 |

---

## 6. 测试工具与依赖

| 工具 | 版本 | 用途 |
|------|------|------|
| JUnit Jupiter | 5.9.2 | 测试框架 |
| JaCoCo | 0.8.12 | 覆盖率统计 |
| Maven Surefire | 3.2.2 | 测试执行 |
| Lombok | 1.18.36 | POJO 简化 |

---

## 7. 测试命名规范

- 测试类名：`{被测类}Test.java`
- 测试方法名：`{场景}_{预期结果}`（驼峰命名）
- 使用 `@DisplayName` 标注中文描述
- Entity/DTO 测试统一遵循 7 步模板：default → allArgs → setters → equalsEqual → equalsNotEqual → hashCode → toString
