# SNC (Supernode Network Controller) 设计文档

> 本文档定义 SNC 模块的类设计，包含领域模型、计算模型、北向数据结构、北向接口、路径规划算法及路径规划详细流程。

---

## 目录

1. [概述](#1-概述)
2. [北向机制](#2-北向机制)
3. [文件目录设计](#3-文件目录设计)
4. [数据结构定义（领域模型 Entity）](#4-数据结构定义)
5. [纯内部数据结构（计算模型）](#5-纯内部数据结构)
6. [北向数据结构（DTO）](#6-北向数据结构)
   - [6.1 PathPlanRequest（路径规划请求）](#61-pathplanrequest路径规划请求)
   - [6.2 PathPlanResult（路径规划响应）](#62-pathplanresult路径规划响应)
   - [6.3 北向数据结构与内部数据结构的关系](#63-北向数据结构与内部数据结构的关系)
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
   - [7.10 AclStore（ACL存储）](#710-aclstoreacl存储)
8. [路径规划算法 — 索引掩码匹配（Indexed Mask Match）](#8-路径规划算法--索引掩码匹配indexed-mask-match)
9. [路径规划详细流程](#9-路径规划详细流程)

---

## 1. 概述

### 1.1 业务背景

SNC（Supernode Network Controller）是一个超级节点控制器，负责网络拓扑、ACL、路由信息的管理，并提供路径规划功能，返回通信覆盖当前路径时所需参数。

### 1.2 核心功能需求

| 功能模块         | 说明                           | 优先级 |
|:----------------:|:-------------------------------|:------:|
| 初始化/去初始化   | SNC服务的启动与停止             | P0     |
| SuperNode数据管理     | 网络拓扑结构下发、查询与删除     | P1     |
| TP-ACL数据管理   | 传输策略访问控制列表下发、查询与删除 | P1     |
| 路径规划   | 基于EID对的路径规划与ACL校验     | P2     |

---

## 2. 北向机制

### 2.1 北向概述

**北向数据流向：**
```
┌──────────────────────────────────────────────────┐
│         上层编排器/管理系统        │ (北向调用方) │
│   - 拓扑数据录入（包含路由信息）    │             │
│   - ACL策略下发                 │             │
│   - 路径规划请求                 │             │
└──────────────┬───────────────────────────────────┘
               │ API 调用
┌──────────────▼──────────────────────────────────┐
│        SNC 模块 (本模块)         │             │
│   - 数据持久化与索引              │             │
│   - 路径规划与路径还原           │             │
│   - ACL 校验                    │             │
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

- **配置类操作（拓扑/ACL下发）：** 同步调用，调用方下发完整数据快照。
- **查询类操作（路径规划）：** 同步调用，请求-响应模式，调用方发送 PathPlanRequest，SNC 返回 PathPlanResult。
- **初始化/去初始化：** 同步调用，SNC 启动时从北向加载数据或接收全量同步；去初始化时清理内存数据。

### 2.3 数据一致性保证

- 拓扑数据（包含路由信息）和 ACL 数据以全量快照方式下发，SNC 不维护增量变更日志。
- 所有数据使用内存 HashMap 索引，保证 O(1) 查找效率。
- 路径规划基于内存中的数据实时计算，不依赖外部存储。

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
│   ├── PortEntity.java                # 端口抽象基类
│   ├── NpuPortEntity.java             # NPU 端口（§4.5.1）
│   ├── SwPortEntity.java              # 交换端口（§4.5.2）
│   ├── LogicPortEntity.java           # 逻辑端口（§4.6）
│   ├── RoutingTable.java              # 路由表（§4.7）
│   ├── RoutingEntry.java              # 路由条目（§4.9）
│   ├── RoutePrefix.java               # 路由前缀结构体（§4.8）
│   ├── RoutingTableKey.java           # 路由表联合键（superNodeName + deviceName + chipIndex，§4.7.1）
│   ├── OutPortInfo.java               # 出端口信息（§4.9.1）
│   ├── AclData.java                   # ACL 数据容器（§4.10）
│   ├── AclKey.java                    # ACL 复合键（§4.11）
│   ├── TpAclEntity.java               # TP-ACL 实体（§4.12）
│   ├── TransportType.java             # 传输类型枚举（RMTP/RCTP/CTP/UTP）（§4.10）
│   ├── InternalPathInfo.java          # §5.1 内部路径信息（引擎计算上下文）
│   ├── InternalPathHop.java           # §5.1 内部路径跳
│   └── RouteSelectionRecord.java      # §5.2 内部选路记录
│
├── dto/                               # §6 北向 API DTO（与领域模型解耦）
│   ├── PathPlanRequest.java           # 路径规划请求（§6.1）
│   ├── PathPlanResult.java            # 路径规划响应 + PlanStatus 枚举（§6.2）
│   ├── PathInfo.java                  # 路径信息（§6.2.1）
│   └── HopInfo.java                   # 跳信息（§6.2.2）
│
├── service/                           # 业务逻辑层（编排）
│   ├── SuperNodeService.java               # 拓扑数据管理
│   ├── AclService.java                # ACL 数据管理
│   └── PathService.java               # 路径规划编排（调用 engine 层）
│
├── store/                             # 数据存储层（HashMap 索引）
│   ├── SuperNodeStore.java                 # 拓扑索引（superNodeName→SuperNode / routingTableMap）
│   └── AclStore.java                  # ACL 索引（superNodeName→AclData / tpAclMap）
│
├── engine/                            # 算法引擎层
│   ├── PathEngine.java                # 路径还原引擎（Step 5~7）
│   ├── RouteLookupEngine.java         # 路径规划引擎 / 索引掩码匹配（Step 8~12，§8）
│   └── AclCheckEngine.java            # ACL 校验引擎（Step 3~4）
│
├── exception/                         # 异常定义（§7.5.2）
│   ├── SNCException.java              # 基础异常
│   ├── SNCStateException.java         # 状态异常
│   ├── SuperNodeNotFoundException.java     # 拓扑数据未找到
│   ├── AclNotFoundException.java      # ACL 数据未找到
│   └── PathPlanException.java         # 路径规划失败（内含 PlanStatus）
│
└── util/                              # 工具类
    └── AddressUtils.java              # CNA 掩码计算、地址格式校验
```

### 3.3 依赖关系

```
                    ┌──────────┐
                    │   dto    │ （§6 北向 API DTO，无内部依赖，纯数据结构）
                    └────▲─────┘
                         │使用
                    ┌────┴─────┐
                    │ service  │ （编排层：SuperNodeService / AclService / PathService）
                    └─┬──┬──┬─┘
                      │  │  │
            ┌─────────┘  │  └─────────┘
            │            │            │
       ┌────────┐  ┌─────────┐  ┌────────┐
       │ store  │  │ engine  │  │ entity │
       │ (索引)  │  │ (算法)   │  │ (模型)  │
       └───┬────┘  └────┬────┘  └────────┘
           │            │
           └─────┬──────┘
                 │查询/写入
           ┌────────┐
           │ entity │ （§4 领域模型 + §5 计算模型，store/engine/service 共同依赖）
           └────────┘
```

| 层 | 可依赖 | 不可依赖 | 说明 |
|:---|:-------|:--------|:-----|
| `dto` | - | entity / service / store / engine | API 契约层，独立于内部实现 |
| `entity` | util | dto / service / store / engine | 纯数据结构层 |
| `store` | entity / util | dto / service / engine | 索引存储，直接操作领域模型 |
| `engine` | entity / util | dto / service / store | 算法引擎，读 entity 输出 §5 计算模型 |
| `service` | entity / dto / store / engine / util | - | 编排层，完成 DTO 与领域模型 映射 |
| `exception` | dto.PathPlanResult.PlanStatus | - | 异常可引用错误码枚举（PlanStatus 定义在 §6.2 PathPlanResult 内部） |
| `util` | - | entity / dto / service / store / engine | 纯工具类 |

### 3.4 接口层与内部层转换映射

`SNCServiceImpl` 位于 package 根，负责将 `dto` 与内部 `entity`/`service` 连接。

```
SNCServiceImpl
    │
    ├── init(SNCConfig)
    │     └→ SuperNodeStore.init() + AclStore.init()
    │     └→ 仅操作 config 和 store，不涉及 dto
    │
    ├── setSuperNode(SuperNode)          // entity.SuperNode（§4.1 领域模型）
    │     └→ SuperNodeService.importSuperNode(superNode)
    │              └→ SuperNodeStore.replace(superNode)
    │
    ├── setAclData(AclData)            // entity.AclData（§4.12 领域模型）
    │     └→ AclService.importAclData(aclData)
    │              └→ AclStore.replace(aclData)
    │
    ├── planPath(PathPlanRequest)      // dto.PathPlanRequest（§6.1 DTO）
    │     └→ PathService.planPath(request)
    │              ├→ superNode.getNpuDevices().get(srcDevice/destDevice)  // Step 0: NPU 设备查找
    │              ├→ srcNpuDevice.findNpuPort() + destNpuDevice.findNpuPort() // Step 1~2: 端口查找（直接使用 NpuForwardingChip.getNpuPorts()，无需 instanceof/cast）
    │              ├→ AclCheckEngine.check()                        // Step 3~4: ACL 双向校验（读 entity.TpAclEntity）
    │              ├→ PathEngine.resolveDirectPath/resolveMultiHopPath(→ InternalPathInfo) // Step 5~7: 路径还原
    │              │    签名: (NpuDevice, NpuPortEntity, NpuDevice, NpuPortEntity, ...)
    │              ├→ superNode.getAllDevices() + RouteLookupEngine.lookup() // Step 8~12: 路径规划
    │              └→ 组装 dto.PathPlanResult                       // Step 13~15: 输出构造（§6.2 DTO）
    │
    └── uninit()
            └→ SuperNodeStore.clear() + AclStore.clear()
```

> `setSuperNode` / `setAclData` 的入参直接使用 `entity.SuperNode` / `entity.AclData`（领域模型），因为它们来自 JSON 反序列化的原始结构，与拓扑文件 1:1 对应，无需额外 DTO 包装。`planPath` 的入参/出参使用 `dto.PathPlanRequest` / `dto.PathPlanResult`，因为它们面向北向调用方，需要稳定的 API 契约。

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

    public NpuPortEntity(String portName, Integer id, Integer chipIndex,
                         String remoteDevice, String remotePort, String cna,
                         String eid, String upi) {
        super(portName, id, chipIndex, remoteDevice, remotePort, cna);
        this.eid = eid;
        this.upi = upi;
    }
}
```

**字段约束：**
- `eid`：128 bit EID 标识，字符串格式。仅 NPU 端口携带 EID 信息。
- NpuPortEntity 存储于 `NpuForwardingChip.ports`（`Map<String, NpuPortEntity>`，§4.4.1），通过 `getNpuPorts()` 直接获取精确类型，无需 instanceof/cast。

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
- 交换设备的端口无 CNA/EID/UPI 概念，`cna` 字段在交换端口场景下为**可选**（可为 null），不参与 ACL 校验和路径规划中的 CNA 匹配。
- `remoteDevice` / `remotePort` 为交换端口的核心字段，用于多跳拓扑路径还原。
- SwPortEntity 存储于 `SwForwardingChip.ports`（`Map<String, SwPortEntity>`，§4.4.2），通过 `getSwPorts()` 直接获取精确类型，无需 instanceof/cast。

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
- `RoutingTable`：路由表独立存储于 `SuperNodeStore.routingTableMap` 中，以 `RoutingTableKey`（`superNodeName + deviceName + chipIndex`）为 key（`Map<RoutingTableKey, RoutingTable>`，§4.7.1），支持全局 O(1) 定位。多个超节点下 deviceName 可能重复，通过 superNodeName 区分。`RoutingTable` 不作为 HashMap key 使用，`equals()`/`hashCode()` 由 Lombok `@EqualsAndHashCode` 生成（全部字段参与，与 `RoutePrefix` §4.8、`AclKey` §4.11 一致）。
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
- `equals()` 和 `hashCode()` 由 Lombok `@EqualsAndHashCode` 自动生成（三个字段参与），保证 HashMap 查找正确性。此做法与 `AclKey`（§4.11）、`RoutePrefix`（§4.8）一致。

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
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutingEntry {
    /** 目标前缀结构体 -- 包含目的地址(dstAddress)和掩码长度(maskLength) */
    private RoutePrefix prefix;

    /** 出端口信息Map -- 支持多出端口（ECMP），Map的key为portName，必填字段 */
    private Map<String, OutPortInfo> outPortInfos;
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| prefix | RoutePrefix | 目标前缀结构体，包含目的地址和掩码长度 |
| outPortInfos | Map\<String, OutPortInfo\> | 出端口信息Map，key为portName，支持多出端口（ECMP），必填字段 |

**说明：**
- `RoutingEntry` 存储在 `RoutingTable.routes` 中，以 `RoutePrefix` 对象为 key。
- 路径规划时，将 CNA 补齐为 32 bit 的 `targetAddr`（见 §4.8.1），从 `RoutingTable.maskLengths` 中取已知掩码，按从长到短逐级构造 key 做 O(1) 查找（§8）。
- 例如 `1.1.1.0/24` 和 `1.1.1.0/20` 是不同的路由，因为掩码不同导致 `RoutePrefix` 不同。

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
    private String portName;         // 出接口名称 -- 必填字段
    private String nextHop;          // 下一跳IP
    private Integer preference;      // 路由优先级(1-255,默认60)
    private Integer tag;             // 路由标签
    private String protocol;         // 路由协议类型
}
```

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| portName | String | 出接口名称 -- 必填字段 |
| nextHop | String | 下一跳IP |
| preference | Integer | 路由优先级(1-255,默认60) |
| tag | Integer | 路由标签 |
| protocol | String | 路由协议类型 |

**说明：**
- 掩码长度已迁移至 `RoutePrefix` 结构体，`OutPortInfo` 不再包含 `maskLength` 字段。
- 上述五个字段统一封装在 `OutPortInfo`，作为 `RoutingEntry.outPortInfos` Map 的 value；Map 的 key 为 `portName`，支持 O(1) 查找和遍历，覆盖 ECMP 场景。

---


### 4.10 AclData（ACL数据）

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class AclData {
    /** ACL标识，对应 SuperNode.name，表示该 ACL 数据归属于哪个超节点 -- 必填字段 */
    private String superNodeName;

    /** ACL Map -- 必填字段，Map的key为AclKey（复合对象） */
    private Map<AclKey, TpAclEntity> tpAcls;
}
```

**Key说明：**
- `superNodeName`：ACL 标识，与 `SuperNode.name`（superNodeName）对应，用于 `AclStore` 中按超节点区分存储。外部可下发多个超节点的 ACL 数据，各自以 `superNodeName` 作为 `AclStore.store` Map 的 key（见 §7.9）。
- `tpAcls`：Map 的 key 为 `AclKey`（复合对象，包含 sourceEid + destEid + transportType），用于 O(1) 查找 ACL 规则。

---

### 4.11 AclKey（ACL复合键）

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class AclKey {
    /** 源 EID -- 128 bit */
    private String sourceEid;

    /** 目的 EID -- 128 bit */
    private String destEid;

    /** 传输类型 */
    private TransportType transportType;
}
```

**约束条件：**
- `equals()` 和 `hashCode()` 由 Lombok `@EqualsAndHashCode` 自动生成（基于三个字段 sourceEid, destEid, transportType），保证 HashMap 查找正确性。
- 三个字段（sourceEid, destEid, transportType）联合唯一标识一条 ACL 规则。
- **AclKey** 存储三元组（sourceEid + destEid + transportType），作为 HashMap 索引键，用于 O(1) 定位 ACL 规则。
- **TpAclEntity** 存储校验字段（sourceCna + destCna + templateId），不冗余存储 EID 三元组。ACL 校验时通过 AclKey 定位 TpAclEntity 后，验证表项中的 CNA 与端口 CNA 的一致性（见 §9.3 Step 3~4）。

---

### 4.12 TpAclEntity（TP-ACL实体）

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class TpAclEntity {
    /** 源地址（只支持CNA）-- 32 bit -- 必填字段 */
    private String sourceCna;

    /** 目的地址（只支持CNA）-- 32 bit -- 必填字段 */
    private String destCna;

    /** 模板ID (1-19) */
    private Integer templateId;
}
```

**传输类型枚举：**

```java
public enum TransportType {
    RMTP,  // Reliable Transfer Protocol (Reliable Connecion)   -- 可靠传输协议(可靠连接)（当前版本已支持）
    RCTP,  // Reliable Transfer Protocol (Reliable Masseging)   -- 可靠传输协议(可靠不连接)（预留，待后续版本启用）
    CTP,   // Connection-oriented Transport Protocol -- 面向连接传输协议（预留，待后续版本启用）
    UTP    // Unreliable Transfer Protocol -- 不可靠传输协议（预留，待后续版本启用）
}
```

> **使用说明：** 当前版本（V1）ACL 校验和路径规划仅支持 `RCTP`，`RMTP`、`UTP`、`CTP` 为预留枚举值。后续版本将在 `PathPlanRequest` 中增加 `transportType` 字段，由调用方指定传输类型后启用。当前 `planPath()` 流程硬编码使用 `RCTP`（见 §9.3）。
> 
> **枚举定义位置说明：** `TransportType` 枚举虽在 §4.12 定义（紧邻 `TpAclEntity`），但 §4.11 `AclKey` 的 `transportType` 字段已引用该枚举类型，读者可向前翻阅 §4.12 查看枚举值定义。

**ACL 校验规则：**
- 路径规划时，使用 `(sourceEid, destEid, transportType)` 在 HashMap 中查找。
- 查找到表项后，验证 `sourceCna` 与源设备端口 CNA 一致，`destCna` 与目的设备端口 CNA 一致。
- 双向检查：先查正向 (EID1→EID2)，再查反向 (EID2→EID1)，两者均通过才认为 ACL 校验成功。


## 5  纯内部数据结构

### 5.1 InternalPathInfo（内部路径信息）

> **设计依据：** 参照 §9.4 阶段3 Step 7 — 多跳路径还原流程。

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

封装完整的内部路径，在 Step 7 构建并在后续 Step 8~12 中消费。

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
Step 7 (多跳路径还原):
    Input:  PathPlanRequest (srcDevice, srcPort, destDevice, destPort, interDevices)
    Output: InternalPathInfo (按拓扑一致性校验逐跳填充)
    
Step 8~12 (路径规划循环):
    Input:  InternalPathInfo (从 Stage 3 构建)
    Process: 遍历 InternalPathInfo.hops，对每个中间设备执行路径规划
    Output: RouteSelectionRecord 列表 (从 Step 11 产生)
    
Step 14 (填充 PathPlanResult):
    Input:  InternalPathInfo.hops
    Output: PathPlanResult.paths (转换为外部 HopInfo 列表)
```

---

### 5.2 RouteSelectionRecord（内部选路记录）

> **设计依据：** 参照 §9.5 阶段4 Step 11 — 出端口判断与选路记录。

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
     *  源 UDP 端口号（8 bit，由 Step 13 计算填入）。
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

| 字段 | 来源 | 对应 Step 11 伪代码中的项 |
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
- 出端口数量 > 1 且设备不支持逐流 → 不记录，返回错误码 **1011**。
- 出端口数量 > 1 且设备支持逐流 → 记录一条 `RouteSelectionRecord`，其中 `candidateOutPorts` 包含所有候选出接口（ECMP 所有路径），与 `interDevices` 指定出端口一致的标记为 `selected=true`（目标端口），其余为 `false`。进入下一跳。

**消费关系：**
```
Step 11 (记录):
    对每个存在 ECMP 的中间设备 → 生成 RouteSelectionRecord
    → candidateOutPorts 记录所有候选出接口 + 选中标记
    
Step 13 (UDP 端口计算):
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
        ACL_CHECK_FAILED(1005, "acl check failed"),
        TOPO_INCOMPLETE(1007, "topo incomplete"),
        TOPO_CONNECTION_ERROR(1008, "topo connection error"),
        TOPO_CONNECTION_NOT_FOUND(1009, "topo connection not found"),
        ROUTE_NOT_REACHABLE(1010, "route not reachable"),
        TOPO_NOT_FOUND(1012, "topo not found"),
        ACL_NOT_FOUND(1013, "acl not found"),
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
| ackUdpSrcPort | Integer | Ack UDP 源端口（8 bit），由 Step 13 计算，用于硬件卸载 |
| dataUdpSrcPort | Integer | Data UDP 源端口（8 bit），由 Step 13 计算，用于硬件卸载 |
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

### 6.3 北向数据结构与内部数据结构的关系

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

SNC 模块对外暴露统一的北向接口 `SNCService`，位于包 `com.huawei.umdk.snc`。调用方（上层编排器/管理系统）通过该接口完成**初始化、数据下发、路径规划、去初始化**四个阶段的操作。

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
    ├── setAclData(AclData) → void                 // ACL 全量下发
    ├── addAclRules(String, Map<AclKey, TpAclEntity>) → void  // ACL 增量：批量添加/更新规则
    ├── removeAclRules(String, List<AclKey>) → void          // ACL 增量：批量删除规则
    ├── getAclData(String) → AclData               // ACL 数据查询
    ├── removeAclData(String) → void               // ACL 数据删除
    │
    ├── planPath(PathPlanRequest) → PathPlanResult     // 路径规划（单路径）
    └── uninit() → void                                // 去初始化
```

> **数据结构引用：** 接口涉及的 `PathPlanRequest`、`PathPlanResult`、`PathInfo`、`HopInfo`、`PlanStatus` 等北向数据结构完整定义见 [§6 北向数据结构](#6-北向数据结构)。

---

### 7.2 SNCService 接口定义

```java
package com.huawei.umdk.snc;

import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.entity.*;
import com.huawei.umdk.snc.config.SNCConfig;

/**
 * SNC 主服务接口 —— 北向调用入口
 *
 * <h3>调用顺序约束</h3>
 * <pre>{@code
 *   sncService.init(config);                    // 1. 初始化
 *   sncService.setSuperNode(superNode);           // 2. 下发拓扑数据（可多次调用更新）
 *   sncService.setAclData(aclData);             // 3. 下发 ACL 数据（可多次调用更新）
 *   sncService.addNpuDevices("A5-superPod-1", List.of(npuDevice));  // 4. 增量：批量添加 NPU 设备
 *   sncService.addSwDevices("A5-superPod-1", List.of(swDevice));    // 5. 增量：批量添加 SW 设备
 *   sncService.removeDevices("A5-superPod-1", List.of("rack1#os0#npu1")); // 6. 增量：批量移除设备
 *   sncService.addRoutingEntries("A5-superPod-1", "rack1#os0#npu1", 0, List.of(entry)); // 6. 增量：批量添加路由
 *   sncService.addAclRules("A5-superPod-1", Map.of(aclKey, aclEntity)); // 7. 增量：批量添加 ACL 规则
 *   sncService.planPath(request);               // 8. 路径规划（可多次并发调用）
 *   SuperNode td = sncService.getSuperNode("A5-superPod-1");   // 9. 拓扑数据查询
 *   AclData ad = sncService.getAclData("A5-superPod-1");     // 10. ACL 数据查询
 *   sncService.removeSuperNode("A5-superPod-1");              // 11. 拓扑数据删除
 *   sncService.removeAclData("A5-superPod-1");               // 12. ACL 数据删除
 *   sncService.uninit();                       // 13. 去初始化
 * }</pre>
 *
 * <h3>状态约束</h3>
 * - 未 init() 调用其他接口：抛出 SNCStateException
 * - uninit() 后再次调用其他接口：抛出 SNCStateException
 * - 重复 init()：幂等处理或抛出 SNCStateException
 *
 * @see PathPlanRequest
 * @see PathPlanResult
 * @see SuperNode
 * @see AclData
 */
public interface SNCService {

    // ============ 生命周期管理 ============

    /**
     * 初始化 SNC 服务
     *
     * 加载配置，初始化内部 HashMap（拓扑索引、ACL 索引）。
     *
     * @param config SNC 配置（日志策略、索引策略等），可为 null（使用默认配置）
     * @throws SNCStateException 状态异常（重复初始化等）
     */
    void init(SNCConfig config);

    /**
     * 去初始化 SNC 服务
     *
     * 清空所有内存数据（拓扑 Map、ACL Map），释放资源。
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

    /**
     * 下发 ACL 数据（全量替换）
     *
     * 将 AclData 解析并索引到内存 HashMap 中。
     * - 使用全量替换（replace）策略。
     * - 可多次调用，每次调用全量替换全部 ACL 表项。
     * - 拓扑和 ACL 下发顺序可互换。
     *
     * @param aclData ACL 数据容器（§4.12）
     * @throws IllegalArgumentException aclData 为 null
     * @throws SNCStateException SNC 未初始化
     */
    void setAclData(AclData aclData);

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

    // ============ 增量更新 - ACL ============

    /**
     * 增量批量添加/更新 ACL 规则
     *
     * 在指定 ACL 数据中批量添加或更新 TP-ACL 规则。
     *
     * @param superNodeName ACL 标识（对应 AclData.superNodeName，§4.10）
     * @param rules ACL 规则 Map（key=AclKey，value=TpAclEntity），每个 entry 的 key 和 value 非 null
     * @throws IllegalArgumentException 任一参数为 null
     * @throws SNCStateException SNC 未初始化
     */
    void addAclRules(String superNodeName, Map<AclKey, TpAclEntity> rules);

    /**
     * 增量批量删除 ACL 规则
     *
     * 从指定 ACL 数据中批量删除 TP-ACL 规则。
     *
     * @param superNodeName ACL 标识（对应 AclData.superNodeName，§4.10）
     * @param keys ACL 复合键列表（§4.11），每个元素非 null
     * @throws IllegalArgumentException 任一参数为 null，或 AclData 不存在
     * @throws SNCStateException SNC 未初始化
     */
    void removeAclRules(String superNodeName, List<AclKey> keys);

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

    /**
     * 查询 ACL 数据
     *
     * 根据 superNodeName（对应 superNodeName）从 AclStore 中获取对应的 AclData 对象。
     *
     * @param superNodeName ACL 标识（对应 AclData.superNodeName，§4.10）
     * @return AclData 对象，若指定 superNodeName 的 ACL 数据不存在则返回 null
     * @throws IllegalArgumentException superNodeName 为 null 或空字符串
     * @throws SNCStateException SNC 未初始化
     */
    AclData getAclData(String superNodeName);

    /**
     * 删除 ACL 数据
     *
     * 根据 superNodeName（对应 superNodeName）从 AclStore 中移除对应的 ACL 数据。
     *
     * @param superNodeName ACL 标识（对应 AclData.superNodeName，§4.10）
     * @throws IllegalArgumentException superNodeName 为 null 或空字符串
     * @throws SNCStateException SNC 未初始化
     */
    void removeAclData(String superNodeName);

    // ============ 路径规划 ============

    /**
     * 路径规划（同步请求-响应模式）
     *
     * 基于源/目的设备及端口信息，执行路径规划与路径规划，返回完整的通信路径参数。
     * 内部执行 Step 0 ~ Step 15 流程。
     *
     * <table>
     *   <tr><th>阶段</th><th>步骤</th><th>说明</th></tr>
     *   <tr><td>阶段1</td><td>Step 0~2</td><td>设备判断与源/目的信息查找 §9.2</td></tr>
     *   <tr><td>阶段2</td><td>Step 3~4</td><td>ACL 双向校验 §9.3</td></tr>
     *   <tr><td>阶段3</td><td>Step 5~7</td><td>路径还原（直连/多跳）§9.4</td></tr>
     *   <tr><td>阶段4</td><td>Step 8~12</td><td>路径规划循环（正向/反向）§9.5</td></tr>
     *   <tr><td>阶段5</td><td>Step 13~15</td><td>构造输出（UDP端口计算+PathPlanResult 填充）§9.6</td></tr>
     * </table>
     *
     * <h3>前置条件</h3>
     * - init() 已完成
     * - setSuperNode() 已调用（拓扑数据存在）
     * - setAclData() 已调用（ACL 数据存在）
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
| setAclData | AclData | void | 同步 | 否（写操作需串行） | 全量替换 ACL 数据 |
| addAclRules | String, Map\<AclKey, TpAclEntity\> | void | 同步 | 否（写操作需串行） | 增量批量添加/更新 ACL 规则 |
| removeAclRules | String, List\<AclKey\> | void | 同步 | 否（写操作需串行） | 增量批量删除 ACL 规则 |
| getSuperNode | String | SuperNode | 同步 | 是（只读，可并发） | 根据 superNodeName 查询拓扑数据 |
| removeSuperNode | String | void | 同步 | 否（写操作需串行） | 根据 superNodeName 删除拓扑数据及关联路由表 |
| getAclData | String | AclData | 同步 | 是（只读，可并发） | 根据 superNodeName 查询 ACL 数据 |
| removeAclData | String | void | 同步 | 否（写操作需串行） | 根据 superNodeName 删除 ACL 数据 |
| planPath | PathPlanRequest | PathPlanResult | 同步 | 是（只读，可并发） | 单路径规划 |

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
   │── setAclData(aclData) ───────────────────────────▶│  阶段3: ACL下发
   │◀── void ────────────────────────────────────────│
   │                                                   │
│── planPath(request1) ────────────────────────────▶│  阶段4: 路径规划
│◀── PathPlanResult { status=0, path=... } ───────│ (可多次并发)
│                                                   │
│── planPath(request2) ────────────────────────────▶│
│◀── PathPlanResult { status=1005, ... } ─────────│
│                                                   │
│── getSuperNode("A5-superPod-1") ──────────────────▶│  阶段5: 数据查询
│◀── SuperNode { name="A5-superPod-1", ... } ──────│
│                                                   │
│── getAclData("A5-superPod-1") ───────────────────▶│
│◀── AclData { superNodeName="A5-superPod-1", ... } ──────│
│                                                   │
│── removeSuperNode("A5-superPod-1") ───────────────▶│  阶段6: 数据删除
│◀── void ────────────────────────────────────────│
│                                                   │
│── removeAclData("A5-superPod-1") ────────────────▶│
│◀── void ────────────────────────────────────────│
│                                                   │
│── uninit() ──────────────────────────────────────▶│  阶段7: 去初始化
│◀── void ────────────────────────────────────────│
   │                                                   │
```

> **说明：** setSuperNode 和 setAclData 调用顺序可互换，但都必须在 planPath 之前完成。

---

### 7.4 状态机

SNC 服务内部维护以下生命周期状态：

```
         init()                                 uninit()
  INIT ──────────▶ READY ──(setSuperNode & setAclData 均已完成)──▶ DATAREADY
   │                                │                                 │
   │                                │ 增量操作 (add/remove/get/…)       │ planPath (可多次并发)
   │                                │ setSuperNode / setAclData         │ setSuperNode / setAclData (可更新)
   │                                │ uninit()                         │ 增量操作 (add/remove/get/…)
   │                                │                                 │
   └──── uninit() ───▶ UNINIT ◀───────────────────────────────────────┘
```

| 状态 | 说明 | 允许的操作 |
|:-----|:-----|:----------|
| INIT | 初始状态（未初始化） | init()、uninit() |
| READY | 就绪状态（已初始化，数据未就绪） | setSuperNode、setAclData；所有增量操作（addNpuDevices、addSwDevices、removeDevices、addRoutingEntries、removeRoutingEntries、addAclRules、removeAclRules）；所有查询操作（getSuperNode、getAclData）；removeSuperNode、removeAclData；uninit |
| DATAREADY | 数据就绪状态（拓扑+ACL 均已下发） | 同 READY，追加 planPath |
| UNINIT | 已去初始化 | （无，调用任何操作均抛 SNCStateException） |

**状态转换规则：**
- `init()`: INIT → READY（非幂等，重复 init 重建全部内部对象）
- `uninit()`: INIT / READY / DATAREADY → UNINIT（INIT 状态调用仅清空状态标记，无副作用）
- `setSuperNode()` + `setAclData()`: READY → DATAREADY（二者均下发后自动迁移）
- `setSuperNode()` / `setAclData()`: DATAREADY → DATAREADY（数据就绪态可继续更新数据）
- `planPath()`: 仅在 **DATAREADY** 状态下可用，未到 DATAREADY 时返回 SNCStateException

---

### 7.5 错误处理

#### 7.5.1 返回状态码

所有路径规划的错误码通过 `PathPlanResult.status`（`PlanStatus` 枚举）返回：

| 错误码 | 枚举常量 | 说明 | 触发阶段 |
|:------:|:--------|:-----|:--------|
| 0 | `SUCCESS` | 成功 | - |
| 1 | `FAILED` | 通用失败 | - |
| 1001 | `SRC_EID_NOT_FOUND` | 源EID 未找到 | Step 0 |
| 1002 | `DEST_EID_NOT_FOUND` | 目的 EID 未找到 | Step 0 |
| 1003 | `SRC_INFO_ERR` | 源信息缺失或错误 | Step 1 |
| 1004 | `DST_INFO_ERR` | 目的信息缺失或错误 | Step 2 |
| 1005 | `ACL_CHECK_FAILED` | ACL 检查失败（含 ACL 数据不存在和 ACL 表项不匹配） | Step 3/4 |

| 1007 | `TOPO_INCOMPLETE` | 拓扑不完整（设备在超节点 devices 中找不到） | Step 0 / Step 5~7 |
| 1008 | `TOPO_CONNECTION_ERROR` | 拓扑连接错误（直连验证失败） | Step 6 |
| 1009 | `TOPO_CONNECTION_NOT_FOUND` | 未找到拓扑连接（多跳路径还原失败） | Step 7 |
| 1010 | `ROUTE_NOT_REACHABLE` | 路由不可达（索引掩码匹配未命中或路由条目无出端口） | Step 10 |
| 1011 | `MULTI_PATH_NOT_SUPPORTED` | 存在多路径且设备不支持逐流 | Step 11 |
| 1012 | `TOPO_NOT_FOUND` | 拓扑数据未找到（superNodeName 为空或对应的 SuperNode 不存在） | Step 0 |
| 1013 | `ACL_NOT_FOUND` | ACL 数据未找到（setAclData 未调用或 superNodeName 对应 AclData 不存在） | Step 3 |
| 3002 | `SRC_AND_DST_MUST_BE_NPU` | 源和目的必须为 NPU | Step 0 |
| 3003 | `UPI_MISMATCH` | 源和目的端口 UPI 不一致 | Step 0 |

> **完整枚举定义：** [§6.2 PathPlanResult.PlanStatus](#62-pathplanresult路径规划响应)。

**错误码编码规则：**
- `0`：成功
- `1xxx`：路径规划阶段错误（设备/端口/ACL/路由/拓扑相关）
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
├── AclNotFoundException     // ACL 数据未找到
└── PathPlanException        // 路径规划失败（内含 PlanStatus 错误码和描述）
```

| 异常类 | 使用场景 | 处理方式 |
|:-------|:--------|:--------|
| `SNCStateException` | 非法调用顺序（未 init 就 planPath、uninit 后再次调用等） | 直接抛出，北向调用方捕获并处理 |
| `IllegalArgumentException` | 入参为 null、必填字段缺失 | 入口校验，直接抛出 |
| `SuperNodeNotFoundException` | `setSuperNode` 未调用或拓扑数据不完整（含 superNodeName 不存在和设备找不到） | service 层转换为错误码 1012/1001/1002/1007 |
| `AclNotFoundException` | `setAclData` 未调用或 ACL 数据不完整 | service 层转换为错误码 1013/1005 |
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
| `aclData` 非 null | `setAclData(AclData)` 入参 | 抛出 `IllegalArgumentException` |
| `request` 非 null | `planPath(PathPlanRequest)` 入参 | 抛出 `IllegalArgumentException` |
| `request.superNodeName` 非空 | 超节点名称必填（§6.1），用于多超节点场景定位 | 抛出 `IllegalArgumentException` |
| `request.srcDevice` 非空 | 源设备必填（§6.1） | 抛出 `IllegalArgumentException` |
| `request.destDevice` 非空 | 目的设备必填（§6.1） | 抛出 `IllegalArgumentException` |
| `request.srcPort` 非空 | 源端口必填（§6.1） | 抛出 `IllegalArgumentException` |
| `request.destPort` 非空 | 目的端口必填（§6.1） | 抛出 `IllegalArgumentException` |
| `superNodeName` 非空 | `getSuperNode(String)` / `removeSuperNode(String)` 入参 | 抛出 `IllegalArgumentException` |
| `superNodeName` 非空 | `getAclData(String)` / `removeAclData(String)` 入参 | 抛出 `IllegalArgumentException` |
| deviceName 格式 | `rack#os#npu` 或 `rack#l1sw0` 格式 | engine 层校验，返回错误码 1003/1004 |

> **业务规则校验**（设备类型必须为 NPU、EID/CNA 完整性等）在 engine 层进行，不在入口处校验。

---

### 7.7 接口实现映射

`SNCServiceImpl` 实现类将接口方法委托给内部组件：

```
SNCServiceImpl
    │
    ├── init(SNCConfig)
    │     └→ SuperNodeStore.init() + AclStore.init()  // 初始化 HashMap
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
    ├── setAclData(AclData)
    │     └→ AclService.importAclData(aclData)
    │              └→ AclStore.replace(aclData)    // 全量替换 ACL 索引
    │
    ├── addAclRules(String, Map<AclKey, TpAclEntity>)
    │     └→ AclService.addAclRules(superNodeName, rules)              // 循环调用 store.addAclRule()
    │              └→ AclStore.addAclRule(superNodeName, key, entity)  // 增量添加/更新 ACL 规则（单条）
    │
    ├── removeAclRules(String, List<AclKey>)
    │     └→ AclService.removeAclRules(superNodeName, keys)                  // 循环调用 store.removeAclRule()
    │              └→ AclStore.removeAclRule(superNodeName, key)  // 增量删除 ACL 规则（单条）
    │
    ├── getSuperNode(String)
    │     └→ SuperNodeStore.getSuperNode(superNodeName)        // 查询拓扑数据
    │
    ├── removeSuperNode(String)
    │     └→ SuperNodeStore.removeSuperNode(superNodeName)     // 删除拓扑数据及关联路由表
    │
    ├── getAclData(String)
    │     └→ AclStore.getAclData(superNodeName)             // 查询 ACL 数据
    │
    ├── removeAclData(String)
    │     └→ AclStore.removeAclData(superNodeName)          // 删除 ACL 数据
    │
    ├── planPath(PathPlanRequest)
    │     └→ PathService.planPath(request)
    │              ├→ AclCheckEngine.check()        // ACL 校验 (Step 3~4)
    │              ├→ PathEngine.resolvePath()      // 路径还原 (Step 5~7)
    │              ├→ RouteLookupEngine.lookup()    // 路径规划 (Step 8~12)
    │              └→ 组装 PathPlanResult            // 输出构造 (Step 13~15)
    │
    └── uninit()
            └→ SuperNodeStore.clear() + AclStore.clear()  // 清空数据
```

### 7.8 错误调用顺序说明

以下调用序列是非法的，SNC 应返回错误：

| 非法序列                              | 错误原因                          | 建议处理            |
|:--------------------------------------|:----------------------------------|:--------------------|
| 未 `init()` 直接调用其他接口            | 内部数据结构未初始化               | 抛出 SNCException   |
| `uninit()` 后再次调用其他接口          | 已去初始化，内存数据已清空         | 抛出 SNCException   |
| 未下发拓扑数据直接调用 `planPath()`   | 查不到设备信息                     | 返回错误码 1001/1002 |
| 未下发 ACL 数据直接调用 `planPath()`  | ACL 校验失败                      | 返回错误码 1005      |
| 重复 `init()` 不调用 `uninit()`       | 状态机重复初始化                   | 幂等处理或抛异常     |



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

// Step 10: 查找路由表
RoutingTableKey rtKey = new RoutingTableKey(superNodeName, deviceName, chipIndex);
RoutingTable rt = superNodeStore.getRoutingTable(rtKey);
```

---

### 7.10 AclStore（ACL存储）

ACL 数据的核心存储层，维护超节点→ACL数据的一级索引。

```java
public class AclStore {
    /** ACL 数据一级索引 -- Map的key为AclData.superNodeName（与superNodeName对应，§4.10），支持多超节点场景 */
    private Map<String, AclData> store;

    // ========== 生命周期方法 ==========

    /**
     * 初始化存储
     * <p>创建空的 HashMap 实例。
     */
    public void init() {
        this.store = new HashMap<>();
    }

    /**
     * 全量替换 ACL 数据
     * <p>以 aclData.superNodeName 为 key，将 AclData 对象存入 store Map。
     * 同一 superNodeName 的旧数据被覆盖。
     *
     * @param aclData ACL 数据容器（§4.10），要求 superNodeName 非空
     */
    public void replace(AclData aclData) {
        store.put(aclData.getSuperNodeName(), aclData);
    }

    /**
     * 清空所有 ACL 数据
     */
    public void clear() {
        if (store != null) {
            store.clear();
        }
    }

    /**
     * 删除指定 superNodeName 的 ACL 数据
     *
     * <p>从 store 中移除指定 superNodeName 对应的 AclData。
     *
     * @param superNodeName ACL 标识（§4.10 AclData.superNodeName）
     */
    public void removeAclData(String superNodeName) {
        store.remove(superNodeName);
    }

    // ========== 查询方法 ==========

    /**
     * 根据 superNodeName（对应 superNodeName）获取 ACL 数据
     *
     * @param superNodeName ACL 标识（§4.10 AclData.superNodeName）
     * @return AclData 对象，不存在返回 null
     */
    public AclData getAclData(String superNodeName) {
        return store.get(superNodeName);
    }
}
```

**设计说明：**

| 特性 | 说明 |
|:-----|:-----|
| 一级索引 `store` | 以 `superNodeName`（即 superNodeName）为 key，O(1) 定位超节点的 ACL 数据 |
| `replace()` 策略 | 全量替换：同一 superNodeName 的旧数据被覆盖 |
| `clear()` 策略 | Map.clear() 清空 |
| ACL 规则查找 | 通过 `AclData.tpAcls`（`Map<AclKey, TpAclEntity>`，§4.10）进行二级 O(1) 查找 |

**查询流程示例：**
```
// Step 3/4: ACL 校验
AclData aclData = aclStore.getAclData(request.getSuperNodeName());
AclKey key = new AclKey(sourceEid, destEid, TransportType.RCTP);
TpAclEntity acl = aclData.getTpAcls().get(key);
```

---

## 8 路径规划算法 — 索引掩码匹配（Indexed Mask Match）

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
 * PathService → RouteLookupEngine，对应 §9.5 阶段4 Step 10。
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

---
## 9 路径规划详细流程

### 9.1 流程概述

路径规划以**二阶段循环（前向→反向）+ 直连短路**为整体控制结构，共 16 个步骤（Step 0 ~ Step 15）：

```
                                      阶段1+2
                                  ┌──────────────┐
                                  │ Step 0 ~ 5    │
                                  │ 设备判断/ACL  │
                                  │ /节点判断     │
                                  └───────┬──────┘
                                          │
                              ┌───────────┴───────────┐
                              ▼                       ▼
                     ┌────────────────┐     ┌──────────────────┐
                     │ interDevices   │     │ interDevices     │
                     │ 为空 (直连)    │     │ 非空 (多跳)      │
                     └───────┬────────┘     └────────┬─────────┘
                             │ Step 6               │ Step 7
                             ▼                      ▼
                     ┌────────────────┐     ┌──────────────────┐
                     │ 直连路径验证    │     │ 多跳路径还原      │
                     │ (终端步，无路由) │     │ → InternalPathInfo│
                     └───────┬────────┘     └────────┬─────────┘
                             │ 成功返回               │
                             │ (码0)                 │
                             │                       ▼
                             │              ┌──────────────────┐
                             │              │ Step 8           │
                             │              │ 前向初始化        │
                             │              │ dst=dev2         │
                             │              └────────┬─────────┘
                             │                       ▼
                             │              ╔══════════════════╗
                             │              ║ 前向规划循环     ║
                             │              ║ Step 10→11 × n  ║
                             │              ╚══════╤═══════════╝
                             │                       ▼
                             │              ┌──────────────────┐
                             │              │ Step 12          │
                             │              │ dst==dev2?       │──→ Step 9 (反向)
                             │              │ 是 (前向完成)    │     dst=dev1
                             │              └──────────────────┘         │
                             │                                          ▼
                             │                                 ╔════════════════════╗
                             │                                 ║ 反向规划循环       ║
                             │                                 ║ Step 10→11 × n    ║
                             │                                 ╚══════╤═════════════╝
                             │                                          ▼
                             │                                 ┌──────────────────┐
                             │                                 │ Step 12          │
                             │                                 │ dst==dev1?       │──→ Step 14 (构造输出)
                             │                                 │ 是 (反向完成)    │
                             │                                 └──────────────────┘
                             │                                          │
                             │                                          ▼
                             │                                 ┌──────────────────┐
                             │                                 │ Step 13~15       │
                             │                                 │ UDP端口计算+输出 │
                             └─────────────────────────────────┴──────────────────┘
```

**二阶段循环说明：**

| 阶段 | 方向 | 目标地址 (targetAddr) | 目的设备 | 执行路径 |
|:-----|:-----|:----------------------|:---------|:---------|
| 前向 (Step 8) | dev1 → dev2 | CNA2 (= dev2 端口 IP) | dev2 | Step 8 → [10 → 11]^n → 12 |
| 反向 (Step 9) | dev2 → dev1 | CNA1 (= dev1 端口 IP) | dev1 | Step 9 → [10 → 11]^n → 12 → 14 |

**直连短路说明：**
- Step 6 为**终端步骤**——直连路径验证通过后**直接返回成功**（码 0），跳过阶段4（路由规划 Step 8~12）和阶段5（构造输出 Step 13~15）。
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

### 9.3 阶段2：ACL双向校验（Step 3 ~ 4）

> **数据结构参见：** §4.10 AclData、§4.11 AclKey、§4.12 TpAclEntity

**Step 3 - 正向 ACL 校验：**
使用 `(sourceEid=EID1, destEid=EID2, transportType=RCTP)` 构造 `AclKey`（§4.11），在 TP-ACL HashMap（`AclData.tpAcls`，§4.10）中查找。
- 若 `AclData` 对象不存在 → 返回错误码 **1013**（`ACL_NOT_FOUND`，§6.2）。
- 查找失败（key 不存在）→ 返回错误码 **1005**（`ACL_CHECK_FAILED`，§6.2）。
- 查找成功：验证 ACL 表项（`TpAclEntity`，§4.12）中的 `sourceCna == CNA1` 且 `destCna == CNA2`。
  - CNA 不匹配 → 返回错误码 **1005**（`ACL_CHECK_FAILED`）。
- 验证通过 → 进入 Step 4。

**Step 4 - 反向 ACL 校验：**
使用 `(sourceEid=EID2, destEid=EID1, transportType=RCTP)` 构造 `AclKey`，在 TP-ACL HashMap 中查找。
- 若 `AclData` 对象不存在 → 返回错误码 **1013**（`ACL_NOT_FOUND`，§6.2）。
- 查找失败（key 不存在）→ 返回错误码 **1005**（`ACL_CHECK_FAILED`）。
- 查找成功：验证 ACL 表项中的 `sourceCna == CNA2` 且 `destCna == CNA1`。
  - CNA 不匹配 → 返回错误码 **1005**（`ACL_CHECK_FAILED`）。
- 验证通过 → 进入 Step 5。

> **传输类型说明：** 当前阶段仅支持 `RCTP`（可靠传输协议 — 可靠不连接），ACL 校验硬编码使用 `transportType=RCTP`。`RMTP`（可靠连接）、`UTP`（不可靠传输协议）和 `CTP`（面向连接传输协议）为预留枚举值，待后续版本 `PathPlanRequest` 增加 `transportType` 字段后启用。参见 §4.12 TransportType 枚举。

---

### 9.4 阶段3：路径还原（Step 5 ~ 7）

> **数据结构参见：** §4.3 DeviceEntity（含 getForwardingChips() 抽象方法）、§4.4 ForwardingChip（含 getPorts() 抽象方法）、§4.5 PortEntity、§5.1 InternalPathInfo/InternalPathHop、§6.1 PathPlanRequest

**Step 5 - 判断中间节点：**
检查 `request.interDevices`（§6.1）是否为空：
- 无中间节点 → 跳转到 Step 6（直连场景）。
  > **V1 行为说明：** 当前版本 V1 未实现自动寻路算法。`interDevices` 为空时，引擎仅处理直连场景：
  > - 先执行 Step 6 直连验证：若端口连接关系验证通过 → 返回直连结果（成功）。
  > - 若直连验证失败 → 返回错误码 **1008**（`TOPO_CONNECTION_ERROR`，§6.2），流程终止。引擎不会尝试自动发现多跳路径。
  > - 调用方需自行保证：若源和目的设备非直连，必须在 `interDevices` 中显式指定中间设备及出端口。
- 有中间节点 → 跳转到 Step 7（多跳场景，必须显式指定中间设备及出端口）。

**Step 6 - 直连路径验证（终端步骤）：**
验证双向连接关系：
- `port1.remoteDevice == dev2.deviceName` 且 `port1.remotePort == port2.portName`
- `port2.remoteDevice == dev1.deviceName` 且 `port2.remotePort == port1.portName`

若验证通过 → 按 `PathPlanResult` 构造返回结果（两跳路径，§6.2），**直接返回成功（码 0）**，不再执行阶段4和阶段5。

若验证失败 → 返回错误码 **1008**（`TOPO_CONNECTION_ERROR`，§6.2）。

> **直连短路语义：** Step 6 为终端步骤。直连场景的通信路径由端口物理连接关系保证，不依赖路由表（§4.7）转发，因此**不执行**阶段4（Step 8~12，路由规划）和阶段5（Step 13~15，UDP端口计算与输出构造）。这是设计上的有意行为。

**Step 7 - 多跳路径还原：**
使用 `request.interDevices` 和真实拓扑数据，构建完整的 `InternalPathInfo`（§5.1）。

**7.1 拓扑数据校验：**
依次遍历 `interDevices` 的每个 `{deviceName → outPort}` 条目，在 `SuperNode.devices` 中检查：
- 设备存在性：若 `superNode.devices.get(deviceName)` 返回 null → 返回错误码 **1007**（`TOPO_INCOMPLETE`），流程终止。
- 端口存在性：若该设备的任何转发芯片的 `ports` 中找不到 `outPort`（通过 `device.getForwardingChips()` 遍历所有芯片，再调用 `chip.getPorts()` 查找端口） → 返回错误码 **1007**（`TOPO_INCOMPLETE`），流程终止。

**7.2 路径构建：**
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

**7.3 连接关系验证：**
每一跳的 `remoteDevice` / `remotePort` 必须与下一跳的 `deviceName` / `inPort` 一致。若不一致 → 返回错误码 **1009**（`TOPO_CONNECTION_NOT_FOUND`，§6.2）。

> **实现说明：** 设备查找使用 `superNode.getAllDevices()` 返回的统一视图（合并 npuDevices + swDevices），通过 HashMap O(1) 定位；端口通过 `NpuDevice.findNpuPort()`（NPU 设备，直接使用 `NpuForwardingChip.getNpuPorts()`，无需 instanceof/cast）或遍历转发芯片的 `getPorts()` Map（SW 设备）进行查找（§4.4、§4.5）。端口所属芯片（`chipIndex`）在 Step 10 路由查找时通过遍历设备所有 `ForwardingChip`（通过 `device.getForwardingChips()`）自动覆盖，无需在 Step 7 额外记录。

---

### 9.5 阶段4：路径规划循环（Step 8 ~ 12）

> **数据结构参见：** §4.7 RoutingTable（含 maskLengths）、§4.8 RoutePrefix、§4.9 RoutingEntry/OutPortInfo、§5.2 RouteSelectionRecord、§8 索引掩码匹配算法

阶段4 的核心结构为一个**二阶段循环**，以 `currentPhase` 状态标识区分前向/反向：

```
前向 (Step 8)          反向 (Step 9)
     │                       │
     ▼                       ▼
┌─────────────────────────────────────┐
│ Step 10: 路径规划循环（中间设备逐一执行） │
│   for each intermediate device:     │
│     1. 遍历该设备所有 ForwardingChip │
│     2. 对每个芯片做索引掩码匹配 (targetAddr) │
│     3. 取所有芯片的最优结果               │
│     4. 验证路由出端口与拓扑连接一致性      │
│     5. 若 ECMP → 记录 RouteSelectionRecord │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Step 12: 方向切换判断                   │
│   if currentPhase == FORWARD:        │
│       → Step 9 (切换反向)             │
│   if currentPhase == REVERSE:        │
│       → Step 14 (构造输出)            │
└─────────────────────────────────────┘
```

#### 9.5.1 前向阶段（Step 8 → 10 → 11 → 12）

**Step 8 - 前向路径规划初始设置：**
- 设置当前阶段标识 `currentPhase = FORWARD`
- 目的设备 = `dev2`，目的端口 = `port2`，目的地址 = `CNA2`（32 bit），源地址 = `CNA1`（32 bit）
- 进入 Step 10

#### 9.5.2 反向阶段（Step 9 → 10 → 11 → 12）

**Step 9 - 反向路径规划初始设置：**
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
- 进入 Step 10

#### 9.5.3 Step 10 - 路径规划循环（核心）

从当前 `InternalPathInfo.hops` 列表中**排除首尾节点**（首 = 当前源设备，尾 = 当前目的设备），对剩余中间设备依次执行路径规划。

> **首尾排除规则（与方向相关）：**
> - 前向阶段（FORWARD）：排除 hops[0]（dev1，源）和 hops[last]（dev2，目的）
> - 反向阶段（REVERSE）：排除 hops[0]（原 dev2，已逆序为路径的起点）和 hops[last]（原 dev1，已逆序为路径的终点）
> - 中间设备标准：**DeviceType == SW** 的交换设备。若反向阶段出现 NPU 设备（不合理路径），其端口无路由表（SW 端口无 CNA），算法在后续步骤会失败。

**对每个中间设备的处理流程：**

**① 地址确定：**
- `targetAddr` = 当前阶段的目的地址（前向 = `CNA2`，反向 = `CNA1`），32 bit CNA 地址。
- `prevHop` = 前一个 hop（已在循环中处理过的前一设备），用于 Step 10 ⑤ 的下一跳验证。

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

**⑤ 结果汇总后进入 Step 11：**
将最终的 `RoutingEntry` 和当前设备信息传入 Step 11 做出端口判断。

> **下一跳关系：** 对于当前处理的中间设备 `currentHop`：
> - 前向阶段：`currentHop` 的下一个 hop 在路径中索引更大（更靠近目的设备）
> - 反向阶段：`currentHop` 的下一个 hop 在路径中索引更大（此时更靠近原 dev1，即反转后的目的）

如果当前循环已处理完所有中间设备 → 跳过 Step 11，进入 Step 12。

#### 9.5.4 Step 11 - 出端口判断与选路记录

对 Step 10 返回的 `RoutingEntry.outPortInfos` 做出端口判断：

| 条件 | 处理 |
|:-----|:-----|
| `outPortInfos.size() == 1` | 正常使用该出端口，进入下一跳 |
| `outPortInfos.size() > 1 && 设备不支持自主逐流` | 返回错误码 **1011**（`MULTI_PATH_NOT_SUPPORTED`，§6.2） |
| `outPortInfos.size() > 1 && 设备支持自主逐流` | 创建一条 `RouteSelectionRecord`（§5.2），记录选路信息，进入下一跳 |

**RouteSelectionRecord 创建规则（ECMP 场景）：**

```
RouteSelectionRecord record = new RouteSelectionRecord();
record.setDeviceName(currentHop.deviceName);
record.setPrefix(matchedPrefix);                           // 匹配到的 RoutePrefix
record.setCandidateOutPorts(candidateList);                // 所有候选 OutPortInfo
record.setScna(CNA1);                                      // 源 CNA（不变）
record.setDcna(CNA2);                                      // 目的 CNA（不变）
record.setDirection(currentPhase == FORWARD ? Direction.FORWARD : Direction.REVERSE);
// hashInfo 记录三元组标识（SCNA:DCNA），供 Step 13 hash 计算使用
record.setHashInfo(CNA1 + ":" + CNA2);
```

- `candidateOutPorts`：所有候选 `OutPortInfo` 都加入，其中与 `interDevices` 指定出端口一致的端口标记为 `selected=true`（即路径指定的目标端口），其余为 `false`。
- 该记录追加到 `RouteSelectionRecord` 列表末尾，供 Step 13 使用。

> **框间多路径选路说明：** 当路径上存在多段 ECMP 时（如 L1SW0→L2SW 和 L2SW→L1SW1 均为多路径），Step 11 仅记录候选出端口列表及路径指定的目标端口（`selected=true`）。hash 算法搜索满足所有 ECMP 段约束的 UDP 端口号的详细流程见 Step 13。

#### 9.5.5 Step 12 - 方向切换判断

根据当前阶段标识 `currentPhase` 决定流程走向：

```
if currentPhase == FORWARD:
    // 前向阶段已完成所有中间设备的路由查找
    // 切换到反向阶段
    → 跳转到 Step 9（反向路径设置）

if currentPhase == REVERSE:
    // 反向阶段也已完成
    // 将路径恢复为正向顺序（再次反转）
    → 执行 path 反转（规则同 Step 9），恢复到正向顺序
    → 跳转到 Step 14（构造输出）
```

---

### 9.6 阶段5：构造输出（Step 13 ~ 15）

> **数据结构参见：** §5.2 RouteSelectionRecord、§6.2 PathPlanResult/PathInfo/HopInfo

**Step 13 - UDP 端口计算（框间多路径场景）：**

当 `RouteSelectionRecord` 列表非空时，需要为正向和反向分别计算一个 8 bit 源 UDP 端口号（0~255），使 hash 算法在每段 ECMP 上都选中 `interDevices` 指定的路径。

> **位宽约束说明：** `dataUdpSrcPort` 和 `ackUdpSrcPort` 均严格限定为 8 bit（0~255），由硬件卸载寄存器位宽决定。所有涉及 UDP 端口搜索的算法均在此空间内进行。

> **背景：** 框间多路径场景下（如 NPU0↔L1SW0↔L2SW↔L1SW1↔NPU1），中间设备 L1SW0 和 L2SW 上的路由表可能同时存在多个出端口（ECMP）。同一个源 UDP 端口号必须同时满足所有 ECMP 段的 hash 选路约束，确保整个路径按照 `interDevices` 指定的端口连通。

**13.1 Hash 算法定义：**

```
选中端口索引 = hash(SCNA, DCNA, srcUdpPort) % candidateOutPorts.size()
```

- **输入三元组**：`SCNA`（源 CNA，32 bit）+ `DCNA`（目的 CNA，32 bit）+ `srcUdpPort`（源 UDP 端口号，8 bit）
- **输出**：整数 hash 值，对候选端口数取模后得到选中的出端口索引
- **可打桩（stub）**：hash 函数可在测试时注入桩实现，精确控制特定三元组的输出值，绕过多段耦合的搜索复杂度

**13.2 正向路径端口计算（dataUdpSrcPort）：**

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

**13.3 反向路径端口计算（ackUdpSrcPort）：**

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

**13.4 正反向关系说明：**

| 属性 | 正向（dataUdpSrcPort） | 反向（ackUdpSrcPort） |
|:-----|:----------------------|:----------------------|
| Hash 输入 SCNA | CNA1（源端口 CNA） | CNA2（目的端口 CNA） |
| Hash 输入 DCNA | CNA2（目的端口 CNA） | CNA1（源端口 CNA） |
| 源 UDP 端口 | `dataUdpSrcPort`（8 bit） | `ackUdpSrcPort`（8 bit） |
| 对应结果字段 | `PathPlanResult.dataUdpSrcPort` | `PathPlanResult.ackUdpSrcPort` |

- 正反向路径经过的设备和出端口一致（由 `interDevices` 保证），但 hash 输入中的 SCNA/DCNA 互换，因此 `dataUdpSrcPort` 与 `ackUdpSrcPort` **独立计算**，取值可以不同。
- 当路径上仅有一段 ECMP 时，通常存在多个 UDP 端口值满足约束，搜索空间充裕。
- 当路径上存在多段 ECMP（如 L1SW0 和 L2SW 均存在多路径），同一个 UDP 端口必须同时满足多段约束，搜索空间缩小。由于 hash 为打桩实现，测试时可注入精确映射绕过多段耦合。

**13.5 无 ECMP 场景：**

若 `RouteSelectionRecord` 列表为空（路径上所有设备出端口均唯一），此步跳过，`dataUdpSrcPort` 和 `ackUdpSrcPort` 使用默认值或置空。

**13.6 RouteSelectionRecord 生命周期回顾：**

| 阶段 | 操作 | 记录方向 |
|:-----|:-----|:---------|
| 前向 (Step 8→10→11→12) | 正向路径的 ECMP 节点 → 追加记录 | FORWARD |
| 反向 (Step 9→10→11→12) | 反向路径的 ECMP 节点 → 追加记录 | REVERSE |
| Step 13 | 按方向分组消费，独立计算 dataUdpSrcPort / ackUdpSrcPort | 两方向 |

**Step 14 - 填充 PathPlanResult：**
填入以下信息到 `PathPlanResult` 对象（§6.2）：
- `sourceEid` / `destEid`：EID 对信息（来自 Step 1/2）
- `path`：路径逐跳信息（`PathInfo` → `List<HopInfo>`），由 `InternalPathInfo.hops`（§5.1）转换为外部 `HopInfo`（§6.2.2）
- `ackUdpSrcPort` / `dataUdpSrcPort`：UDP 端口对信息（若 Step 13 已计算）

**Step 15 - 返回成功：**
返回成功（码 **0**），附带完整的 `PathPlanResult` 信息。

---

### 9.7 错误码与步骤映射

| 错误码 | 名称 | 触发步骤 | 说明 |
|:-------|:-----|:---------|:-----|
| 0 | SUCCESS | Step 6 / 15 | 成功（直连成功或完整路径规划成功） |
| 1003 | SRC_INFO_ERR | Step 1 | 源信息缺失 |
| 1004 | DST_INFO_ERR | Step 2 | 目的信息缺失 |
| 1005 | ACL_CHECK_FAILED | Step 3 / 4 | ACL 校验失败（key 不存在或 CNA 不匹配） |
| 1007 | TOPO_INCOMPLETE | Step 0 / 7 | 拓扑不完整（设备在 SuperNode 中找不到） |
| 1008 | TOPO_CONNECTION_ERROR | Step 6 | 直连验证失败（端口连接关系不匹配） |
| 1009 | TOPO_CONNECTION_NOT_FOUND | Step 7 | 多跳路径还原失败（连接关系错误） |
| 1010 | ROUTE_NOT_REACHABLE | Step 10 | 路由不可达（无路由、无出端口或出端口与拓扑不一致） |
| 1011 | MULTI_PATH_NOT_SUPPORTED | Step 11 | 多路径（ECMP）且设备不支持自主逐流 |
| 1012 | TOPO_NOT_FOUND | Step 0 | 超节点不存在 |
| 1013 | ACL_NOT_FOUND | Step 3 / 4 | AclData 对象不存在（补充检查） |
| 3002 | SRC_AND_DST_MUST_BE_NPU | Step 0 | 源和目的必须为 NPU 设备 |
| 3003 | UPI_MISMATCH | Step 0 | 源和目的端口 UPI 不一致 |

---

### 9.8 流程数据流总览

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
┌──────────────────────────────────────────────────────────────────────────┐
│ 阶段2 (Step 3~4): ACL 双向校验                                            │
│   AclData.tpAcls → AclKey(EID1, EID2, RCTP) → TpAclEntity               │
│   验证: sourceCna == CNA1, destCna == CNA2 (正向+反向)                    │
│   错误码: 1005, 1013                                                      │
└─────────────────────────┬────────────────────────────────────────────────┘
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
┌─────────────────────────┐  ┌──────────────────────────────────────────────┐
│ 阶段3: interDevices 为空  │  │ 阶段3: interDevices 非空                       │
│ Step 6: 直连验证 (终端)   │  │ Step 7: 多跳路径还原 → InternalPathInfo         │
│ 错误码: 1008              │  │   校验: 设备存在性, 端口存在性, 连接连续性      │
│ 成功: 直接返回 (码 0)     │  │   错误码: 1007, 1009                           │
└─────────────────────────┘  └─────────────────────┬────────────────────────┘
                                                    │
┌──────────────────────────────────────────────────────────────────────────┐
│ 阶段4 (Step 8→9→10→11→12): 路径规划循环 (前向 + 反向)                      │
│   Step 8: 前向设置 (target=CNA2, dst=dev2, phase=FORWARD)                  │
│   Step 9: 反向设置 (反转路径, target=CNA1, dst=dev1, phase=REVERSE)         │
│                                                                           │
│   Step 10 (对每个中间设备):                                                 │
│     ┌─────────────────────────────────────────────────────────────────┐  │
│     │ ① 遍历 device.getForwardingChips() 所有芯片                         │  │
│     │ ② 对每个芯片: RoutingTableKey → superNodeStore.getRoutingTable   │  │
│     │ ③ 索引掩码匹配: maskLengths[0..n] → RoutePrefix → O(1) 命中       │  │
│     │ ④ 跨芯片择优: 取 maskLen 最大的 RoutingEntry                      │  │
│     │ ⑤ 出端口与下一跳一致性校验                                         │  │
│     │ ⑥ 结果送入 Step 11                                                │  │
│     └─────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│   Step 11: 出端口判断                                                     │
│     1个出端口 → 正常进入下一跳                                            │
│     多个出端口(不支持ECMP) → 1011                                        │
│     多个出端口(支持ECMP) → 追加 RouteSelectionRecord                     │
│                                                                           │
│   错误码: 1010, 1011                                                      │
└──────────────────────────────────────────┬───────────────────────────────┘
                                           │
┌──────────────────────────────────────────────────────────────────────────┐
│ 阶段5 (Step 13~15): 构造输出                                              │
│   Step 13: UDP 端口计算 (基于前向+反向 的 RouteSelectionRecord 列表)       │
│   Step 14: InternalPathInfo → PathPlanResult [§6.2]                     │
│   Step 15: 返回成功 (码 0)                                               │
└──────────────────────────────────────────────────────────────────────────┘
```

---

---
