# SNC 模块接口文档

## 1. 概述

SNC（SuperNode Network Controller）模块提供 SuperNode 拓扑管理、ACL 访问控制、路径规划等功能。对外暴露统一的 `SNCService` 接口，内部采用分层架构：Service → Engine → Store。

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

### 2.3 ACL 管理

| 方法 | 参数 | 返回值 | 描述 | 异常说明 |
|------|------|--------|------|---------|
| `setAclData` | `AclData aclData` | `void` | 导入（**按 superNodeName 覆盖**）ACL 数据，标记 aclLoaded，更新数据就绪状态；同 superNodeName 的旧 ACL 被覆盖，不同 name 的 ACL 共存不受影响 | INIT/UNINIT → `SNCStateException`；参数 null/name空 → `IllegalArgumentException`；**子字段（tpAcls/AclKey/TpAclEntity 内部字段）不校验**，缺失时 `planPath` 返回 `ACL_CHECK_FAILED` |
| `addAclRules` | `String superNodeName, Map<AclKey, TpAclEntity> rules` | `void` | 批量添加 ACL 规则；ACL 数据不存在则**抛 IllegalStateException**（"ACL data not found for superNode: \<name\>"） | INIT/UNINIT → `SNCStateException`；null参数 → `IllegalArgumentException`；null key/value → `IllegalArgumentException`；目标 ACL 不存在 → `IllegalStateException` |
| `removeAclRules` | `String superNodeName, List<AclKey> keys` | `void` | 批量移除 ACL 规则；目标 ACL 数据不存在则**抛 IllegalStateException**（"ACL data not found for superNode: \<name\>"） | INIT/UNINIT → `SNCStateException`；null参数 → `IllegalArgumentException`；null key → `IllegalArgumentException`；目标 ACL 不存在 → `IllegalStateException` |
| `getAclData` | `String superNodeName` | `AclData` | 查询指定 SuperNode 的 ACL 数据 | INIT/UNINIT → `SNCStateException`；不存在返回 `null`（非异常） |
| `removeAclData` | `String superNodeName` | `void` | 删除指定 SuperNode 的 ACL 数据 | INIT/UNINIT → `SNCStateException` |

### 2.4 路径规划

| 方法 | 参数 | 返回值 | 描述 | 异常说明 |
|------|------|--------|------|---------|
| `planPath` | `PathPlanRequest request` | `PathPlanResult` | 规划源到目的的传输路径 | 非 DATAREADY 状态 → `SNCStateException`（消息格式："SNC is not in DATAREADY state, current state: \<STATE\>"，**不同于**其他方法的 checkNotUninit 拦截消息） |
| | | | | request 为 null 或 superNodeName/srcDevice/destDevice/srcPort/destPort 任一为 null/空 → `IllegalArgumentException` |
| | | | | **interDevices 字段可选**（可为 null/空，表示直连场景） |
| | | | | 业务失败时不抛异常，返回 `PathPlanResult.status` 非 SUCCESS，详见下方 `PlanStatus` 映射表 |
| | | | | **路由查找机制**：planPath 内部路由查找以目的端口的 CNA（`destCna`）作为查找目标，直接与路由前缀做 LPM 匹配。|

---

## 3. 状态机

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
| `INIT` | 初始状态（未初始化） | init()、uninit() |
| `READY` | 就绪状态（已初始化，数据未就绪） | setSuperNode、setAclData；所有增量操作（addNpuDevices、addSwDevices、removeDevices、addRoutingEntries、removeRoutingEntries、addAclRules、removeAclRules）；所有查询操作（getSuperNode、getAclData）；removeSuperNode、removeAclData；uninit |
| `DATAREADY` | 数据就绪状态（拓扑+ACL 均已下发） | 同 READY，追加 planPath |
| `UNINIT` | 已去初始化 | （无，调用任何操作均抛 SNCStateException） |

**状态转换规则：**
- `init()`: INIT → READY（非幂等，重复 init 重建全部内部对象）
- `uninit()`: INIT / READY / DATAREADY → UNINIT（INIT 状态调用仅清空状态标记，无副作用）
- `setSuperNode()` + `setAclData()`: READY → DATAREADY（二者均下发后自动迁移）
- `setSuperNode()` / `setAclData()`: DATAREADY → DATAREADY（数据就绪态可继续更新数据）
- `planPath()`: 仅在 **DATAREADY** 状态下可用，非 DATAREADY 时抛 `SNCStateException`，消息为 `"SNC is not in DATAREADY state, current state: <STATE>"`（**注意**：planPath 不走 `checkNotUninit`，自有状态判断，消息格式与其他方法不同）

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

### 3a.2 setAclData 校验层级

| 层级 | 字段 | 校验规则 | 非法时行为 |
|------|------|---------|-----------|
| L0 | `aclData` 本身 | non-null | `IllegalArgumentException` |
| L1 | `aclData.superNodeName` | non-null, non-empty | `IllegalArgumentException` |
| L1 | `aclData.tpAcls` | **不校验** | 可为 null/空，后续 `addAclRules` 需 ACL 数据已存在，否则抛 `IllegalStateException` |
| L2 | `AclKey.srcEid` | **不校验** | `AclCheckEngine.checkBothDirection` 中用 null 查 Map → 匹配失败 |
| L2 | `AclKey.dstEid` | **不校验** | 同上 |
| L2 | `AclKey.transportType` | **不校验** | 同上（RCTP 硬编码查找，其他类型不匹配） |
| L2 | `TpAclEntity.sourceCna/destCna` | **不校验** | `checkBothDirection` 中比较 null CNA → `ACL_CHECK_FAILED` |
| L2 | `TpAclEntity.templateId` | **不校验** | 当前未使用 |

### 3a.3 增量操作校验层级

与导入同理，增量操作（`addNpuDevices`、`addSwDevices`、`addAclRules` 等）仅校验自身入参，**嵌套对象字段不做校验**：

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
| 无 | 无 | ACL 规则内部字段（srcEid, sourceCna...） |

---

## 3b. 通用异常行为

所有方法（除 `init` 外）在错误状态调用时抛出 `SNCStateException`：

> ⚠️ **planPath 例外**：`planPath` 不走 `checkNotUninit` 拦截，自有 `state != DATAREADY` 判断，统一抛 `"SNC is not in DATAREADY state, current state: <STATE>"`（INIT/READY/UNINIT 同形）。其余方法走 `checkNotUninit`，消息为 `"SNC is in INIT state"` 或 `"SNC is in UNINIT state"`。

| 当前状态 | 调用 `init` | 调用 `uninit` | 调用其他方法 |
|----------|------------|--------------|-------------|
| `INIT` | 正常执行 → READY | 正常执行 → UNINIT | 抛 `SNCStateException("SNC is in INIT state")` |
| `READY` | 正常执行（重新初始化） | 正常执行 → UNINIT | 正常执行 |
| `DATAREADY` | 正常执行（重新初始化） | 正常执行 → UNINIT | 正常执行 |
| `UNINIT` | 正常执行 → READY | 正常执行 | 抛 `SNCStateException("SNC is in UNINIT state")` |

### 3b.2 参数校验异常

**有校验的方法**（setSuperNode、addNpuDevices、addSwDevices、removeDevices、addRoutingEntries、removeRoutingEntries、setAclData、addAclRules、removeAclRules、planPath、getSuperNode、removeSuperNode、getAclData、removeAclData）：

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
| `getAclData(name)` | AclData 对象 | `null`（非异常） |

---

## 3c. 调用时序异常场景

### 3c.1 先增量操作，后 setSuperNode/setAclData

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
| `addAclRules` → `setAclData` | 同上，ACL 侧同理 | `IllegalStateException` |

### 3c.2 未导入拓扑/ACL 就增量操作

| 操作 | 条件 | 行为 | 结果 |
|------|------|------|------|
| `addNpuDevices("nonExistent", ...)` | 该 SuperNode 不存在 | **抛 IllegalStateException** | 明确提示 |
| `addSwDevices("nonExistent", ...)` | 该 SuperNode 不存在 | **抛 IllegalStateException** | 明确提示 |
| `removeDevices("nonExistent", ...)` | 该 SuperNode 不存在 | **静默无操作** | 数据未被删除，也无异常 |
| `addRoutingEntries("nonExistent", ...)` | 该路由表不存在 | **抛 IllegalStateException** | 明确提示 |
| `removeRoutingEntries("nonExistent", ...)` | 该路由表不存在 | **静默无操作** | 同上 |
| `addAclRules("nonExistent", ...)` | 该 ACL 数据不存在 | **抛 IllegalStateException** | 明确提示："ACL data not found for superNode: nonExistent" |
| `removeAclRules("nonExistent", ...)` | 该 ACL 数据不存在 | **抛 IllegalStateException** | 同上 |
| `removeSuperNode("nonExistent")` | 该 SuperNode 不存在 | **静默无操作** | Map.remove null → 无影响 |
| `removeAclData("nonExistent")` | 该 ACL 不存在 | **静默无操作** | 同上 |

### 3c.3 只做增量操作，不调 setSuperNode/setAclData

```java
sncService.init(config);
sncService.addNpuDevices("sn1", devices);       // 抛 IllegalStateException（SuperNode 不存在）
// 无法跳过 setSuperNode 直接增量操作
```

仅 `setSuperNode()` 和 `setAclData()` 会设置 `superNodeLoaded`/`aclLoaded` 标志。全部增量操作**不设置**这些标志 → 状态永远不会进入 DATAREADY → `planPath` 始终失败。

### 3c.4 重复导入

| 操作 | 行为 |
|------|------|
| `setSuperNode(SN1)` → `setSuperNode(SN2)` | **同 name**：第二次覆盖第一次（`Map.put` 语义），SN1 旧数据丢失；**不同 name**：两者共存互不影响 |
| `setAclData(AD1)` → `setAclData(AD2)` | 同上，ACL 侧同理（按 `superNodeName` 覆盖） |
| `init()` → `init()` | 每次创建新的 Store/Engine/Service 实例，旧实例被丢弃 |
| `init()` → `uninit()` → `init()` | 正常：先清理，后重新初始化 |

### 3c.5 跨 SuperNode 不匹配

| 场景 | 行为 | 结果 |
|------|------|------|
| `setSuperNode("snA", ...)` + `setAclData("snB", ...)` | SuperNode 名 "snA" ≠ ACL 名 "snB" | 两者在各自 store 中均存在，但 `planPath("snA", ...)` 查 ACL 时返回 null → `ACL_NOT_FOUND` |

### 3c.5a 进入 DATAREADY 后删除数据，状态会回退

```java
setSuperNode(sn);                         // superNodeLoaded=true
setAclData(acl);                           // aclLoaded=true  → DATAREADY
removeSuperNode("sn1");                    // 数据已删，superNodeLoaded = getSuperNode("sn1") != null → false
planPath(req);                             // 状态检查失败 → SNCStateException（状态已回退到 READY）
```

`updateDataReadyState()` 在 `superNodeLoaded` 或 `aclLoaded` 变为 false 时，会将状态从 DATAREADY 回退到 READY。因此删除数据后**状态会回退**，后续 `planPath` 调用会抛出 `SNCStateException`。

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

### 3c.7 setSuperNode 后状态不完全

```java
setSuperNode(sn);  // superNodeLoaded = true, aclLoaded = false
// 状态仍为 READY
planPath(req);     // SNCStateException
```

必须 `setSuperNode` 和 `setAclData` 都调用，状态才能变为 DATAREADY。

### 3c.8 init 异常场景

| 场景 | 行为 | 后果 |
|------|------|------|
| `init(null)` | config 未使用，正常运行 | 无异常，正常进入 READY |
| `init()` 连续调用两次 | 第二次重建所有 Store/Engine/Service | 第一次加载的数据完全丢失（无合并），状态重置为 READY |
| `init()` 时字段状态 | 创建新实例，重置 `superNodeLoaded=false, aclLoaded=false` | 之前状态完全清空 |
| `init()` → 之后立即调其他方法 | 正常执行，状态为 READY | 仅 `planPath` 被阻止（需 DATAREADY） |

### 3c.9 uninit 异常场景

| 场景 | 行为 | 后果 |
|------|------|------|
| `uninit()` 在 `init()` 之前调用 | Store 字段为 null，但 `uninit` 有 null 检查 | 安全无操作，状态 → UNINIT |
| `uninit()` 连续调用两次 | 第二次时 Store 已空，`clear()` 安全无副作用 | 状态保持 UNINIT |
| `uninit()` → 调非 init 方法 | `checkNotUninit()` 检测到 UNINIT | 抛 `SNCStateException("SNC is in UNINIT state")` |
| `uninit()` → `init()` → 正常操作 | 重建 Store，重新进入 READY | 正常工作 |

### 3c.10 planPath 异常场景

| 场景 | 行为 | 结果 |
|------|------|------|
| `planPath` 时状态为 INIT | `SNCServiceImpl.planPath` 自有状态判断（不走 checkNotUninit） | `SNCStateException("SNC is not in DATAREADY state, current state: INIT")` |
| `planPath` 时状态为 READY | 同上 | `SNCStateException("SNC is not in DATAREADY state, current state: READY")` |
| `planPath` 时状态为 UNINIT | 同上 | `SNCStateException("SNC is not in DATAREADY state, current state: UNINIT")` |
| `planPath(request)` 中 srcDevice 不存在于 SuperNode | PathService.planPath lookup 返回 null | `TOPO_INCOMPLETE` |
| `planPath(request)` 中 destDevice 不存在 | 同上 | `TOPO_INCOMPLETE` |
| `planPath(request)` 中 srcDevice/destDevice 为交换机（非 NPU） | PathService.planPath 两层判断：设备存在于 swDevices 但 deviceType ≠ NPU | `SRC_AND_DST_MUST_BE_NPU(3002)` |
| `planPath(request)` 中 srcPort 在设备上不存在 | NpuDevice.findNpuPort 返回 null | `SRC_INFO_ERR` |
| `planPath(request)` 中 destPort 在设备上不存在 | 同上 | `DST_INFO_ERR` |
| `planPath` 时 ACL 数据在 store 中不存在（跨名错配） | getAclData 返回 null | `ACL_NOT_FOUND` |
| `planPath` 直连场景两端 remote 不匹配 | PathService 验证失败 | `TOPO_CONNECTION_ERROR` |
| `planPath` 多跳场景中间连接不一致 | PathEngine.resolveMultiHopPath 抛出异常 | `TOPO_CONNECTION_NOT_FOUND` |
| `planPath` 路由不可达（中间设备最长前缀匹配未命中或无出端口） | PathService.routePhase 抛 `PathPlanException(ROUTE_NOT_REACHABLE)` | `ROUTE_NOT_REACHABLE(1010)` |
| `planPath` 直连场景经 init 重置后未重设拓扑/ACL | 状态为 READY | `SNCStateException`（不会进入 planPath 逻辑） |

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
| `SUCCESS` | 0 | success | 路径规划成功 |
| `SRC_INFO_ERR` | 1003 | src info error | 源端口不存在/EID 或 CNA 为 null/格式错误 |
| `DST_INFO_ERR` | 1004 | dst info error | 目的端口不存在/EID 或 CNA 为 null/格式错误 |
| `ACL_CHECK_FAILED` | 1005 | acl check failed | 正向或反向 ACL 条目缺失/CNA 不匹配 |
| `TOPO_INCOMPLETE` | 1007 | topo incomplete | srcDevice 或 destDevice 在 SuperNode 中不存在 |
| `TOPO_CONNECTION_ERROR` | 1008 | topo connection error | 直连拓扑中 src 和 dest 端口 remoteDevice/remotePort 不匹配 |
| `TOPO_CONNECTION_NOT_FOUND` | 1009 | topo connection not found | 多跳拓扑中某跳间连接不一致 |
| `ROUTE_NOT_REACHABLE` | 1010 | route not reachable | 中间设备路由不可达 |
| `TOPO_NOT_FOUND` | 1012 | topo not found | 请求的 SuperNode 名称在 store 中不存在 |
| `ACL_NOT_FOUND` | 1013 | acl not found | 请求的 SuperNode 的 ACL 数据未加载 |
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

---

## 5. 异常定义

| 异常类 | 父类 | 说明 |
|--------|------|------|
| `SNCException` | `RuntimeException` | 基类异常 |
| `SNCStateException` | `SNCException` | SNC 状态错误 |
| `SuperNodeNotFoundException` | `SNCException` | SuperNode 或设备未找到 |
| `AclNotFoundException` | `SNCException` | ACL 数据未找到 |
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

### `AclService`

| 方法 | 参数 | 返回值 |
|------|------|--------|
| `importAclData` | `AclData` | `void` |
| `addAclRules` | `String, Map<AclKey, TpAclEntity>` | `void` |
| `removeAclRules` | `String, List<AclKey>` | `void` |
| `getAclData` | `String` | `AclData` |
| `removeAclData` | `String` | `void` |

### `PathService`

| 方法 | 参数 | 返回值 |
|------|------|--------|
| `planPath` | `PathPlanRequest` | `PathPlanResult` |

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
| `AclCheckEngine` | `checkBothDirection` | `AclData, String, String, String, String` | `boolean` |

---

## 8. Store 内部接口

| Store | 方法 |
|-------|------|
| `SuperNodeStore` | `init, clear, replace, removeSuperNode, getSuperNode, getRoutingTable, addNpuDevice, addSwDevice, removeDevice, addRoutingEntry, removeRoutingEntry` |
| `AclStore` | `init, clear, replace, removeAclData, getAclData, addAclRule, removeAclRule` |
