# 路由收敛功能设计 Wiki

## 1. 概述

### 1.1 功能定位
路由收敛是 SNC（Supernode Network Controller）在收到 link 事件（端口 up/down）后，按广度优先策略在互联转发节点间逐跳传播收敛状态，并刷新各节点路由可达性的能力。收敛结果直接写入 SNCService 持有的 `instantiationRouteMap`，供后续路由查询、下发使用。

### 1.2 设计目标
- 类似路由协议的逐跳传播：可达性变化才传播，无变化不传播，避免无效扩散。
- 转发隔离：同一设备内不同 `ForwardingChip` 是转发隔离的，收敛只在端口所属 chip 的路由表内传播，且向对端传播时只更新对端 peerPort 所属 chip 的路由表。
- 增量传播：BFS 任务只携带可达性变化的路由前缀集合 `changedPrefixes`，对端仅在这些前缀范围内检查，减少冗余扫描。
- 状态可恢复：down 收敛与 up 恢复对称，多次事件复用历史 link 状态。

### 1.3 入口
`SNCService.notifyLinkEvent(supernode, event)`：先调用 `LinkEventService` 更新端口 linkStatus，再调用 `RouteConvergeService.converge` 触发收敛。

## 2. 核心数据结构

### 2.1 OutPortInfo（出端口信息）
- 取消原 `active` 字段，替换为 `int convergedFlag`，按位表达多种收敛状态。
- 两种收敛标志位（位于 `OutPortInfo.java`）：

| 常量 | 值 | 含义 |
|---|---|---|
| `FLAG_PASSIVE_CONVERRGED` | `1 << 0` | 被动 link 事件收敛（端口 down 触发） |
| `FLAG_ACTIVE_CONVERRGED`  | `1 << 1` | 主动操作收敛（运维下发、策略变更） |

- 关键方法：
  - `isConverged()`：`convergedFlag != 0`，表示该出端口不再参与转发。
  - `setFlag(flag)`：按位或，叠加收敛原因。
  - `clearFlag(flag)`：清除指定位，保留其它位。

### 2.2 RoutingEntry（路由条目）
- 新增 `boolean reachable = true`，表达路由可达性（即 `outPortInfos` 中是否存在 `convergedFlag==0` 的有效出端口）。
- `refreshReachable()`：遍历出端口，任一 `convergedFlag==0` 则 `reachable=true`，否则 `false`。
- `getMutableOutPortInfos()`：返回可变 Map，供收敛逻辑直接修改 `OutPortInfo.convergedFlag`；`getOutPortInfos()` 返回不可变视图。

### 2.3 LinkEvent（链路事件）
- 静态常量 `LINK_STATUS_UP="up"`、`LINK_STATUS_DOWN="down"`，统一事件类型字面量，消除硬编码。
- 字段：`deviceName`、`portName`、`eventType`、`eventTime`。

### 2.4 instantiationRouteMap（路由表存储）
- 类型：`Map<String, Map<String, RoutingEntry>>`
- 外层 key：`"deviceName#chipIndex"`，由 `RouteInstantiationService.buildRouteTableKey` 生成，分隔符常量 `KEY_SEPARATOR="#"` 定义在 `RouteInstantiationService`。
- 内层 key：路由前缀（prefix 字符串）。

## 3. 算法设计

### 3.1 总体流程
1. `prepareContext`：校验入参、定位事件端口所属 chip、构造 `ConvergeContext`。
2. `processLocalChip`：在起始节点本地 chip 路由表中扫描事件端口出接口，刷新 `OutPortInfo.convergedFlag` 与 `RoutingEntry.reachable`，得到可达性变化的前缀集合 `startChanged`。若为空则直接结束。
3. 起始任务 `ConvergeTask(ctx, startDevice, startPort, startChipIndex, startChanged)` 入队。
4. BFS 循环：每轮从队列取出 task，调用 `propagateToPeers` 向对端传播。
5. 队列空，收敛结束。

### 3.2 ConvergeTask 设计
```
ConvergeTask {
    ConvergeContext ctx;          // 整个 BFS 共享上下文
    String device;                // 本节点设备名
    String inPort;                // 接收传播的入端口
    int chipIndex;                // inPort 所属 chip
    Set<String> changedPrefixes;  // 本节点可达性变化的前缀集合
}
```
- `inPort` 语义：
  - 起始任务为 link 事件端口（接收外部事件的"入端口"）。
  - 传播任务为对端转发节点接收上游传播的入接口。
- `propagateToPeers` 遍历 chip 所有端口时跳过 `inPort`，避免往回传播给上游节点。
- `changedPrefixes` 由上游计算后传入，对端仅在这些前缀范围内检查可达性变化。

### 3.3 propagateToPeers（向所有对端传播）
位于 `RouteConvergeService.java#propagateToPeers`。遍历 `task.chipIndex` 这个 chip 的所有端口：
1. 跳过 null、跳过 `task.inPort`（避免回传上游）。
2. 跳过 `linkStatus==down` 的端口（down 端口无法将本节点可达性传递给对端）。
3. 通过 `port.getRemoteDevice()/getRemotePort()` 定位对端入接口。
4. `visited` 集合去重（key = `peerDevice#peerPort`），已访问的对端跳过。
5. 调用 `propagateToPeer` 向单个对端传播。

### 3.4 propagateToPeer（向单个对端传播）
1. `findChipByPort` 定位 peerPort 所属 chip（转发隔离：只更新对端对应 chip 的路由表）。
2. `updateOutPortOnChipByPrefixes`：在 `"peerDevice#peerChipIndex"` 路由表中，仅查询 `task.changedPrefixes` 范围内的路由，刷新其中出端口为 peerPort 的 `OutPortInfo.convergedFlag`，并 `refreshReachable`，返回 reachable 变化的前缀集合 `peerRouteChanged`。
3. 若 `peerRouteChanged` 非空，构造新任务 `ConvergeTask(ctx, peerDevice, peerPort, peerChipIndex, peerRouteChanged)` 入队，继续 BFS。

### 3.5 applyConverge（收敛动作）
- down 事件：`outPort.setFlag(FLAG_PASSIVE_CONVERRGED)`。
- up 事件：`outPort.clearFlag(FLAG_PASSIVE_CONVERRGED)`。
- 刷新 `routingEntry.refreshReachable()`，返回 reachable 是否变化。

### 3.6 关键不变量
- 转发隔离：收敛只在端口所属 chip 路由表内传播；向对端传播时只更新对端 peerPort 所属 chip 的路由表。
- 增量传播：只传播 `changedPrefixes` 范围；对端 reachable 无变化则不入队。
- 链路状态过滤：down 端口不参与传播。
- 回传保护：遍历时跳过 `task.inPort`，避免往回传播给上游节点。
- visited 去重：`(peerDevice, peerPort)` 只访问一次。

## 4. 接口与集成

### 4.1 SNCService 集成点
- 字段：`private RouteConvergeService routeConvergeService;`
- 初始化：`this.routeConvergeService = new RouteConvergeService();`（无参构造）
- 触发：`notifyLinkEvent` 中先更新 linkStatus，再调用 `routeConvergeService.converge(instantiationRouteMap, supernode, event)`
- 卸载：`uninit` 中置 null。

### 4.2 RouteConvergeService 对外接口
```
public void converge(Map<String, Map<String, RoutingEntry>> instantiationRouteMap,
                     SuperNode supernode, LinkEvent event)
```
- 入参为路由表存储、超级节点拓扑、链路事件。
- 无返回值，结果直接写入 `instantiationRouteMap`。
- 异常：入参 null 或 eventType 非法抛 `IllegalArgumentException`；端口/chip 不存在抛 `IllegalStateException`。

## 5. 收敛示例（NPU-L1-L2 三层拓扑）

### 5.1 拓扑
```
NPU0 -- L1SW -- L2SW
NPU1 -- L1SW
```
- L1SW 上有 4 个端口：`L1SW_DOWN_TO_NPU0`(连 NPU0)、`L1SW_DOWN_TO_NPU1`(连 NPU1)、`L1SW_UP`(连 L2SW)、本机内部。
- 每个节点上都有到所有 NPU 前缀的路由（`PREFIX_NPU0`、`PREFIX_NPU1`、`PREFIX_L2SW` 等）。

### 5.2 场景：L1SW_DOWN_TO_NPU0 down（中间节点端口 down）
1. 起始任务：device=L1SW, inPort=L1SW_DOWN_TO_NPU0, chip=SW_CHIP。
2. `processLocalChip`：L1SW 上 PREFIX_NPU0 的 L1SW_DOWN_TO_NPU0 出端口收敛，reachable 变 false → `startChanged={PREFIX_NPU0}`。
3. `propagateToPeers`：遍历 L1SW 其他端口，跳过 L1SW_DOWN_TO_NPU0（已 down）。
   - 经 `L1SW_DOWN_TO_NPU1` → NPU1：在 NPU1 上 PREFIX_NPU0 的 NPU1_UP 出端口收敛，reachable 变 false → 入队。
   - 经 `L1SW_UP` → L2SW：在 L2SW 上 PREFIX_NPU0 的 L2SW_DOWN 出端口收敛，reachable 变 false → 入队。
4. NPU1/L2SW 均为叶子（单端口），`propagateToPeers` 无其他端口可遍历，BFS 结束。
5. 结果：L1SW/NPU1/L2SW 上 PREFIX_NPU0 不可达；NPU0 上 PREFIX_NPU0 仍可达（L1SW_DOWN_TO_NPU0 已 down 被跳过，未向 NPU0 传播）。

### 5.3 场景：down L1SW_DOWN_TO_NPU0 → down L1SW_UP → up L1SW_UP → up L1SW_DOWN_TO_NPU0
- 验证连续多事件复用历史 link 状态：每次 converge 基于当前 `port.getLinkStatus()` 过滤；down 端口在后续传播中被跳过；up 恢复时若对端前缀未被收敛过则 reachable 不变，不入队。

## 6. 测试覆盖

测试类：`RouteConvergeServiceTest.java`，12 个用例：

| 场景 | 验证点 |
|---|---|
| 本地收敛不传播（叶子节点端口 down） | 仅本地 reachable 变化，无对端传播 |
| 中间节点端口 down 跨节点传播 | L1SW→NPU1/L2SW 三层传播 |
| 多路径不重复传播 | visited 去重 |
| down 后 up 恢复 | 收敛标志清除、reachable 恢复 |
| 连续多事件复用 link 状态 | down 端口跳过、恢复顺序影响 |
| 参数校验 | null 入参、非法 eventType 抛异常 |

## 7. 文件清单

| 文件 | 变更 |
|---|---|
| `route/service/RouteConvergeService.java` | 新增，BFS 收敛算法实现 |
| `route/service/RouteInstantiationService.java` | 新增 `KEY_SEPARATOR`、`buildRouteTableKey` |
| `SNCService.java` | 集成 `RouteConvergeService`，`notifyLinkEvent` 触发收敛 |
| `entity/OutPortInfo.java` | `active` → `convergedFlag` + 标志位 |
| `entity/RoutingEntry.java` | 新增 `reachable` + `refreshReachable` |
| `entity/LinkEvent.java` | 新增 `LINK_STATUS_UP/DOWN` 常量 |
| `service/LinkEventService.java` | 引用 `LinkEvent` 常量，去重 |
| `test/.../RouteConvergeServiceTest.java` | 新增，12 个测试用例 |

## 8. 约束与注意事项

1. **路由表必须先实例化**：`converge` 依赖 `instantiationRouteMap` 已由 `RouteInstantiationService` 填充完毕，否则 `processLocalChip` 扫描不到路由，`startChanged` 为空直接返回。
2. **linkStatus 必须先更新**：`notifyLinkEvent` 中 `linkEventService.notifyLinkEvent` 必须先于 `converge` 执行，否则 `propagateToPeers` 的 down 端口过滤基于旧状态。
3. **线程安全**：`RouteConvergeService` 无状态，`instantiationRouteMap` 由 `SNCService` 持有，调用方需保证并发访问安全。
4. **不自动补传**：若某前缀在某次 up 事件中因端口 down 未恢复到某节点，后续不会自动补传，需再次触发相关 link 事件。
