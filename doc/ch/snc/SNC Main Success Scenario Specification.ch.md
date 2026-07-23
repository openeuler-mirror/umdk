# SNC PathService 主成功场景测试设计

> 基于 `topo_data_2npu_1port.json` / `acl_data_2npu_1port.json` 和 `topo_data_4npu_8port.json` / `acl_data_4npu_8port.json` 两组测试工具，设计 planPath 主成功场景。

---

## 1. 全局假设与数据修正

### 1.1 AclData.superNodeName 映射

`AclData` 的标识字段已从 `aclId` 重命名为 `superNodeName`。JSON 中 ACL 的 `aclId` 字段值（`"acl-001"`）在加载时需映射为 `AclData.superNodeName` 为 `"A5-superPod-1"`，以匹配 `aclStore.getAclData(request.getSuperNodeName())` 的查找逻辑。

### 1.2 2npu_1port 路由前缀修正

JSON 中 L1SW0 路由前缀与 NPU 端口 CNA 经 `cnaToTargetAddr()` 后的结果不匹配：

| L1SW 路由(JSON) | 应修正为 | 对应的 NPU 端口 CNA | cnaToTargetAddr |
|---|---|---|---|
| `170.170.170.17/32` | `170.170.170.18/32` | NPU1 `400GE 0/0/1` → `170.170.170.18` | `170.170.170.18` |
| `221.221.221.68/32` | `221.221.221.66/32` | NPU2 `400GE 0/1/1` → `221.221.221.66` | `221.221.221.66` |

否则 `routePhase` 中 LPM 查找因 `/32` 精确匹配失败，抛出 `ROUTE_NOT_REACHABLE`。

### 1.3 4npu_8port 路由前缀修正

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
| 3 | ACL 双向检查 | srcEid=AAAA...02, dstEid=DDDD...02, srcCna=170.170.170.18, destCna=221.221.221.66 → 匹配 |
| 5 | interDevices 非空 | 进入多跳逻辑 |
| 7 | 多跳路径还原 | hops=[NPU1, L1SW0, NPU2] |
| 8 | 正向 routePhase | 中间跳 L1SW0, target=`cnaToTargetAddr("221.221.221.66")`=`"221.221.221.66"` |
| 8 | L1SW0 路由查找 | 前缀 `221.221.221.66/32`(修正后) → 匹配, outPort=400GE 1/0/2 |
| 9 | 反向 routePhase | 中间跳 L1SW0, target=`cnaToTargetAddr("170.170.170.18")`=`"170.170.170.18"` |
| 9 | L1SW0 路由查找 | 前缀 `170.170.170.18/32`(修正后) → 匹配, outPort=400GE 1/0/1 |
| 13-15 | 构建结果 | SUCCESS |

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
| 3 | ACL 检查 | ACL 中存在 AAAA...01 ↔ DDDD...01 条目 |
| 5 | interDevices 非空 | 进入多跳逻辑 |
| 7 | 多跳路径还原 | hops=[NPU1, L1SW0, NPU2] |
| 8 | 正向 routePhase | target=`cnaToTargetAddr("221.221.221.68")`=`"221.221.221.68"` |
| 8 | L1SW0 路由查找 | `221.221.221.68/32` → 1/0/2 → 匹配 outPort=`400GE 1/0/2` |
| 9 | 反向 routePhase | target=`cnaToTargetAddr("170.170.170.17")`=`"170.170.170.17"` |
| 9 | L1SW0 路由查找 | `170.170.170.17/32` → 1/0/0 → 匹配 outPort=`400GE 1/0/0` |
| 13-15 | 构建结果 | SUCCESS |

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

需修正路由前缀后使用（见 1.3 节 L1SW1 路由修正）。

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
| ACL 检查 | 匹配 AAAA...02 ↔ EEEE...02 条目 |
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

## 4. 数据验证清单

需确认数据满足以下约束：

### 4.1 路由一致性

对每对 `(L1SW, NPU端口)` 组合：

```
cnaToTargetAddr(NPU端口.CNA) ∈ L1SW.routingTables[].prefix.dstAddress
```

即：NPU 端口的 CNA 经过 `cnaToTargetAddr` 变换后，必须在所连 L1SW 的路由表中有匹配的前缀。

### 4.2 ACL 一致性

对每对 `(srcNPU端口, destNPU端口)`：

```
srcNPU端口.EID + "|" + destNPU端口.EID + "|RCTP" ∈ aclData.tpAcls
```

即：ACL 中的每条双向规则，其 EID 对必须在 topo 数据中存在对应的 NPU 端口。

### 4.3 AclData.superNodeName

`AclData.superNodeName` 必须等于 superNode 的 name，因为 `aclStore.getAclData(request.getSuperNodeName())` 使用 superNodeName 查找。JSON 中 ACL 的 `aclId` 字段值需在映射时赋值为 `superNodeName`。

---

## 5. 覆盖率标注

| 测试用例 | 覆盖 flow | 覆盖 RoutePhase 方向 |
|---|---|---|
| 2.2.1 多跳 npu1→npu2 via l1sw0 | 多跳 SUCCESS | 正向 + 反向 |
| 2.2.1 反向 npu2→npu1 via l1sw0 | 多跳 SUCCESS（反转路径） | 正向 + 反向（PathServiceTest 覆盖） |
| 3.2.1 npu1→npu2 via l1sw0 (port0) | 多跳 SUCCESS + L1SW0 路由 | 正向 + 反向 |
| 3.2.2 npu1→npu3 via l1sw1 (port1) | 多跳 SUCCESS + L1SW1 路由 | 正向 + 反向 |
| 4npu_8port 全量遍历（6 对 × 8 端口） | 多跳 SUCCESS × 96 | 正向 + 反向 × 96 |

---
