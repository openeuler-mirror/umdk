# SNC PathService Main Success Scenario Test Design

> Based on two test fixture sets — `topo_data_2npu_1port.json` / `acl_data_2npu_1port.json` and `topo_data_4npu_8port.json` / `acl_data_4npu_8port.json` — this document designs the planPath main success scenarios.

---

## 1. Global Assumptions and Data Corrections

### 1.1 AclData.superNodeName Mapping

The identifier field of `AclData` has been renamed from `aclId` to `superNodeName`. The `aclId` field value (`"acl-001"`) in the ACL JSON must be mapped to `AclData.superNodeName` as `"A5-superPod-1"` during loading, to match the lookup logic of `aclStore.getAclData(request.getSuperNodeName())`.

### 1.2 2npu_1port Route Prefix Corrections

The route prefixes for L1SW0 in the JSON do not match the results of NPU port CNA values after `cnaToTargetAddr()`:

| L1SW Route (JSON) | Should Be Corrected To | Corresponding NPU Port CNA | cnaToTargetAddr |
|---|---|---|---|
| `170.170.170.17/32` | `170.170.170.18/32` | NPU1 `400GE 0/0/1` → `170.170.170.18` | `170.170.170.18` |
| `221.221.221.68/32` | `221.221.221.66/32` | NPU2 `400GE 0/1/1` → `221.221.221.66` | `221.221.221.66` |

Otherwise, the LPM lookup in `routePhase` will fail due to `/32` exact match failure, resulting in `ROUTE_NOT_REACHABLE`.

### 1.3 4npu_8port Route Prefix Corrections

Only L1SW0's route prefixes match the CNA values of connected ports (NPU2 port0/0/0's CNA `221.221.221.68` = route prefix). L1SW1/2/3's route prefixes do not match the CNA values of their connected ports. If all L1SWs need to work, corrections are as follows:

| L1SW | Port | Connected NPU Port | That Port's CNA | cnaToTargetAddr | Corrected Route Prefix |
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

Subsequent test cases in this document assume the above corrections have been applied; otherwise, only L1SW0-related scenarios will pass.

---

## 2. Test Fixture 1: 2npu_1port

### 2.1 Topology Structure

```
rack1#os0#npu1:400GE 0/0/1  ←→  rack1#l1sw0:400GE 1/0/1  ←→  rack1#os0#npu2:400GE 0/1/1
```

### 2.2 Main Success Scenario

#### Test Case 2.2.1: Multi-hop path npu1 → l1sw0 → npu2

**Input:**

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

**Processing Trace:**

| Step | Operation | Result |
|---|---|---|
| 0 | Look up SuperNode | `A5-superPod-1` found |
| 0 | Look up src/dest Device | npu1 / npu2 found in superNode.getNpuDevices(), both are NPU |
| 1 | Look up srcPort | `400GE 0/0/1` → `npu1.findNpuPort()` → CNA=`170.170.170.18`, EID=`AAAAAA12000000000000000000000002` |
| 1 | Port direct connection | remoteDevice=`rack1#l1sw0`, remotePort=`400GE 1/0/1` |
| 2 | Look up destPort | `400GE 0/1/1` → `npu2.findNpuPort()` → CNA=`221.221.221.66`, EID=`DDDDDD42000000000000000000000002` |
| 2 | Port direct connection | remoteDevice=`rack1#l1sw0`, remotePort=`400GE 1/0/2` |
| 3 | ACL bidirectional check | srcEid=AAAA...02, dstEid=DDDD...02, srcCna=170.170.170.18, destCna=221.221.221.66 → match |
| 5 | interDevices not empty | Enter multi-hop logic |
| 7 | Multi-hop path resolution | hops=[NPU1, L1SW0, NPU2] |
| 8 | Forward routePhase | Intermediate hop L1SW0, target=`cnaToTargetAddr("221.221.221.66")`=`"221.221.221.66"` |
| 8 | L1SW0 route lookup | Prefix `221.221.221.66/32` (corrected) → match, outPort=400GE 1/0/2 |
| 9 | Reverse routePhase | Intermediate hop L1SW0, target=`cnaToTargetAddr("170.170.170.18")`=`"170.170.170.18"` |
| 9 | L1SW0 route lookup | Prefix `170.170.170.18/32` (corrected) → match, outPort=400GE 1/0/1 |
| 13-15 | Build result | SUCCESS |

**Expected Output:**

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

**Assertion Points:**
- `result.status == PlanStatus.SUCCESS`
- `result.srcEid == "AAAAAA12000000000000000000000002"`
- `result.dstEid == "DDDDDD42000000000000000000000002"`
- `result.path.hops.size() == 3`
- `hops[0].deviceName == "rack1#os0#npu1"`, `hops[0].inPort == null`, `hops[0].outPort == "400GE 0/0/1"`
- `hops[1].deviceName == "rack1#l1sw0"`, `hops[1].inPort == "400GE 1/0/1"`, `hops[1].outPort == "400GE 1/0/2"`
- `hops[2].deviceName == "rack1#os0#npu2"`, `hops[2].inPort == "400GE 0/1/1"`, `hops[2].outPort == null`

---

## 3. Test Fixture 2: 4npu_8port

### 3.1 Topology Structure

```
4 NPU (npu1~npu4) + 4 L1SW (l1sw0~l1sw3) + 1 L2SW (lc#0)
Each NPU has 8 ports, split into 4 groups connecting to 4 L1SWs (2 ports per L1SW)
Each L1SW has 8 ports, split into 4 groups connecting to 4 NPUs + 4 ports connecting to L2SW
```

See `topo_4npu_8port_connection_relationship.md` for detailed connection relationships.

### 3.2 Main Success Scenario

#### Test Case 3.2.1: npu1 → l1sw0 → npu2 (port 0/0/0)

This is the most direct path: npu1 and npu2 each use port0 to connect to l1sw0, with exact route prefix match.

**Input:**

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

**Processing Trace:**

| Step | Operation | Result |
|---|---|---|
| 0 | Look up SuperNode | `A5-superPod-2` found |
| 0 | Look up src/dest Device | npu1 / npu2 found in `superNode.getNpuDevices()` |
| 1 | Look up srcPort | `npu1.findNpuPort("400GE 0/0/0")` → CNA=`170.170.170.17`, EID=`AAAAAA12000000000000000000000001`, remoteDevice=`rack1#l1sw0`, remotePort=`400GE 1/0/0` |
| 2 | Look up destPort | `npu2.findNpuPort("400GE 0/0/0")` → CNA=`221.221.221.68`, EID=`DDDDDD42000000000000000000000001`, remoteDevice=`rack1#l1sw0`, remotePort=`400GE 1/0/2` |
| 3 | ACL check | ACL entry AAAA...01 ↔ DDDD...01 exists |
| 5 | interDevices not empty | Enter multi-hop logic |
| 7 | Multi-hop path resolution | hops=[NPU1, L1SW0, NPU2] |
| 8 | Forward routePhase | target=`cnaToTargetAddr("221.221.221.68")`=`"221.221.221.68"` |
| 8 | L1SW0 route lookup | `221.221.221.68/32` → 1/0/2 → match, outPort=`400GE 1/0/2` |
| 9 | Reverse routePhase | target=`cnaToTargetAddr("170.170.170.17")`=`"170.170.170.17"` |
| 9 | L1SW0 route lookup | `170.170.170.17/32` → 1/0/0 → match, outPort=`400GE 1/0/0` |
| 13-15 | Build result | SUCCESS |

**Expected Output:**

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

**Assertion Points:**
- `result.status == PlanStatus.SUCCESS`
- `result.srcEid == "AAAAAA12000000000000000000000001"`
- `result.dstEid == "DDDDDD42000000000000000000000001"`
- `result.path.hops.size() == 3`
- `hops[0].deviceName == "rack1#os0#npu1"`, `hops[0].outPort == "400GE 0/0/0"`
- `hops[1].deviceName == "rack1#l1sw0"`, `hops[1].inPort == "400GE 1/0/0"`, `hops[1].outPort == "400GE 1/0/2"`
- `hops[2].deviceName == "rack1#os0#npu2"`, `hops[2].inPort == "400GE 0/0/0"`

#### Test Case 3.2.2: npu1 → l1sw1 → npu3 (port 0/0/1)

Requires route prefix corrections before use (see Section 1.3 L1SW1 route corrections).

**Input:**

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

**Processing Trace:**

| Step | Result |
|---|---|
| srcPort | `npu1.findNpuPort("400GE 0/0/1")` → CNA=`170.170.170.18`, EID=`AAAAAA12000000000000000000000002`, remote=`l1sw1:1/0/0` |
| destPort | `npu3.findNpuPort("400GE 0/0/1")` → CNA=`238.238.238.86`, EID=`EEEEEE55000000000000000000000002`, remote=`l1sw1:1/0/4` |
| ACL check | Matches AAAA...02 ↔ EEEE...02 entry |
| Forward routePhase | target=`cnaToTargetAddr("238.238.238.86")`=`"238.238.238.86"` → L1SW1 route `238.238.238.86/32` (corrected) → outPort=`400GE 1/0/4` |
| Reverse routePhase | target=`cnaToTargetAddr("170.170.170.18")`=`"170.170.170.18"` → L1SW1 route `170.170.170.18/32` (corrected) → outPort=`400GE 1/0/0` |

**Expected Output:**

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

## 4. Data Validation Checklist

Data must satisfy the following constraints:

### 4.1 Route Consistency

For each `(L1SW, NPU port)` combination:

```
cnaToTargetAddr(NPU_port.CNA) ∈ L1SW.routingTables[].prefix.dstAddress
```

That is: the NPU port's CNA, after `cnaToTargetAddr` transformation, must have a matching prefix in the routing table of the connected L1SW.

### 4.2 ACL Consistency

For each `(srcNPU_port, destNPU_port)` pair:

```
srcNPU_port.EID + "|" + destNPU_port.EID + "|RCTP" ∈ aclData.tpAcls
```

That is: each bidirectional rule in the ACL must have a corresponding NPU port pair in the topology data with matching EIDs.

### 4.3 AclData.superNodeName

`AclData.superNodeName` must equal the SuperNode's name, because `aclStore.getAclData(request.getSuperNodeName())` uses superNodeName for lookup. The `aclId` field value in the ACL JSON must be mapped to `superNodeName` during loading.

---

## 5. Coverage Markers

| Test Case | Covered Flow | Covered RoutePhase Direction |
|---|---|---|
| 2.2.1 Multi-hop npu1→npu2 via l1sw0 | Multi-hop SUCCESS | Forward + Reverse |
| 2.2.1 Reverse npu2→npu1 via l1sw0 | Multi-hop SUCCESS (reversed path) | Forward + Reverse (covered by PathServiceTest) |
| 3.2.1 npu1→npu2 via l1sw0 (port0) | Multi-hop SUCCESS + L1SW0 routing | Forward + Reverse |
| 3.2.2 npu1→npu3 via l1sw1 (port1) | Multi-hop SUCCESS + L1SW1 routing | Forward + Reverse |
| 4npu_8port full traversal (6 pairs × 8 ports) | Multi-hop SUCCESS × 96 | Forward + Reverse × 96 |

---
