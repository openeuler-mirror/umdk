# SNC PathService Main Success Scenario Test Design

> Based on two test fixture sets — `topo_data_2npu_1port.json` and `topo_data_4npu_8port.json` — this document designs the planPath main success scenarios.

---

## 1. Global Assumptions and Data Corrections

### 1.1 2npu_1port Route Prefix Corrections

The route prefixes for L1SW0 in the JSON do not match the results of NPU port CNA values after `cnaToTargetAddr()`:

| L1SW Route (JSON) | Should Be Corrected To | Corresponding NPU Port CNA | cnaToTargetAddr |
|---|---|---|---|
| `170.170.170.17/32` | `170.170.170.18/32` | NPU1 `400GE 0/0/1` → `170.170.170.18` | `170.170.170.18` |
| `221.221.221.68/32` | `221.221.221.66/32` | NPU2 `400GE 0/1/1` → `221.221.221.66` | `221.221.221.66` |

Otherwise, the LPM lookup in `routePhase` will fail due to `/32` exact match failure, resulting in `ROUTE_NOT_REACHABLE`.

### 1.2 4npu_8port Route Prefix Corrections

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
| 3 | interDevices not empty | Enter multi-hop logic |
| 5 | Multi-hop path resolution | hops=[NPU1, L1SW0, NPU2] |
| 6 | Forward routePhase | Intermediate hop L1SW0, target=`cnaToTargetAddr("221.221.221.66")`=`"221.221.221.66"` |
| 6 | L1SW0 route lookup | Prefix `221.221.221.66/32` (corrected) → match, outPort=400GE 1/0/2 |
| 7 | Reverse routePhase | Intermediate hop L1SW0, target=`cnaToTargetAddr("170.170.170.18")`=`"170.170.170.18"` |
| 7 | L1SW0 route lookup | Prefix `170.170.170.18/32` (corrected) → match, outPort=400GE 1/0/1 |
| 9-10 | Build result | SUCCESS |

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
| 3 | interDevices not empty | Enter multi-hop logic |
| 5 | Multi-hop path resolution | hops=[NPU1, L1SW0, NPU2] |
| 6 | Forward routePhase | target=`cnaToTargetAddr("221.221.221.68")`=`"221.221.221.68"` |
| 6 | L1SW0 route lookup | `221.221.221.68/32` → 1/0/2 → match, outPort=`400GE 1/0/2` |
| 7 | Reverse routePhase | target=`cnaToTargetAddr("170.170.170.17")`=`"170.170.170.17"` |
| 7 | L1SW0 route lookup | `170.170.170.17/32` → 1/0/0 → match, outPort=`400GE 1/0/0` |
| 9-10 | Build result | SUCCESS |

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

Requires route prefix corrections before use (see Section 1.2 L1SW1 route corrections).

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

## 4. Main Success Scenario: Coverage Planning (planPathsCoverage / planPathsCoverageEx)

### 4.1 planPathsCoverage — 4npu_8port main success scenario

**Precondition:** `setSuperNode(topo_4npu_8port)` has been called, state is DATAREADY.

**Input (CoveragePathsRequest):**

```json
{
  "superNodeName": "A5-superPod-2",
  "coverageRequirement": "MIN_COVERAGE"
}
```

**Processing Trace:**

| Step | Operation | Result |
|---|---|---|
| 1 | PathService.planPathsCoverage | Construct CoveragePlanEngine(superNode, hashFunc, ...) |
| 2 | engine.findCoverage(MIN_COVERAGE) | Collect L1SW↔L2SW out-port coverage domain |
| 3 | Enumerate EID pairs | All src×dst NPU port combinations across-chassis + same-chassis |
| 4 | Trace 4-hop forward/reverse path for each EID pair | Use H3a/H3b, H5a/H5b for port selection; NPU last-hop out-port takes get(0) |
| 5 | Greedy selection | Pick EID pairs that cover the most uncovered L1SW↔L2SW ports |
| 6 | Termination | All coverage domain ports coverCount >= 1 (MIN_COVERAGE) |
| 7 | Statistics | totalStats = { totalLinks, coveredLinks=totalLinks, coverageRate=1.0, ... } |
| 8 | Assemble result | scope=L1_L2, layerStats=null |

**Expected Output (CoveragePathsResult):**

```json
{
  "scope": "L1_L2",
  "status": "SUCCESS",
  "eidPairs": [
    { "srcEid": "AAAAAA12...", "dstEid": "DDDDDD42...", "coveredLinks": [...4 items...], "type": null },
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

**Assertion Points:**
- `result.status == PlanStatus.SUCCESS`
- `result.scope == CoverageLinkScope.L1_L2`
- `result.layerStats == null`
- All entries in `result.coverageLinks` have `layer == null`, `deviceType == null`
- All entries in `result.eidPairs` have `type == null`
- Each `CoveredEidPair.coveredLinks.size() == 4` (2 forward + 2 reverse)
- `totalStats.coverageRate == 1.0`
- `totalStats.coveredLinks == totalStats.totalLinks`

### 4.2 planPathsCoverageEx — 4npu_8port main success scenario (two-stage)

**Precondition:** Same as 4.1; the topology input NPU ports must contain the `jettyId` field.

**Input (CoveragePathsRequest):**

```json
{
  "superNodeName": "A5-superPod-2",
  "coverageRequirement": "MIN_COVERAGE"
}
```

**Processing Trace (two-stage):**

| Stage | Step | Operation | Result |
|---|---|---|---|
| Stage 1 | 1 | engine.findCoverageEx | Collect all NPU↔L1SW↔L2SW coverage domains |
| Stage 1 | 2 | Enumerate cross-chassis EID pairs | src/dst in different chassis |
| Stage 1 | 3 | Trace 4-hop forward/reverse path | Use H1/H2, H3a/H3b, H4, H5a/H5b for port selection |
| Stage 1 | 4 | Greedy select CROSS_L2 EID pairs | Cover L1SW↔L2SW gaps |
| Stage 1 | 5 | Termination condition | All L1_L2 layer ports coverCount >= 1 |
| Stage 2 | 6 | Filter NPU_L1 gaps | layer == NPU_L1 && coverCount < required |
| Stage 2 | 7 | Enumerate same-chassis EID pairs | src/dst in the same chassis |
| Stage 2 | 8 | Trace 2-hop forward/reverse path | Use H6, H7a/H7b for port selection |
| Stage 2 | 9 | Greedy fill LOCAL_L1 EID pairs | Cover NPU↔L1SW gaps |
| Merge | 10 | Statistics | totalStats + layerStats=[NPU_L1, L1_L2] |
| Merge | 11 | Assemble result | scope=NPU_L1_L2 |

**Expected Output (CoveragePathsResult):**

```json
{
  "scope": "NPU_L1_L2",
  "status": "SUCCESS",
  "eidPairs": [
    { ..., "type": "CROSS_L2", "coveredLinks": [...8 items... (4 forward + 4 reverse)...] },
    { ..., "type": "LOCAL_L1", "coveredLinks": [...4 items... (2 forward + 2 reverse)...] },
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

**Assertion Points:**
- `result.scope == CoverageLinkScope.NPU_L1_L2`
- `result.layerStats.size() == 2`, containing NPU_L1 and L1_L2 layers
- `result.coverageLinks[*].layer ∈ {NPU_L1, L1_L2}`
- `result.coverageLinks[*].deviceType ∈ {"NPU", "SW"}`
- `eidPairs[*].type ∈ {CROSS_L2, LOCAL_L1}`
- CROSS_L2 `coveredLinks.size() == 8` (4 forward + 4 reverse)
- LOCAL_L1 `coveredLinks.size() == 4` (2 forward + 2 reverse)
- `totalStats.coverageRate == 1.0`
- `layerStats[0].stats.coverageRate == 1.0` (NPU_L1 fully covered)
- `layerStats[1].stats.coverageRate == 1.0` (L1_L2 fully covered)

### 4.3 planPathsCoverageEx — jettyId missing fallback scenario

**Precondition:** The topology input does not carry the `jettyId` field (simulating an old topology).

**Processing Trace:**

| Step | Operation | Result |
|---|---|---|
| 1 | CoveragePlanEngine.jettyIdOf(port) | jettyId is null → fallback `32 + port.id` |
| 2 | Accumulate diagnostic counter | `exJettyFallback++` |
| 3 | Continue two-stage coverage planning | Call `HashUtils.nativeHashDstCnaJetty` with the fallback jettyId |

**Assertion Points:**
- `result.status == SUCCESS` (path selection still completes)
- `engine.getExDiagnostics().jettyIdFallback > 0`
- All other diagnostic counters are 0

### 4.4 planPathsCoverage — COVERAGE_INCOMPLETE scenario

**Precondition:** Some L1SW routing tables in the topology are missing or incomplete, making it impossible to cover certain L1SW↔L2SW ports.

**Expected Output:**

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

**Assertion Points:**
- `result.status == PlanStatus.COVERAGE_INCOMPLETE`
- `result.totalStats.coverageRate < 1.0`
- Still returns `eidPairs` and `coverageLinks` (partial coverage result; the caller decides whether to accept or retry)

---

## 5. Main Success Scenario: Route Calculation and Instantiation (routeCalculate + makeRoutes + getNodeRoute)

### 5.1 routeCalculate — first call (idempotent)

**Precondition:** `init()` has completed, state is READY (no SuperNode deployment required).

**Input:** No parameters.

**Processing Trace:**

| Step | Operation | Result |
|---|---|---|
| 1 | Enter synchronized block | routeCalculated == false, continue |
| 2 | TopoTemplateService.parseTemplateFile | Load 128_npu_rack.json + 128_npu_inter_rack.json |
| 3 | RouteMspService.routeMsp | BFS to compute shortest path from each forwarding node to other nodes |
| 4 | RouteInstantiationService.buildXpodRoutes | Generate template routing table routes |
| 5 | routeCalculated = true | Subsequent repeated calls return directly |

**Assertion Points:**
- Method returns normally with no exception
- Second call also returns with no exception (idempotent); internally `routeCalculated == true` skips the actual computation

### 5.2 makeRoutes — instantiate route table

**Precondition:** `routeCalculate()` has been called; `setSuperNode(superNode)` has been called.

**Input:** SuperNode (already deployed).

**Processing Trace:**

| Step | Operation | Result |
|---|---|---|
| 1 | Check routeCalculated | true, continue |
| 2 | RouteInstantiationService.instantiateXpodRoute | Iterate over NPU/L1SW/L2SW devices |
| 3 | NPU instantiation | Match template by chassis/slot/ubpu/die labels |
| 4 | L1SW instantiation | Match template by chassis/index labels |
| 5 | L2SW instantiation | Match template by index/chip labels, port index remapping |
| 6 | deepCopyRoutingEntry | Deep copy to prevent external modifications from affecting internal state |
| 7 | instantiationRouteMap.put | key="deviceName#chipIndex" |

**Expected Output:** `Map<String, Map<String, RoutingEntry>>`

**Assertion Points:**
- Returned Map is not empty
- The Map contains one record per chip per device in the SuperNode
- Each `RoutingEntry` is **not equal** to the internal object in `instantiationRouteMap` (deep copy verification)
- Modifying the returned Map does not affect the result of a subsequent `getNodeRoute` call

### 5.3 getNodeRoute — query single device route

**Precondition:** `makeRoutes(superNode)` has been called.

**Input:**

```java
getNodeRoute("rack1#os0#npu1", 0)
```

**Processing Trace:**

| Step | Operation | Result |
|---|---|---|
| 1 | Look up instantiationRouteMap | key="rack1#os0#npu1#0" |
| 2 | Return the corresponding Map<String, RoutingEntry> | That chip's route prefix → RoutingEntry |

**Assertion Points:**
- Returned Map contains multiple route prefixes
- Each RoutingEntry.prefix is not null
- Each RoutingEntry.outPortInfos contains at least one out-port
- The returned value is equal in content to the corresponding sub-Map returned by `makeRoutes` (deep copy but same content)

### 5.4 Error scenario: makeRoutes without routeCalculate

**Precondition:** `routeCalculate()` has not been called.

**Call:** `makeRoutes(superNode)`

**Expected:** Throws `IllegalStateException`, error message contains "routeCalculate" or "not calculated".

### 5.5 Error scenario: getNodeRoute without makeRoutes

**Precondition:** `makeRoutes(superNode)` has not been called.

**Call:** `getNodeRoute("rack1#os0#npu1", 0)`

**Expected:** Throws `IllegalArgumentException` (key does not exist) or `IllegalStateException`.

---

## 6. Main Success Scenario: Link Event and Route Convergence (notifyLinkEvent)

### 6.1 Link down event — single-hop convergence

**Precondition:** `makeRoutes(superNode)` has completed; in the topology `rack1#l1sw0:400GE 1/0/2` is the uplink of `rack1#os0#npu2`.

**Input (LinkEvent):**

```json
{
  "deviceName": "rack1#l1sw0",
  "portName": "400GE 1/0/2",
  "eventType": "down",
  "eventTime": 1716230400000
}
```

**Processing Trace:**

| Step | Operation | Result |
|---|---|---|
| 1 | LinkEventService.handleLinkEvent | Locate chip 0 of l1sw0 containing port 1/0/2 |
| 2 | PortEntity.setLinkStatus | port.linkStatus = LINK_DOWN, port.updateAt = 1716230400000 |
| 3 | RouteConvergeService.converge | Iterate over the "rack1#l1sw0#0" routing table |
| 4 | Locate the RoutingEntry containing 1/0/2 | Found, corresponding to prefix "221.221.221.68/32" |
| 5 | OutPortInfo.setFlag | convergedFlag \|= FLAG_PASSIVE_CONVERRGED |
| 6 | RoutingEntry.refreshReachable | This entry has only this one out-port → reachable = false |
| 7 | BFS propagation | reachable changed (true→false) |
| 8 | Find npu1 via port 1/0/0's remoteDevice | Look up prefix "221.221.221.68/32" in npu1 chip 0 routing table |
| 9 | npu1 corresponding OutPortInfo.setFlag | Mark 1/0/0 as PASSIVE_CONVERGED |
| 10 | npu1 refreshReachable for this entry | If npu1 has multiple out-ports and the rest are valid → reachable = true (no change), BFS terminates |

**Assertion Points:**
- Method returns normally with no exception
- In the routing table returned by `getNodeRoute("rack1#l1sw0", 0)`, for the RoutingEntry with prefix "221.221.221.68/32":
  - `reachable == false`
  - `outPortInfos["400GE 1/0/2"].isConverged() == true`
  - `outPortInfos["400GE 1/0/2"].getConvergedFlag() & FLAG_PASSIVE_CONVERRGED != 0`

### 6.2 Link up event — clear PASSIVE_CONVERGED

**Precondition:** 6.1 has been executed, route has converged.

**Input (LinkEvent):**

```json
{
  "deviceName": "rack1#l1sw0",
  "portName": "400GE 1/0/2",
  "eventType": "up",
  "eventTime": 1716230500000
}
```

**Processing Trace:**

| Step | Operation | Result |
|---|---|---|
| 1 | PortEntity.setLinkStatus | port.linkStatus = LINK_UP, port.updateAt = 1716230500000 |
| 2 | RouteConvergeService.converge | Iterate over the routing table |
| 3 | OutPortInfo.clearFlag | convergedFlag &= ~FLAG_PASSIVE_CONVERRGED |
| 4 | RoutingEntry.refreshReachable | reachable = true (true→false→true, changes again) |
| 5 | BFS propagation | Same as 6.1 steps 7~10, the peer npu1 also clears PASSIVE_CONVERGED |

**Assertion Points:**
- For the RoutingEntry returned by `getNodeRoute("rack1#l1sw0", 0)`:
  - `reachable == true`
  - `outPortInfos["400GE 1/0/2"].isConverged() == false`
  - `outPortInfos["400GE 1/0/2"].getConvergedFlag() == 0`

### 6.3 Repeated down event — idempotency

**Precondition:** 6.1 has been executed.

**Input:** Same as 6.1 (send the down event again).

**Assertion Points:**
- Method returns normally with no exception
- Routing table state unchanged (FLAG_PASSIVE_CONVERRGED already set, idempotent)
- BFS does not propagate (reachable unchanged)

### 6.4 Error scenario: device or port does not exist

**Input:**

```json
{ "deviceName": "rack1#l1sw99", "portName": "400GE 1/0/0", "eventType": "down", "eventTime": 1716230400000 }
```

**Expected:** Throws `IllegalStateException`, error message contains "device" or "port" does not exist.

### 6.5 Error scenario: invalid eventType

**Input:**

```json
{ "deviceName": "rack1#l1sw0", "portName": "400GE 1/0/2", "eventType": "freeze", "eventTime": 1716230400000 }
```

**Expected:** Throws `IllegalArgumentException`, error message contains "eventType".

---

## 7. Data Validation Checklist

Data must satisfy the following constraints:

### 7.1 Route Consistency

For each `(L1SW, NPU port)` combination:

```
cnaToTargetAddr(NPU_port.CNA) ∈ L1SW.routingTables[].prefix.dstAddress
```

That is: the NPU port's CNA, after `cnaToTargetAddr` transformation, must have a matching prefix in the routing table of the connected L1SW.

### 7.2 jettyId Value Consistency (planPathsCoverageEx)

For each NPU port:

```
NPU_port.jettyId ∈ [32, 1023]   or   NPU_port.jettyId is null (triggers fallback)
```

When missing or out of range, `CoveragePlanEngine.jettyIdOf` falls back to `32 + port.id` and accumulates the diagnostic counter `exJettyFallback`.

### 7.3 Coverage Domain Completeness (planPathsCoverage/Ex)

```
CoveragePathsResult.totalStats.coveredLinks == CoveragePathsResult.totalStats.totalLinks
(when status == SUCCESS; when COVERAGE_INCOMPLETE, coveredLinks < totalLinks)
```

### 7.4 Route Convergence Consistency (notifyLinkEvent)

After link down:

```
corresponding OutPortInfo.convergedFlag & FLAG_PASSIVE_CONVERRGED != 0
RoutingEntry.reachable == false (if this entry has only this one out-port)
```

After link up:

```
corresponding OutPortInfo.convergedFlag & FLAG_PASSIVE_CONVERRGED == 0
RoutingEntry.reachable == true
```

---

## 8. Coverage Markers

| Test Case | Covered Flow | Covered RoutePhase Direction |
|---|---|---|
| 2.2.1 Multi-hop npu1→npu2 via l1sw0 | Multi-hop SUCCESS | Forward + Reverse |
| 2.2.1 Reverse npu2→npu1 via l1sw0 | Multi-hop SUCCESS (reversed path) | Forward + Reverse (covered by PathServiceTest) |
| 3.2.1 npu1→npu2 via l1sw0 (port0) | Multi-hop SUCCESS + L1SW0 routing | Forward + Reverse |
| 3.2.2 npu1→npu3 via l1sw1 (port1) | Multi-hop SUCCESS + L1SW1 routing | Forward + Reverse |
| 4npu_8port full traversal (6 pairs × 8 ports) | Multi-hop SUCCESS × 96 | Forward + Reverse × 96 |
| 4.1 planPathsCoverage L1↔L2 coverage | Coverage planning SUCCESS + statistics | Forward + Reverse |
| 4.2 planPathsCoverageEx NPU↔L1↔L2 two-stage | Coverage planning SUCCESS + layered statistics + jettyId hash | Forward + Reverse |
| 4.3 planPathsCoverageEx jettyId missing fallback | Diagnostic counter jettyIdFallback > 0 + SUCCESS | - |
| 4.4 planPathsCoverage COVERAGE_INCOMPLETE | Partial coverage | - |
| 5.1 routeCalculate idempotent | Route template computation + second call idempotent | - |
| 5.2 makeRoutes instantiation | Template instantiation + deep copy | - |
| 5.3 getNodeRoute query | HashMap query | - |
| 5.4 makeRoutes without routeCalculate error | IllegalStateException | - |
| 5.5 getNodeRoute without makeRoutes error | IllegalArgumentException/IllegalStateException | - |
| 6.1 Link down convergence | OutPortInfo.setFlag + refreshReachable + BFS propagation | - |
| 6.2 Link up clear | OutPortInfo.clearFlag + refreshReachable + BFS propagation | - |
| 6.3 Repeated down idempotent | Bitwise idempotent + BFS does not propagate | - |
| 6.4 Device/port does not exist error | IllegalStateException | - |
| 6.5 eventType invalid error | IllegalArgumentException | - |

---
