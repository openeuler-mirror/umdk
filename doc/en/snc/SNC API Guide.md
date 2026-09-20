# SNC Module API Guide

## 1. Overview

The SNC (SuperNode Network Controller) module provides SuperNode topology management and path planning capabilities. It exposes a unified `SNCService` interface, with an internal layered architecture: Service → Engine → Store.

---

## 2. Core Interface — `SNCService`

Package path: `com.huawei.umdk.snc.SNCService`

### 2.1 Lifecycle Management

| Method | Parameters | Return Value | Description | Exception Notes |
|------|------|--------|------|---------|
| `init` | `SNCConfig config` | `void` | Initialize the SNC service, create Store, Engine, Service instances, transition state to READY | Can be called in any state; when `config` is `null`, **log level defaults to INFO**; repeated calls **rebuild all internal instances**, old Store data is lost |
| `uninit` | None | `void` | Deinitialize, clear all Stores, transition state to UNINIT | Can be called in any state (including a state that has never been `init`); repeated calls are safe with no side effects; after `uninit`, **all methods except `init` throw SNCStateException** |

### 2.1a init Parameter Details

`SNCConfig.logLevel` controls the log level of `SNCServiceImpl` (applied via `LOG.setLevel()`):

| Invocation | Log Behavior |
|---------|---------|
| `init(new SNCConfig())` | `logLevel=INFO` (default), outputs `INFO` level logs |
| `init(new SNCConfig(Level.WARNING))` | Only outputs `WARNING` and above; `INFO` is filtered by the Logger natively |
| `init(null)` | config is null → defaults to `INFO` |

### 2.2 SuperNode Topology Management

| Method | Parameters | Return Value | Description | Exception Notes |
|------|------|--------|------|---------|
| `setSuperNode` | `SuperNode superNode` | `void` | Import (**replace by name**) SuperNode topology, mark superNodeLoaded, update data ready state; old data with the same name is overwritten, SuperNodes with different names coexist without interference | INIT/UNINIT → `SNCStateException`; null name/empty name/empty devices → `IllegalArgumentException`; **Sub-fields (deviceName/forwardingChips/routingTable etc.) are not validated** — missing values are silently stored, subsequent planPath returns corresponding error codes |
| `addNpuDevices` | `String superNodeName, List<NpuDevice> devices` | `void` | Add NPU devices to an existing SuperNode; if SuperNode does not exist, **throws IllegalStateException** | INIT/UNINIT → `SNCStateException`; null parameters → `IllegalArgumentException` |
| `addSwDevices` | `String superNodeName, List<SwDevice> devices` | `void` | Add SW devices to an existing SuperNode; if SuperNode does not exist, **throws IllegalStateException** | INIT/UNINIT → `SNCStateException`; null parameters → `IllegalArgumentException` |
| `removeDevices` | `String superNodeName, List<String> deviceNames` | `void` | Remove devices from SuperNode's npuDevices and swDevices; if not found, **silent no-op** | INIT/UNINIT → `SNCStateException`; null parameters → `IllegalArgumentException` |
| `addRoutingEntries` | `String superNodeName, String deviceName, Integer chipIndex, List<RoutingEntry> entries` | `void` | Add routing entries to the routing table of the specified chip; if routing table does not exist, **throws IllegalStateException** | INIT/UNINIT → `SNCStateException`; null parameters → `IllegalArgumentException` |
| `removeRoutingEntries` | `String superNodeName, String deviceName, Integer chipIndex, List<RoutePrefix> prefixes` | `void` | Remove routing entries by prefix from the routing table; if not found, **silent no-op** | INIT/UNINIT → `SNCStateException`; null parameters → `IllegalArgumentException` |
| `getSuperNode` | `String name` | `SuperNode` | Query SuperNode by name | INIT/UNINIT → `SNCStateException`; returns `null` if not found (not an exception) |
| `removeSuperNode` | `String name` | `void` | Delete SuperNode by name | INIT/UNINIT → `SNCStateException` |

### 2.3 Path Planning

| Method | Parameters | Return Value | Description | Exception Notes |
|------|------|--------|------|---------|
| `planPath` | `PathPlanRequest request` | `PathPlanResult` | Plan a transmission path from source to destination | Non-DATAREADY state → `SNCStateException` (message format: "SNC is not in DATAREADY state, current state: \<STATE\>", **different from** other methods' `checkNotUninit` interception message) |
| | | | | request is null or any of superNodeName/srcDevice/destDevice/srcPort/destPort is null/empty → `IllegalArgumentException` |
| | | | | **interDevices field is optional** (can be null/empty, indicating a direct connection scenario) |
| | | | | On business failure, no exception is thrown; `PathPlanResult.status` is non-SUCCESS, see the `PlanStatus` mapping table below |
| | | | | **Routing lookup mechanism**: planPath internally uses the destination port's CNA (`destCna`) as the lookup target, performing LPM matching directly against route prefixes. |

### 2.3a Coverage Planning

| Method | Parameters | Return Value | Description | Exception Notes |
|------|------|--------|------|---------|
| `planPathsCoverage` | `CoveragePathsRequest request` | `CoveragePathsResult` | **Inter-chassis coverage planning**: Given a SuperNode topology (including routing tables), select a set of EID pairs so that their forward/reverse hash routing results traverse the **L1SW↔L2SW** outport set | Non-DATAREADY state → `SNCStateException` (same form as `planPath`) |
| | | | | request is null → `IllegalArgumentException` |
| | | | | `superNodeName` is null/empty or SuperNode not found → returns `PlanStatus.TOPO_NOT_FOUND` (no exception thrown) |
| | | | | Coverage not reaching 100% returns `PlanStatus.COVERAGE_INCOMPLETE`, `errorMessage` carries coverage rate details |
| | | | | **Result `scope = L1_L2`**, each EID pair has exactly 4 coverage links (2 forward + 2 reverse) |
| | | | | **Coverage domain**: only L1SW→L2SW and L2SW→L1SW ECMP outports |
| `planPathsCoverageEx` | `CoveragePathsRequest request` | `CoveragePathsResult` | **Extended coverage planning (with NPU↔L1SW)**: On top of the `planPathsCoverage` coverage domain, adds **NPU↔L1SW** outport coverage. NPU→L1SW outport is selected by **`(DstCNA, jettyId)` tuple CRC-8 hash**; **the CNA of the selected NPU port serves as the downstream SCNA**; ACK direction selects routing by **the source NPU port's jettyId** (same jettyId as forward) | Non-DATAREADY state → `SNCStateException` (same form as `planPath`) |
| | | | | request is null → `IllegalArgumentException` |
| | | | | `superNodeName` is null/empty or SuperNode not found → returns `PlanStatus.TOPO_NOT_FOUND` (no exception thrown) |
| | | | | Coverage not reaching 100% returns `PlanStatus.COVERAGE_INCOMPLETE`, `errorMessage` appends layered coverage rate details (e.g., `[NPU_L1: 98.4% 1008/1024; L1_L2: 95.3% 1008/1056]`) |
| | | | | **Result `scope = NPU_L1_L2`**, inter-chassis EID pairs have 8 coverage links (4 forward + 4 reverse), intra-chassis EID pairs have 4 (2 forward + 2 reverse) |
| | | | | **Two-stage flow**: Stage 1 enumerates cross-chassis EID pairs for inter-chassis coverage (`type = CROSS_L2`); Stage 2 uses intra-chassis EID pairs to fill gaps in uncovered NPU↔L1SW outports from Stage 1 (`type = LOCAL_L1`); finally merges statistics |
| | | | | **jettyId values**: `[32, 1023]`, one per NPU physical port; when missing from topology, falls back to `32 + portId` and increments diagnostic counter `jettyIdFallback` |
| | | | | **Reused config**: `hashFunc` / `fixedDataUdpPort` / `fixedAckUdpPort` / `hashTuple` / `dieHashFunctionSelect`, no new config items added |

#### 2.3a.1 `planPathsCoverage` vs `planPathsCoverageEx` Comparison

| Dimension | `planPathsCoverage` | `planPathsCoverageEx` |
|:---|:---|:---|
| Coverage link domain | L1SW↔L2SW | NPU↔L1SW ＋ L1SW↔L2SW |
| NPU→L1SW outport selection | Fixed by candidates (physical connection), not hash-based | NPU routing LPM + **`(DstCNA, jettyId)` CRC-8 hash** selection |
| L1SW→NPU last-hop outport | `get(0)` deterministic, picks first | **hash** selection (L1SW routing outport set to destination NPU) |
| Links per EID pair | 4 (2 forward + 2 reverse) | Inter-chassis 8 / intra-chassis 4 |
| Path type `type` | `null` | `CROSS_L2` (inter-chassis) / `LOCAL_L1` (intra-chassis) |
| Layered stats `layerStats` | `null` | `NPU_L1` + `L1_L2` two layers |
| `coverageLinks[*].layer` | `null` | `NPU_L1` / `L1_L2` |
| `coverageLinks[*].deviceType` | `null` | `"NPU"` / `"SW"` |
| ACK jettyId | None (last hop `get(0)`) | **Source NPU port jettyId** (same as forward) |
| Native hash symbol | `ubswitch_Hash_ecmp` | `ubswitch_Hash_ecmp` ＋ **`ubswitch_Hash_dieEcmp`** (CRC-8/ATM) |
| Failure diagnostics | `fwdFail1..12` / `revFailA..H` | Appends `npuRouteFail` / `npuPortFail` / `jettyIdFallback` / `l1Fail` / `l2Fail` / `dstL1Fail` / `revNpuFail` / `revDstL1Fail` / `revL2Fail` / `revSrcL1Fail` (`CoveragePlanEngine.getExDiagnostics()`) |

#### 2.3a.2 Coverage Planning Request and Status

**`CoveragePathsRequest`** reuses the same DTO; the two API signatures differ only in method name (the coverage domain is not distinguished via request fields):

| Field | Type | Description |
|------|------|------|
| `superNodeName` | `String` | SuperNode name (required) |
| `coverageRequirement` | `CoverageRequirement` | Coverage requirement enum; `null` is treated as `MIN_COVERAGE` |

**`CoverageRequirement` enum:**

| Value | Meaning | Min coverage count per link |
|:---|:---|:---:|
| `MIN_COVERAGE` | Minimum coverage, each link covered by at least 1 EID pair | 1 |
| `REDUNDANT` | Redundant coverage, each link covered by at least 2 **mutually disjoint** EID pairs (`runGreedyCoverageDualDisjoint`) | 2 |

**Coverage planning `PlanStatus` values:**

| Status | Code | Trigger Condition |
|------|------|---------|
| `SUCCESS` | 0 | All links `coverCount ≥ required` (full coverage) |
| `COVERAGE_INCOMPLETE` | 1011 | Some links `coverCount < required`; `errorMessage` carries coverage rate details |
| `TOPO_NOT_FOUND` | 1012 | `superNodeName` is empty or SuperNode not found |

### 2.3b Link Event and Route Management

| Method | Parameters | Return Value | Description | Exception Notes |
|------|------|--------|------|---------|
| `notifyLinkEvent` | `SuperNode supernode, LinkEvent event` | `void` | Notify link up/down events, update port `linkStatus` and `updateAt`, and trigger **BFS route convergence** (`RouteConvergeService.converge`) to propagate reachability changes among interconnected forwarding nodes | INIT/UNINIT → `SNCStateException` (via `checkNotUninit`) |
| | | | | `supernode` is null → `IllegalArgumentException` |
| | | | | `event` is null → `IllegalArgumentException` |
| | | | | `event.deviceName` / `event.portName` is null/empty → `IllegalArgumentException` |
| | | | | `event.eventType` not `"up"`/`"down"` → `IllegalArgumentException` |
| | | | | Device or port not found in topology → `IllegalStateException` |
| | | | | **Route convergence algorithm**: Locate the chip owning the event port, refresh `OutPortInfo.convergedFlag` for entries in that chip's routing table using the port as outport (down=set PASSIVE, up=clear PASSIVE) and call `RoutingEntry.refreshReachable()`; prefixes with reachability changes are propagated to peer forwarding nodes via other up ports on the chip, iterating until no reachability changes (BFS). Different forwardingChips on the same device are isolated; convergence propagates only within the chip's routing table that owns the port |
| | | | | **Target**: `SncService`'s `instantiationRouteMap` (populated by `makeRoutes`); convergence results affect subsequent `getNodeRoute` queries |
| `routeCalculate` | None | `void` | **Synchronized method** (`synchronized`): Computes and instantiates route templates based on built-in topology templates (`128_npu_rack.json`, `128_npu_inter_rack.json`), populating `routes`. **Idempotent**: returns directly if already calculated | INIT/UNINIT → `SNCStateException` (via `checkNotUninit`) |
| | | | | Calculation flow: `TopoTemplateService.parseTemplateFile` parses template → `RouteMspService.routeMsp` generates template routes by shortest path strategy → `RouteInstantiationService.instantiateXpodRoute` instantiates by chassis |
| | | | | **Must be called before `makeRoutes`**, otherwise `makeRoutes` throws `IllegalStateException("calculate routeCalculate first")` |
| | | | | **Does not require SuperNode to be loaded**: Can be called at any time after `init` (non-INIT/UNINIT) |
| `makeRoutes` | `SuperNode superNode` | `Map<String, Map<String, RoutingEntry>>` | Generates instantiated routing tables for NPU/L1SW/L2SW devices in the SuperNode based on pre-computed route templates, stores them in `instantiationRouteMap` and returns a copy | INIT/UNINIT → `SNCStateException` (via `checkNotUninit`) |
| | | | | `routeCalculate` not called → `IllegalStateException("calculate routeCalculate first")` |
| | | | | `superNode` is null → `IllegalArgumentException` |
| | | | | **Return value key**: `"deviceName#chipIndex"` (built by `RouteInstantiationService.buildRouteTableKey`); value is the chip's route prefix → `RoutingEntry` mapping |
| | | | | **Instantiation rules**: NPU matches template by `chassis/slot/ubpu/die` labels; L1SW matches by `chassis/index`; L2SW matches by `index/chip`; when instantiating 4 chassis, L2SW outport indices/names are remapped per inter-chassis topology |
| | | | | **Deep copy**: `RouteInstantiationService.deepCopyRoutingEntry` ensures internal `instantiationRouteMap` and return value do not affect each other |
| `getNodeRoute` | `String deviceName, int chipIndex` | `Map<String, RoutingEntry>` | Query the instantiated routing table of a single device's single chip (read from `instantiationRouteMap`) | INIT/UNINIT → `SNCStateException` (via `checkNotUninit`) |
| | | | | `deviceName` is null → `IllegalArgumentException` |
| | | | | key `"deviceName#chipIndex"` not found in `instantiationRouteMap` → `IllegalArgumentException("not found route for " + key)` |
| | | | | **Typical usage**: Query converged reachability state after route convergence (`notifyLinkEvent`) |
| `routeMSP` (static) | None | `Map<String, Map<String, RouteTable>>` | Utility method: parses built-in topology template and generates route template (does not write to `routes`), returns `xpodType → (nodeLabel → RouteTable)` | No state validation (static method) |

---

## 3. State Machine

```
          init()                       uninit()
    INIT ──────────▶ READY ──(setSuperNode completed)──▶ DATAREADY
     │                                │                                 │
     │                                │ Incremental ops (add/remove/get/…) │ planPath (may be called multiple times concurrently)
     │                                │ setSuperNode                     │ planPathsCoverage / planPathsCoverageEx
     │                                │ routeCalculate                   │ setSuperNode (may update data)
     │                                │ makeRoutes                       │ Incremental ops (add/remove/get/…)
     │                                │ getNodeRoute                     │ notifyLinkEvent
     │                                │ notifyLinkEvent                  │ routeCalculate (idempotent)
     │                                │ uninit()                         │ makeRoutes / getNodeRoute / notifyLinkEvent
     │                                │                                 │ uninit()
     └──── uninit() ───▶ UNINIT ◀───────────────────────────────────────┘
```

| State | Description | Allowed Operations |
|:-----|:-----|:----------|
| `INIT` | Initial state (not initialized) | init(), uninit() |
| `READY` | Ready state (initialized, data not ready) | setSuperNode; all incremental operations (addNpuDevices, addSwDevices, removeDevices, addRoutingEntries, removeRoutingEntries); all query operations (getSuperNode); removeSuperNode; routeCalculate; makeRoutes (requires routeCalculate first); getNodeRoute (requires makeRoutes first); notifyLinkEvent; uninit |
| `DATAREADY` | Data ready state (topology has been loaded) | Same as READY, plus planPath / planPathsCoverage / planPathsCoverageEx |
| `UNINIT` | Deinitialized | (None — any operation throws SNCStateException) |

**State Transition Rules:**
- `init()`: INIT → READY (non-idempotent, repeated init rebuilds all internal objects)
- `uninit()`: INIT / READY / DATAREADY → UNINIT (calling in INIT state only clears state markers, no side effects)
- `setSuperNode()`: READY → DATAREADY (auto-transition after topology has been loaded)
- `setSuperNode()`: DATAREADY → DATAREADY (data can still be updated in data-ready state)
- `routeCalculate()`: No state transition within READY/DATAREADY; only sets `routeCalculated = true` (idempotent, repeated calls return directly)
- `planPath()` / `planPathsCoverage()` / `planPathsCoverageEx()`: Only available in **DATAREADY** state; throws `SNCStateException` if not in DATAREADY, message is `"SNC is not in DATAREADY state, current state: <STATE>"` (**Note**: these three methods do not use `checkNotUninit`, have their own state check, message format differs from other methods)
- `notifyLinkEvent()` / `routeCalculate()` / `makeRoutes()` / `getNodeRoute()`: Use `checkNotUninit`; callable in both READY/DATAREADY (INIT/UNINIT throws `"SNC is in INIT state"` / `"SNC is in UNINIT state"`)

---

## 3a. Data Import Validation Rules

### 3a.1 setSuperNode Validation Levels

| Level | Field | Validation Rule | Behavior on Invalid Input |
|------|------|---------|-----------|
| L0 | `superNode` itself | non-null | `IllegalArgumentException` |
| L1 | `superNode.name` | non-null, non-empty | `IllegalArgumentException` |
| L1 | `superNode.npuDevices` + `superNode.swDevices` | at least one non-empty | `IllegalArgumentException` |
| L2 | Each `NpuDevice`/`SwDevice` (key/value) in `npuDevices`/`swDevices` | **Not validated** | Empty Map → passes, null value → stored, may cause NPE later |
| L3 | `DeviceEntity.deviceName` | **Not validated** | Can be null/empty, stored with null name as index key |
| L3 | `DeviceEntity.deviceType` | **Not validated** | Can be null; `planPath` uses `getNpuDevices()` which only queries NPU, SW devices won't be mixed in |
| L3 | `DeviceEntity.forwardingChips` | **Not validated** | Can be null/empty; after storage, the device has no forwarding chips or ports |
| L4 | `ForwardingChip.chipIndex` | **Not validated** | Can be null; routing table indexed by null chipIndex |
| L4 | `ForwardingChip.ports` | **Not validated** | Can be null/empty; `findNpuPort` returns null during iteration |
| L4 | `ForwardingChip.routingTable` | **Not validated** | Can be null; routing table not indexed, `addRoutingEntries` throws IllegalStateException |
| L5 | `PortEntity.portName` | **Not validated** | null → port stored with null name, cannot be found by name lookup |
| L5 | `NpuPortEntity.eid` | **Not validated** | `planPath` detects null → `SRC/DST_INFO_ERR` |
| L5 | `NpuPortEntity.cna` | **Not validated** | `planPath` detects null → `SRC/DST_INFO_ERR` |
| L5 | `PortEntity.remoteDevice/remotePort` | **Not validated** | `resolveDirectPath` mismatch → `TOPO_CONNECTION_ERROR` |
| L5 | `RoutingEntry.prefix` | **Not validated** | `addRoutingEntries` with null entry.prefix → `IllegalArgumentException` (Service layer checks) |
| L5 | `OutPortInfo` fields | **Not validated** | Stored; route lookup may cause NPE later |

### 3a.2 Incremental Operation Validation Levels

Same as import: incremental operations (`addNpuDevices`, `addSwDevices`, etc.) only validate their own input parameters; **nested object fields are not validated**:

```java
addNpuDevices("sn1", Arrays.asList(
    new NpuDevice()   // deviceName=null, deviceType=null, forwardingChips=null
    // Passes validation and is stored → subsequent operations may cause NPE
));
```

Complete validation boundary principles:

| Validation Scope | Validation Content | Not Validated Scope |
|---------|---------|-----------|
| Method input non-null | `devices != null` | Device internal fields (deviceName, forwardingChips...) |
| Collection elements non-null | Each `device != null` in list | Port fields (eid, cna, remoteDevice...) |
| Identifier non-empty string | `superNodeName != ""` | Routing table fields (prefix, outPortInfos...) |

---

## 3b. General Exception Behavior

All methods (except `init`) throw `SNCStateException` when called in an incorrect state:

> ⚠️ **planPath / planPathsCoverage / planPathsCoverageEx exception**: These three methods do not use `checkNotUninit` interception; they have their own `state != DATAREADY` check, uniformly throwing `"SNC is not in DATAREADY state, current state: <STATE>"` (same format for INIT/READY/UNINIT). Other methods (`notifyLinkEvent` / `routeCalculate` / `makeRoutes` / `getNodeRoute` etc.) use `checkNotUninit`, with messages `"SNC is in INIT state"` or `"SNC is in UNINIT state"`.

| Current State | Call `init` | Call `uninit` | Call Other Methods |
|----------|------------|--------------|-------------|
| `INIT` | Normal execution → READY | Normal execution → UNINIT | Throws `SNCStateException("SNC is in INIT state")` |
| `READY` | Normal execution (reinitialize) | Normal execution → UNINIT | Normal execution (except `planPath`/`planPathsCoverage`/`planPathsCoverageEx`, which require DATAREADY) |
| `DATAREADY` | Normal execution (reinitialize) | Normal execution → UNINIT | Normal execution |
| `UNINIT` | Normal execution → READY | Normal execution | Throws `SNCStateException("SNC is in UNINIT state")` |

### 3b.2 Parameter Validation Exceptions

**Methods with validation** (setSuperNode, addNpuDevices, addSwDevices, removeDevices, addRoutingEntries, removeRoutingEntries, planPath, planPathsCoverage, planPathsCoverageEx, notifyLinkEvent, makeRoutes, getNodeRoute, getSuperNode, removeSuperNode):

| Check | Condition | Exception |
|--------|------|------|
| null parameter | Any non-null input parameter is null | `IllegalArgumentException` |
| empty collection/string | List/Map/String is empty | `IllegalArgumentException` |
| null/empty string | superNodeName, deviceName, etc. | `IllegalArgumentException` |

**Only init does not validate parameters:**

| Method | Behavior with null input |
|------|-----------------|
| `init(null)` | config is unused, runs normally (enters READY) |

### 3b.3 Query Return Value Convention

| Method | Return When Found | Return When Not Found |
|------|-----------|--------|
| `getSuperNode(name)` | SuperNode object | `null` (not an exception) |

---

## 3c. Invocation Order Exception Scenarios

### 3c.1 Incremental Operation Before setSuperNode

```java
// Incorrect order: incremental add before import
sncService.addNpuDevices("sn1", devices);    // ① SuperNode not found → IllegalStateException
sncService.addRoutingEntries("sn1", ...);    // ② Routing table not found → IllegalStateException
sncService.setSuperNode(completeSN);         // ③ Normal import
```

| Call Order | Behavior | Consequence |
|---------|------|------|
| `addNpuDevices` → `setSuperNode` | addNpuDevices requires SuperNode to exist, will not implicitly create | `IllegalStateException` |
| `addRoutingEntries` → `setSuperNode` | addRoutingEntries requires routing table to exist | `IllegalStateException` |

### 3c.2 Incremental Operations Without Prior Topology Import

| Operation | Condition | Behavior | Result |
|------|------|------|------|
| `addNpuDevices("nonExistent", ...)` | SuperNode not found | **Throws IllegalStateException** | Clear error message |
| `addSwDevices("nonExistent", ...)` | SuperNode not found | **Throws IllegalStateException** | Clear error message |
| `removeDevices("nonExistent", ...)` | SuperNode not found | **Silent no-op** | Data not deleted, no exception |
| `addRoutingEntries("nonExistent", ...)` | Routing table not found | **Throws IllegalStateException** | Clear error message |
| `removeRoutingEntries("nonExistent", ...)` | Routing table not found | **Silent no-op** | Same as above |
| `removeSuperNode("nonExistent")` | SuperNode not found | **Silent no-op** | Map.remove null → no effect |

### 3c.3 Only Incremental Operations, Without setSuperNode

```java
sncService.init(config);
sncService.addNpuDevices("sn1", devices);       // Throws IllegalStateException (SuperNode not found)
// Cannot skip setSuperNode and directly do incremental operations
```

Only `setSuperNode()` sets the `superNodeLoaded` flag. All incremental operations **do not set** this flag → state never transitions to DATAREADY → `planPath` always fails.

### 3c.4 Repeated Import

| Operation | Behavior |
|------|------|
| `setSuperNode(SN1)` → `setSuperNode(SN2)` | **Same name**: Second call overwrites first (`Map.put` semantics), SN1 old data lost; **Different name**: Both coexist independently |
| `init()` → `init()` | Creates new Store/Engine/Service instances each time; old instances discarded |
| `init()` → `uninit()` → `init()` | Normal: clean first, then reinitialize |

### 3c.5 Data Deletion After Entering DATAREADY Causes State Rollback

```java
setSuperNode(sn);                         // superNodeLoaded=true → DATAREADY
removeSuperNode("sn1");                    // Data deleted, superNodeLoaded = getSuperNode("sn1") != null → false
planPath(req);                             // State check fails → SNCStateException (state rolled back to READY)
```

`updateDataReadyState()` rolls the state back from DATAREADY to READY when `superNodeLoaded` becomes false. After data deletion, **state rolls back**, and subsequent `planPath` calls throw `SNCStateException`.

### 3c.6 Batch Operation Validation Failure (Atomicity)

```java
// First two devices normal, third is null
addNpuDevices("sn1", Arrays.asList(d1, d2, null, d3));
```

| Step | Behavior |
|------|------|
| Pre-validation phase | Validate each element for legality |
| null | Service layer detects null → throws `IllegalArgumentException`, **pre-validation aborts** |
| d1, d2, d3 | **All not committed** (no Store changes when pre-validation fails) |

Batch operations use a **pre-validate + all-commit (two-phase)** design: Phase 1 traverses all elements for legality validation; if an invalid element is found, an exception is thrown immediately (Store has not been modified at this point). Phase 2 only executes Store operations after all validations pass. This ensures atomicity — **either all succeed (validation passes + all committed), or all fail (validation fails + exception thrown + no Store changes)**.

### 3c.7 init Exception Scenarios

| Scenario | Behavior | Consequence |
|------|------|------|
| `init(null)` | config unused, runs normally | No exception, enters READY normally |
| `init()` called twice consecutively | Second call rebuilds all Store/Engine/Service | First call's data completely lost (no merge), state reset to READY |
| `init()` field state | Creates new instance, resets `superNodeLoaded=false` | Previous state completely cleared |
| `init()` → immediately call other methods | Normal execution, state is READY | Only `planPath` is blocked (requires DATAREADY) |

### 3c.8 uninit Exception Scenarios

| Scenario | Behavior | Consequence |
|------|------|------|
| `uninit()` called before `init()` | Store fields are null, but `uninit` has null checks | Safe no-op, state → UNINIT |
| `uninit()` called twice consecutively | Second call: Store already empty, `clear()` safe with no side effects | State remains UNINIT |
| `uninit()` → call non-init method | `checkNotUninit()` detects UNINIT | Throws `SNCStateException("SNC is in UNINIT state")` |
| `uninit()` → `init()` → normal operations | Rebuilds Store, re-enters READY | Works normally |

### 3c.9 planPath Exception Scenarios

| Scenario | Behavior | Result |
|------|------|------|
| `planPath` in INIT state | `SncService.planPath` has its own state check (not `checkNotUninit`) | `SNCStateException("SNC is not in DATAREADY state, current state: INIT")` |
| `planPath` in READY state | Same | `SNCStateException("SNC is not in DATAREADY state, current state: READY")` |
| `planPath` in UNINIT state | Same | `SNCStateException("SNC is not in DATAREADY state, current state: UNINIT")` |
| `planPath(request)` with srcDevice not in SuperNode | PathService.planPath lookup returns null | `TOPO_INCOMPLETE` |
| `planPath(request)` with destDevice not found | Same | `TOPO_INCOMPLETE` |
| `planPath(request)` with srcDevice/destDevice being a switch (not NPU) | PathService.planPath two-layer check: device exists in swDevices but deviceType ≠ NPU | `SRC_AND_DST_MUST_BE_NPU(3002)` |
| `planPath(request)` with srcPort not on device | NpuDevice.findNpuPort returns null | `SRC_INFO_ERR` |
| `planPath(request)` with destPort not on device | Same | `DST_INFO_ERR` |
| `planPath` direct connection with mismatched remote ports | PathService validation fails | `TOPO_CONNECTION_ERROR` |
| `planPath` multi-hop with inconsistent intermediate connections | PathEngine.resolveMultiHopPath throws exception | `TOPO_CONNECTION_NOT_FOUND` |
| `planPath` route unreachable (intermediate device LPM miss or no out port) | PathService.routePhase throws `PathPlanException(ROUTE_NOT_REACHABLE)` | `ROUTE_NOT_REACHABLE(1010)` |
| `planPath` direct connection after init reset without reloading topology | State is READY | `SNCStateException` (does not enter planPath logic) |

### 3c.10 planPathsCoverage / planPathsCoverageEx Exception Scenarios

| Scenario | Behavior | Result |
|------|------|------|
| State not DATAREADY | `SncService` own state check (not `checkNotUninit`) | `SNCStateException("SNC is not in DATAREADY state, current state: <STATE>")` |
| `request == null` | `SncService` intercepts directly | `IllegalArgumentException("CoveragePathsRequest must not be null")` |
| `request.superNodeName` is null/empty | `PathService.planPathsCoverageInternal` returns result with errorMessage | `PlanStatus.TOPO_NOT_FOUND` (no exception thrown) |
| `superNodeName` not found in store | Same | `PlanStatus.TOPO_NOT_FOUND` |
| All links `coverCount ≥ required` | `buildResult` sets `fullCoverage = true` | `PlanStatus.SUCCESS` |
| Some links `coverCount < required` | `buildResult` sets `fullCoverage = false`, `errorMessage` carries coverage rate details; `planPathsCoverageEx` appends layered details | `PlanStatus.COVERAGE_INCOMPLETE` |
| `planPathsCoverageEx` with no NPU devices in topology | `collectNpuCandidates` returns empty | `emptyResult()` (`totalLinks=0`, `SUCCESS`) |
| `planPathsCoverageEx` with no L2SW | Stage 1 has no cross-chassis candidates → skipped; Stage 2 covers NPU↔L1SW with intra-chassis EID pairs | `SUCCESS`, `eidPairs[*].type = LOCAL_L1`, `layerStats[L1_L2].totalLinks = 0` |
| NPU routing LPM miss (`dst.cna` has no route) | `traceForwardPathEx` `selectNpuEgress` returns null, `exFailNpuRoute++` | EID pair unavailable, `continue` (does not change API return) |
| NPU routing outport has no L1SW-facing port | `exFailNpuPort++` | Same |
| `jettyId` missing or out of bounds | `jettyIdOf` falls back to `32 + portId`, `exJettyFallback++` | Routing continues, no exception; diagnostic counter visible in `CoveragePlanEngine.getExDiagnostics()` |
| L1SW→L2SW routing LPM miss | `exFailL1++` | EID pair unavailable |
| L2SW→L1SW routing LPM miss | `exFailL2++` | Same |
| Destination L1SW→NPU routing LPM miss | `exFailDstL1++` | Same |
| Reverse NPU routing failure (including source port jettyId parse failure) | `exFailRevNpu++` | Reverse path unavailable, EID pair `continue` |
| Reverse destination L1SW failure | `exFailRevDstL1++` | Same |
| Reverse L2SW failure | `exFailRevL2++` | Same |
| Reverse source L1SW failure | `exFailRevSrcL1++` | Same |
| No available EID pairs at all | `selectedPairs` empty, `coveredCount = 0` | `COVERAGE_INCOMPLETE`, `errorMessage` like `physical traversal coverage did not reach 100%: 0.00% (0/N outports covered) [NPU_L1: 0.00% 0/M; L1_L2: 0.00% 0/K]` |

### 3c.11 notifyLinkEvent Exception Scenarios

| Scenario | Behavior | Result |
|------|------|------|
| State is INIT/UNINIT | `checkNotUninit` intercepts | `SNCStateException("SNC is in INIT state")` or `("SNC is in UNINIT state")` |
| `supernode == null` | `SncService` intercepts | `IllegalArgumentException("supernode must not be null")` |
| `event == null` | `SncService` intercepts | `IllegalArgumentException("event must not be null")` |
| `event.deviceName` is null/empty | `LinkEventService` intercepts | `IllegalArgumentException("deviceName must not be null or empty")` |
| `event.portName` is null/empty | `LinkEventService` intercepts | `IllegalArgumentException("portName must not be null or empty")` |
| `event.eventType` not `"up"`/`"down"` | `LinkEventService` intercepts | `IllegalArgumentException("invalid eventType: {X}, expected: up|down")` |
| Device not found in topology | `LinkEventService` cannot find device | `IllegalStateException("Device not found: <deviceName>")` |
| Port not found on device | `findPortByName` returns null | `IllegalStateException("Port not found: <portName> in device <deviceName>")` |
| Event port has no route changes | `processLocalChip` returns empty set | Direct return, no propagation (log `"converge finished: ... no reachable change on start"`) |
| `instantiationRouteMap` empty (`makeRoutes` not called) | `RouteConvergeService.converge` `routeMap.get(...)` returns null, `updateOutPortOnChip` returns empty set | Port status still updated (`port.setLinkStatus/setUpdateAt`), but no route convergence propagation |
| Peer chip not found | `findChipByPort` returns null | Skip that peer (log warning, not enqueued) |
| Peer port link status is down | `propagateToPeers` skips down ports | Does not propagate to that peer (avoids propagating reachability via down ports) |

### 3c.12 routeCalculate Exception Scenarios

| Scenario | Behavior | Result |
|------|------|------|
| State is INIT/UNINIT | `checkNotUninit` intercepts | `SNCStateException` |
| Topology template file not found | `TopoTemplateService.parseTemplateFile` throws exception | Exception propagates upward |
| Topology `label.names["type"]` is null | `calculateDefaultTemplateRoute` throws `IllegalArgumentException("find invalid xpod type")` | Exception propagates upward |
| Repeated call | `routeCalculated == true` returns directly | Log `"route has calculated"`, idempotent with no side effects |
| Call then `uninit` then `init` | `init` rebuilds instance, `routeCalculated` reset to false | Must call `routeCalculate` again |

### 3c.13 makeRoutes Exception Scenarios

| Scenario | Behavior | Result |
|------|------|------|
| State is INIT/UNINIT | `checkNotUninit` intercepts | `SNCStateException` |
| `routeCalculate` not called | `routeCalculated == false` | `IllegalStateException("calculate routeCalculate first")` |
| `superNode == null` | `SncService` intercepts | `IllegalArgumentException("superNode is null")` |
| NPU device has no forwardingChips | `makeNpuRoutes` throws `IllegalArgumentException("npu device <X> has no forwarding chips")` | Exception propagates upward |
| L1SW/L2SW device has no forwardingChips | `makeL1SwRoutes`/`makeL2SwRoutes` throws `IllegalArgumentException` | Exception propagates upward |
| Template has no matching route label for device | `makeNpuRoutes`/`makeL1SwRoutes`/`makeL2SwRoutes` logs error then `continue` | That chip's route is missing, not placed in `instantiationRouteMap`; other devices processed normally |
| `rack` format cannot parse number | `extractRackNumber` throws `IllegalArgumentException("invalid rack format: <X>")` | Exception propagates upward |

### 3c.14 getNodeRoute Exception Scenarios

| Scenario | Behavior | Result |
|------|------|------|
| State is INIT/UNINIT | `checkNotUninit` intercepts | `SNCStateException` |
| `deviceName == null` | `SncService` intercepts | `IllegalArgumentException("device info is null")` |
| key `"deviceName#chipIndex"` not in `instantiationRouteMap` | `SncService` throws exception | `IllegalArgumentException("not found route for <key>")` |
| `makeRoutes` not called (`instantiationRouteMap` empty) | Same | Same |

---

## 4. DTO Definitions

### `PathPlanRequest`

| Field | Type | Description |
|------|------|------|
| `superNodeName` | `String` | SuperNode name |
| `srcPort` | `String` | Source port name |
| `destPort` | `String` | Destination port name |
| `srcDevice` | `String` | Source device name |
| `destDevice` | `String` | Destination device name |
| `interDevices` | `LinkedHashMap<String, String>` | Intermediate device mapping (deviceName → connectionPort) |

### `PathPlanResult`

| Field | Type | Description |
|------|------|------|
| `srcEid` | `String` | Source EID |
| `dstEid` | `String` | Destination EID |
| `path` | `PathInfo` | Path information |
| `status` | `PlanStatus` | Planning result status |
| `errorMessage` | `String` | Error message |
| `ackUdpSrcPort` | `int` | ACK UDP source port |
| `dataUdpSrcPort` | `int` | Data UDP source port |
| `spray` | `boolean` | Spray enabled |

### `PlanStatus` Enum

| Name | Code | Message | Trigger Condition |
|------|------|------|---------|
| `SUCCESS` | 0 | success | Path planning successful / coverage planning full coverage |
| `SRC_INFO_ERR` | 1003 | src info error | Source port not found / EID or CNA is null / format error |
| `DST_INFO_ERR` | 1004 | dst info error | Destination port not found / EID or CNA is null / format error |
| `TOPO_INCOMPLETE` | 1007 | topo incomplete | srcDevice or destDevice not found in SuperNode |
| `TOPO_CONNECTION_ERROR` | 1008 | topo connection error | Direct topology: src and dest port remoteDevice/remotePort mismatch |
| `TOPO_CONNECTION_NOT_FOUND` | 1009 | topo connection not found | Multi-hop topology: inconsistent connection between hops |
| `ROUTE_NOT_REACHABLE` | 1010 | route not reachable | Intermediate device route unreachable |
| `COVERAGE_INCOMPLETE` | 1011 | coverage incomplete | Coverage planning did not reach 100% (`planPathsCoverage` / `planPathsCoverageEx`) |
| `TOPO_NOT_FOUND` | 1012 | topo not found | Requested SuperNode name not found in store |
| `SRC_AND_DST_MUST_BE_NPU` | 3002 | src and dst must be npu | srcDevice or destDevice type is not NPU |
| `UPI_MISMATCH` | 3003 | upi mismatch | Source and destination ports both have UPI but they differ |

### `PathInfo`

| Field | Type | Description |
|------|------|------|
| `hops` | `List<HopInfo>` | Hop list |

### `HopInfo`

| Field | Type | Description |
|------|------|------|
| `deviceName` | `String` | Device name |
| `inPort` | `String` | Inbound port |
| `outPort` | `String` | Outbound port |
| `multiPath` | `boolean` | Whether multi-path is supported |
| `deviceType` | `String` | Device type |

### `CoveragePathsRequest`

`planPathsCoverage` and `planPathsCoverageEx` share the same request DTO; the coverage domain is determined by the method name (no `scope` field is added to the request).

| Field | Type | Description |
|------|------|------|
| `superNodeName` | `String` | SuperNode name (required) |
| `coverageRequirement` | `CoverageRequirement` | Coverage requirement enum; `null` is treated as `MIN_COVERAGE` |

### `CoverageRequirement` Enum

| Value | Description |
|:---|:---|
| `MIN_COVERAGE` | Minimum coverage, each link covered by at least 1 EID pair |
| `REDUNDANT` | Redundant coverage, each link covered by at least 2 mutually disjoint EID pairs |

### `CoveragePathsResult`

| Field | Type | Description |
|------|------|------|
| `status` | `PlanStatus` | `SUCCESS` / `COVERAGE_INCOMPLETE` / `TOPO_NOT_FOUND` |
| `errorMessage` | `String` | Carries coverage rate details when not fully covered; `planPathsCoverageEx` appends layered details, e.g.: `physical traversal coverage did not reach 100%: 96.88% (2016/2080 outports covered) [NPU_L1: 98.4% 1008/1024; L1_L2: 95.3% 1008/1056]` |
| `eidPairs` | `List<CoveredEidPair>` | Selected EID pair list (each pair includes its coverage links) |
| `coverageLinks` | `List<CoverageLink>` | All outports with their `coverCount` / `coveredPairs` / `layer` / `deviceType` |
| `stats` | `CoverageStats` | Aggregate statistics (same basis as `planPathsCoverage`) |
| `scope` | `CoverageLinkScope` | Coverage link domain used this time; `planPathsCoverage` is always `L1_L2`, `planPathsCoverageEx` is `NPU_L1_L2` |
| `layerStats` | `Map<CoverageLinkLayer, CoverageLayerStats>` | Layered statistics; only set by `planPathsCoverageEx`, `null` for `planPathsCoverage` |

### `CoverageLinkScope` Enum

| Value | Description |
|:---|:---|
| `L1_L2` | Only L1SW↔L2SW outports (domain of `planPathsCoverage`) |
| `NPU_L1_L2` | NPU↔L1SW ＋ L1SW↔L2SW outports (domain of `planPathsCoverageEx`) |

### `CoverageLinkLayer` Enum

Link layer classification, used to group outports into NPU↔L1SW or L1SW↔L2SW. Direction is not expressed in this enum; it is derived from the device types at both ends of the link (if the device is NPU, it is NPU→L1SW; if the device is L1SW and the peer is NPU, it is L1SW→NPU).

| Value | Description |
|:---|:---|
| `NPU_L1` | NPU↔L1SW (NPU uplink outports / L1SW's NPU-facing outports) |
| `L1_L2` | L1SW↔L2SW |

### `CoveragePathType` Enum

Path type identifier for EID pairs (`CoveredEidPair.type`), named by NPU/L1/L2 layer, independent of the physical chassis concept.

| Value | Description | Links per EID pair |
|:---|:---|:---:|
| `CROSS_L2` | Inter-chassis path: `NPU → L1SW → L2SW → L1SW → NPU` | 8 (4 forward + 4 reverse) |
| `LOCAL_L1` | Intra-chassis path: `NPU → L1SW → NPU` (same chassis, no L2SW) | 4 (2 forward + 2 reverse) |

### `CoverageLayerStats`

Coverage rate statistics for a single layer (`CoverageLinkLayer`), with field semantics aligned with `CoverageStats`.

| Field | Type | Calculation |
|------|------|------|
| `totalLinks` | `Integer` | Number of links in `linkMap` for this layer |
| `coveredCount` | `Integer` | Number of links with `coverCount > 0` in this layer |
| `coverageRate` | `Double` | `totalLinks > 0 ? coveredCount / totalLinks : 0` |
| `minRepeatCount` | `Integer` | Min `coverCount` of covered links in this layer; 0 if no covered links |
| `maxRepeatCount` | `Integer` | Max `coverCount` of covered links in this layer; 0 if no covered links |
| `avgRepeatCount` | `Double` | `ΣcoverCount / coveredCount` of covered links in this layer; 0 if `coveredCount == 0` |
| `repeatRate` | `Double` | `(ΣcoverCount - coveredCount) / totalLinks` |

### `CoverageStats`

Aggregate statistics (covering all layers), with field semantics consistent with `CoverageLayerStats`, plus EID uniformity fields.

| Field | Type | Description |
|------|------|------|
| `totalLinks` | `Integer` | Total outport count |
| `coveredCount` | `Integer` | Covered outport count |
| `coverageRate` | `Double` | `coveredCount / totalLinks` |
| `minRepeatCount` | `Integer` | Min coverage count per link |
| `maxRepeatCount` | `Integer` | Max coverage count per link |
| `avgRepeatCount` | `Double` | Average coverage count per link |
| `repeatRate` | `Double` | `(ΣcoverCount - coveredCount) / totalLinks` |
| `uniqueEidCount` | `Integer` | Unique EID count |
| `totalEidAppearances` | `Integer` | Total EID appearance count |
| `eidRepeatRate` | `Double` | EID repeat rate |
| `eidMinRepeat` / `eidMaxRepeat` / `eidAvgRepeat` | `Integer`/`Integer`/`Double` | EID repeat count statistics |
| `srcEidMinRepeat` / `srcEidMaxRepeat` / `srcEidAvgRepeat` | `Integer`/`Integer`/`Double` | Source EID repeat count statistics |
| `dstEidMinRepeat` / `dstEidMaxRepeat` / `dstEidAvgRepeat` | `Integer`/`Integer`/`Double` | Destination EID repeat count statistics |
| `npuUsageByChassis` | `Map<String, Integer>` | NPU usage count by chassis |

### `CoveredEidPair`

| Field | Type | Description |
|------|------|------|
| `srcEid` | `String` | Source EID |
| `dstEid` | `String` | Destination EID |
| `srcCna` | `String` | Source CNA |
| `dstCna` | `String` | Destination CNA |
| `srcDevice` | `String` | Source device name |
| `srcPort` | `String` | Source port name (endpoint identity, **does not constrain** the physical outport; the actual outport is determined by `(DstCNA, jettyId)` hash, see `coveredLinks[0].outPort`) |
| `destDevice` | `String` | Destination device name |
| `destPort` | `String` | Destination port name (endpoint identity) |
| `coveredLinks` | `List<CoverageLink>` | Coverage link list; `planPathsCoverage` always has 4 (indices 0..3 = 2 forward + 2 reverse), `planPathsCoverageEx` has 8 for inter-chassis / 4 for intra-chassis |
| `type` | `CoveragePathType` | Path type; `null` for `planPathsCoverage`, `CROSS_L2` / `LOCAL_L1` for `planPathsCoverageEx` |

**`planPathsCoverageEx` inter-chassis EID pair `coveredLinks` order (8 links):**

| Index | Direction | Device (outport) | Peer | layer |
|:---:|:---|:---|:---|:---|
| 0 | Forward | Source NPU | Source L1SW | `NPU_L1` |
| 1 | Forward | Source L1SW | L2SW | `L1_L2` |
| 2 | Forward | L2SW | Destination L1SW | `L1_L2` |
| 3 | Forward | Destination L1SW | Destination NPU | `NPU_L1` |
| 4 | Reverse | Destination NPU | Destination L1SW | `NPU_L1` |
| 5 | Reverse | Destination L1SW | L2SW | `L1_L2` |
| 6 | Reverse | L2SW | Source L1SW | `L1_L2` |
| 7 | Reverse | Source L1SW | Source NPU | `NPU_L1` |

**`planPathsCoverageEx` intra-chassis EID pair `coveredLinks` order (4 links):**

| Index | Direction | Device (outport) | Peer | layer |
|:---:|:---|:---|:---|:---|
| 0 | Forward | Source NPU | L1SW | `NPU_L1` |
| 1 | Forward | L1SW | Destination NPU | `NPU_L1` |
| 2 | Reverse | Destination NPU | L1SW | `NPU_L1` |
| 3 | Reverse | L1SW | Source NPU | `NPU_L1` |

### `CoverageLink`

| Field | Type | Description |
|------|------|------|
| `switchDevice` | `String` | Device name owning the outport (**semantic extension**: may be SW or NPU) |
| `chipIndex` | `Integer` | Forwarding chip index |
| `outPort` | `String` | Outport name |
| `remoteSwitch` | `String` | Peer device name |
| `remotePort` | `String` | Peer port name |
| `outPortIndex` | `Integer` | Index of the outport in the ECMP member set |
| `totalOutPorts` | `Integer` | ECMP member set size |
| `coveredPairs` | `List<CoveredEidPairRef>` | List of EID pair references covering this outport |
| `coverCount` | `Integer` | Coverage count |
| `deviceType` | `String` | Device type owning the outport, values `"NPU"` / `"SW"` (converted from `DeviceType.name()`, dto layer does not depend on entity package); not set by `planPathsCoverage` (`null`) |
| `layer` | `CoverageLinkLayer` | Link layer (`NPU_L1` / `L1_L2`); not set by `planPathsCoverage` (`null`) |

> **Architecture constraint:** The `dto` layer must not depend on the `entity` package. `deviceType` uses `String` instead of `DeviceType`, converted by the Service layer from `DeviceType.name()`, consistent with the existing approach for `HopInfo.deviceType`.
>
> **Compatibility note:** The `switchDevice` field name is retained (to avoid breaking JSON contracts and existing parsing), but its semantics are relaxed from "switch device name" to "device name owning the outport".

### `CoveredEidPairRef`

| Field | Type | Description |
|------|------|------|
| `srcEid` | `String` | Source EID |
| `dstEid` | `String` | Destination EID |

### `LinkEvent`

| Field | Type | Description |
|------|------|------|
| `deviceName` | `String` | Device name where the link resides (required) |
| `portName` | `String` | Link port name (required) |
| `eventType` | `String` | Event type, values `"up"` / `"down"` (corresponding to constants `LinkEvent.LINK_STATUS_UP` / `LINK_STATUS_DOWN`) |
| `eventTime` | `Long` | Event timestamp (written to `PortEntity.updateAt`) |

---

## 5. Exception Definitions

| Exception Class | Parent Class | Description |
|--------|------|------|
| `SNCException` | `RuntimeException` | Base exception |
| `SNCStateException` | `SNCException` | SNC state error |
| `SuperNodeNotFoundException` | `SNCException` | SuperNode or device not found |
| `PathPlanException` | `SNCException` | Path planning failure (contains `PlanStatus status`) |

---

## 6. Service Internal Interfaces

### `SuperNodeService`

| Method | Parameters | Return Value |
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

| Method | Parameters | Return Value |
|------|------|--------|
| `planPath` | `PathPlanRequest` | `PathPlanResult` |
| `planPathsCoverage` | `CoveragePathsRequest` | `CoveragePathsResult` |
| `planPathsCoverageEx` | `CoveragePathsRequest` | `CoveragePathsResult` |

### `LinkEventService`

| Method | Parameters | Return Value |
|------|------|--------|
| `notifyLinkEvent` | `SuperNode supernode, LinkEvent event` | `void` |

> `LinkEventService` only updates port `linkStatus` and `updateAt`; route convergence is performed by `RouteConvergeService.converge` called explicitly within `SncService.notifyLinkEvent`.

### `RouteConvergeService`

| Method | Parameters | Return Value |
|------|------|--------|
| `converge` | `Map<String, Map<String, RoutingEntry>> instantiationRouteMap, SuperNode supernode, LinkEvent event` | `void` |

> BFS route convergence algorithm. **Target** is `SncService.instantiationRouteMap` (populated by `makeRoutes`); convergence results affect subsequent `getNodeRoute` queries.

### `RouteInstantiationService`

| Method | Parameters | Return Value | Description |
|------|------|--------|------|
| `instantiateXpodRoute` (static) | `Map<String, SncTopology>, Map<String, Map<String, RouteTable>>, Map<String, RouteTable>` | `void` | Instantiate template routes into `routes` by chassis |
| `makeNpuRoutes` | `NpuDevice, Map<String, RouteTable>, Map<String, Map<String, RoutingEntry>>` | `void` | Generate instantiated routes for a single NPU device |
| `makeSwRoutes` | `SwDevice, Map<String, RouteTable>, Map<String, Map<String, RoutingEntry>>` | `void` | Generate instantiated routes for a single SW device (dispatched by L1/L2) |
| `buildRouteTableKey` (static) | `String deviceName, int chipIndex` | `String` | Build key: `"deviceName#chipIndex"` |
| `deepCopyRoutingEntry` (static) | `Map<String, Map<String, RoutingEntry>>` | Same type | Deep copy (ensures internal `instantiationRouteMap` and return value do not affect each other) |

### `RouteMspService`

| Method | Parameters | Return Value | Description |
|------|------|--------|------|
| `routeMsp` (static) | `SncTopology` | `Map<String, RouteTable>` | Generate single-node template routes by shortest path strategy |

### `TopoTemplateService`

| Method | Parameters | Return Value | Description |
|------|------|--------|------|
| `parseTemplateFile` (static) | `String filePath` | `SncTopology` | Parse built-in topology template JSON |

---

## 7. Engine Internal Interfaces

| Engine | Method | Parameters | Return Value |
|--------|------|------|--------|
| `PathEngine` | `resolveDirectPath` | `NpuDevice, NpuPortEntity, NpuDevice, NpuPortEntity` | `InternalPathInfo` |
| `PathEngine` | `resolveMultiHopPath` | `NpuDevice, NpuPortEntity, NpuDevice, NpuPortEntity, Map, Map` | `InternalPathInfo` |
| `PathEngine` | `reverseHops` | `List<InternalPathHop>` | `List<InternalPathHop>` |
| `PathEngine` | `findPortByName` | `DeviceEntity, String` | `PortEntity` |
| `PathEngine` | `findPortByConnection` | `DeviceEntity` | `PortEntity` |
| `RouteLookupEngine` | `lookup` | `String, Map, List<Integer>` | `RoutingEntry` |
| `CoveragePlanEngine` | `findCoverage` | `SuperNode, int, int, CoverageRequirement` | `CoverageSearchResult` |
| `CoveragePlanEngine` | `findCoverageEx` | `SuperNode, int dataUdpSrcPort, int ackUdpSrcPort, CoverageRequirement` | `CoverageSearchResult` (includes `layerTotalLinks` / `layerCoveredCount`) |
| `CoveragePlanEngine` | `getExDiagnostics` | None | `Map<String, Integer>` (includes `npuRouteFail` / `npuPortFail` / `jettyIdFallback` / `l1Fail` / `l2Fail` / `dstL1Fail` / `revNpuFail` / `revDstL1Fail` / `revL2Fail` / `revSrcL1Fail`) |

**`CoveragePlanEngine` Constructor Parameters:**

| Parameter | Type | Source | Description |
|------|------|------|------|
| `superNodeStore` | `SuperNodeStore` | `SncService.init` | Topology store |
| `hashFunc` | `int` | `SNCConfig.getHashFunc()` | Hash function selector (1=FNV-1a, other=simple accumulation) |
| `fixedDataUdpPort` | `int` | `SNCConfig.getFixedDataUdpPort()` | Fixed UDP source port for data flow |
| `fixedAckUdpPort` | `int` | `SNCConfig.getFixedAckUdpPort()` | Fixed UDP source port for ACK flow |
| `hashTuple` | `HashTuple` | `SNCConfig.getHashTuple()` | Hash tuple width (TWO/FIVE) |
| `dieHashFunctionSelect` | `int` | `SNCConfig.getDieHashFunctionSelect()` | NPU→L1SW CRC-8 hash function selector (0/1) |

---

## 8. Store Internal Interfaces

| Store | Methods |
|-------|------|
| `SuperNodeStore` | `init, clear, replace, removeSuperNode, getSuperNode, getRoutingTable, addNpuDevice, addSwDevice, removeDevice, addRoutingEntry, removeRoutingEntry` |

---

## 9. Coverage Planning Algorithm Overview

### 9.1 Hash Usage Points

`CoveragePlanEngine.nativePortIdx(scna, dcna, sport, dport, ecmpCnt)` uniformly wraps the hash for L1SW↔L2SW and L1SW→NPU (reusing `ubswitch_Hash_ecmp`); NPU→L1SW uses the independent `HashUtils.nativeHashDstCnaJetty(dstCna, jettyId, ecmpCnt, hashFunc)` (`ubswitch_Hash_dieEcmp`, CRC-8/ATM).

**`planPathsCoverage` hash points (4 points, all `nativePortIdx`):**

| Index | Location | Direction | scna / dcna | sport / dport | Member set |
|:---:|:---|:---|:---|:---|:---|
| H1 | `traceForwardPath` | L1SW→L2SW | `src.cna` / `dst.cna` | `dataUdpSrcPort` / `ackUdpSrcPort` | Set of L1SW routing outports with remote being L2SW |
| H2 | `traceForwardPath` | L2SW→L1SW | `src.cna` / `dst.cna` | `dataUdpSrcPort` / `ackUdpSrcPort` | Set of ports on the L2SW inbound port's chip towards `dst.remoteL1sw` |
| H3 | `traceReversePath` | L1SW→L2SW (reverse) | `dst.cna` / `src.cna` | `ackUdpSrcPort` / `dataUdpSrcPort` | Set of destination L1SW routing outports with remote being L2SW |
| H4 | `traceReversePath` | L2SW→L1SW (reverse) | `dst.cna` / `src.cna` | `ackUdpSrcPort` / `dataUdpSrcPort` | Set of ports on the reverse L2SW inbound port's chip towards `src.remoteL1sw` |

**`planPathsCoverageEx` additional hash points (H5/H6 use `nativeHashDstCnaJetty` and `nativePortIdx`):**

| Index | Location | Direction | hash input | Member set | Native symbol |
|:---:|:---|:---|:---|:---|:---|
| H5 | `traceForwardPathEx` | NPU→L1SW (forward) | **`(DstCNA=dst.cna, jettyId=source port jettyId)`** | NPU routing LPM hit entries with remote being L1SW outports | `ubswitch_Hash_dieEcmp` |
| H6 | `traceForwardPathEx` | L1SW→NPU (forward, last hop) | `nativePortIdx(scna, dst.cna, data, ack, M.size())`, scna = CNA of H5 selected port | Destination L1SW routing LPM hit entries with remote = `dst.deviceName` outports | `ubswitch_Hash_ecmp` |
| H7a | `traceReversePathEx` | NPU→L1SW (reverse) | **`(DstCNA=src.cna, jettyId=source port jettyId)`** (same jettyId as forward) | Destination NPU routing LPM hit entries with remote being L1SW outports | `ubswitch_Hash_dieEcmp` |
| H7d | `traceReversePathEx` | L1SW→NPU (reverse, last hop) | `nativePortIdx(scnaRev, src.cna, ack, data, M.size())` | Source L1SW routing LPM hit entries with remote = `src.deviceName` outports | `ubswitch_Hash_ecmp` |

### 9.2 SCNA Chaining

In `planPathsCoverageEx`, **the CNA of the selected NPU port serves as the SCNA** for subsequent L1SW→L2SW, L2SW→L1SW, and L1SW→NPU hash port selection. ACK direction works similarly: the CNA of the H7a selected port serves as the reverse SCNA (`scnaRev`), driving reverse L1SW/L2SW port selection.

### 9.3 Two-Stage Coverage (`planPathsCoverageEx`)

1. **Stage 1 (inter-chassis CROSS_L2)**: Enumerate cross-chassis EID pairs, trace 4-hop forward/reverse paths (`traceForwardPathEx` / `traceReversePathEx`), greedily select EID pairs covering L1SW↔L2SW;
2. **Stage 2 (intra-chassis LOCAL_L1)**: From the Stage 1 results, filter outports with `layer == NPU_L1 && coverCount < required` as the gap set, enumerate intra-chassis EID pairs and trace 2-hop forward/reverse paths (`traceIntraForwardPathEx` / `traceIntraReversePathEx`), greedily select pairs targeting the gap set;
3. **Merge statistics**: After merging Stage 1 + Stage 2 EID pairs, recompute coverage rate / repeat rate and other statistics on the complete link domain.

> In some topologies, Stage 2 may produce 0 pairs (inter-chassis has already covered all NPU↔L1SW outports), which is a normal result; for single-chassis (or when cross-chassis paths are unavailable), all coverage is intra-chassis.

### 9.4 Route Scope Extension and Reception Semantics (`planPathsCoverageEx`)

**Reception semantics (key premise)**: The destination CNA belongs to an NPU device, and that NPU can receive the packet even if the packet arrives at a port that is not the CNA's own physical port. Therefore, the routing/port selection constraint is relaxed from "CNA ↔ port one-to-one correspondence" to "the NPU device owning the CNA is reachable".

| Location | `planPathsCoverage` basis | `planPathsCoverageEx` basis |
|:---|:---|:---|
| L1SW routing | Build /32 routes only for "physically connected ports" CNAs | For each NPU with ports, build /32 routes for each of its CNAs, outport = all ports from this L1SW to that NPU (enhanced by test fixture `CoverageRouteAugmentor.augmentL1swNpuRouting`) |
| L2SW→L1SW port selection | Fixed to `dst.remoteL1sw` | Any "L1SW that can reach the destination NPU device" (`PrecomputedTopo.npuL1Peers` + `l2PortsTowardsL1Peers`) |
| L1SW→NPU port selection | Route has only 1 outport (no ECMP), `get(0)` | All ports from this L1SW to the destination NPU (≥2 → hash selectable), `l1PortsTowardsDevice` + `nativePortIdx` |

### 9.5 EID and Outport Relationship

- `srcPort / srcCna / srcEid` identify the **endpoint identity** (which logical port of which device initiates/receives the flow), **not constraining** the physical outport of the packet;
- After the source NPU receives the packet, it selects the actual outport among its uplink ports (all ports towards the L1SW on the path to the destination) using **CRC8 `(DstCNA, jettyId)`**; **the CNA of the selected port is the SCNA used for subsequent L1/L2 port selection**;
- Therefore, `CoveredEidPair.srcPort` (selected endpoint identity) and `coveredLinks[0].outPort` (actual outport) **may differ**, which is intentional by design;
- ACK direction works similarly: `destPort` is the ACK sending endpoint identity, and the actual outport is determined by `(srcCna, source port jettyId)` (jettyId taken from the source NPU port, same as forward).

### 9.6 jettyId Values and Native Library

| Item | Description |
|:---|:---|
| jettyId value range | `[32, 1023]`, one per NPU physical port; entry validation throws `IllegalArgumentException` on out-of-bounds (`HashUtils.JETTY_ID_MIN/MAX`, `isValidJettyId`) |
| topo input fields | SuperNode JSON `jettyId` (`TestDataLoader`); template JSON `jetty_id` (`128_npu_rack.json`) + `PortLoader`/`SncPort`; `FullRackTopologyGenerator` uses fixed allocation `JETTY_ID_BASE + portIndex` (32..39, fully consistent each generation); falls back to `32 + portId` when missing and increments `jettyIdFallback` |
| Native library `ubswitch_Hash_ecmp` | L1SW↔L2SW port selection, L1SW→NPU port selection; Java entry `HashUtils.nativeHash(...)` / `nativePortIdx(...)` |
| Native library `ubswitch_Hash_dieEcmp` | **NPU→L1SW port selection (CRC-8/ATM)**; Java entry `HashUtils.nativeHashDstCnaJetty(dstCna, jettyId, ecmpCnt, hashFunc)`; byte stream = `DstCNA` ASCII + `jettyId` low byte + `jettyId` high byte; `ecmpCnt == 0` returns raw CRC (0..255), `ecmpCnt > 0` returns `CRC % ecmpCnt` |
| Java fallback | `UbSwitchHash` (pure Java implementation of both hash algorithms), automatically falls back when native library fails to load, results fully consistent with native library |
