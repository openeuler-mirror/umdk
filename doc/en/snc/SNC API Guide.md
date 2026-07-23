# SNC Module API Guide

## 1. Overview

The SNC (SuperNode Network Controller) module provides SuperNode topology management, ACL access control, and path planning capabilities. It exposes a unified `SNCService` interface, with an internal layered architecture: Service → Engine → Store.

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

### 2.3 ACL Management

| Method | Parameters | Return Value | Description | Exception Notes |
|------|------|--------|------|---------|
| `setAclData` | `AclData aclData` | `void` | Import (**replace by superNodeName**) ACL data, mark aclLoaded, update data ready state; old ACL with the same superNodeName is overwritten, ACL data with different names coexist without interference | INIT/UNINIT → `SNCStateException`; null name/empty name → `IllegalArgumentException`; **Sub-fields (tpAcls/AclKey/TpAclEntity internal fields) are not validated** — missing values cause `planPath` to return `ACL_CHECK_FAILED` |
| `addAclRules` | `String superNodeName, Map<AclKey, TpAclEntity> rules` | `void` | Batch add ACL rules; if ACL data does not exist, **throws IllegalStateException** ("ACL data not found for superNode: \<name\>") | INIT/UNINIT → `SNCStateException`; null parameters → `IllegalArgumentException`; null key/value → `IllegalArgumentException`; target ACL not found → `IllegalStateException` |
| `removeAclRules` | `String superNodeName, List<AclKey> keys` | `void` | Batch remove ACL rules; if target ACL data does not exist, **throws IllegalStateException** ("ACL data not found for superNode: \<name\>") | INIT/UNINIT → `SNCStateException`; null parameters → `IllegalArgumentException`; null key → `IllegalArgumentException`; target ACL not found → `IllegalStateException` |
| `getAclData` | `String superNodeName` | `AclData` | Query ACL data for the specified SuperNode | INIT/UNINIT → `SNCStateException`; returns `null` if not found (not an exception) |
| `removeAclData` | `String superNodeName` | `void` | Delete ACL data for the specified SuperNode | INIT/UNINIT → `SNCStateException` |

### 2.4 Path Planning

| Method | Parameters | Return Value | Description | Exception Notes |
|------|------|--------|------|---------|
| `planPath` | `PathPlanRequest request` | `PathPlanResult` | Plan a transmission path from source to destination | Non-DATAREADY state → `SNCStateException` (message format: "SNC is not in DATAREADY state, current state: \<STATE\>", **different from** other methods' `checkNotUninit` interception message) |
| | | | | request is null or any of superNodeName/srcDevice/destDevice/srcPort/destPort is null/empty → `IllegalArgumentException` |
| | | | | **interDevices field is optional** (can be null/empty, indicating a direct connection scenario) |
| | | | | On business failure, no exception is thrown; `PathPlanResult.status` is non-SUCCESS, see the `PlanStatus` mapping table below |
| | | | | **Routing lookup mechanism**: planPath internally uses the destination port's CNA (`destCna`) as the lookup target, performing LPM matching directly against route prefixes. |

---

## 3. State Machine

```
         init()                                 uninit()
  INIT ──────────▶ READY ──(setSuperNode & setAclData both completed)──▶ DATAREADY
   │                                │                                 │
   │                                │ Incremental ops (add/remove/get/…) │ planPath (may be called multiple times concurrently)
   │                                │ setSuperNode / setAclData         │ setSuperNode / setAclData (may update data)
   │                                │ uninit()                         │ Incremental ops (add/remove/get/…)
   │                                │                                 │
   └──── uninit() ───▶ UNINIT ◀───────────────────────────────────────┘
```

| State | Description | Allowed Operations |
|:-----|:-----|:----------|
| `INIT` | Initial state (not initialized) | init(), uninit() |
| `READY` | Ready state (initialized, data not ready) | setSuperNode, setAclData; all incremental operations (addNpuDevices, addSwDevices, removeDevices, addRoutingEntries, removeRoutingEntries, addAclRules, removeAclRules); all query operations (getSuperNode, getAclData); removeSuperNode, removeAclData; uninit |
| `DATAREADY` | Data ready state (both topology and ACL have been loaded) | Same as READY, plus planPath |
| `UNINIT` | Deinitialized | (None — any operation throws SNCStateException) |

**State Transition Rules:**
- `init()`: INIT → READY (non-idempotent, repeated init rebuilds all internal objects)
- `uninit()`: INIT / READY / DATAREADY → UNINIT (calling in INIT state only clears state markers, no side effects)
- `setSuperNode()` + `setAclData()`: READY → DATAREADY (auto-transition after both have been loaded)
- `setSuperNode()` / `setAclData()`: DATAREADY → DATAREADY (data can still be updated in data-ready state)
- `planPath()`: Only available in **DATAREADY** state; throws `SNCStateException` if not in DATAREADY, message is `"SNC is not in DATAREADY state, current state: <STATE>"` (**Note**: planPath does not use `checkNotUninit`, has its own state check, message format differs from other methods)

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

### 3a.2 setAclData Validation Levels

| Level | Field | Validation Rule | Behavior on Invalid Input |
|------|------|---------|-----------|
| L0 | `aclData` itself | non-null | `IllegalArgumentException` |
| L1 | `aclData.superNodeName` | non-null, non-empty | `IllegalArgumentException` |
| L1 | `aclData.tpAcls` | **Not validated** | Can be null/empty; subsequent `addAclRules` requires ACL data to exist, otherwise throws `IllegalStateException` |
| L2 | `AclKey.srcEid` | **Not validated** | `AclCheckEngine.checkBothDirection` uses null to search Map → match fails |
| L2 | `AclKey.dstEid` | **Not validated** | Same as above |
| L2 | `AclKey.transportType` | **Not validated** | Same as above (RCTP hardcoded lookup, other types don't match) |
| L2 | `TpAclEntity.sourceCna/destCna` | **Not validated** | `checkBothDirection` compares null CNA → `ACL_CHECK_FAILED` |
| L2 | `TpAclEntity.templateId` | **Not validated** | Currently unused |

### 3a.3 Incremental Operation Validation Levels

Same as import: incremental operations (`addNpuDevices`, `addSwDevices`, `addAclRules`, etc.) only validate their own input parameters; **nested object fields are not validated**:

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
| None | None | ACL rule internal fields (srcEid, sourceCna...) |

---

## 3b. General Exception Behavior

All methods (except `init`) throw `SNCStateException` when called in an incorrect state:

> ⚠️ **planPath exception**: `planPath` does not use `checkNotUninit` interception; it has its own `state != DATAREADY` check, uniformly throwing `"SNC is not in DATAREADY state, current state: <STATE>"` (same format for INIT/READY/UNINIT). Other methods use `checkNotUninit`, with messages `"SNC is in INIT state"` or `"SNC is in UNINIT state"`.

| Current State | Call `init` | Call `uninit` | Call Other Methods |
|----------|------------|--------------|-------------|
| `INIT` | Normal execution → READY | Normal execution → UNINIT | Throws `SNCStateException("SNC is in INIT state")` |
| `READY` | Normal execution (reinitialize) | Normal execution → UNINIT | Normal execution |
| `DATAREADY` | Normal execution (reinitialize) | Normal execution → UNINIT | Normal execution |
| `UNINIT` | Normal execution → READY | Normal execution | Throws `SNCStateException("SNC is in UNINIT state")` |

### 3b.2 Parameter Validation Exceptions

**Methods with validation** (setSuperNode, addNpuDevices, addSwDevices, removeDevices, addRoutingEntries, removeRoutingEntries, setAclData, addAclRules, removeAclRules, planPath, getSuperNode, removeSuperNode, getAclData, removeAclData):

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
| `getAclData(name)` | AclData object | `null` (not an exception) |

---

## 3c. Invocation Order Exception Scenarios

### 3c.1 Incremental Operation Before setSuperNode/setAclData

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
| `addAclRules` → `setAclData` | Same logic applies to ACL side | `IllegalStateException` |

### 3c.2 Incremental Operations Without Prior Topology/ACL Import

| Operation | Condition | Behavior | Result |
|------|------|------|------|
| `addNpuDevices("nonExistent", ...)` | SuperNode not found | **Throws IllegalStateException** | Clear error message |
| `addSwDevices("nonExistent", ...)` | SuperNode not found | **Throws IllegalStateException** | Clear error message |
| `removeDevices("nonExistent", ...)` | SuperNode not found | **Silent no-op** | Data not deleted, no exception |
| `addRoutingEntries("nonExistent", ...)` | Routing table not found | **Throws IllegalStateException** | Clear error message |
| `removeRoutingEntries("nonExistent", ...)` | Routing table not found | **Silent no-op** | Same as above |
| `addAclRules("nonExistent", ...)` | ACL data not found | **Throws IllegalStateException** | Clear error message: "ACL data not found for superNode: nonExistent" |
| `removeAclRules("nonExistent", ...)` | ACL data not found | **Throws IllegalStateException** | Same as above |
| `removeSuperNode("nonExistent")` | SuperNode not found | **Silent no-op** | Map.remove null → no effect |
| `removeAclData("nonExistent")` | ACL not found | **Silent no-op** | Same as above |

### 3c.3 Only Incremental Operations, Without setSuperNode/setAclData

```java
sncService.init(config);
sncService.addNpuDevices("sn1", devices);       // Throws IllegalStateException (SuperNode not found)
// Cannot skip setSuperNode and directly do incremental operations
```

Only `setSuperNode()` and `setAclData()` set the `superNodeLoaded`/`aclLoaded` flags. All incremental operations **do not set** these flags → state never transitions to DATAREADY → `planPath` always fails.

### 3c.4 Repeated Import

| Operation | Behavior |
|------|------|
| `setSuperNode(SN1)` → `setSuperNode(SN2)` | **Same name**: Second call overwrites first (`Map.put` semantics), SN1 old data lost; **Different name**: Both coexist independently |
| `setAclData(AD1)` → `setAclData(AD2)` | Same logic on ACL side (overwrite by `superNodeName`) |
| `init()` → `init()` | Creates new Store/Engine/Service instances each time; old instances discarded |
| `init()` → `uninit()` → `init()` | Normal: clean first, then reinitialize |

### 3c.5 Cross-SuperNode Mismatch

| Scenario | Behavior | Result |
|------|------|------|
| `setSuperNode("snA", ...)` + `setAclData("snB", ...)` | SuperNode name "snA" ≠ ACL name "snB" | Both exist in their respective stores, but `planPath("snA", ...)` finds null ACL → `ACL_NOT_FOUND` |

### 3c.5a Data Deletion After Entering DATAREADY Causes State Rollback

```java
setSuperNode(sn);                         // superNodeLoaded=true
setAclData(acl);                           // aclLoaded=true  → DATAREADY
removeSuperNode("sn1");                    // Data deleted, superNodeLoaded = getSuperNode("sn1") != null → false
planPath(req);                             // State check fails → SNCStateException (state rolled back to READY)
```

`updateDataReadyState()` rolls the state back from DATAREADY to READY when `superNodeLoaded` or `aclLoaded` becomes false. After data deletion, **state rolls back**, and subsequent `planPath` calls throw `SNCStateException`.

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

### 3c.7 Incomplete State After setSuperNode

```java
setSuperNode(sn);  // superNodeLoaded = true, aclLoaded = false
// State remains READY
planPath(req);     // SNCStateException
```

Both `setSuperNode` and `setAclData` must be called for the state to transition to DATAREADY.

### 3c.8 init Exception Scenarios

| Scenario | Behavior | Consequence |
|------|------|------|
| `init(null)` | config unused, runs normally | No exception, enters READY normally |
| `init()` called twice consecutively | Second call rebuilds all Store/Engine/Service | First call's data completely lost (no merge), state reset to READY |
| `init()` field state | Creates new instance, resets `superNodeLoaded=false, aclLoaded=false` | Previous state completely cleared |
| `init()` → immediately call other methods | Normal execution, state is READY | Only `planPath` is blocked (requires DATAREADY) |

### 3c.9 uninit Exception Scenarios

| Scenario | Behavior | Consequence |
|------|------|------|
| `uninit()` called before `init()` | Store fields are null, but `uninit` has null checks | Safe no-op, state → UNINIT |
| `uninit()` called twice consecutively | Second call: Store already empty, `clear()` safe with no side effects | State remains UNINIT |
| `uninit()` → call non-init method | `checkNotUninit()` detects UNINIT | Throws `SNCStateException("SNC is in UNINIT state")` |
| `uninit()` → `init()` → normal operations | Rebuilds Store, re-enters READY | Works normally |

### 3c.10 planPath Exception Scenarios

| Scenario | Behavior | Result |
|------|------|------|
| `planPath` in INIT state | `SNCServiceImpl.planPath` has its own state check (not `checkNotUninit`) | `SNCStateException("SNC is not in DATAREADY state, current state: INIT")` |
| `planPath` in READY state | Same | `SNCStateException("SNC is not in DATAREADY state, current state: READY")` |
| `planPath` in UNINIT state | Same | `SNCStateException("SNC is not in DATAREADY state, current state: UNINIT")` |
| `planPath(request)` with srcDevice not in SuperNode | PathService.planPath lookup returns null | `TOPO_INCOMPLETE` |
| `planPath(request)` with destDevice not found | Same | `TOPO_INCOMPLETE` |
| `planPath(request)` with srcDevice/destDevice being a switch (not NPU) | PathService.planPath two-layer check: device exists in swDevices but deviceType ≠ NPU | `SRC_AND_DST_MUST_BE_NPU(3002)` |
| `planPath(request)` with srcPort not on device | NpuDevice.findNpuPort returns null | `SRC_INFO_ERR` |
| `planPath(request)` with destPort not on device | Same | `DST_INFO_ERR` |
| `planPath` with ACL data not in store (cross-name mismatch) | getAclData returns null | `ACL_NOT_FOUND` |
| `planPath` direct connection with mismatched remote ports | PathService validation fails | `TOPO_CONNECTION_ERROR` |
| `planPath` multi-hop with inconsistent intermediate connections | PathEngine.resolveMultiHopPath throws exception | `TOPO_CONNECTION_NOT_FOUND` |
| `planPath` route unreachable (intermediate device LPM miss or no out port) | PathService.routePhase throws `PathPlanException(ROUTE_NOT_REACHABLE)` | `ROUTE_NOT_REACHABLE(1010)` |
| `planPath` direct connection after init reset without reloading topology/ACL | State is READY | `SNCStateException` (does not enter planPath logic) |

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
| `SUCCESS` | 0 | success | Path planning successful |
| `SRC_INFO_ERR` | 1003 | src info error | Source port not found / EID or CNA is null / format error |
| `DST_INFO_ERR` | 1004 | dst info error | Destination port not found / EID or CNA is null / format error |
| `ACL_CHECK_FAILED` | 1005 | acl check failed | Forward or reverse ACL entry missing / CNA mismatch |
| `TOPO_INCOMPLETE` | 1007 | topo incomplete | srcDevice or destDevice not found in SuperNode |
| `TOPO_CONNECTION_ERROR` | 1008 | topo connection error | Direct topology: src and dest port remoteDevice/remotePort mismatch |
| `TOPO_CONNECTION_NOT_FOUND` | 1009 | topo connection not found | Multi-hop topology: inconsistent connection between hops |
| `ROUTE_NOT_REACHABLE` | 1010 | route not reachable | Intermediate device route unreachable |
| `TOPO_NOT_FOUND` | 1012 | topo not found | Requested SuperNode name not found in store |
| `ACL_NOT_FOUND` | 1013 | acl not found | ACL data for requested SuperNode not loaded |
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

---

## 5. Exception Definitions

| Exception Class | Parent Class | Description |
|--------|------|------|
| `SNCException` | `RuntimeException` | Base exception |
| `SNCStateException` | `SNCException` | SNC state error |
| `SuperNodeNotFoundException` | `SNCException` | SuperNode or device not found |
| `AclNotFoundException` | `SNCException` | ACL data not found |
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

### `AclService`

| Method | Parameters | Return Value |
|------|------|--------|
| `importAclData` | `AclData` | `void` |
| `addAclRules` | `String, Map<AclKey, TpAclEntity>` | `void` |
| `removeAclRules` | `String, List<AclKey>` | `void` |
| `getAclData` | `String` | `AclData` |
| `removeAclData` | `String` | `void` |

### `PathService`

| Method | Parameters | Return Value |
|------|------|--------|
| `planPath` | `PathPlanRequest` | `PathPlanResult` |

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
| `AclCheckEngine` | `checkBothDirection` | `AclData, String, String, String, String` | `boolean` |

---

## 8. Store Internal Interfaces

| Store | Methods |
|-------|------|
| `SuperNodeStore` | `init, clear, replace, removeSuperNode, getSuperNode, getRoutingTable, addNpuDevice, addSwDevice, removeDevice, addRoutingEntry, removeRoutingEntry` |
| `AclStore` | `init, clear, replace, removeAclData, getAclData, addAclRule, removeAclRule` |
