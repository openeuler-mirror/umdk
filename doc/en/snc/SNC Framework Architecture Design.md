# SNC (Supernode Network Controller) Design Document

> This document defines the class design for the SNC module, including the domain model, computation model, northbound data structures, northbound interfaces, path planning algorithm, and detailed path planning flow.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Northbound Mechanism](#2-northbound-mechanism)
3. [File Directory Design](#3-file-directory-design)
4. [Data Structure Definitions (Domain Model Entity)](#4-data-structure-definitions)
5. [Pure Internal Data Structures (Computation Model)](#5-pure-internal-data-structures)
6. [Northbound Data Structures (DTO)](#6-northbound-data-structures-dto)
   - [6.1 PathPlanRequest (Path Planning Request)](#61-pathplanrequest-path-planning-request)
   - [6.2 PathPlanResult (Path Planning Response)](#62-pathplanresult-path-planning-response)
   - [6.3 Coverage Planning DTO](#63-coverage-planning-dto)
   - [6.4 Relationship Between Northbound and Internal Data Structures](#64-relationship-between-northbound-and-internal-data-structures)
7. [Northbound Interface](#7-northbound-interface)
   - [7.1 Interface Overview](#71-interface-overview)
   - [7.2 SNCService Interface Definition](#72-sncservice-interface-definition)
   - [7.3 Invocation Sequence](#73-invocation-sequence)
   - [7.4 State Machine](#74-state-machine)
   - [7.5 Error Handling](#75-error-handling)
   - [7.6 Parameter Validation Rules](#76-parameter-validation-rules)
   - [7.7 Interface Implementation Mapping](#77-interface-implementation-mapping)
   - [7.8 Invalid Invocation Order Description](#78-invalid-invocation-order-description)
   - [7.9 SuperNodeStore (Topology Storage)](#79-supernodestore-topology-storage)
8. [Algorithm](#8-algorithm)
   - [8.1 Indexed Mask Match](#81-algorithm-description)
   - [8.2 RouteLookupEngine](#82-engine-interface)
   - [8.3 Coverage Planning Algorithm (CoveragePlanEngine)](#83-coverage-planning-algorithm-coverageplanengine)
   - [8.4 Route Convergence Algorithm (RouteConvergeService)](#84-route-convergence-algorithm-routeconvergeservice)
   - [8.5 Route MSP Calculation and Instantiation Algorithm](#85-route-msp-calculation-and-instantiation-algorithm)
   - [8.6 HashUtils (hash wrapper)](#86-hashutils-hash-wrapper)
   - [8.7 Coverage Planning Key Design Decisions](#87-coverage-planning-key-design-decisions)
9. [Detailed Path Planning Flow](#9-detailed-path-planning-flow)

---

## 1. Overview

### 1.1 Business Background

SNC (Supernode Network Controller) is a super node controller responsible for managing network topology and routing information, and providing path planning, coverage planning, link event route convergence functionality, returning the parameters required for communication path coverage.

### 1.2 Core Functional Requirements

| Functional Module | Description | Priority |
|:----------------:|:-------------------------------|:------:|
| Initialization/Deinitialization | SNC service startup and shutdown | P0 |
| SuperNode Data Management | Network topology structure provisioning, querying, and deletion | P1 |
| Path Planning | Path planning based on EID pairs | P2 |
| Coverage Planning | Given a topology, select a set of EID pairs whose hash route selection traverses and covers the coverage domain out ports; supports L1↔L2 and NPU↔L1↔L2 coverage domains | P2 |
| Link Event Notification | Receive link up/down events, trigger BFS route convergence to refresh OutPortInfo.convergedFlag and RoutingEntry.reachable | P2 |
| Route Template Calculation and Instantiation | Calculate MSP routes based on built-in topology templates and instantiate per SuperNode chassis, for use by getNodeRoute / notifyLinkEvent | P2 |

---

## 2. Northbound Mechanism

### 2.1 Northbound Overview

**Northbound Data Flow:**
```
┌──────────────────────────────────────────────────┐
│         Upper-layer Orchestrator/Management System│ (Northbound caller) │
│   - Topology data entry (including routing info) │             │
│   - Path planning request                       │             │
└──────────────┬───────────────────────────────────┘
               │ API Call
┌──────────────▼──────────────────────────────────┐
│        SNC Module (this module)                  │             │
│   - Data persistence and indexing               │             │
│   - Path planning and path resolution           │             │
└──────────────┬──────────────────────────────────┘
               │ Southbound collection/injection (not developed in current phase)
┌──────────────▼──────────────────────────────────┐
│      Device Layer (NPU/L1SW/L2SW)               │             │
│   - Topology connection relationships           │             │
│   - Routing tables                              │             │
│   - Port information                            │             │
└──────────────────────────────────────────────────┘
```

### 2.2 Interaction Mode

- **Configuration operations (topology provisioning):** Synchronous calls; the caller provides complete data snapshots.
- **Query operations (path planning):** Synchronous calls; request-response mode; the caller sends a PathPlanRequest, SNC returns a PathPlanResult.
- **Coverage Planning:** Synchronous call; request-response mode; the caller sends a CoveragePathsRequest, SNC returns a CoveragePathsResult (including EID pairs, coverage links, coverage rate statistics).
- **Link Event Notification:** Synchronous call; the caller sends a LinkEvent, SNC internally updates port status and triggers BFS route convergence, returns void.
- **Route Calculate/Instantiate/Query:** Synchronous call; `routeCalculate` is idempotent and repeatable; `makeRoutes` generates instantiated routing tables for SuperNode based on already-calculated template routes; `getNodeRoute` queries from instantiation results.
- **Initialization/Deinitialization:** Synchronous calls; SNC loads data from the northbound at startup or receives full synchronization; deinitialization clears in-memory data.

### 2.3 Data Consistency Guarantee

- Topology data (including routing information) is provisioned as full snapshots; SNC does not maintain incremental change logs.
- All data uses in-memory HashMap indexing, ensuring O(1) lookup efficiency.
- Path planning is computed in real-time based on in-memory data, with no dependency on external storage.
- Link events (up/down) update `PortEntity.linkStatus` and `updateAt` in real-time, and refresh `OutPortInfo.convergedFlag` and `RoutingEntry.reachable` through BFS route convergence, ensuring subsequent `getNodeRoute` queries reflect the latest topology state.
- `instantiationRouteMap` (populated by `makeRoutes`) is decoupled from SuperNode topology data; `setSuperNode` full replacement does not affect `instantiationRouteMap`, requires re-calling `makeRoutes` to sync.
- `routeCalculate` is idempotent: if already calculated, returns directly, avoiding repeated template parsing and MSP computation.

### 2.4 Internal Call Chains

#### 2.4.1 planPath Call Chain

```
SNCService.planPath(PathPlanRequest)
└→ PathService.planPath(request)
   ├→ superNode.getNpuDevices().get(srcDevice/destDevice)              // Step 0: NPU device lookup
   ├→ srcNpuDevice.findNpuPort() + destNpuDevice.findNpuPort()         // Step 1~2: Port lookup
   ├→ PathEngine.resolveDirectPath/resolveMultiHopPath(InternalPathInfo) // Step 3~5: Path resolution
   ├→ superNode.getAllDevices() + RouteLookupEngine.lookup()           // Step 6~8: Path planning
   └→ Assemble dto.PathPlanResult                                      // Step 9~10: Output construction
```

#### 2.4.2 planPathsCoverage / planPathsCoverageEx Call Chain

```
SNCService.planPathsCoverage(req) / planPathsCoverageEx(req)
└→ PathService.planPathsCoverage / planPathsCoverageEx(req)
   ├→ SuperNodeStore.get(superNodeName)                                // Topology lookup
   ├→ CoveragePlanEngine.findCoverage / findCoverageEx(superNode, requirement)
   │   ├→ Construct coverage domain OutPortInfo collection (L1↔L2 or NPU↔L1↔L2)
   │   ├→ Enumerate candidate EID pairs (src/dst NPU port combinations)
   │   ├→ For each EID pair trace forward/reverse paths (planPathsCoverageEx calls HashUtils.nativeHashDstCnaJetty)
   │   ├→ Greedily select EID pairs covering missed out ports
   │   └→ Accumulate statistics (coverage rate / redundancy rate / EID uniformity / layer stats)
   └→ Assemble dto.CoveragePathsResult
```

#### 2.4.3 notifyLinkEvent Call Chain

```
SNCService.notifyLinkEvent(superNode, LinkEvent)
└→ LinkEventService.handleLinkEvent(superNode, event)
   ├→ Locate the PortEntity corresponding to deviceName + portName
   ├→ port.setLinkStatus(LINK_UP/LINK_DOWN) + port.setUpdateAt(eventTime)
   ├→ RouteConvergeService.converge(superNode, deviceName, chipIndex, portName, isDown)
   │   ├→ Iterate chip routing table, locate RoutingEntry containing this port
   │   ├→ OutPortInfo.setFlag(FLAG_PASSIVE_CONVERRGED) [down] / clearFlag(FLAG_PASSIVE_CONVERRGED) [up]
   │   ├→ RoutingEntry.refreshReachable() → record prefixes with reachable changes
   │   └→ BFS propagation: locate peer forwarding node via PortEntity.remoteDevice/remotePort
   │       └→ Query changed prefixes in remote chip routing table → refresh OutPortInfo.convergedFlag for the in-interface → refreshReachable
   └→ (No return value; convergence results stored in instantiationRouteMap)
```

#### 2.4.4 routeCalculate / makeRoutes / getNodeRoute Call Chain

```
SNCService.routeCalculate()
└→ synchronized { if already calculated, return directly }
   ├→ TopoTemplateService.parseTemplateFile("128_npu_rack.json")
   ├→ TopoTemplateService.parseTemplateFile("128_npu_inter_rack.json")
   ├→ RouteMspService.routeMsp(topoTemplate)                  // BFS shortest path + path policy
   └→ routes = RouteInstantiationService.buildXpodRoutes(template) // Template routing table (not instantiated)

SNCService.makeRoutes(superNode)
└→ RouteInstantiationService.instantiateXpodRoute(routes, superNode)
   ├→ Iterate NPU devices: match template by chassis/slot/ubpu/die labels
   ├→ Iterate L1SW devices: match template by chassis/index labels
   ├→ Iterate L2SW devices: match template by index/chip labels (4-chassis instantiation remaps ports)
   ├→ deepCopyRoutingEntry(...)                                // Deep copy to avoid external modification affecting internal
   └→ instantiationRouteMap.put("deviceName#chipIndex", routingEntryMap)
       Return a copy of instantiationRouteMap

SNCService.getNodeRoute(deviceName, chipIndex)
└→ instantiationRouteMap.get("deviceName#chipIndex")          // Direct HashMap lookup
```

---

## 3. File Directory Design

### 3.1 Design Principles

A **DDD layered package structure** is adopted, separating the domain model (§4), computation model (§5), and API contract DTOs (§6) into independent packages, preventing northbound callers from directly depending on the internal domain model while ensuring precise correspondence of field semantics.

### 3.2 Package Structure Overview

```
com.huawei.umdk.snc
├── SNCService.java                    # Northbound interface definition (§7.2)
├── SNCServiceImpl.java                # Northbound interface implementation (delegation entry point)
│
├── config/
│   └── SNCConfig.java                 # SNC configuration (logging strategy, indexing strategy, etc.)
│
├── entity/                            # §4 Domain Model + §5 Internal Computation Model
│   ├── SuperNode.java                  # Topology data top-level container (§4.1) with npuDevices + swDevices + getAllDevices()
│   ├── DeviceEntity.java              # Device abstract base class (with getForwardingChips() abstract method)
│   ├── MgmtInfo.java                  # Management information (ip, port, user, password)
│   ├── NpuDevice.java                 # NPU device (with forwardingChips precise type + findNpuPort())
│   ├── SwDevice.java                  # Switch device (with forwardingChips precise type)
│   ├── DeviceType.java                # Device type enum (NPU/SW)
│   ├── SwitchLevel.java               # Switch level enum (L1/L2)
│   ├── ForwardingChip.java            # Forwarding chip abstract base class (with getPorts() abstract method)
│   ├── NpuForwardingChip.java         # NPU forwarding chip (with ports precise type + getNpuPorts())
│   ├── SwForwardingChip.java          # Switch forwarding chip (with ports precise type + getSwPorts())
│   ├── PortEntity.java                # Port abstract base class (with linkStatus, updateAt fields, for LinkEventService to update)
│   ├── NpuPortEntity.java             # NPU port (§4.5.1, with jettyId field for planPathsCoverageEx)
│   ├── SwPortEntity.java              # Switch port (§4.5.2)
│   ├── LogicPortEntity.java           # Logical port (§4.6)
│   ├── LinkEvent.java                 # Link event (deviceName + portName + eventType + eventTime, for notifyLinkEvent)
│   ├── RoutingTable.java              # Routing table (§4.7)
│   ├── RoutingEntry.java              # Routing entry (§4.9, with reachable status, for route convergence refreshReachable)
│   ├── RoutePrefix.java               # Route prefix structure (§4.8)
│   ├── RoutingTableKey.java           # Routing table composite key (superNodeName + deviceName + chipIndex, §4.7.1)
│   ├── OutPortInfo.java               # Out port information (§4.9.1, with convergedFlag bit: down=set PASSIVE, up=clear PASSIVE)
│   ├── InternalPathInfo.java          # §5.1 Internal path information (engine computation context)
│   ├── InternalPathHop.java           # §5.1 Internal path hop
│   └── RouteSelectionRecord.java      # §5.2 Internal route selection record
│
├── dto/                               # §6 Northbound API DTO (decoupled from domain model)
│   ├── PathPlanRequest.java           # Path planning request (§6.1)
│   ├── PathPlanResult.java            # Path planning response + PlanStatus enum (§6.2)
│   ├── PathInfo.java                  # Path information (§6.2.1)
│   ├── HopInfo.java                   # Hop information (§6.2.2)
│   ├── CoveragePathsRequest.java      # Coverage planning request (superNodeName + coverageRequirement, reused by planPathsCoverage/Ex)
│   ├── CoveragePathsResult.java       # Coverage planning response (with scope, layerStats layer statistics)
│   ├── CoverageStats.java             # Coverage summary statistics (with EID uniformity field)
│   ├── CoverageLayerStats.java        # Layer statistics (NPU_L1 / L1_L2 each one)
│   ├── CoverageLink.java              # Coverage link (with deviceType, layer fields)
│   ├── CoverageLinkScope.java         # Coverage domain enum (L1_L2 / NPU_L1_L2)
│   ├── CoverageLinkLayer.java         # Link layer enum (NPU_L1 / L1_L2)
│   ├── CoveragePathType.java          # Path type enum (CROSS_L2 / LOCAL_L1)
│   ├── CoverageRequirement.java      # Coverage requirement enum (MIN_COVERAGE / REDUNDANT)
│   ├── CoveredEidPair.java            # Covered EID pair (with type field)
│   └── CoveredEidPairRef.java         # EID pair reference (srcEid + dstEid)
│
├── service/                           # Business logic layer (orchestration)
│   ├── SuperNodeService.java               # Topology data management
│   ├── PathService.java               # Path planning orchestration + coverage planning orchestration (planPath / planPathsCoverage / planPathsCoverageEx)
│   └── LinkEventService.java          # Link event processing (updates port.linkStatus/updateAt)
│
├── route/                             # Route calculation and convergence submodule (orchestrated by SncService)
│   ├── model/                         # Route model
│   │   ├── RouteTable.java            #   Template routing table (Prefix → RouteEntry)
│   │   ├── RouteEntry.java            #   Template route entry (with NhpSet + shortest/secondShortest/other classification)
│   │   ├── Inbound.java               #   Inbound interface (inPortId + parentNodeId + cost + outIfSet)
│   │   ├── NextHopPort.java           #   Next hop port (outPortId + outPortName + cost + pathType)
│   │   └── OriginNode.java            #   MSP search node (layer + inboundMap)
│   ├── service/                       # Route services
│   │   ├── RouteMspService.java       #   Template route MSP computation (BFS shortest path + path policy)
│   │   ├── RouteInstantiationService.java # Template route instantiation (chassis extension + NPU/L1SW/L2SW dispatch + buildRouteTableKey + deepCopyRoutingEntry)
│   │   └── RouteConvergeService.java  #   Route convergence (BFS propagates reachable changes between interconnected forwarding nodes)
│   └── topo/                          # Topology template
│       └── template/
│           ├── model/                 # Template model (SncTopology, SncNode, SncPort, Label, Address, Prefix, Bitmap, PolicyPath, PolicyPrefix, AddrType)
│           ├── loader/                # Template loaders (TemplateLoader, NodeLoader, PortLoader, PrefixLoader, PolicyLoader, PathPolicyLoader, LogicalPortLoader, PermitOrDenyPolicy, PrefixPolicyLoader, PortFwdPolicyLoader, PathPolicyItemsLoader, Deserializers)
│           └── service/               # Template service (TopoTemplateService.parseTemplateFile)
│
├── store/                             # Data storage layer (HashMap indexing)
│   └── SuperNodeStore.java               # Topology index (superNodeName→SuperNode / routingTableMap)
│
├── engine/                            # Algorithm engine layer
│   ├── PathEngine.java                # Path resolution engine (Step 3~5)
│   ├── RouteLookupEngine.java         # Path planning engine / Indexed Mask Match (Step 6~8, §8)
│   └── CoveragePlanEngine.java        # Coverage planning engine (findCoverage / findCoverageEx + two-stage coverage + layer stats + getExDiagnostics)
│
├── exception/                         # Exception definitions (§7.5.2)
│   ├── SNCException.java              # Base exception
│   ├── SNCStateException.java         # State exception
│   ├── SuperNodeNotFoundException.java     # Topology data not found
│   └── PathPlanException.java         # Path planning failure (contains PlanStatus)
│
└── util/                              # Utility classes
    ├── AddressUtils.java              # CNA mask calculation, address format validation
    ├── HashUtils.java                 # hash wrapper (nativeHash + nativeHashDstCnaJetty + JETTY_ID_MIN/MAX + isValidJettyId)
    ├── UbSwitchHash.java              # Pure Java hash fallback (corresponds 1:1 to the two C files logic)
    └── DllLoader.java                 # JNA native library search and loading (jar sibling directory, classpath extraction, etc.)
```

### 3.3 Dependency Relationships

```
                    ┌──────────┐
                    │   dto    │ (§6 Northbound API DTO, no internal dependencies, pure data structures)
                    └────▲─────┘
                         │uses
                    ┌────┴─────┐
                    │ service  │ (Orchestration layer: SuperNodeService / PathService / LinkEventService)
                    └─┬──┬──┬─┘
                      │  │  │
            ┌─────────┘  │  └─────────┘
            │            │            │
       ┌────────┐  ┌─────────┐  ┌────────┐
       │ store  │  │ engine  │  │ entity │
       │(index) │  │(algo)   │  │(model) │
       └───┬────┘  └────┬────┘  └────────┘
           │            │
           │     ┌──────┴───────┐
           │     │              │
           │  ┌──┴─────┐  ┌─────┴──────┐
           │  │ route  │  │   util     │
           │  │(template/│  │(HashUtils │
           │  │converge)│  │/AddressUtils)│
           │  └──┬─────┘  └────────────┘
           │     │
           └─────┴──────┘
                 │query/write
           ┌────────┐
           │ entity │ (§4 Domain Model + §5 Computation Model, shared dependency of store/engine/service/route)
           └────────┘
```

| Layer | Can Depend On | Cannot Depend On | Description |
|:---|:-------|:--------|:-----|
| `dto` | - | entity / service / store / engine / route / util | API contract layer, independent of internal implementation |
| `entity` | util | dto / service / store / engine / route | Pure data structure layer |
| `store` | entity / util | dto / service / engine / route | Index storage, directly operates on domain model |
| `engine` | entity / util | dto / service / store / route | Algorithm engine, reads entity and outputs §5 computation model |
| `route` | entity / util | dto / service / store / engine | Route MSP computation, instantiation, convergence, template parsing |
| `service` | entity / dto / store / engine / route / util | - | Orchestration layer, completes DTO-to-domain-model mapping |
| `exception` | dto.PathPlanResult.PlanStatus | - | Exceptions can reference error code enum (PlanStatus defined inside §6.2 PathPlanResult) |
| `util` | - | entity / dto / service / store / engine / route | Pure utility classes (HashUtils, UbSwitchHash, DllLoader, AddressUtils) |

### 3.4 Interface Layer to Internal Layer Conversion Mapping

`SNCServiceImpl` is located at the package root, responsible for connecting `dto` with internal `entity`/`service`.

```
SNCServiceImpl
    │
    ├── init(SNCConfig)
    │     └→ SuperNodeStore.init()
    │     └→ Only operates on config and store, does not involve dto
    │
    ├── setSuperNode(SuperNode)          // entity.SuperNode (§4.1 Domain Model)
    │     └→ SuperNodeService.importSuperNode(superNode)
    │              └→ SuperNodeStore.replace(superNode)
    │
    ├── planPath(PathPlanRequest)      // dto.PathPlanRequest (§6.1 DTO)
    │     └→ PathService.planPath(request)
    │              ├→ superNode.getNpuDevices().get(srcDevice/destDevice)  // Step 0: NPU device lookup
    │              ├→ srcNpuDevice.findNpuPort() + destNpuDevice.findNpuPort() // Step 1~2: Port lookup (directly uses NpuForwardingChip.getNpuPorts(), no instanceof/cast)
    │              ├→ PathEngine.resolveDirectPath/resolveMultiHopPath(→ InternalPathInfo) // Step 3~5: Path resolution
    │              │    Signature: (NpuDevice, NpuPortEntity, NpuDevice, NpuPortEntity, ...)
    │              ├→ superNode.getAllDevices() + RouteLookupEngine.lookup() // Step 6~8: Path planning
    │              └→ Assemble dto.PathPlanResult                       // Step 9~10: Output construction (§6.2 DTO)
    │
    └── uninit()
            └→ SuperNodeStore.clear()
```

> `setSuperNode` input parameter directly uses `entity.SuperNode` (domain model) because it originates from JSON deserialization of the raw structure and corresponds 1:1 to topology files, requiring no additional DTO wrapping. `planPath` input/output uses `dto.PathPlanRequest` / `dto.PathPlanResult` because they are oriented toward northbound callers and require stable API contracts.

---

## 4. Data Structure Definitions

> **Lombok Note:** All getter/setter, equals/hashCode, toString methods in the Java code throughout this chapter are automatically generated by Lombok annotations (`@Getter`, `@Setter`, `@NoArgsConstructor`, `@EqualsAndHashCode`, `@ToString`) and are not hand-written. The code listings only retain field declarations, custom constructors, and overridden methods. **Note:** Abstract classes `DeviceEntity` (§4.3) and `ForwardingChip` (§4.4) no longer use `@AllArgsConstructor` (replaced with custom protected constructors), and their subclasses `NpuDevice`, `SwDevice`, `NpuForwardingChip`, `SwForwardingChip` also no longer use `@AllArgsConstructor` (replaced with custom public constructors). The Lombok dependency has been added to `pom.xml` (scope=provided) and is compiled via the `maven-compiler-plugin` annotation processor.

---

### 4.1 SuperNode (Topology Data — Top-Level Structure)

```java
public class SuperNode {
    /** Super node name, e.g. "A5-superPod-1" -- Required field */
    private String name;

    /** Topology data version number, e.g. "1.0" -- Required field */
    private String version;

    /** NPU device Map -- key is deviceName (device unique identifier), value is NpuDevice */
    private Map<String, NpuDevice> npuDevices;

    /** SW device Map -- key is deviceName (device unique identifier), value is SwDevice */
    private Map<String, SwDevice> swDevices;

    /**
     * Returns an unmodifiable view of npuDevices
     */
    public Map<String, NpuDevice> getNpuDevices() {
        return npuDevices == null ? null : Collections.unmodifiableMap(npuDevices);
    }

    /**
     * Returns an unmodifiable view of swDevices
     */
    public Map<String, SwDevice> getSwDevices() {
        return swDevices == null ? null : Collections.unmodifiableMap(swDevices);
    }

    /**
     * Merges npuDevices and swDevices into a unified DeviceEntity view
     * Used for internal unified lookup (e.g., PathService.routePhase traversing all devices)
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

| Field | Type | Description |
|:-----|:-----|:-----|
| name | String | Super node name, e.g. "A5-superPod-1" -- Required field |
| version | String | Topology data version number, e.g. "1.0" -- Required field |
| npuDevices | Map\<String, NpuDevice\> | NPU device Map, key is deviceName, value is NpuDevice |
| swDevices | Map\<String, SwDevice\> | SW device Map, key is deviceName, value is SwDevice |

**Corresponding JSON Example:**
```json
{
    "name": "A5-superPod-1",
    "version": "1.0",
    "devices": { ... }
}
```

**Key Notes:**
- `SuperNode` is the top-level data structure deserialized from `superNode_data_*.json` files. One `superNode_data_*.json` file corresponds to one super node (e.g., "A5-superPod-1").
- The `name` field also serves as the key in `SuperNodeStore`'s `Map<String, SuperNode>` (see §7.9); externally, topology data for multiple super nodes can be provisioned, each stored and distinguished by `name` (superNodeName).
- `devices` in the JSON remains a single Map (key=deviceName), which the deserializer splits into `npuDevices` and `swDevices` based on the `deviceType` field.
- `getAllDevices()` merges both Maps to provide a unified `Map<String, DeviceEntity>` view for internal traversal lookups (e.g., device queries during path planning).

---

### 4.2 MgmtInfo (Management Information)

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class MgmtInfo {
    /** Management IP address -- Required field */
    private String ip;

    /** Management port number -- Required field */
    private Integer port;

    /** Management username -- Required field */
    private String username;

    /** Management password -- Required field */
    private String password;
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| ip | String | Management IP address -- Required field |
| port | Integer | Management port number, e.g. 8443 -- Required field |
| username | String | Management username -- Required field |
| password | String | Management password -- Required field |

**Corresponding JSON Example:**
```json
"mgmtInfo": {
    "ip": "198.168.0.1",
    "port": 8443,
    "username": "admin",
    "password": "xxx"
}
```

**Notes:**
- `MgmtInfo` stores remote management connection information for devices; all device types (NPU, SW) include this information.
- In JSON, NPU devices use `"userName"` (camelCase), while SW devices use `"username"` (all lowercase). `MgmtInfo` uniformly uses the `username` field for deserialization, requiring compatibility with both naming conventions during JSON deserialization (e.g., configuring `@JsonAlias("userName")`).

---

### 4.3 DeviceEntity (Device Entity — Abstract Class)

```java
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EqualsAndHashCode
@ToString
public abstract class DeviceEntity {
    /** Device unique identifier, format: rack#os#npu or rack#l1sw0 or lc#0 -- Required field */
    private String deviceName;

    /** Device type -- Required field */
    private DeviceType deviceType;

    /** Device management information -- Required field */
    private MgmtInfo mgmtInfo;

    /** Belonging Rack */
    private String rack;

    /** Abstract method: Get forwarding chip Map (for polymorphic iteration), returns wildcard type Map<Integer, ? extends ForwardingChip>.
     *  <p>Each subclass holds a precisely-typed forwardingChips field (NpuDevice→Map<Integer, NpuForwardingChip>,
     *  SwDevice→Map<Integer, SwForwardingChip>), providing a unified traversal view through this abstract method,
     *  for cross-type polymorphic iteration by PathEngine/SuperNodeStore/PathService etc.
     *  <p>Subclasses also provide type-specific getters (e.g., getNpuForwardingChips/getSwForwardingChips),
     *  returning unmodifiable views of the precise type, eliminating instanceof/cast. */
    public abstract Map<Integer, ? extends ForwardingChip> getForwardingChips();

    /** All-args constructor (excluding forwardingChips, which is held by each subclass) */
    protected DeviceEntity(String deviceName, DeviceType deviceType, MgmtInfo mgmtInfo, String rack) {
        this.deviceName = deviceName;
        this.deviceType = deviceType;
        this.mgmtInfo = mgmtInfo;
        this.rack = rack;
    }
}
```

**Field Source Mapping Table:**

| Class Design Field | JSON Field | Device Type | Description |
|:-----------|:----------|:---------|:-----|
| deviceName | deviceName | NPU & SW | Device unique identifier |
| deviceType | deviceType | NPU & SW | Device type, inferred during deserialization |
| mgmtInfo | mgmtInfo | NPU & SW | Management information (§4.2) |
| rack | rack | NPU & SW | Belonging chassis |

**Abstract Method Description:**

| Method | Return Type | Description |
|:-----|:---------|:-----|
| getForwardingChips() | Map\<Integer, ? extends ForwardingChip\> | Abstract method for polymorphic iteration; subclass implementations return their precisely-typed forwardingChips field |

**Key Notes:**
- `getForwardingChips()`: Abstract method returning `Map<Integer, ? extends ForwardingChip>` wildcard type. PathEngine, SuperNodeStore, PathService, etc. access forwarding chips uniformly through this method when traversing across device types, without instanceof/cast.
- Each subclass holds a precisely-typed `forwardingChips` field (NpuDevice→`Map<Integer, NpuForwardingChip>`, SwDevice→`Map<Integer, SwForwardingChip>`), and provides type-specific getters (`getNpuForwardingChips`/`getSwForwardingChips`) returning unmodifiable views of the precise type, eliminating instanceof/cast.
- `DeviceEntity` is an abstract class; concrete device types are derived as `NpuDevice`, `SwDevice`.

#### 4.3.1 Device Type Enum

```java
public enum DeviceType {
    NPU,   // NPU device
    SW     // Switch device (L1SW or L2SW, distinguished by SwitchLevel)
}
```

Device Type Description:

| Type | Description | Typical Scenario | Derived Class |
|:-----|:---------|:-------------------|:---------------|
| NPU  | Compute node | AI training/inference node | NpuDevice |
| SW   | Switch device | L1SW intra-rack switching / L2SW inter-rack switching | SwDevice |

**SwitchLevel (Switch Level Enum):**

```java
public enum SwitchLevel {
    L1,   // L1SW — Intra-rack switching
    L2    // L2SW — Inter-rack switching
}
```

#### 4.3.2 NpuDevice (NPU Device)

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class NpuDevice extends DeviceEntity {
    /** OS name -- only for NPU devices, e.g. "os0" */
    private String osName;

    /** OS IP address -- only for NPU devices, e.g. "172.168.0.1" */
    private String osIp;

    /** Board ID -- only for NPU devices */
    private Integer boardId;

    /** Module ID -- only for NPU devices */
    private Integer moduleId;

    /** Board index (position number in chassis) -- only for NPU devices */
    private Integer boardIndex;

    /** Forwarding chip list -- precise type, Map key is chipIndex (chip number) */
    private Map<Integer, NpuForwardingChip> forwardingChips;

    @Override
    public DeviceType getDeviceType() {
        return DeviceType.NPU;
    }

    @Override
    public Map<Integer, ? extends ForwardingChip> getForwardingChips() {
        return forwardingChips;
    }

    /** Type-specific forwarding chip getter -- returns unmodifiable precise type view, eliminating instanceof/cast */
    public Map<Integer, NpuForwardingChip> getNpuForwardingChips() {
        return forwardingChips == null ? null : Collections.unmodifiableMap(forwardingChips);
    }

    /**
     * All-args constructor
     * <p>First calls super(deviceName, DeviceType.NPU, mgmtInfo, rack) to initialize base class fields,
     * then sets NPU-specific fields and forwardingChips.
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
     * Find NPU port -- directly uses forwardingChips (NpuForwardingChip precise type)
     * <p>No need for instanceof NpuPortEntity + cast; directly gets NpuPortEntity via getNpuPorts().
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

| Field | JSON Field | Description |
|:-----|:---------|:-----|
| osName | osName | OS name, e.g. `"os0"` |
| osIp | osIp | OS IP address, e.g. `"172.168.0.1"` |
| boardId | boardId | Board ID |
| moduleId | moduleId | Module ID (the former `osZone` and `moduleidx` fields are deprecated, replaced by the `boardId` + `moduleId` combination) |
| boardIndex | boardIndex | Board index (position number in chassis) |
| forwardingChips | forwardingChip | NPU forwarding chips, precise type `Map<Integer, NpuForwardingChip>`. JSON is a single object, converted to Map after deserialization |

**Method Description:**

| Method | Return Type | Description |
|:-----|:---------|:-----|
| getForwardingChips() | Map\<Integer, ? extends ForwardingChip\> | Overrides abstract method, returns forwardingChips (satisfies polymorphic iteration contract) |
| getNpuForwardingChips() | Map\<Integer, NpuForwardingChip\> | Type-specific getter, returns unmodifiable precise type view |
| findNpuPort(String) | NpuPortEntity | Simplified implementation: directly uses forwardingChips to iterate NpuForwardingChip, calls chip.getNpuPorts().get(portName), no instanceof/cast needed |

#### 4.3.3 SwDevice (Switch Device)

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class SwDevice extends DeviceEntity {
    /** Switch level -- L1 (intra-rack switching) or L2 (inter-rack switching) */
    private SwitchLevel switchLevel;

    /** Switch index in Rack (sequence number) -- only for SW devices */
    private Integer index;

    /** Forwarding chip list -- precise type, Map key is chipIndex (chip number) */
    private Map<Integer, SwForwardingChip> forwardingChips;

    @Override
    public DeviceType getDeviceType() {
        return DeviceType.SW;
    }

    @Override
    public Map<Integer, ? extends ForwardingChip> getForwardingChips() {
        return forwardingChips;
    }

    /** Type-specific forwarding chip getter -- returns unmodifiable precise type view, eliminating instanceof/cast */
    public Map<Integer, SwForwardingChip> getSwForwardingChips() {
        return forwardingChips == null ? null : Collections.unmodifiableMap(forwardingChips);
    }

    /**
     * All-args constructor
     * <p>First calls super(deviceName, DeviceType.SW, mgmtInfo, rack) to initialize base class fields,
     * then sets SW-specific fields and forwardingChips.
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

| Field | JSON Field | Description |
|:-----|:---------|:-----|
| switchLevel | level | Switch level, L1=intra-rack switching / L2=inter-rack switching |
| index | index | Switch index in Rack (sequence number) |
| forwardingChips | forwardingChip | SW forwarding chips, precise type `Map<Integer, SwForwardingChip>`. JSON is a single object, converted to Map after deserialization |

**Method Description:**

| Method | Return Type | Description |
|:-----|:---------|:-----|
| getForwardingChips() | Map\<Integer, ? extends ForwardingChip\> | Overrides abstract method, returns forwardingChips (satisfies polymorphic iteration contract) |
| getSwForwardingChips() | Map\<Integer, SwForwardingChip\> | Type-specific getter, returns unmodifiable precise type view |

---

### 4.4 ForwardingChip (Forwarding Chip — Abstract Class)

```java
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EqualsAndHashCode
@ToString
public abstract class ForwardingChip {
    /** Chip index, unique within device -- Required field */
    private Integer chipIndex;

    /** Routing table -- extracted and populated by SuperNodeStore.replace() during indexing from top-level JSON; ForwardingChip itself is not responsible for deserializing this field */
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    private RoutingTable routingTable;

    /** Abstract method: Get port Map (for polymorphic iteration), returns wildcard type Map<String, ? extends PortEntity>.
     *  <p>Each subclass holds a precisely-typed ports field (NpuForwardingChip→Map<String, NpuPortEntity>,
     *  SwForwardingChip→Map<String, SwPortEntity>), providing a unified traversal view through this abstract method,
     *  for cross-type polymorphic iteration by PathEngine/SuperNodeStore/PathService etc.
     *  <p>Subclasses also provide type-specific getters (e.g., getNpuPorts/getSwPorts),
     *  returning unmodifiable views of the precise type, eliminating instanceof/cast. */
    public abstract Map<String, ? extends PortEntity> getPorts();

    /** Minimal constructor: only chipIndex (no ports, no routing table), used by subclasses NpuForwardingChip/SwForwardingChip */
    protected ForwardingChip(Integer chipIndex) {
        this.chipIndex = chipIndex;
    }
}
```

**Key Notes:**
- `ForwardingChip`: Uses `chipIndex` as the key for O(1) lookup in each subclass's `forwardingChips` Map.
- `getPorts()`: Abstract method returning `Map<String, ? extends PortEntity>` wildcard type. PathEngine, SuperNodeStore, PathService, etc. access ports uniformly through this method when traversing across chip types, without instanceof/cast.
- Each subclass holds a precisely-typed `ports` field (NpuForwardingChip→`Map<String, NpuPortEntity>`, SwForwardingChip→`Map<String, SwPortEntity>`), and provides type-specific getters (`getNpuPorts`/`getSwPorts`) returning unmodifiable views of the precise type, eliminating instanceof/cast.
- `ForwardingChip` is an abstract class; concrete chip types are derived as `NpuForwardingChip`, `SwForwardingChip`.
- `routingTable`: Extracted and injected by SuperNodeStore during indexing from the device-level input JSON; the ForwardingChip class definition holds this reference for traversal access, but the actual storage of routingTable uses the RoutingTableKey→RoutingTable global index (see §7.9).

#### 4.4.1 NpuForwardingChip (NPU Forwarding Chip)

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class NpuForwardingChip extends ForwardingChip {
    /** Port Map -- precise type, Map key is portName, supports O(1) lookup and traversal */
    private Map<String, NpuPortEntity> ports;

    /** Logical port Map (aggregated ports) -- only for NPU chips, key is portName, supports O(1) lookup */
    private Map<String, LogicPortEntity> logicPorts;

    /** Minimal constructor: only chipIndex */
    public NpuForwardingChip(Integer chipIndex) {
        super(chipIndex);
    }

    /** Chip + ports constructor */
    public NpuForwardingChip(Integer chipIndex, Map<String, NpuPortEntity> ports) {
        super(chipIndex);
        this.ports = ports;
    }

    @Override
    public Map<String, ? extends PortEntity> getPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }

    /** Type-specific port getter -- returns unmodifiable precise type view, eliminating instanceof/cast */
    public Map<String, NpuPortEntity> getNpuPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }
}
```

**Notes:**
- `ports`: Precise type `Map<String, NpuPortEntity>`, Map key is `portName` (port name), supports O(1) lookup and traversal.
- `getNpuPorts()`: Type-specific getter, returns an unmodifiable `Map<String, NpuPortEntity>` view. NpuDevice.findNpuPort() directly calls `chip.getNpuPorts().get(portName)`, without instanceof NpuPortEntity + cast.
- `getPorts()`: Overrides abstract method, returns `Map<String, ? extends PortEntity>` wildcard type, for cross-chip-type polymorphic iteration.
- `logicPorts`: Map key is `portName` (logical port name), supports O(1) lookup, consistent with other Map structures.
- NPU forwarding chips uniquely have logical ports; switch forwarding chips do not have logical ports.

#### 4.4.2 SwForwardingChip (Switch Forwarding Chip)

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class SwForwardingChip extends ForwardingChip {
    /** Port Map -- precise type, Map key is portName, supports O(1) lookup and traversal */
    private Map<String, SwPortEntity> ports;

    /** Minimal constructor: only chipIndex */
    public SwForwardingChip(Integer chipIndex) {
        super(chipIndex);
    }

    /** Chip + ports constructor */
    public SwForwardingChip(Integer chipIndex, Map<String, SwPortEntity> ports) {
        super(chipIndex);
        this.ports = ports;
    }

    @Override
    public Map<String, ? extends PortEntity> getPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }

    /** Type-specific port getter -- returns unmodifiable precise type view, eliminating instanceof/cast */
    public Map<String, SwPortEntity> getSwPorts() {
        return ports == null ? null : Collections.unmodifiableMap(ports);
    }
}
```

**Notes:**
- `ports`: Precise type `Map<String, SwPortEntity>`, Map key is `portName` (port name), supports O(1) lookup and traversal.
- `getSwPorts()`: Type-specific getter, returns an unmodifiable `Map<String, SwPortEntity>` view, eliminating instanceof/cast.
- `getPorts()`: Overrides abstract method, returns `Map<String, ? extends PortEntity>` wildcard type, for cross-chip-type polymorphic iteration.

**General Notes:**
- Each device can have one or more forwarding chips, each independently managing its own ports.
- `chipIndex` is unique within the device, identifying the chip number.
- Routing table data is independent of superNode, located via the composite key `superNodeName + deviceName + chipIndex` (see RoutingTableKey §4.7.1).

---

### 4.5 PortEntity (Port Entity — Abstract Class)

```java
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EqualsAndHashCode
@ToString
public abstract class PortEntity {
    /** Port name, e.g. "400GE 0/0/1" -- Required field */
    private String portName;

    /** Port ID */
    private Integer id;

    /** Belonging chip index */
    private Integer chipIndex;

    /** Connected device -- Required field */
    private String remoteDevice;

    /** Connected port -- Required field */
    private String remotePort;

    /** Associated CNA -- 32 bit (IP format) -- Required field */
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

**Field Constraints:**
- `cna`: 32-bit CNA address, string format (e.g., "0.1.2.3"). **NPU port cna is required; switch device (SW) port cna is optional and can be null** (see §4.5.2).
- `remoteDevice` / `remotePort`: Describe the physical connection's peer device and port, used for path resolution.
- `PortEntity` is an abstract class; concrete port types are derived as `NpuPortEntity`, `SwPortEntity`. Ports are stored in each subclass forwarding chip's precisely-typed `ports` field (NpuForwardingChip.ports is `Map<String, NpuPortEntity>`, SwForwardingChip.ports is `Map<String, SwPortEntity>`), accessed via the `getPorts()` abstract method for unified polymorphic access (§4.4).

#### 4.5.1 NpuPortEntity (NPU Port)

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class NpuPortEntity extends PortEntity {
    /** Associated EID -- 128 bit -- only for NPU ports */
    private String eid;

    /** UPI -- 32 bit -- Required field */
    private String upi;

    /** jettyId -- the jettyId field of the (DstCNA, jettyId) tuple used by NPU→L1SW route selection hash;
     *  value range [32, 1023], one per NPU physical port; used by planPathsCoverageEx
     *  (§4.5.1.a jettyId). When missing or out of range, CoveragePlanEngine.jettyIdOf falls back
     *  to HashUtils.JETTY_ID_MIN + portId (= 32 + portId) and increments the exJettyFallback diagnostic counter */
    private Integer jettyId;

    public NpuPortEntity(String portName, Integer id, Integer chipIndex,
                         String remoteDevice, String remotePort, String cna,
                         String eid, String upi) {
        super(portName, id, chipIndex, remoteDevice, remotePort, cna);
        this.eid = eid;
        this.upi = upi;
    }

    /** Extended constructor with jettyId (for planPathsCoverageEx) */
    public NpuPortEntity(String portName, Integer id, Integer chipIndex,
                         String remoteDevice, String remotePort, String cna,
                         String eid, String upi, Integer jettyId) {
        super(portName, id, chipIndex, remoteDevice, remotePort, cna);
        this.eid = eid;
        this.upi = upi;
        this.jettyId = jettyId;
    }
}
```

**Field Constraints:**
- `eid`: 128-bit EID identifier, string format. Only NPU ports carry EID information.
- `upi`: UPI identifier, only carried by NPU ports, used for source/destination UPI consistency validation (`planPath` §9 Step 0).
- `jettyId`: Physical port identifier for NPU→L1SW route selection hash, value range **`[32, 1023]`** (`HashUtils.JETTY_ID_MIN = 32`, `HashUtils.JETTY_ID_MAX = 1023`), one per NPU physical port. Only used by `planPathsCoverageEx` (as the jettyId field of the `(DstCNA, jettyId)` tuple, see §8 Path Planning Algorithm); not used by `planPath` or `planPathsCoverage`. When topology input is missing or out of range, `CoveragePlanEngine.jettyIdOf` falls back to `32 + portId` and increments the `exJettyFallback` diagnostic counter.
- NpuPortEntity is stored in `NpuForwardingChip.ports` (`Map<String, NpuPortEntity>`, §4.4.1), accessed directly via `getNpuPorts()` for the precise type, without instanceof/cast.

##### 4.5.1.a jettyId Value Rules (planPathsCoverageEx)

| Item | Description |
|:---|:---|
| Value range | `[32, 1023]`, defined by `HashUtils.JETTY_ID_MIN` / `HashUtils.JETTY_ID_MAX`; out-of-range validated by `HashUtils.isValidJettyId`, throws `IllegalArgumentException` |
| Topo input field | Super node JSON `jettyId` (parsed by `TestDataLoader`); template JSON `jetty_id` (`128_npu_rack.json`, carried by `PortLoader`/`SncPort`); `FullRackTopologyGenerator` uses fixed allocation `JETTY_ID_BASE + portIndex` (32..39, fully consistent each generation, pinned by `FullRackTopologyJettyIdTest`) |
| Missing fallback | When jettyId is null or out of range, `CoveragePlanEngine.jettyIdOf(port)` falls back to `HashUtils.JETTY_ID_MIN + (port.id == null ? 0 : port.id)`, and increments diagnostic counter `exJettyFallback`, ensuring old topology input (without jettyId) can still complete route selection |
| Hash usage | `HashUtils.nativeHashDstCnaJetty(dstCna, jettyId, ecmpCnt, hashFunc)` calls native library `ubswitch_Hash_dieEcmp` (CRC-8/ATM), see §8 Path Planning Algorithm |
| ACK direction | ACK direction NPU port selection still uses the **source NPU port's jettyId** (same jettyId as forward), and DstCNA is the source CNA |

#### 4.5.2 SwPortEntity (Switch Port)

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

**Field Constraints:**
- Switch device ports have no CNA/EID/UPI concept; the `cna` field in switch port scenarios is **optional** (can be null) and does not participate in CNA matching in path planning.
- `remoteDevice` / `remotePort` are core fields for switch ports, used for multi-hop topology path resolution.
- SwPortEntity is stored in `SwForwardingChip.ports` (`Map<String, SwPortEntity>`, §4.4.2), accessed directly via `getSwPorts()` for the precise type, without instanceof/cast.

#### 4.5.3 LinkEvent (Link Event Entity)

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class LinkEvent {
    /** Device name the link belongs to -- required, corresponds to SuperNode's npuDevices/swDevices key */
    private String deviceName;

    /** Port name -- required, corresponds to ForwardingChip.ports key */
    private String portName;

    /** Event type: "up" / "down" -- required, case-sensitive; other values throw IllegalArgumentException */
    private String eventType;

    /** Event timestamp (milliseconds, epoch) -- required; used to update PortEntity.updateAt */
    private long eventTime;
}
```

**Field Constraints:**
- `eventType` only accepts `"up"` or `"down"`; other values throw `IllegalArgumentException`.
- `eventTime` is used to update `PortEntity.updateAt` (for subsequent audit / route convergence snapshots).
- `deviceName` + `portName` must be able to locate the specific `PortEntity` in the SuperNode topology; if not found, throws `IllegalStateException`.
- Processing flow see §7.2 `notifyLinkEvent` method description and §8 Route Convergence Algorithm.

---

### 4.6 LogicPortEntity (Logical Port Entity)

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class LogicPortEntity {
    /** Logical port name, e.g. "port_group1" -- Required field */
    private String portName;

    /** Associated CNA -- 32 bit (IP format) */
    private String cna;

    /** Associated EID -- 128 bit */
    private String eid;

    /** List of included physical ports -- Required field */
    private List<String> ports;
}
```

**Notes:**
- A logical port is an aggregation of physical ports.
- `ports` stores the `portName` of each physical port.

---

### 4.7 RoutingTable (Routing Table)

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutingTable {
    /** Belonging device */
    private String deviceName;

    /** Belonging forwarding chip index */
    private Integer chipIndex;

    /** Route entry Map -- Map key is RoutePrefix object, lookup by constructing key with known mask for O(1) hit (§4.8) */
    private Map<RoutePrefix, RoutingEntry> routes;

    /** List of mask lengths present in this routing table (deduplicated, sorted descending), maintained by engine during replace/incremental updates.
     *  <p>For example, external input with masks 32 and 20 → [32, 20]; lookup uses only these masks for matching, no full table traversal needed. */
    private List<Integer> maskLengths;
}
```

**Key Notes:**
- `RoutingTable`: Stored independently in `SuperNodeStore.routingTableMap`, keyed by `RoutingTableKey` (`superNodeName + deviceName + chipIndex`) (`Map<RoutingTableKey, RoutingTable>`, §4.7.1), supporting global O(1) lookup. Under multiple super nodes, deviceName may be duplicated, distinguished by superNodeName. `RoutingTable` is not used as a HashMap key; `equals()`/`hashCode()` is generated by Lombok `@EqualsAndHashCode` (all fields participate, consistent with `RoutePrefix` §4.8).
- `chipIndex`: Corresponds to ForwardingChip.chipIndex, identifying the forwarding chip to which this routing table belongs.
- `routes`: Map key is `RoutePrefix` object (including dstAddress and maskLength). Path planning no longer traverses the full table; instead, it takes the longest mask from `maskLengths` first, applies bitwise AND of `targetAddr` with that mask to get `networkAddr`, then constructs `(networkAddr, maskLen)` as a `RoutePrefix` HashMap key for O(1) hit (see §4.8).
- `maskLengths`: List of actually existing mask lengths in the routing table (deduplicated, sorted descending). For example, if external input only provides mask 32 detailed routes and mask 20 chassis-level routes, then `maskLengths = [32, 20]`. This list is automatically extracted and maintained by the engine during `SuperNodeStore.replace()` or incremental updates. Lookup only tries masks from this list in order, without full table traversal.

**Routing Table Storage Flow:**
- First construct a `RoutePrefix` object (including network address + mask length, e.g., `192.168.1.0/24`).
- Create a `RoutingEntry` object (including next hop, out interface, etc.).
- Store in HashMap with `RoutePrefix` as key and `RoutingEntry` as value.
- `RoutePrefix`'s `equals()` and `hashCode()` are generated by Lombok `@EqualsAndHashCode` (see §4.8).
- The engine simultaneously extracts all `RoutePrefix.maskLength` deduplicated values from the current routing table, sorts them descending, and writes them to the `maskLengths` field.

**Incremental Update maskLengths Maintenance Rules:**
- `addRoutingEntry()`: If the new route's maskLength is not in the existing maskLengths list, insert it and re-sort descending.
- `removeRoutingEntry()`: After deleting a route, check whether that maskLength has any other route entries remaining in the routes Map — if not, remove that mask from maskLengths.
- Full `replace()`: Re-extract all maskLengths from routes, deduplicate and sort descending to generate a new list.

**Corresponding JSON Example (routing table position within SuperNode JSON):**
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
> **Note:** In the input JSON file (`superNode_data_*.json`), `routingTables` data is at the device level (under each device object in §4.1 SuperNode.devices), at the same level as `forwardingChip` rather than nested. `SuperNodeStore.replace()` traverses devices→chips during processing, extracts each chip's `RoutingTable` and stores it in `routingTableMap` (`Map<RoutingTableKey, RoutingTable>`, see §7.9), while injecting the reference into `ForwardingChip.routingTable`. Subsequent path planning routing table lookups no longer depend on the nested structure in JSON, but uniformly use `routingTableMap` for global O(1) lookup.

---

#### 4.7.1 RoutingTableKey (Routing Table Composite Key)

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutingTableKey {
    /** Super node name (superNodeName), e.g. "A5-superPod-1" -- Required field, corresponds to SuperNode.name */
    private String superNodeName;

    /** Device unique identifier, format: rack#os#npu or rack#l1sw0 or lc#0 -- Required field */
    private String deviceName;

    /** Belonging chip index (corresponds to ForwardingChip.chipIndex, §4.4) */
    private Integer chipIndex;
}
```

**Design Notes:**
- The routing table belongs to a super node (superNodeName); under different super nodes, deviceName may be duplicated, so `deviceName + chipIndex` alone cannot globally uniquely identify a routing table.
- `RoutingTableKey`'s three-element composite key uniquely identifies one routing table, used as the Map key in `SuperNodeStore.routingTableMap`.
- `routingTableMap` type is `Map<RoutingTableKey, RoutingTable>`, see §7.9 SuperNodeStore definition.

**HashMap Key Constraints:**
- `equals()` and `hashCode()` are automatically generated by Lombok `@EqualsAndHashCode` (all three fields participate), ensuring HashMap lookup correctness. This approach is consistent with `RoutePrefix` (§4.8).

**Lookup Flow:**
```
PathService obtains superNodeName (from current query context)
    + deviceName (from InternalPathHop)
    + chipIndex (from ForwardingChip.chipIndex)
    → Constructs RoutingTableKey(superNodeName, deviceName, chipIndex)
    → routingTableMap.get(key) → RoutingTable
    → Iterates maskLengths list (from longest to shortest) for O(1) lookup:
        1. Take current longest mask maskLen
        2. targetAddr bitwise AND with maskLen → networkAddr
        3. Construct RoutePrefix(networkAddr, maskLen) → routes.get(prefix)  O(1) hit
        4. If hit → return RoutingEntry; if not → try next mask level
    → If all masks miss → try default route 0.0.0.0/0
    (Indexed Mask Match algorithm detailed in §8, no full table traversal required)
```

---

### 4.8 RoutePrefix (Route Prefix Structure)

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutePrefix {
    /** Destination address (masked network address, e.g. "170.170.170.0"), required field */
    private String dstAddress;

    /** Mask length (0-32), required field */
    private Integer maskLength;

    public String toPrefixString() {
        return dstAddress + "/" + maskLength;
    }
}
```

**Notes:**
RoutePrefix serves as the key for route entries in `RoutingTable.routes` Map. `equals()`/`hashCode()` is automatically generated by Lombok `@EqualsAndHashCode` (based on `dstAddress` + `maskLength` fields). Lookup no longer traverses the full table; instead, it uses the `maskLengths` list maintained within RoutingTable (see §4.7), which contains all actually existing mask lengths in the routing table, deduplicated and sorted descending.

Take the destination address, denoted as variable destAddr.
Example: destination address is 170.170.170.17.

Lookup process:
1. From `maskLengths`, take the current longest (i.e., first) mask maskLen.
   Example: routing table maskLengths = [24, 16], first take maskLen=24.
2. Call `AddressUtils.applyMask(destAddr, maskLen)` to bitwise AND destAddr with maskLen, yielding networkAddr.
   Example: AddressUtils.applyMask("170.170.170.17", 24) → "170.170.170.0".
3. Construct `RoutePrefix(networkAddr, maskLen)` as key, and perform `get(key)` in `RoutingTable.routes` Map — **O(1) hit**.
   Example: Construct RoutePrefix{dstAddress="170.170.170.0", maskLen=24} → routes.get(prefix).
4. If hit → directly return the corresponding `RoutingEntry` (since maskLen is already the current longest, the current hit is the longest prefix match for this table).
5. If not hit → take the next mask from `maskLengths` (16), repeat steps 2~4.
   Example: Not hit /24, try /16: applyMask("170.170.170.17", 16) → "170.170.0.0" → Construct RoutePrefix{"170.170.0.0", 16} → routes.get(prefix) → hit ✅.
6. If all known masks miss → try default route (`0.0.0.0/0`) — if `maskLengths` does not include 0, construct `RoutePrefix("0.0.0.0", 0)` for one final O(1) lookup; if 0 is already included, it has been covered in the loop, no need to repeat.
7. If default route also misses → return route not found (error).

**Complexity:**
- Lookup count = `maskLengths.size()`, i.e., the number of distinct mask types from external route input. Typical scenarios only have 2~3 types, each achieving O(1) HashMap hit. Overall complexity O(m), m = number of mask types (usually ≤ 5).
- Compared to full table traversal O(n) (n = number of route entries, typically dozens to hundreds), **lookup efficiency is significantly improved**.
- The number of mask types m is independent of the number of route entries n, and does not degrade as routing tables grow.

**Notes:**
- `maskLengths` is automatically extracted and sorted by the engine during routing table full replacement or incremental updates (see §4.7).
- `dstAddress` is guaranteed by data integrity constraints to be a masked network address; no additional mask computation is needed when constructing keys.

---

### 4.9 RoutingEntry (Route Entry Entity)

A route entry, representing one routing table record.

```java
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutingEntry {
    /** Target prefix structure -- includes destination address (dstAddress) and mask length (maskLength) */
    private RoutePrefix prefix;

    /** Out port information Map -- supports multiple out ports (ECMP), Map key is portName, required field;
     *  internally uses LinkedHashMap to maintain insertion order, setOutPortInfos copies input to LinkedHashMap */
    private Map<String, OutPortInfo> outPortInfos = new LinkedHashMap<>();

    /** Route reachability: indicates whether outPortInfos contains a valid out port with convergedFlag==0;
     *  default true; refreshed by refreshReachable() during link event convergence (§8 Route Convergence Algorithm) */
    private boolean reachable = true;

    public RoutingEntry(RoutePrefix prefix, Map<String, OutPortInfo> outPortInfos, boolean reachable) {
        this.prefix = prefix;
        this.reachable = reachable;
        this.outPortInfos = new LinkedHashMap<>();
        if (outPortInfos != null) {
            this.outPortInfos.putAll(outPortInfos);
        }
    }

    /** Iterate outPortInfos, if any port with convergedFlag==0 exists then reachable=true, otherwise false */
    public void refreshReachable();

    /** Deep copy: copies prefix, outPortInfos (including each OutPortInfo instance) and reachable */
    public static RoutingEntry copy(RoutingEntry src);
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| prefix | RoutePrefix | Target prefix structure, includes destination address and mask length |
| outPortInfos | Map\<String, OutPortInfo\> | Out port information Map, key is portName, supports multiple out ports (ECMP), required field; internally LinkedHashMap maintains order |
| reachable | boolean | Route reachability. Default true; refreshed by `refreshReachable()` during link event convergence: true as long as at least one out port has `convergedFlag==0` (valid), otherwise false |

**Notes:**
- `RoutingEntry` is stored in `RoutingTable.routes`, keyed by `RoutePrefix` object.
- During path planning, CNA is padded to a 32-bit `targetAddr` (see §4.8.1), and known masks are taken from `RoutingTable.maskLengths` for level-by-level O(1) lookup by constructing keys (§8).
- For example, `1.1.1.0/24` and `1.1.1.0/20` are different routes because different masks result in different `RoutePrefix`.
- The `reachable` field is refreshed during the BFS route convergence flow triggered by `notifyLinkEvent` (§7.2), affecting the routing table state returned by subsequent `getNodeRoute` queries.
- `RoutingEntry.copy(src)` is used by `RouteInstantiationService.deepCopyRoutingEntry`, ensuring the instantiated routing table returned by `makeRoutes` and the internal `instantiationRouteMap` do not affect each other.

#### 4.9.1 OutPortInfo (Out Port Information)

Out port information; one route entry can contain multiple, supporting ECMP.

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class OutPortInfo {
    /** Link down convergence passive flag: set on link event down */
    public static final int FLAG_PASSIVE_CONVERRGED = 1 << 0;

    /** Active convergence flag: used for two-dimensional routing policy maintenance */
    public static final int FLAG_ACTIVE_CONVERRGED = 1 << 1;

    private String portName;         // Out interface name -- Required field
    private String nextHop;          // Next hop IP
    private Integer preference;      // Route priority (1-255, default 60)
    private Integer tag;             // Route tag
    private String protocol;         // Route protocol type
    private int convergedFlag;       // Convergence flag bit, bitwise combination of FLAG_PASSIVE_CONVERRGED / FLAG_ACTIVE_CONVERRGED

    /** Determine whether this out port is in converged state (no longer participates in forwarding) */
    public boolean isConverged() { return convergedFlag != 0; }

    /** Set the specified flag on convergedFlag (does not affect other bits) */
    public void setFlag(int flag) { this.convergedFlag |= flag; }

    /** Clear the specified flag on convergedFlag (does not affect other bits) */
    public void clearFlag(int flag) { this.convergedFlag &= ~flag; }
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| portName | String | Out interface name -- Required field |
| nextHop | String | Next hop IP |
| preference | Integer | Route priority (1-255, default 60) |
| tag | Integer | Route tag |
| protocol | String | Route protocol type |
| convergedFlag | int | Convergence flag bit (bitwise combination): `FLAG_PASSIVE_CONVERRGED` (set on link down), `FLAG_ACTIVE_CONVERRGED` (set on active route policy convergence). `isConverged()` returns `convergedFlag != 0`, indicating this out port does not participate in forwarding |

**Convergence Flag Usage Rules:**
- Link down event: `notifyLinkEvent` → `LinkEventService` locates the port's chip routing table → finds the `RoutingEntry` containing this port → `OutPortInfo.setFlag(FLAG_PASSIVE_CONVERRGED)` → `RoutingEntry.refreshReachable()`.
- Link up event: `OutPortInfo.clearFlag(FLAG_PASSIVE_CONVERRGED)` → `RoutingEntry.refreshReachable()`.
- Active route policy convergence: `OutPortInfo.setFlag(FLAG_ACTIVE_CONVERRGED)` / `clearFlag(FLAG_ACTIVE_CONVERRGED)`.
- `RoutingEntry.refreshReachable()` iterates `outPortInfos`; as long as one port with `convergedFlag == 0` exists, `reachable = true`, otherwise `false`.

**Notes:**
- Mask length has been migrated to the `RoutePrefix` structure; `OutPortInfo` no longer contains a `maskLength` field.
- The above fields are uniformly encapsulated in `OutPortInfo`, serving as the value in `RoutingEntry.outPortInfos` Map; Map key is `portName`, supporting O(1) lookup and traversal, covering ECMP scenarios.


## 5 Pure Internal Data Structures

### 5.1 InternalPathInfo (Internal Path Information)

> **Design Basis:** Refer to §9.3 Phase 2 Step 5 — Multi-hop path resolution flow.

#### 5.1.1 InternalPathHop (Internal Path Hop)

An internal representation of a single hop, containing all connection and address information needed for topology resolution.

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class InternalPathHop {
    /** Current device ID -- Required field */
    private String deviceName;

    /** Device type */
    private DeviceType deviceType;

    /** Inbound port name -- null for source node */
    private String inPort;

    /** Outbound port name -- null for destination node */
    private String outPort;

    /** CNA associated with the current port (32 bit). Forward path takes outPort's cna, reverse path takes inPort's cna (forward outPort = reverse inPort) */
    private String cna;

    /** EID associated with the current port (128 bit). Forward path takes outPort's eid, reverse path takes inPort's eid */
    private String eid;

    /** Peer device ID connected by this port -- for topology connection validation */
    private String remoteDevice;

    /** Peer port name connected by this port -- for topology connection validation */
    private String remotePort;

    /** Belonging Rack */
    private String rack;

    /** Hop sequence number (starting from 0, source node is 0) */
    private int hopIndex;
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| deviceName | String | Current device ID -- Required field |
| deviceType | DeviceType | Device type (NPU / SW) |
| inPort | String | Inbound port name -- null for source node |
| outPort | String | Outbound port name -- null for destination node |
| cna | String | CNA associated with the current port (32 bit), from PortEntity.cna. NPU port uses NpuPortEntity.cna (required), switch port uses SwPortEntity.cna (optional, can be null). Forward path takes out port cna, reverse path takes in port cna (forward out port = reverse in port) |
| eid | String | EID associated with the current port (128 bit), only NPU ports have this (from NpuPortEntity.eid), switch ports are null. Forward path takes out port eid, reverse path takes in port eid |
| remoteDevice | String | Peer device ID connected by this port, for topology connection validation |
| remotePort | String | Peer port name connected by this port, for topology connection validation |
| rack | String | Belonging Rack |
| hopIndex | int | Hop sequence number (starting from 0, source node is 0) |

**Field Constraints:**
- Source node (hopIndex=0): `inPort=null`, `outPort` is source device out port, `cna`/`eid` taken from source port.
- Destination node (hopIndex maximum): `outPort=null`, `inPort` taken from previous hop's `remotePort`.
- Intermediate nodes: `inPort` is previous hop's `remotePort` (peer port), `outPort` specified by `interDevices`.

**Mapping to External HopInfo:**

| Internal InternalPathHop | External HopInfo | Description |
|:---------------------|:-------------|:-----|
| deviceName | deviceName | Direct mapping |
| deviceType | deviceType | Direct mapping |
| inPort | inPort | Direct mapping |
| outPort | outPort | Direct mapping |
| cna | - | Internal use only, not exposed externally |
| eid | - | Internal use only, not exposed externally |
| remoteDevice | - | Internal topology validation use |
| remotePort | - | Internal topology validation use |
| rack | - | Internal use only |
| hopIndex | - | hopIndex=0 is source node, hopIndex maximum is destination node |

#### 5.1.2 InternalPathInfo (Internal Path Information)

Encapsulates the complete internal path, constructed in Step 5 and consumed in subsequent Steps 6~8.

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class InternalPathInfo {
    /** Path hop-by-hop list */
    private List<InternalPathHop> hops;

    /** Source EID */
    private String sourceEid;

    /** Destination EID */
    private String destEid;

    /** Source CNA */
    private String sourceCna;

    /** Destination CNA */
    private String destCna;

    /** Total hop count (should equal hops.size()) */
    private int hopCount;
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| hops | List\<InternalPathHop\> | Path hop-by-hop list, each hop contains complete information needed for topology resolution |
| sourceEid | String | Source EID, from Step 1 |
| destEid | String | Destination EID, from Step 2 |
| sourceCna | String | Source CNA, from Step 1 |
| destCna | String | Destination CNA, from Step 2 |
| hopCount | int | Total hop count |

**Data Flow Description:**
```
Step 5 (Multi-hop path resolution):
    Input:  PathPlanRequest (srcDevice, srcPort, destDevice, destPort, interDevices)
    Output: InternalPathInfo (hop-by-hop populated with topology consistency validation)
    
Step 6~8 (Path planning loop):
    Input:  InternalPathInfo (constructed from Phase 2)
    Process: Iterate InternalPathInfo.hops, perform path planning for each intermediate device
    Output: RouteSelectionRecord list (produced from Step 9)
    
Step 10 (Populate PathPlanResult):
    Input:  InternalPathInfo.hops
    Output: PathPlanResult.paths (converted to external HopInfo list)
```

---

### 5.2 RouteSelectionRecord (Internal Route Selection Record)

> **Design Basis:** Refer to §9.4 Phase 3 Step 9 — Out port determination and route selection recording.

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RouteSelectionRecord {
    /** Device ID performing route selection */
    private String deviceName;

    /** Matched route prefix (32 bit, padded) */
    private String prefix;

    /** List of all candidate out interfaces (need to record both selected and unselected out interfaces) */
    private List<CandidateOutPort> candidateOutPorts;

    /** Source CNA (tuple element SCNA) */
    private String scna;

    /** Destination CNA (tuple element DCNA) */
    private String dcna;

    /** Hash information -- for ECMP load balancing computation.
     *  <p>Hash algorithm input is triple: source CNA (SCNA, 32 bit), destination CNA (DCNA, 32 bit),
     *  source UDP port number (8 bit, calculated and filled in by Step 9).
     *  Output is integer hash value, modulo candidate out port count to get the selected out port index.
     *  <p>Hash function can be stubbed; tests can inject specific implementations to ensure specific triples output specified hash values. */
    private String hashInfo;

    /** Direction indicator */
    private Direction direction;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @EqualsAndHashCode
    @ToString
    public static class CandidateOutPort {
        /** Out interface name, from OutPortInfo.portName */
        private String portName;

        /** Next hop IP */
        private String nextHop;

        /** Whether this is the selected out interface (ECMP route selection result). Uses boolean primitive type, default false, avoiding null semantic ambiguity */
        private boolean selected;
    }

    /** Direction enum */
    public enum Direction {
        FORWARD,  // Forward: source address = CNA1
        REVERSE   // Reverse: source address = CNA2
    }
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| deviceName | String | Device ID performing route selection |
| prefix | String | Matched route prefix (32 bit) |
| candidateOutPorts | List\<CandidateOutPort\> | List of all candidate out interfaces, recording both selected and unselected out interfaces |
| scna | String | Source CNA (32 bit), tuple element SCNA |
| dcna | String | Destination CNA (32 bit), tuple element DCNA |
| hashInfo | String | Hash information -- for ECMP load balancing (triple hash key: SCNA + DCNA + srcUdpPort) |
| direction | Direction | Direction: FORWARD (source=CNA1) or REVERSE (source=CNA2) |

**CandidateOutPort Sub-structure:**

| Field | Type | Description |
|:-----|:-----|:-----|
| portName | String | Out interface name, from OutPortInfo.portName |
| nextHop | String | Next hop IP, from OutPortInfo.nextHop |
| selected | boolean | Whether this is the selected out interface: `true`=ECMP route selection hit, `false`=not selected. Primitive type, default `false`, no null check needed |

**Route Selection Record Field Source Description:**

| Field | Source | Corresponding Item in Step 9 Pseudocode |
|:-----|:-----|:--------------------------|
| prefix | Path planning result RoutingEntry.prefix | `Route information (prefix)` |
| candidateOutPorts[].portName | OutPortInfo.portName | `Route information (portName)` |
| candidateOutPorts[].nextHop | OutPortInfo.nextHop | Next hop information |
| candidateOutPorts[].selected | ECMP hash route selection result | Whether selected |
| scna / dcna | CNA1 / CNA2 extracted in Step 1 / Step 2 | `Tuple information (SCNA, DCNA)` |
| hashInfo | ECMP hash algorithm input (triple: SCNA, DCNA, srcUdpPort) | `Hash information` |
| direction | Forward lookup CNA1→CNA2, reverse lookup CNA2→CNA1 | `Direction flag` |

**Recording Rules:**
- Out port count == 1: Do not record `RouteSelectionRecord`, directly proceed to next hop.
- Out port count > 1: Record one `RouteSelectionRecord`, where `candidateOutPorts` contains all candidate out interfaces (all ECMP paths), the port consistent with `interDevices` specified out port is marked as `selected=true` (target port), others as `false`. Proceed to next hop. SNC notifies the caller through `HopInfo.multiPath=true` and `PathPlanResult.spray=true` that this path contains ECMP multi-path; the caller decides per-flow strategy; no longer returns MULTI_PATH_NOT_SUPPORTED error code.

**Consumption Relationship:**
```
§9.4.4 Step 9 (Record):
    For each intermediate device with ECMP → generate RouteSelectionRecord
    → candidateOutPorts records all candidate out interfaces + selected marker
    
§9.5 Step 9 (UDP port computation):
    Iterate RouteSelectionRecord list
    → Based on hashInfo + scna/dcna compute 8-bit src_udp_port / dst_udp_port
    → Fill into PathPlanResult.ackUdpSrcPort / dataUdpSrcPort
```

---

## 6 Northbound Data Structures (DTO)

> This chapter defines the northbound API data structures exposed by SNC. For detailed definitions of internal data structures, see [§4. Data Structure Definitions](#4-data-structure-definitions).

---

### 6.1 PathPlanRequest (Path Planning Request)

Northbound path planning request, submitted by the caller, specifying source/destination devices and ports, and intermediate path constraints.

```java
public class PathPlanRequest {
    /** Super node name (superNodeName), corresponding to SuperNode.name (§4.1), used to locate target super node in multi-super-node scenarios -- Required field */
    private String superNodeName;

    /** Source port name -- Required field */
    private String srcPort;

    /** Destination port name -- Required field */
    private String destPort;

    /** Source device ID -- Required field */
    private String srcDevice;

    /** Destination device ID -- Required field */
    private String destDevice;

    /** Intermediate device and out port Map, key=deviceName, value=portName. Required when intermediate devices exist; if not provided, defaults to direct connection */
    private Map<String, String> interDevices;
}
```

**Field Description:**

| Field | Type | Required | Description |
|:-----|:-----|:-----|:-----|
| superNodeName | String | Yes | Super node name, corresponding to SuperNode.name (§4.1), used to locate target super node in multi-super-node scenarios |
| srcPort | String | Yes | Source physical port name, e.g. `"400GE 0/0/1"` |
| destPort | String | Yes | Destination physical port name, e.g. `"400GE 0/1/1"` |
| srcDevice | String | Yes | Source device deviceName, e.g. `"rack1#os0#npu1"` |
| destDevice | String | Yes | Destination device deviceName, e.g. `"rack1#os0#npu2"` |
| interDevices | Map\<String,String\> | No | Intermediate device and corresponding out port, key=deviceName, value=portName. When empty, engine attempts auto-routing. **Note:** "Auto-routing" algorithm is not implemented in current version V1; when `interDevices` is empty, only direct connection scenario Step 6 is handled, auto-discovery of multi-hop paths is not supported. Multi-hop scenarios must explicitly specify intermediate devices and out ports via `interDevices`. |

**Field-to-SuperNode Mapping:**

| PathPlanRequest Field | Corresponding SuperNode Field | Description |
|:---------------------|:-----------------------|:-----|
| srcDevice / destDevice | `SuperNode.devices` key (deviceName) | Direct correspondence, see §4.1 |
| srcPort / destPort | Each subclass forwarding chip's `ports` key (portName), accessed via `getPorts()` abstract method | See §4.4, §4.5 |
| interDevices key | `SuperNode.devices` key (deviceName) | See §4.3 |
| interDevices value | `PortEntity.portName` | Intermediate device out port name, see §4.5 |

---

### 6.2 PathPlanResult (Path Planning Response)

Northbound path planning response, returning path planning results.

```java
public class PathPlanResult {
    /** Source EID -- 128 bit */
    private String sourceEid;

    /** Destination EID -- 128 bit */
    private String destEid;

    /** Path details */
    private PathInfo path;

    /** Query status */
    private PlanStatus status;

    /** Failure reason (if query failed) */
    private String errorMessage;

    /** Ack UDP source port -- 8 bit, for hardware offload */
    private Integer ackUdpSrcPort;

    /** Data UDP source port -- 8 bit, for hardware offload */
    private Integer dataUdpSrcPort;

    /** Spray enable -- whether multi-path spray is enabled */
    private Boolean spray;

    /** ========== Query Status Enum ========== */
    public enum PlanStatus {
        SUCCESS(0, "success"),
        SRC_INFO_ERR(1003, "src info error"),
        DST_INFO_ERR(1004, "dst info error"),
        TOPO_INCOMPLETE(1007, "topo incomplete"),
        TOPO_CONNECTION_ERROR(1008, "topo connection error"),
        TOPO_CONNECTION_NOT_FOUND(1009, "topo connection not found"),
        ROUTE_NOT_REACHABLE(1010, "route not reachable"),
        TOPO_NOT_FOUND(1012, "topo not found"),
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

**Field Description:**

| Field | Type | Description |
|:-----|:-----|:-----|
| sourceEid | String | Source EID (128 bit), from source NPU port, see §4.5.1 NpuPortEntity.eid |
| destEid | String | Destination EID (128 bit), from destination NPU port, see §4.5.1 NpuPortEntity.eid |
| path | PathInfo | Path details, containing hop-by-hop information |
| status | PlanStatus | Query status, 0=success, non-0=failure (error codes see table above) |
| errorMessage | String | Failure reason description, filled when status is not SUCCESS |
| ackUdpSrcPort | Integer | Ack UDP source port (8 bit), computed by Step 9, for hardware offload |
| dataUdpSrcPort | Integer | Data UDP source port (8 bit), computed by Step 9, for hardware offload |
| spray | Boolean | Spray enable flag, true=multi-path spray enabled |

---

#### 6.2.1 PathInfo (Path Information)

```java
public class PathInfo {
    /** Hop-by-hop list -- ordered from source to destination */
    private List<HopInfo> hops;
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| hops | List\<HopInfo\> | Hop-by-hop list, hops[0] is source node, hops[last] is destination node |

---

#### 6.2.2 HopInfo (Hop Information)

```java
public class HopInfo {
    /** Device ID -- Required field */
    private String deviceName;

    /** Inbound port -- destination and intermediate nodes always have this, source node is null */
    private String inPort;

    /** Outbound port -- source and intermediate nodes always have this, destination node is null */
    private String outPort;

    /** Multi-path enable -- whether this hop supports ECMP per-flow */
    private Boolean multiPath;

    /** Device type -- "NPU" or "SW" (uses string constant, avoiding dto layer direct dependency on entity.DeviceType enum).
     *  <p>Possible values: {@code "NPU"} (compute node), {@code "SW"} (switch device).
     *  <p>Populated by service layer via {@code DeviceType.name()} conversion. */
    private String deviceType;
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| deviceName | String | Device unique identifier, corresponding to `DeviceEntity.deviceName` (§4.3) |
| inPort | String | Inbound port name, null for source node |
| outPort | String | Outbound port name, null for destination node |
| multiPath | Boolean | Whether this hop supports multi-path (ECMP per-flow) |
| deviceType | String | Device type (`"NPU"` / `"SW"`), using string constant, converted from `DeviceType.name()` by service layer (§4.3.1). **Design reason:** dto layer cannot depend on entity package (§3.3 layering constraint), so String type is used to avoid cross-layer enum references |

> **Architecture Constraint:** §3.3 explicitly states dto layer cannot depend on entity package. `DeviceType` is an enum in the entity package; HopInfo (dto package) uses `String deviceType` instead of `DeviceType`, with the service layer responsible for `DeviceType.name()` to `String` conversion.

**Field Constraints:**
- Source node (hops[0]): `inPort=null`, `outPort` is source device out port.
- Destination node (hops[last]): `outPort=null`, `inPort` is last hop inbound port.
- Intermediate nodes: both `inPort` and `outPort` are non-null.

**Mapping to SuperNode Internal Data Structures:**

| HopInfo Field | Corresponding Internal Field | Source |
|:-------------|:-------------|:-----|
| deviceName | DeviceEntity.deviceName | §4.3 |
| inPort / outPort | PortEntity.portName | §4.5 |
| deviceType | DeviceType enum | §4.3.1 |
| multiPath | Derived from path planning result (ECMP scenario) | §4.9 RoutingEntry.outPortInfos.size() > 1 |

---

### 6.3 Coverage Planning DTO

#### 6.3.1 CoveragePathsRequest (Coverage Planning Request)

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoveragePathsRequest {
    /** Super node name -- required, corresponds to SuperNode.name (§4.1) */
    private String superNodeName;

    /** Coverage requirement; null defaults to MIN_COVERAGE (§6.3.6 CoverageRequirement) */
    private CoverageRequirement coverageRequirement;
}
```

> planPathsCoverage and planPathsCoverageEx share this DTO; the coverage domain difference is determined by the method name, not by request fields.

#### 6.3.2 CoveragePathsResult (Coverage Planning Response)

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoveragePathsResult {
    /** Coverage domain: L1_L2 (planPathsCoverage) / NPU_L1_L2 (planPathsCoverageEx) */
    private CoverageLinkScope scope;

    /** Status: SUCCESS / COVERAGE_INCOMPLETE / TOPO_NOT_FOUND */
    private PathPlanResult.PlanStatus status;

    /** Error message; null when status=SUCCESS */
    private String errorMessage;

    /** Selected EID pair list */
    private List<CoveredEidPair> eidPairs;

    /** All coverage links (deduplicated), grouped by layer */
    private List<CoverageLink> coverageLinks;

    /** Summary statistics (full coverage domain) */
    private CoverageStats totalStats;

    /** Layer statistics; planPathsCoverage returns null, planPathsCoverageEx returns NPU_L1 + L1_L2 two layers */
    private List<CoverageLayerStats> layerStats;
}
```

**Field Constraints:**
- `scope`: Required when SUCCESS, can be null when TOPO_NOT_FOUND.
- `eidPairs`: Required when SUCCESS / COVERAGE_INCOMPLETE (may be partial coverage results); empty list when TOPO_NOT_FOUND.
- `coverageLinks[*].layer`: null for planPathsCoverage; ∈ {NPU_L1, L1_L2} for planPathsCoverageEx.
- `coverageLinks[*].deviceType`: null for planPathsCoverage; ∈ {"NPU", "SW"} for planPathsCoverageEx.
- `eidPairs[*].type`: null for planPathsCoverage; ∈ {CROSS_L2, LOCAL_L1} for planPathsCoverageEx.

#### 6.3.3 CoverageLinkScope (Coverage Domain Enum)

```java
public enum CoverageLinkScope {
    /** planPathsCoverage: only covers L1SW↔L2SW out ports */
    L1_L2,
    /** planPathsCoverageEx: covers NPU↔L1SW↔L2SW out ports (including jettyId hash route selection) */
    NPU_L1_L2
}
```

#### 6.3.4 CoverageLinkLayer (Link Layer Enum)

```java
public enum CoverageLinkLayer {
    /** NPU↔L1SW link layer (only used by planPathsCoverageEx) */
    NPU_L1,
    /** L1SW↔L2SW link layer */
    L1_L2
}
```

#### 6.3.5 CoveragePathType (Path Type Enum)

```java
public enum CoveragePathType {
    /** Cross-chassis: source/destination NPU in different chassis, 4-hop path NPU→L1SW→L2SW→L1SW→NPU */
    CROSS_L2,
    /** Same chassis: source/destination NPU in same chassis, 2-hop path NPU→L1SW→NPU */
    LOCAL_L1
}
```

#### 6.3.6 CoverageRequirement (Coverage Requirement Enum)

```java
public enum CoverageRequirement {
    /** Minimum coverage: each out port covered by at least 1 EID pair (coverCount >= 1) */
    MIN_COVERAGE,
    /** Redundant coverage: each out port covered by at least 2 EID pairs (coverCount >= 2) */
    REDUNDANT
}
```

#### 6.3.7 CoverageStats (Coverage Summary Statistics)

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoverageStats {
    /** Total out port count in current coverage domain */
    private int totalLinks;
    /** Covered out port count */
    private int coveredLinks;
    /** Coverage rate = coveredLinks / totalLinks */
    private double coverageRate;
    /** Out port count covered ≥ 2 times */
    private int redundantLinks;
    /** Redundancy rate = redundantLinks / totalLinks */
    private double redundantRate;
    /** Total EID pair count */
    private int eidPairCount;
    /** EID uniformity: standard deviation of coverage count per out port, lower is more uniform */
    private double eidUniformity;
}
```

#### 6.3.8 CoverageLayerStats (Layer Statistics)

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoverageLayerStats {
    /** Belonging layer */
    private CoverageLinkLayer layer;
    /** Statistics for this layer (same structure as CoverageStats) */
    private CoverageStats stats;
}
```

> planPathsCoverage returns `layerStats = null`; planPathsCoverageEx returns `[NPU_L1 layer stats, L1_L2 layer stats]`.

#### 6.3.9 CoverageLink (Coverage Link)

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoverageLink {
    /** Device name the link belongs to */
    private String deviceName;
    /** Chip index the link belongs to */
    private int chipIndex;
    /** Out port name */
    private String outPortName;
    /** Out port ID */
    private int outPortId;
    /** Peer device name (PortEntity.remoteDevice) */
    private String remoteDevice;
    /** Peer port name (PortEntity.remotePort) */
    private String remotePort;
    /** Coverage count (how many EID pairs hit) */
    private int coverCount;
    /** Link layer; null for planPathsCoverage, ∈ {NPU_L1, L1_L2} for planPathsCoverageEx */
    private CoverageLinkLayer layer;
    /** Device type; null for planPathsCoverage, ∈ {"NPU", "SW"} for planPathsCoverageEx */
    private String deviceType;
}
```

#### 6.3.10 CoveredEidPair (Covered EID Pair)

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoveredEidPair {
    /** Source EID (128 bit string) */
    private String srcEid;
    /** Destination EID (128 bit string) */
    private String dstEid;
    /** List of links covered by this EID pair (grouped by layer, forward+reverse merged) */
    private List<CoverageLink> coveredLinks;
    /** Path type; null for planPathsCoverage, ∈ {CROSS_L2, LOCAL_L1} for planPathsCoverageEx */
    private CoveragePathType type;
}
```

> `coveredLinks` link order: forward path in source→destination order, reverse path appended in destination→source order; the 4 (planPathsCoverage) or 4/8 (planPathsCoverageEx) coverage links of the same EID pair are stored consecutively in the list.

#### 6.3.11 CoveredEidPairRef (EID Pair Reference)

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class CoveredEidPairRef {
    /** Source EID */
    private String srcEid;
    /** Destination EID */
    private String dstEid;
}
```

> Used as a lightweight reference for CoveragePlanEngine internal candidate EID pair enumeration, avoiding constructing a full CoveredEidPair prematurely during the search phase.

#### 6.3.12 LinkEvent (Link Event)

```java
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @EqualsAndHashCode @ToString
public class LinkEvent {
    /** Device name the link belongs to -- required */
    private String deviceName;
    /** Port name -- required */
    private String portName;
    /** Event type: "up" / "down" -- required, case-sensitive */
    private String eventType;
    /** Event timestamp (milliseconds, epoch) -- required */
    private long eventTime;
}
```

---

### 6.4 Relationship Between Northbound and Internal Data Structures

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Northbound API (§6)                                                    │
│   PathPlanRequest    PathPlanResult                                    │
│       │                     ▲                                          │
│       │   ┌─────────────────┘                                          │
│       │   │                                                              │
│ ┌──────────────────────────────────────────────────┐                   │
│ │ SNC Engine (path planning + path resolution)    │                   │
│ │  Internal Data Structures: InternalPathInfo (§5.1) │                   │
│ └──────────────────────────────────────────────────┘                   │
│       │                     ▲                                          │
│       │                     │                                          │
│ ┌──────────────────────────────────────────────────┐                   │
│ │ Topology Data Layer (§4)                         │                   │
│ │  SuperNode / DeviceEntity / ForwardingChip       │                   │
│ │           / PortEntity / RoutingTable            │                   │
│ │  (Abstract classes provide polymorphic iteration │                   │
│ │   via getForwardingChips/getPorts,              │                   │
│ │   subclasses hold precise-type fields)          │                   │
│ └──────────────────────────────────────────────────┘                   │
└──────────────────────────────────────────────────────────────────────────┘
```

**Data Flow Description:**
1. The caller constructs `PathPlanRequest` (§6.1), specifying source/destination devices and ports.
2. The engine finds the corresponding `DeviceEntity` (§4.3) from `SuperNode` (§4.1), extracting port CNA/EID.
3. The engine constructs internal `InternalPathInfo` (§5.1), performing hop-by-hop topology validation and path planning.
4. The engine converts internal results to `PathPlanResult` (§6.2), returned to the caller.

## 7 Northbound Interface

### 7.1 Interface Overview

The SNC module exposes a unified northbound interface `SNCService`, located in package `com.huawei.umdk.snc`. The caller (upper-layer orchestrator/management system) uses this interface to perform six phases of operations: **initialization, data provisioning, path planning, coverage planning, link event and route management, and deinitialization**.

```
Northbound Interface (SNCService)
    │
    ├── init(SNCConfig) → void                   // Initialization
    │
    ├── setSuperNode(SuperNode) → void             // Topology full provisioning
    ├── addNpuDevices(String, List<NpuDevice>) → void    // Topology incremental: batch add NPU devices
    ├── addSwDevices(String, List<SwDevice>) → void         // Topology incremental: batch add SW devices
    ├── removeDevices(String, List<String>) → void              // Topology incremental: batch remove devices
    ├── addRoutingEntries(String, String, Integer, List<RoutingEntry>) → void  // Topology incremental: batch add/update route entries
    ├── removeRoutingEntries(String, String, Integer, List<RoutePrefix>) → void  // Topology incremental: batch remove route entries
    ├── getSuperNode(String) → SuperNode           // Topology data query
    ├── removeSuperNode(String) → void             // Topology data deletion
    │
    ├── planPath(PathPlanRequest) → PathPlanResult     // Path planning (single path)
    ├── planPathsCoverage(CoveragePathsRequest) → CoveragePathsResult       // Coverage planning (L1↔L2)
    ├── planPathsCoverageEx(CoveragePathsRequest) → CoveragePathsResult     // Coverage planning extended (NPU↔L1↔L2)
    │
    ├── notifyLinkEvent(SuperNode, LinkEvent) → void                     // Link up/down notification + BFS route convergence
    ├── routeCalculate() → void                                          // Route template calculation (idempotent, before makeRoutes)
    ├── makeRoutes(SuperNode) → Map<String, Map<String, RoutingEntry>>   // Route instantiation
    ├── getNodeRoute(String, int) → Map<String, RoutingEntry>            // Query single device single chip routing table
    │
    └── uninit() → void                                // Deinitialization
```

> **Data Structure Reference:** For complete definitions of northbound data structures involved in the interface such as `PathPlanRequest`, `PathPlanResult`, `PathInfo`, `HopInfo`, `PlanStatus`, `CoveragePathsRequest`, `CoveragePathsResult`, `CoverageLink`, `CoverageLinkScope`, `CoverageLinkLayer`, `CoveragePathType`, `CoverageRequirement`, `CoverageStats`, `CoverageLayerStats`, `CoveredEidPair`, `CoveredEidPairRef`, `LinkEvent`, etc., see [§6 Northbound Data Structures](#6-northbound-data-structures-dto).

---

### 7.2 SNCService Interface Definition

```java
package com.huawei.umdk.snc;

import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.entity.*;
import com.huawei.umdk.snc.dto.*;
import com.huawei.umdk.snc.config.SNCConfig;

/**
 * SNC main service interface — Northbound entry point
 *
 * <h3>Invocation Order Constraints</h3>
 * <pre>{@code
 *   sncService.init(config);                    // 1. Initialization
 *   sncService.setSuperNode(superNode);           // 2. Provision topology data (can be called multiple times to update)
 *   sncService.addNpuDevices("A5-superPod-1", List.of(npuDevice));  // 3. Incremental: batch add NPU devices
 *   sncService.addSwDevices("A5-superPod-1", List.of(swDevice));    // 4. Incremental: batch add SW devices
 *   sncService.removeDevices("A5-superPod-1", List.of("rack1#os0#npu1")); // 5. Incremental: batch remove devices
 *   sncService.addRoutingEntries("A5-superPod-1", "rack1#os0#npu1", 0, List.of(entry)); // 6. Incremental: batch add routes
 *   sncService.planPath(request);               // 7. Path planning (can be called concurrently multiple times)
 *   sncService.planPathsCoverage(req);          // 7a. Coverage planning (L1↔L2)
 *   sncService.planPathsCoverageEx(req);        // 7b. Coverage planning (NPU↔L1↔L2, including jettyId)
 *   sncService.routeCalculate();                // 7c. Route template calculation (idempotent, must be before makeRoutes)
 *   sncService.makeRoutes(superNode);           // 7d. Instantiate routing tables (fills instantiationRouteMap)
 *   sncService.getNodeRoute("rack1#os0#npu1", 0); // 7e. Query single device single chip routing table
 *   sncService.notifyLinkEvent(superNode, event); // 7f. Notify link up/down (triggers BFS route convergence)
 *   SuperNode td = sncService.getSuperNode("A5-superPod-1");   // 8. Topology data query
 *   sncService.removeSuperNode("A5-superPod-1");              // 9. Topology data deletion
 *   sncService.uninit();                       // 10. Deinitialization
 * }</pre>
 *
 * <h3>State Constraints</h3>
 * - Calling other interfaces without init(): throws SNCStateException
 * - Calling other interfaces after uninit(): throws SNCStateException
 * - Repeated init(): idempotent handling or throws SNCStateException
 * - planPath / planPathsCoverage / planPathsCoverageEx: requires state DATAREADY
 * - notifyLinkEvent / routeCalculate / makeRoutes / getNodeRoute: requires state not INIT/UNINIT (READY / DATAREADY both OK)
 *
 * @see PathPlanRequest
 * @see PathPlanResult
 * @see CoveragePathsRequest
 * @see CoveragePathsResult
 * @see LinkEvent
 * @see SuperNode
 */
public interface SNCService {

    // ============ Lifecycle Management ============

    /**
     * Initialize SNC service
     *
     * Load configuration, initialize internal HashMaps (topology index).
     *
     * @param config SNC configuration (logging strategy, indexing strategy, etc.), can be null (uses default configuration)
     * @throws SNCStateException State exception (duplicate initialization, etc.)
     */
    void init(SNCConfig config);

    /**
     * Deinitialize SNC service
     *
     * Clear all in-memory data (topology Map), release resources.
     *
     * @throws SNCStateException State exception (not initialized, etc.)
     */
    void uninit();

    // ============ Data Provisioning ============

    /**
     * Provision topology data (full replacement)
     *
     * Parse and index SuperNode into in-memory HashMap.
     * - Uses full replacement (replace) strategy: new data overwrites old data.
     * - Can be called multiple times; each call fully replaces all data for the same name topology.
     *
     * @param superNode Topology data, from superNode_data_*.json deserialization (§4.1)
     * @throws IllegalArgumentException superNode is null or required fields are missing
     * @throws SNCStateException SNC not initialized
     */
    void setSuperNode(SuperNode superNode);

    // ============ Incremental Update - Topology ============

    /**
     * Incrementally batch add NPU devices
     *
     * Batch add NPU devices (overwriting existing) to the specified super node's npuDevices,
     * while indexing routing tables. SuperNode must have been imported via setSuperNode,
     * otherwise throws IllegalStateException.
     *
     * @param superNodeName Super node name (corresponding to SuperNode.name, §4.1)
     * @param devices NPU device list (§4.3.2), each element non-null
     * @throws IllegalArgumentException superNodeName or devices is null/empty
     * @throws IllegalStateException SuperNode does not exist
     * @throws SNCStateException SNC not initialized
     */
    void addNpuDevices(String superNodeName, List<NpuDevice> devices);

    /**
     * Incrementally batch add SW devices
     *
     * Batch add SW devices (overwriting existing) to the specified super node's swDevices,
     * while indexing routing tables. SuperNode must have been imported via setSuperNode,
     * otherwise throws IllegalStateException.
     *
     * @param superNodeName Super node name (corresponding to SuperNode.name, §4.1)
     * @param devices SW device list (§4.3.3), each element non-null
     * @throws IllegalArgumentException superNodeName or devices is null/empty
     * @throws IllegalStateException SuperNode does not exist
     * @throws SNCStateException SNC not initialized
     */
    void addSwDevices(String superNodeName, List<SwDevice> devices);

    /**
     * Incrementally batch remove devices
     *
     * Batch remove devices from the specified super node's topology data,
     * while clearing their routing table entries in routingTableMap.
     *
     * @param superNodeName Super node name (corresponding to SuperNode.name, §4.1)
     * @param deviceNames Device unique identifier list, each element non-null/non-empty
     * @throws IllegalArgumentException superNodeName or deviceNames is null/empty
     * @throws SNCStateException SNC not initialized
     */
    void removeDevices(String superNodeName, List<String> deviceNames);

    /**
     * Incrementally batch add/update route entries
     *
     * Batch add or update route entries in the specified device's specified chip routing table.
     * Each route's prefix is extracted from the RoutingEntry.prefix field.
     *
     * @param superNodeName Super node name
     * @param deviceName Device unique identifier
     * @param chipIndex Chip index
     * @param entries Route entry list (§4.9), each entry and its prefix non-null
     * @throws IllegalArgumentException Any parameter is null, or routing table does not exist
     * @throws SNCStateException SNC not initialized
     */
    void addRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                           List<RoutingEntry> entries);

    /**
     * Incrementally batch remove route entries
     *
     * Batch remove route entries from the specified device's specified chip routing table.
     *
     * @param superNodeName Super node name
     * @param deviceName Device unique identifier
     * @param chipIndex Chip index
     * @param prefixes Route prefix list (§4.8), each element non-null
     * @throws IllegalArgumentException Any parameter is null, or routing table does not exist
     * @throws SNCStateException SNC not initialized
     */
    void removeRoutingEntries(String superNodeName, String deviceName, Integer chipIndex,
                              List<RoutePrefix> prefixes);

    // ============ Data Query ============

    /**
     * Query topology data
     *
     * Get the corresponding SuperNode object from SuperNodeStore by superNodeName.
     *
     * @param superNodeName Super node name (corresponding to SuperNode.name, §4.1)
     * @return SuperNode object, returns null if topology data for the specified superNodeName does not exist
     * @throws IllegalArgumentException superNodeName is null or empty string
     * @throws SNCStateException SNC not initialized
     */
    SuperNode getSuperNode(String superNodeName);

    /**
     * Delete topology data
     *
     * Remove the corresponding topology data (including topology primary index and associated routing table data)
     * from SuperNodeStore by superNodeName.
     *
     * @param superNodeName Super node name (corresponding to SuperNode.name, §4.1)
     * @throws IllegalArgumentException superNodeName is null or empty string
     * @throws SNCStateException SNC not initialized
     */
    void removeSuperNode(String superNodeName);

    // ============ Path Planning ============

    /**
     * Path planning (synchronous request-response mode)
     *
     * Based on source/destination device and port information, execute path planning and path resolution,
     * returning complete communication path parameters.
     * Internally executes Step 0 ~ Step 10 flow.
     *
     * <table>
     *   <tr><th>Phase</th><th>Step</th><th>Description</th></tr>
     *   <tr><td>Phase 1</td><td>Step 0~2</td><td>Device judgment and source/destination info lookup §9.2</td></tr>
     *   <tr><td>Phase 2</td><td>Step 3~5</td><td>Path resolution (direct/multi-hop) §9.3</td></tr>
     *   <tr><td>Phase 3</td><td>Step 6~8</td><td>Path planning loop (forward/reverse) §9.4</td></tr>
     *   <tr><td>Phase 4</td><td>Step 9~10</td><td>Output construction (UDP port computation + PathPlanResult filling) §9.5</td></tr>
     * </table>
     *
     * <h3>Prerequisites</h3>
     * - init() has been completed
     * - setSuperNode() has been called (topology data exists)
     *
     * <h3>Concurrency Guarantee</h3>
     * This method is a read-only operation (does not modify in-memory data), supporting multi-threaded concurrent invocation.
     *
     * @param request Path planning request (§6.1)
     * @return PathPlanResult path planning result, path is valid when status=SUCCESS (§6.2)
     * @throws IllegalArgumentException request or required fields are null
     * @throws SNCStateException SNC not initialized
     */
    PathPlanResult planPath(PathPlanRequest request);

    // ============ Coverage Planning ============

    /**
     * Coverage planning (inter-chassis L1SW↔L2SW)
     *
     * Given a super node topology (including routing tables), select a set of EID pairs (src/dst NPU ports)
     * such that their forward/reverse hash route selection results traverse the L1SW↔L2SW out port set,
     * outputting EID pair → coverage link mapping and coverage rate / redundancy rate / EID uniformity statistics.
     *
     * <h3>Coverage Domain</h3>
     * <ul>
     *   <li>L1SW→L2SW: all out ports in L1SW routing with remoteDevice ∈ L2SW set (including single-port routes);</li>
     *   <li>L2SW→L1SW: ECMP out ports in L2SW routing with remoteDevice being L1SW (non-default route and out port count &gt; 1).</li>
     * </ul>
     *
     * <p>NPU↔L1SW out ports are not in this coverage domain; NPU out ports are fixed by candidate physical binding, last hop out port takes get(0).
     *
     * <h3>Result Characteristics</h3>
     * <ul>
     *   <li>{@code scope = L1_L2};</li>
     *   <li>each EID pair has 4 coverage links (2 forward + 2 reverse);</li>
     *   <li>{@code eidPairs[*].type = null}; {@code layerStats = null}; {@code coverageLinks[*].layer = null}.</li>
     * </ul>
     *
     * @param request Coverage planning request (§6.x), {@code superNodeName} required; {@code coverageRequirement} null defaults to MIN_COVERAGE
     * @return Coverage planning result; status is SUCCESS / COVERAGE_INCOMPLETE / TOPO_NOT_FOUND
     * @throws SNCStateException current state is not DATAREADY
     * @throws IllegalArgumentException request is null
     */
    CoveragePathsResult planPathsCoverage(CoveragePathsRequest request);

    /**
     * Coverage planning (extended version: including NPU↔L1SW)
     *
     * On top of {@link #planPathsCoverage} coverage domain, adds NPU↔L1SW out port coverage:
     * <ul>
     *   <li>NPU→L1SW out port selected by {@code (DstCNA, jettyId)} tuple CRC-8 hash (NPU route LPM hit entry's L1SW-direction out ports are ECMP member set);</li>
     *   <li>The selected NPU port's CNA serves as downstream SCNA, participating in L1SW→L2SW, L2SW→L1SW, L1SW→NPU hash port selection;</li>
     *   <li>L1SW→NPU last hop out port selected by hash (no longer takes get(0));</li>
     *   <li>ACK direction uses source NPU port's jettyId for route selection (same jettyId as forward), DstCNA is source CNA.</li>
     * </ul>
     *
     * <h3>Two-Phase Flow</h3>
     * <ol>
     *   <li>Phase 1 (inter-chassis CROSS_L2): enumerate cross-chassis EID pairs, trace 4-hop forward/reverse paths, greedily select EID pairs covering L1SW↔L2SW;</li>
     *   <li>Phase 2 (intra-chassis LOCAL_L1): filter out {@code layer == NPU_L1 && coverCount < required} gaps from Phase 1 results, enumerate same-chassis EID pairs and trace 2-hop forward/reverse paths to fill gaps;</li>
     *   <li>Merged statistics: after Phase 1 + Phase 2 EID pairs are merged, recompute coverage rate / redundancy rate / EID uniformity / layer statistics on the complete link domain.</li>
     * </ol>
     *
     * <h3>Result Characteristics</h3>
     * <ul>
     *   <li>{@code scope = NPU_L1_L2};</li>
     *   <li>inter-chassis EID pair has 8 coverage links (4 forward + 4 reverse, {@code type = CROSS_L2});</li>
     *   <li>intra-chassis EID pair has 4 coverage links (2 forward + 2 reverse, {@code type = LOCAL_L1});</li>
     *   <li>{@code layerStats} contains NPU_L1 / L1_L2 two layers; {@code coverageLinks[*].layer ∈ {NPU_L1, L1_L2}}; {@code coverageLinks[*].deviceType ∈ {"NPU", "SW"}}.</li>
     * </ul>
     *
     * <h3>jettyId Values</h3>
     * <p>Value range {@code [32, 1023]}, one per NPU physical port; when topology missing, falls back to {@code 32 + portId} and increments diagnostic counter {@code jettyIdFallback}.
     *
     * @param request Coverage planning request (same DTO reused with {@link #planPathsCoverage}, coverage domain determined by method name)
     * @return Coverage planning result (with scope and layerStats layer statistics)
     * @throws SNCStateException current state is not DATAREADY
     * @throws IllegalArgumentException request is null
     * @see CoverageLinkScope#NPU_L1_L2
     * @see CoverageLinkLayer
     * @see CoveragePathType
     */
    CoveragePathsResult planPathsCoverageEx(CoveragePathsRequest request);

    // ============ Link Event and Route Management ============

    /**
     * Notify link up/down event
     *
     * Update port {@code linkStatus} and {@code updateAt} (handled by {@link LinkEventService}),
     * and trigger BFS route convergence (handled by {@link RouteConvergeService#converge}): propagates reachability
     * changes between interconnected forwarding nodes, refreshes {@code OutPortInfo.convergedFlag}
     * (down=set PASSIVE, up=clear PASSIVE) and {@code RoutingEntry.reachable}.
     *
     * <h3>Convergence Algorithm</h3>
     * <ol>
     *   <li>Locate the event port's chip C, iterate RoutingEntry with this port as out port in the "device#C" routing table, refresh the hit OutPortInfo.convergedFlag;</li>
     *   <li>Call {@link RoutingEntry#refreshReachable()} to refresh reachability, record prefixes with reachable changes;</li>
     *   <li>If reachable changed, iterate other up ports on chip C, locate peer forwarding node's in-interface via PortEntity.remoteDevice/remotePort;</li>
     *   <li>On peer forwarding node, locate the in-interface's chip C', query changed prefixes in "peerDevice#C'" routing table, refresh OutPortInfo status for out port being in-interface and refresh reachable;</li>
     *   <li>Iterate until no more forwarding node route reachable changes need propagation (BFS).</li>
     * </ol>
     *
     * <p>Different forwardingChips of the same device are forwarding-isolated; convergence propagates only within the port's chip routing table.
     * The target is the {@code instantiationRouteMap} held by SNCService (populated by {@link #makeRoutes}),
     * convergence results affect subsequent {@link #getNodeRoute} queries.
     *
     * @param supernode The super node the link event belongs to
     * @param event Link event (deviceName + portName + eventType + eventTime)
     * @throws IllegalArgumentException supernode/event is null, or event required fields are null/empty, or eventType is not "up"/"down"
     * @throws IllegalStateException device or port does not exist in topology
     * @throws SNCStateException SNC is in INIT/UNINIT state
     */
    void notifyLinkEvent(SuperNode supernode, LinkEvent event);

    /**
     * Route calculation (based on built-in topology template)
     *
     * Synchronized method: parses built-in topology templates ({@code 128_npu_rack.json}, {@code 128_npu_inter_rack.json}),
     * calls {@link RouteMspService#routeMsp} to generate template routes by shortest path policy,
     * then calls {@link RouteInstantiationService#instantiateXpodRoute} to instantiate per chassis, populating {@code routes}.
     *
     * <h3>Idempotency</h3>
     * <p>If already calculated, returns directly ({@code routeCalculated == true}); repeated calls are safe with no side effects.
     *
     * <h3>Invocation Order</h3>
     * <p>Must be called before {@link #makeRoutes}, otherwise {@code makeRoutes} throws {@link IllegalStateException}.
     * Does not depend on SuperNode being provisioned: can be called at any time (non INIT/UNINIT) after init.
     *
     * @throws SNCStateException SNC is in INIT/UNINIT state
     */
    void routeCalculate();

    /**
     * Route instantiation (generate instantiated routing tables for SuperNode based on already-calculated route templates)
     *
     * Iterate NPU/L1SW/L2SW devices in SuperNode, match template route labels by device type and chassis/index,
     * convert to {@code Map<String, RoutingEntry>} (key = route prefix IP) via {@link RouteInstantiationService},
     * store in {@code instantiationRouteMap} (key = {@code "deviceName#chipIndex"}) and return a copy.
     *
     * <h3>Instantiation Rules</h3>
     * <ul>
     *   <li>NPU: match template by {@code chassis/slot/ubpu/die} labels;</li>
     *   <li>L1SW: match by {@code chassis/index} labels;</li>
     *   <li>L2SW: match by {@code index/chip} labels, 4-chassis instantiation remaps L2SW out port index/name per inter-chassis topology.</li>
     * </ul>
     *
     * <p>Deep copy ensures internal {@code instantiationRouteMap} and return value do not affect each other
     * ({@link RouteInstantiationService#deepCopyRoutingEntry}).
     *
     * @param superNode Already provisioned super node topology
     * @return Instantiated routing tables (key = "deviceName#chipIndex", value = route prefix → RoutingEntry mapping for that chip)
     * @throws IllegalArgumentException superNode is null, or device has no forwardingChips
     * @throws IllegalStateException {@link #routeCalculate} not called
     * @throws SNCStateException SNC is in INIT/UNINIT state
     */
    Map<String, Map<String, RoutingEntry>> makeRoutes(SuperNode superNode);

    /**
     * Query single device single chip instantiated routing table
     *
     * Read the routing table for the specified device and chip from {@code instantiationRouteMap}.
     * Typical use: query converged reachability state after route convergence ({@link #notifyLinkEvent}).
     *
     * @param deviceName Device unique identifier
     * @param chipIndex Chip index
     * @return Route prefix → RoutingEntry mapping for that chip
     * @throws IllegalArgumentException deviceName is null, or key does not exist
     * @throws SNCStateException SNC is in INIT/UNINIT state
     */
    Map<String, RoutingEntry> getNodeRoute(String deviceName, int chipIndex);
}
```

**Method Summary Table:**

| Method | Input | Output | Type | Thread-safe | Description |
|:-----|:-----|:-----|:-----|:--------|:-----|
| init | SNCConfig | void | Synchronous | No (initialization phase) | Load configuration, initialize in-memory structures |
| uninit | - | void | Synchronous | No (cleanup phase) | Clear data, release resources |
| setSuperNode | SuperNode | void | Synchronous | No (write operations require serialization) | Full replacement of topology data |
| addNpuDevices | String, List\<NpuDevice\> | void | Synchronous | No (write operations require serialization) | Incremental batch add NPU devices |
| addSwDevices | String, List\<SwDevice\> | void | Synchronous | No (write operations require serialization) | Incremental batch add SW devices |
| removeDevices | String, List\<String\> | void | Synchronous | No (write operations require serialization) | Incremental batch remove devices |
| addRoutingEntries | String, String, Integer, List\<RoutingEntry\> | void | Synchronous | No (write operations require serialization) | Incremental batch add/update route entries |
| removeRoutingEntries | String, String, Integer, List\<RoutePrefix\> | void | Synchronous | No (write operations require serialization) | Incremental batch remove route entries |
| getSuperNode | String | SuperNode | Synchronous | Yes (read-only, concurrent) | Query topology data by superNodeName |
| removeSuperNode | String | void | Synchronous | No (write operations require serialization) | Delete topology data and associated routing tables by superNodeName |
| planPath | PathPlanRequest | PathPlanResult | Synchronous | Yes (read-only, concurrent) | Single path planning |
| planPathsCoverage | CoveragePathsRequest | CoveragePathsResult | Synchronous | No (internally enumerates EID pairs, recommend serialization) | Coverage planning (L1↔L2 out port domain) |
| planPathsCoverageEx | CoveragePathsRequest | CoveragePathsResult | Synchronous | No (two-phase enumerates EID pairs, recommend serialization) | Coverage planning extended (NPU↔L1↔L2, including jettyId hash) |
| notifyLinkEvent | SuperNode, LinkEvent | void | Synchronous | No (modifies port status + triggers BFS route convergence, requires serialization) | Notify link up/down event, refresh OutPortInfo.convergedFlag and RoutingEntry.reachable |
| routeCalculate | - | void | Synchronous | No (synchronized, idempotent) | Parse built-in topology template, compute MSP template routes; must be before makeRoutes |
| makeRoutes | SuperNode | Map\<String, Map\<String, RoutingEntry\>\> | Synchronous | No (fills instantiationRouteMap, requires serialization) | Instantiate template routes per chassis; depends on routeCalculate completed |
| getNodeRoute | String, int | Map\<String, RoutingEntry\> | Synchronous | Yes (read-only, concurrent) | Query single device single chip routing table from instantiationRouteMap |

---

### 7.3 Invocation Sequence

```
Northbound Caller                                     SNCService
   │                                                   │
   │── init(config) ──────────────────────────────────▶│  Phase 1: Initialization
   │◀── void ────────────────────────────────────────│
   │                                                   │
   │── setSuperNode(superNode) ────────────────────────▶│  Phase 2: Topology provisioning
   │◀── void ────────────────────────────────────────│
   │                                                   │
│── planPath(request1) ────────────────────────────▶│  Phase 3a: Path planning
│◀── PathPlanResult { status=0, path=... } ───────│ (can be called concurrently multiple times)
│                                                   │
│── planPath(request2) ────────────────────────────▶│
│◀── PathPlanResult { status=1010, ... } ─────────│
│                                                   │
│── planPathsCoverage(req) ────────────────────────▶│  Phase 3b: Coverage planning (L1↔L2)
│◀── CoveragePathsResult { scope=L1_L2, ... } ────│
│                                                   │
│── planPathsCoverageEx(req) ──────────────────────▶│  Phase 3c: Coverage planning extended (NPU↔L1↔L2)
│◀── CoveragePathsResult { scope=NPU_L1_L2, ... } ─│
│                                                   │
│── routeCalculate() ──────────────────────────────▶│  Phase 3d-1: Route template calculation (idempotent)
│◀── void ────────────────────────────────────────│  Parse 128_npu_rack.json + 128_npu_inter_rack.json
│                                                   │
│── makeRoutes(superNode) ─────────────────────────▶│  Phase 3d-2: Route instantiation
│◀── Map<dev#chip, Map<prefix, RoutingEntry>> ────│  Fill instantiationRouteMap
│                                                   │
│── getNodeRoute("rack1#os0#npu1", 0) ──────────────▶│  Phase 3d-3: Query single device route
│◀── Map<prefix, RoutingEntry> ───────────────────│
│                                                   │
│── notifyLinkEvent(superNode, event) ──────────────▶│  Phase 3e: Link event notification
│◀── void ────────────────────────────────────────│  Triggers BFS route convergence
│                                                   │
│── getSuperNode("A5-superPod-1") ──────────────────▶│  Phase 4: Data query
│◀── SuperNode { name="A5-superPod-1", ... } ──────│
│                                                   │
│── removeSuperNode("A5-superPod-1") ───────────────▶│  Phase 5: Data deletion
│◀── void ────────────────────────────────────────│
│                                                   │
│── uninit() ──────────────────────────────────────▶│  Phase 6: Deinitialization
│◀── void ────────────────────────────────────────│
   │                                                   │
```

> **Notes:**
> - setSuperNode must be completed before planPath / planPathsCoverage / planPathsCoverageEx (state transitions to DATAREADY).
> - routeCalculate must be called before makeRoutes (idempotent, safe to repeat); getNodeRoute can only be used after makeRoutes completes.
> - notifyLinkEvent depends on the instantiationRouteMap populated by makeRoutes for route convergence.
> - Coverage domain differences for planPathsCoverage / planPathsCoverageEx see §7.2 method description.

---

### 7.4 State Machine

The SNC service internally maintains the following lifecycle states:

```
         init()                          uninit()
  INIT ──────────▶ READY ──(setSuperNode completed)──▶ DATAREADY
   │                                │                                 │
   │                                │ Incremental operations (add/remove/get/…) │ planPath (can be called concurrently)
   │                                │ setSuperNode                     │ planPathsCoverage / planPathsCoverageEx
   │                                │ routeCalculate                   │ setSuperNode (can update)
   │                                │ makeRoutes                       │ Incremental operations (add/remove/get/…)
   │                                │ getNodeRoute                     │ routeCalculate / makeRoutes / getNodeRoute
   │                                │ notifyLinkEvent                  │ notifyLinkEvent
   │                                │ uninit()                         │ uninit()
   │                                │                                 │
   └──── uninit() ───▶ UNINIT ◀───────────────────────────────────────┘
```

| State | Description | Allowed Operations |
|:-----|:-----|:----------|
| INIT | Initial state (not initialized) | init(), uninit() |
| READY | Ready state (initialized, data not ready) | setSuperNode; all incremental operations (addNpuDevices, addSwDevices, removeDevices, addRoutingEntries, removeRoutingEntries); all query operations (getSuperNode); removeSuperNode; routeCalculate, makeRoutes, getNodeRoute, notifyLinkEvent; uninit |
| DATAREADY | Data ready state (topology provisioned) | Same as READY, plus planPath, planPathsCoverage, planPathsCoverageEx |
| UNINIT | Deinitialized | (None, calling any operation throws SNCStateException) |

**State Transition Rules:**
- `init()`: INIT → READY (non-idempotent, repeated init rebuilds all internal objects)
- `uninit()`: INIT / READY / DATAREADY → UNINIT (calling in INIT state only clears state flag, no side effects)
- `setSuperNode()`: READY → DATAREADY (auto-transitions when topology data is provisioned)
- `setSuperNode()`: DATAREADY → DATAREADY (data ready state can continue updating data)
- `planPath()` / `planPathsCoverage()` / `planPathsCoverageEx()`: Only available in **DATAREADY** state; returns SNCStateException when not in DATAREADY
- `routeCalculate()` / `makeRoutes()` / `getNodeRoute()` / `notifyLinkEvent()`: **READY / DATAREADY** both OK, only requires SNC initialized (non INIT/UNINIT); does not depend on SuperNode being provisioned (routeCalculate does not read SuperNode; makeRoutes requires SuperNode parameter)

---

### 7.5 Error Handling

#### 7.5.1 Return Status Codes

All path planning error codes are returned via `PathPlanResult.status` (`PlanStatus` enum):

| Error Code | Enum Constant | Description | Trigger Phase |
|:------:|:--------|:-----|:--------|
| 0 | `SUCCESS` | Success | - |
| 1003 | `SRC_INFO_ERR` | Source info missing or incorrect | Step 1 |
| 1004 | `DST_INFO_ERR` | Destination info missing or incorrect | Step 2 |
| 1007 | `TOPO_INCOMPLETE` | Topology incomplete (device not found in super node devices) | Step 0 / Step 3~5 |
| 1008 | `TOPO_CONNECTION_ERROR` | Topology connection error (direct connection validation failed) | Step 4 |
| 1009 | `TOPO_CONNECTION_NOT_FOUND` | Topology connection not found (multi-hop path resolution failed) | Step 5 |
| 1010 | `ROUTE_NOT_REACHABLE` | Route not reachable (indexed mask match missed or route entry has no out port) | Step 8 |
| 1011 | `COVERAGE_INCOMPLETE` | Coverage planning incomplete: after enumerating all candidate EID pairs, still could not reach the minimum coverage rate required by `coverageRequirement` (only returned by `planPathsCoverage` / `planPathsCoverageEx`; result still contains selected EID pairs and statistics, caller decides whether to accept) | planPathsCoverage / planPathsCoverageEx |
| 1012 | `TOPO_NOT_FOUND` | Topology data not found (superNodeName is empty or corresponding SuperNode does not exist); also used in `planPathsCoverage` / `planPathsCoverageEx` / `notifyLinkEvent` for SuperNode missing scenarios | Step 0 / Coverage planning / Link event |
| 3002 | `SRC_AND_DST_MUST_BE_NPU` | Source and destination must be NPU | Step 0 |
| 3003 | `UPI_MISMATCH` | Source and destination port UPI mismatch | Step 0 |

> **Complete Enum Definition:** [§6.2 PathPlanResult.PlanStatus](#62-pathplanresult-path-planning-response). The complete enum values correspond 1:1 to `com.huawei.umdk.snc.dto.PathPlanResult.PlanStatus`.

**Error Code Encoding Rules:**
- `0`: Success
- `1xxx`: Path planning phase errors (device/port/route/topology related)
- `3xxx`: Parameter validation errors

**Layer-by-layer Processing Principles:**

| Layer | Processing Strategy |
|:---------|:---------------------------------------------------------------|
| Northbound interface | Catch all exceptions, convert to unified error response (error code + error message) |
| service | Do not swallow exceptions, throw PathPlanException with explicit error code upward |
| engine | Throw specific exceptions (route unreachable, route not found, etc.), do not handle business logic |
| store | Return null or Optional when data does not exist, service layer judges and converts to exceptions |

**Northbound Error Response Format:**

All northbound interfaces should return the following structure when an exception occurs:

```json
{
    "code": 1001,
    "message": "Source EID not found",
    "detail": "deviceName=rack1#os#npu1 not found in superNode"
}
```


**Parameter Validation:**

- **Required field validation:** Required fields in input parameters (such as deviceName, srcPort, etc.) are validated uniformly at the service layer entry point; null or empty strings immediately return parameter errors.
- **Format validation:** deviceName format, EID length (128 bit), CNA range (32 bit), etc. are validated by utility classes in the `util` package.
- **Business rule validation:** Business rules such as device type must be NPU are validated in the engine layer.

#### 7.5.2 Exception System

```
SNCException (base exception)
├── SNCStateException        // State exception (not initialized, deinitialized, duplicate initialization)
├── SuperNodeNotFoundException    // Topology data not found
└── PathPlanException        // Path planning failure (contains PlanStatus error code and description)
```

| Exception Class | Usage Scenario | Handling Method |
|:-------|:--------|:--------|
| `SNCStateException` | Illegal invocation order (calling planPath without init, calling after uninit, etc.) | Throw directly, northbound caller catches and handles |
| `IllegalArgumentException` | Input parameter is null, required fields missing | Entry validation, throw directly |
| `SuperNodeNotFoundException` | setSuperNode not called or topology data incomplete (including superNodeName not existing and device not found) | Service layer converts to error code 1012/1001/1002/1007 |
| `PathPlanException` | Any business failure during planPath execution | Contains PlanStatus, northbound interface converts to PathPlanResult |

#### 7.5.3 Error Propagation Chain

```
Northbound Caller
    ↑ Get error code via PathPlanResult.status, description via .errorMessage
Northbound Interface Layer (SNCServiceImpl)
    ↑ Catch SNCException, convert to PathPlanResult { status=error code, errorMessage=description }
Service Layer
    ↑ Throw corresponding exception based on null / validation failure
Engine / Store Layer
    ↑ Return null / throw low-level exception
```

---

### 7.6 Parameter Validation Rules

Parameter validation is performed uniformly at the northbound interface entry point (`SNCServiceImpl`).

| Validation Item | Validation Content | Violation Handling |
|:-------|:--------|:--------|
| `superNode` non-null | `setSuperNode(SuperNode)` input parameter | Throw `IllegalArgumentException` |
| `superNode.name` non-empty | Super node name is required (§4.1) | Throw `IllegalArgumentException` |
| `superNode.devices` non-empty | Device Map is required (§4.1) | Throw `IllegalArgumentException` |
| `request` non-null | `planPath(PathPlanRequest)` input parameter | Throw `IllegalArgumentException` |
| `request.superNodeName` non-empty | Super node name is required (§6.1), used for multi-super-node scenario positioning | Throw `IllegalArgumentException` |
| `request.srcDevice` non-empty | Source device is required (§6.1) | Throw `IllegalArgumentException` |
| `request.destDevice` non-empty | Destination device is required (§6.1) | Throw `IllegalArgumentException` |
| `request.srcPort` non-empty | Source port is required (§6.1) | Throw `IllegalArgumentException` |
| `request.destPort` non-empty | Destination port is required (§6.1) | Throw `IllegalArgumentException` |
| `superNodeName` non-empty | `getSuperNode(String)` / `removeSuperNode(String)` input parameter | Throw `IllegalArgumentException` |
| deviceName format | `rack#os#npu` or `rack#l1sw0` format | Engine layer validation, returns error code 1003/1004 |

> **Business rule validation** (device type must be NPU, EID/CNA completeness, etc.) is performed in the engine layer, not at the entry point.

---

### 7.7 Interface Implementation Mapping

The `SNCServiceImpl` implementation class delegates interface methods to internal components:

```
SNCServiceImpl
    │
    ├── init(SNCConfig)
    │     └→ SuperNodeStore.init()  // Initialize HashMap
    │
    ├── setSuperNode(SuperNode)
    │     └→ SuperNodeService.importSuperNode(superNode)
    │              └→ SuperNodeStore.replace(superNode)  // Full replacement of topology index
    │
    ├── addNpuDevices(String, List<NpuDevice>)
    │     └→ SuperNodeService.addNpuDevices(superNodeName, devices)     // Loop calls store.addNpuDevice()
    │              └→ SuperNodeStore.addNpuDevice(superNodeName, device)  // Incremental add NPU device and routing table index
    │
    ├── addSwDevices(String, List<SwDevice>)
    │     └→ SuperNodeService.addSwDevices(superNodeName, devices)     // Loop calls store.addSwDevice()
    │              └→ SuperNodeStore.addSwDevice(superNodeName, device)  // Incremental add SW device and routing table index
    │
    ├── removeDevices(String, List<String>)
    │     └→ SuperNodeService.removeDevices(superNodeName, deviceNames)       // Loop calls store.removeDevice()
    │              └→ SuperNodeStore.removeDevice(superNodeName, deviceName)  // Remove device from npuDevices/swDevices and routing table index
    │
    ├── addRoutingEntries(String, String, Integer, List<RoutingEntry>)
    │     └→ SuperNodeService.addRoutingEntries(superNodeName, deviceName, chipIndex, entries) // Loop calls store.addRoutingEntry()
    │              └→ SuperNodeStore.addRoutingEntry(superNodeName, deviceName, chipIndex, prefix, entry)  // Incremental add/update route (single entry)
    │
    ├── removeRoutingEntries(String, String, Integer, List<RoutePrefix>)
    │     └→ SuperNodeService.removeRoutingEntries(superNodeName, deviceName, chipIndex, prefixes) // Loop calls store.removeRoutingEntry()
    │              └→ SuperNodeStore.removeRoutingEntry(superNodeName, deviceName, chipIndex, prefix)  // Incremental delete route (single entry)
    │
    ├── getSuperNode(String)
    │     └→ SuperNodeStore.getSuperNode(superNodeName)        // Query topology data
    │
    ├── removeSuperNode(String)
    │     └→ SuperNodeStore.removeSuperNode(superNodeName)     // Delete topology data and associated routing tables
    │
    ├── planPath(PathPlanRequest)
    │     └→ PathService.planPath(request)
    │              ├→ PathEngine.resolvePath()      // Path resolution (Step 3~5)
    │              ├→ RouteLookupEngine.lookup()    // Path planning (Step 6~8)
    │              └→ Assemble PathPlanResult            // Output construction (Step 9~10)
    │
    ├── planPathsCoverage(CoveragePathsRequest)
    │     └→ PathService.planPathsCoverage(request)
    │              ├→ SuperNodeStore.getSuperNode(superNodeName)   // Topology lookup
    │              ├→ new CoveragePlanEngine(superNode, hashFunc, ...)  // Construct engine
    │              ├→ engine.findCoverage(requirement)             // L1↔L2 coverage
    │              └→ Assemble CoveragePathsResult { scope=L1_L2, ... }
    │
    ├── planPathsCoverageEx(CoveragePathsRequest)
    │     └→ PathService.planPathsCoverageEx(request)
    │              ├→ SuperNodeStore.getSuperNode(superNodeName)
    │              ├→ new CoveragePlanEngine(superNode, hashFunc, dieHashFuncSelect, ...)
    │              ├→ engine.findCoverageEx(requirement)          // Two phases: CROSS_L2 + LOCAL_L1
    │              └→ Assemble CoveragePathsResult { scope=NPU_L1_L2, layerStats=[...], ... }
    │
    ├── notifyLinkEvent(SuperNode, LinkEvent)
    │     └→ LinkEventService.handleLinkEvent(superNode, event)
    │              ├→ port.setLinkStatus(LINK_UP/LINK_DOWN) + port.setUpdateAt(eventTime)
    │              └→ RouteConvergeService.converge(superNode, deviceName, chipIndex, portName, isDown)
    │                       ├→ OutPortInfo.setFlag/clearFlag(FLAG_PASSIVE_CONVERRGED)
    │                       ├→ RoutingEntry.refreshReachable()
    │                       └→ BFS propagate to peer forwarding node
    │
    ├── routeCalculate()
    │     └→ synchronized { if (routeCalculated) return; }
    │              ├→ TopoTemplateService.parseTemplateFile("128_npu_rack.json")
    │              ├→ TopoTemplateService.parseTemplateFile("128_npu_inter_rack.json")
    │              ├→ RouteMspService.routeMsp(topoTemplate)             // BFS shortest path
    │              ├→ RouteInstantiationService.buildXpodRoutes(template) // Template routing table
    │              └→ routeCalculated = true
    │
    ├── makeRoutes(SuperNode)
    │     └→ if (!routeCalculated) throw IllegalStateException
    │     └→ RouteInstantiationService.instantiateXpodRoute(routes, superNode)
    │              ├→ Iterate NPU/L1SW/L2SW devices to match template by labels
    │              ├→ deepCopyRoutingEntry(...)                         // Deep copy
    │              └→ instantiationRouteMap.put("deviceName#chipIndex", routingEntryMap)
    │                  Return a copy of instantiationRouteMap
    │
    ├── getNodeRoute(String, int)
    │     └→ instantiationRouteMap.get("deviceName#chipIndex")          // Direct HashMap lookup
    │
    └── uninit()
            └→ SuperNodeStore.clear()  // Clear data
```

### 7.8 Invalid Invocation Order Description

The following invocation sequences are illegal, and SNC should return an error:

| Invalid Sequence | Error Reason | Suggested Handling |
|:--------------------------------------|:----------------------------------|:--------------------|
| Calling other interfaces without `init()` | Internal data structures not initialized | Throw SNCStateException |
| Calling other interfaces after `uninit()` | Already deinitialized, in-memory data cleared | Throw SNCStateException |
| Calling `planPath()` / `planPathsCoverage()` / `planPathsCoverageEx()` without provisioning topology data | State not DATAREADY | Throw SNCStateException |
| Repeated `init()` without calling `uninit()` | State machine duplicate initialization | Idempotent handling or throw exception |
| Calling `makeRoutes()` without calling `routeCalculate()` first | Template routes not calculated, cannot instantiate | Throw IllegalStateException |
| Calling `getNodeRoute()` / `notifyLinkEvent()` without calling `makeRoutes()` first | instantiationRouteMap is empty | Throw IllegalStateException / return key does not exist |
| `notifyLinkEvent()` `deviceName` + `portName` not found in topology | Device or port does not exist | Throw IllegalStateException |
| `notifyLinkEvent()` `eventType` is not "up"/"down" | Invalid parameter | Throw IllegalArgumentException |



---

### 7.9 SuperNodeStore (Topology Storage)

The core storage layer for topology data, maintaining the super node → topology data primary index and the global routing table index.

```java
public class SuperNodeStore {
    /** Topology data primary index -- Map key is SuperNode.name (superNodeName, §4.1), supporting multi-super-node scenarios */
    private Map<String, SuperNode> superNodeMap;

    /** Routing table global index -- Map key is RoutingTableKey (superNodeName + deviceName + chipIndex, §4.7.1) */
    private Map<RoutingTableKey, RoutingTable> routingTableMap;

    // ========== Lifecycle Methods ==========

    /**
     * Initialize storage
     * <p>Create empty HashMap instances for subsequent replace to fill with data.
     */
    public void init() {
        this.superNodeMap = new HashMap<>();
        this.routingTableMap = new HashMap<>();
    }

    /**
     * Full replacement of topology data
     * <p>Parse SuperNode (§4.1) and write the following data into indexes:
     * <ol>
     *   <li>Store SuperNode object in superNodeMap with superNode.name as key</li>
     *   <li>Remove all old routing table entries belonging to this superNodeName from routingTableMap</li>
     *   <li>Iterate all devices of superNode (via getAllDevices()), extract each chip's RoutingTable to routingTableMap:
     *       <br>key = construct RoutingTableKey(superNode.name, device.deviceName, chip.chipIndex)
     *       <br>value = the chip's RoutingTable object</li>
     * </ol>
     *
     * @param superNode Topology data (§4.1), requires name non-empty, npuDevices or swDevices at least one non-empty
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
     * Clear all stored data
     * <p>Call superNodeMap.clear() and routingTableMap.clear() to release memory.
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
     * Delete topology data and associated routing tables for the specified super node
     *
     * <p>Remove the SuperNode corresponding to the specified superNodeName from superNodeMap,
     * and clear all routing table entries belonging to this superNodeName from routingTableMap.
     *
     * @param superNodeName Super node name (§4.1 SuperNode.name)
     */
    public void removeSuperNode(String superNodeName) {
        superNodeMap.remove(superNodeName);
        // Remove all entries in routingTableMap where superNodeName matches
        routingTableMap.keySet().removeIf(key -> superNodeName.equals(key.getSuperNodeName()));
    }

    // ========== Query Methods ==========

    /**
     * Get topology data by superNodeName
     *
     * @param superNodeName Super node name (§4.1 SuperNode.name)
     * @return SuperNode object, returns null if not exists
     */
    public SuperNode getSuperNode(String superNodeName) {
        return superNodeMap.get(superNodeName);
    }

    /**
     * Get routing table by composite key
     *
     * @param key RoutingTableKey (superNodeName + deviceName + chipIndex, §4.7.1)
     * @return RoutingTable object, returns null if not exists
     */
    public RoutingTable getRoutingTable(RoutingTableKey key) {
        return routingTableMap.get(key);
    }
}
```

**Design Notes:**

| Feature | Description |
|:-----|:-----|
| Primary index `superNodeMap` | Keyed by `superNodeName`, O(1) locate super node, supporting multi-super-node coexistence |
| Routing table index `routingTableMap` | Keyed by `RoutingTableKey` (superNodeName + deviceName + chipIndex), globally O(1) lookup of any device chip's routing table |
| `replace()` strategy | Full replacement: first clear old routing table index, then re-index all devices. Uses `getMutableAllDevices()` to uniformly iterate npuDevices and swDevices |
| `clear()` strategy | Call Map.clear() to clear memory, no data retained |
| Routing table extraction | `replace()` uses `indexRoutingTable()` private method to iterate device→chip hierarchy (via `device.getForwardingChips()` abstract method to iterate all forwarding chips), extract RoutingTable and update maskLengths. In input JSON, routingTables is at device level, injected by deserializer into ForwardingChip.routingTable |
| `addNpuDevice()` | Incremental add NPU device to `npuDevices` Map, while calling `indexRoutingTable()` to index its routing table. If `npuDevices` is null, automatically create new HashMap |
| `addSwDevice()` | Incremental add SW device to `swDevices` Map, while calling `indexRoutingTable()` to index its routing table. If `swDevices` is null, automatically create new HashMap |
| `removeDevice()` | Try removing specified deviceName from both `npuDevices` and `swDevices` Maps, and clear corresponding routing table entries in routingTableMap |

**Query Flow Example:**
```
// Step 0: Locate super node
SuperNode superNode = superNodeStore.getSuperNode(request.getSuperNodeName());

// Step 8: Lookup routing table
RoutingTableKey rtKey = new RoutingTableKey(superNodeName, deviceName, chipIndex);
RoutingTable rt = superNodeStore.getRoutingTable(rtKey);
```

---

## 8 Algorithm

### 8.1 Algorithm Description

A level-by-level longest prefix match algorithm based on pre-indexed masks. Internally records mask lengths from external route input (e.g., 32 for detailed routes, 20 for chassis-level routes), and during lookup only tries these known masks level by level, directly locating via HashMap O(1) hit.

**Design Note:** This algorithm is consistent with §4.7/§4.8 — `RoutingTable` internally maintains a `maskLengths` list (deduplicated, sorted descending), and during lookup uses this list to construct keys from longest mask to shortest mask for HashMap O(1) queries, without full table traversal.

**Input:** `targetAddr` (32 bit); `RoutingTable` (containing `routes` Map and `maskLengths` list).

**Prerequisites:**
- `RoutingTable.maskLengths` has been maintained by the engine during routing table construction/update, guaranteed to contain all deduplicated descending values of `RoutePrefix.maskLength` from the current routing table.

**Lookup Steps:**
1. Take the current longest (i.e., first) mask `maskLen` from `RoutingTable.maskLengths` (mask list is sorted from longest to shortest)
2. Call `AddressUtils.applyMask(targetAddr, maskLen)` to bitwise AND `targetAddr` with `maskLen`, yielding `networkAddr`
3. Construct `RoutePrefix(networkAddr, maskLen)` as key, execute `get(key)` in `RoutingTable.routes` Map — **O(1) hit**
4. If hit → return the corresponding `RoutingEntry` (since maskLen is already the current longest, the current hit is the longest prefix match for this table)
5. If not hit → take the next mask from `maskLengths`, repeat steps 2~4
6. If all known masks miss → try default route (`0.0.0.0/0`) — if `maskLengths` does not yet include 0, take `maskLen=0` and construct `RoutePrefix("0.0.0.0", 0)` for one final O(1) lookup; if 0 is already included, it has been covered in the loop, no need to repeat
7. If default route also misses → return route not found (error)

**Algorithm Example:**
```
Routing table entries:
├── {dstAddress="170.170.170.0", maskLen=24} → eth0
├── {dstAddress="170.170.0.0",   maskLen=16} → eth1
└── {dstAddress="0.0.0.0",       maskLen=0}  → wan

Routing table maskLengths (engine auto-extracted): [24, 16, 0]

Lookup target targetAddr = 170.170.170.17 (32 bit)

Round 1: take maskLen=24 (longest)
   applyMask("170.170.170.17", 24) → "170.170.170.0"
   Construct RoutePrefix("170.170.170.0", 24) → routes.get(prefix) → hit eth0 ✅
   Return directly, no need to continue trying subsequent masks.

Matched entry: A(maskLen=24) → return eth0 ✅
```

**Edge Case Example (missed longest, hit next-longest):**
```
Lookup target targetAddr = 170.170.171.17 (32 bit)

Round 1: take maskLen=24
   applyMask("170.170.171.17", 24) → "170.170.171.0"
   RoutePrefix("170.170.171.0", 24) → routes.get → missed ❌

Round 2: take maskLen=16
   applyMask("170.170.171.17", 16) → "170.170.0.0"
   RoutePrefix("170.170.0.0", 16) → routes.get → hit eth1 ✅
   Return.
```

**Complexity:**
- Lookup count = `maskLengths.size()`, i.e., the number of deduplicated mask types m actually existing in the routing table. Typical scenarios m = 2~3 (e.g., only /32 detailed routes and /20 chassis-level routes)
- Each round of query is O(1) HashMap get. Overall complexity **O(m)**, m = mask type count (usually ≤ 5)
- Compared to full table traversal O(n) (n = route entry count, can reach hundreds), **lookup efficiency is significantly improved and does not degrade as routing table scale grows**

### 8.2 Engine Interface

> **Corresponds to `engine/RouteLookupEngine.java` in the §3.2 package structure**

```java
package com.huawei.umdk.snc.engine;

import com.huawei.umdk.snc.entity.RoutePrefix;
import com.huawei.umdk.snc.entity.RoutingEntry;
import java.util.List;
import java.util.Map;

/**
 * Path planning engine — Indexed Mask Match
 *
 * <h3>Responsibility</h3>
 * Receives a 32-bit targetAddr and a routing table (with maskLengths list),
 * executes the level-by-level O(1) lookup algorithm by known masks described in §8.1,
 * returning the longest matching RoutingEntry.
 *
 * <h3>Caller</h3>
 * PathService → RouteLookupEngine, corresponding to §9.4 Phase 3 Step 8.
 */
public class RouteLookupEngine {

    /**
     * Indexed mask match lookup
     *
     * <p>Takes the current longest mask from maskLengths (sorted descending),
     * bitwise ANDs targetAddr with that mask to get networkAddr,
     * constructs RoutePrefix(networkAddr, maskLen) for O(1) lookup in routes.
     * Returns on hit; tries next mask if not hit.
     *
     * @param targetAddr  32-bit target address
     * @param routes      Routing table Map, key is RoutePrefix (contains dstAddress + maskLength), value is RoutingEntry
     * @param maskLengths List of mask lengths actually existing in the routing table (deduplicated, sorted descending),
     *                    maintained by the engine during routing table construction
     * @return Longest matching RoutingEntry; returns null if no match (caller handles default route/error logic)
     */
    public RoutingEntry lookup(String targetAddr, Map<RoutePrefix, RoutingEntry> routes,
                               List<Integer> maskLengths) {
        // Implementation details in §8.1 algorithm steps 1~7
    }
}
```

### 8.3 Coverage Planning Algorithm (CoveragePlanEngine)

> **Corresponds to `engine/CoveragePlanEngine.java` in the §3.2 package structure** (~2882 lines)

#### 8.3.1 Algorithm Overview

Given a super node topology (including routing tables) and coverage requirement (MIN_COVERAGE / REDUNDANT), greedily select a set of EID pairs from NPU port EID cartesian product such that their forward/reverse hash route selection paths traverse all out ports in the coverage domain. `planPathsCoverage` and `planPathsCoverageEx` share the same engine; the difference is only whether the coverage domain includes NPU↔L1SW:

| Method | Engine Entry | Coverage Domain | Hash Usage Points |
|:-----|:---------|:-------|:-----------|
| planPathsCoverage | findCoverage | L1SW↔L2SW (2 of 4-hop path: L1SW→L2SW, L2SW→L1SW) | H3a/H3b, H5a/H5b |
| planPathsCoverageEx | findCoverageEx | NPU↔L1SW↔L2SW (all 4 segments of 4-hop path + 2-hop intra-chassis path) | H1/H2, H3a/H3b, H4, H5a/H5b, H6, H7a/H7b |

#### 8.3.2 Hash Usage Points

| ID | Location | Input | Hash Function | Output Port |
|:---|:-----|:-----|:---------|:-------|
| H1 | NPU→L1SW (forward) | `(DstCNA, jettyId)` | `ubswitch_Hash_dieEcmp` (CRC-8/ATM) | L1SW-direction ECMP out ports of NPU route LPM hit entry |
| H2 | NPU→L1SW (ACK) | `(sourceCNA, source port jettyId)` | `ubswitch_Hash_dieEcmp` | Same as H1, but jettyId uses source NPU port |
| H3a | L1SW→L2SW (forward) | `(DstCNA, ...)` | `ubswitch_Hash_ecmp` | L2SW-direction out ports of L1SW route LPM hit entry |
| H3b | L1SW→L2SW (ACK) | Same as H3a, reverse direction | `ubswitch_Hash_ecmp` | - |
| H4 | L1SW→NPU (forward, extended version) | `(DstCNA, ...)` | `ubswitch_Hash_ecmp` | NPU-direction out ports of L1SW route LPM hit entry (no longer get(0)) |
| H5a | L2SW→L1SW (forward) | `(DstCNA, ...)` | `ubswitch_Hash_ecmp` | L1SW-direction ECMP out ports of L2SW route LPM hit entry |
| H5b | L2SW→L1SW (ACK) | Same as H5a | `ubswitch_Hash_ecmp` | - |
| H6 | L1SW→L2SW (intra-chassis ACK) | `(sourceCNA, ...)` | `ubswitch_Hash_ecmp` | - |
| H7a/H7b | L1SW→NPU (intra-chassis forward/reverse) | `(DstCNA/sourceCNA, ...)` | `ubswitch_Hash_ecmp` | - |

> Note: planPathsCoverage does not use H1/H2/H4/H6/H7 (only L1↔L2 coverage domain), last hop out port takes get(0).

#### 8.3.3 SCNA Chaining

When `planPathsCoverageEx` enumerates inter-chassis EID pairs in Phase 1, the selected NPU port's CNA (source CNA) serves as the DstCNA (i.e., SCNA) for downstream L1SW/L2SW/L1SW route lookup, determining the downstream hops' hash port selection. That is: source NPU port CNA → affects L1SW→L2SW, L2SW→L1SW, L1SW→NPU out port selection. The forward DstCNA and reverse DstCNA of the same EID pair are different (reverse uses source CNA), causing forward and reverse paths to not necessarily coincide, thereby covering more links.

#### 8.3.4 Two-Phase Coverage (planPathsCoverageEx)

**Phase 1 (inter-chassis CROSS_L2):**
1. Enumerate cross-chassis EID pairs (src in chassis A, dst in chassis B);
2. For each EID pair, trace 4-hop forward/reverse paths (NPU→L1SW→L2SW→L1SW→NPU), using H1~H5b hash port selection;
3. Greedy selection: each time pick the EID pair that covers the most uncovered L1SW↔L2SW links;
4. Until all L1SW↔L2SW out ports have coverCount >= required (MIN_COVERAGE=1, REDUNDANT=2) or candidate EID pairs are exhausted.

**Phase 2 (intra-chassis LOCAL_L1):**
1. Filter out gaps with `layer == NPU_L1 && coverCount < required` from Phase 1 results;
2. Enumerate same-chassis EID pairs (src and dst in same chassis);
3. For each EID pair, trace 2-hop forward/reverse paths (NPU→L1SW→NPU), using H6/H7a/H7b hash port selection;
4. Greedily fill NPU↔L1SW uncovered links.

**Merged Statistics:** After Phase 1 + Phase 2 EID pairs are merged, recompute coverage rate / redundancy rate / EID uniformity / layer statistics (NPU_L1 / L1_L2) on the complete link domain.

#### 8.3.5 EID and Out Port Relationship

| NPU Port Field | Usage | Impact Scope |
|:---|:---|:---|
| eid | EID pair's srcEid/dstEid, as input parameter to planPath | Determines EID pair set |
| cna | As DstCNA for downstream hash / source CNA (SCNA) for reverse | Determines H3a~H7b out port selection |
| jettyId | Only planPathsCoverageEx: jettyId field of NPU→L1SW route selection hash tuple | Determines H1/H2 out port selection |

#### 8.3.6 Route Scope Extension (planPathsCoverageEx)

The NPU route LPM hit entry's out port set is only `get(0)` as last hop out port in planPathsCoverage; in planPathsCoverageEx it serves as ECMP member set, with one selected by H1/H2 hash. L1SW→NPU is similar: planPathsCoverage takes get(0), planPathsCoverageEx selects by H4 hash.

#### 8.3.7 Engine Interface

```java
package com.huawei.umdk.snc.engine;

public class CoveragePlanEngine {

    /** JETTY_ID_MIN/MAX consistent with HashUtils; used to validate jettyId values */
    public static final int JETTY_ID_MIN = HashUtils.JETTY_ID_MIN;
    public static final int JETTY_ID_MAX = HashUtils.JETTY_ID_MAX;

    /**
     * Construct coverage planning engine
     *
     * @param superNode       Super node topology (including routing tables)
     * @param hashFunc        hash function selector (HashUtils.HASH_FUNC_CRC8_ATM, etc.)
     * @param dieHashFuncSelect planPathsCoverageEx NPU→L1SW die hash function selector
     * @param fixedDataUdpPort Fixed data UDP port (for path planning)
     * @param fixedAckUdpPort  Fixed ACK UDP port (for path planning)
     * @param hashTuple        hash tuple configuration
     */
    public CoveragePlanEngine(SuperNode superNode, int hashFunc, int dieHashFuncSelect,
                              int fixedDataUdpPort, int fixedAckUdpPort, int hashTuple);

    /** planPathsCoverage entry: only covers L1SW↔L2SW */
    public CoveragePathsResult findCoverage(CoverageRequirement requirement);

    /** planPathsCoverageEx entry: covers NPU↔L1SW↔L2SW, two-phase flow */
    public CoveragePathsResult findCoverageEx(CoverageRequirement requirement);

    /** Get jettyId; falls back to 32 + portId when missing or out of range and increments exJettyFallback */
    private int jettyIdOf(NpuPortEntity port);

    /** Get extended version diagnostic counters (for planPathsCoverageEx) */
    public ExDiagnostics getExDiagnostics();
}
```

**`ExDiagnostics` Fields:**

| Field | Description |
|:---|:---|
| npuRouteFail | NPU route LPM miss count |
| npuPortFail | NPU port lookup failure count |
| jettyIdFallback | jettyId missing or out-of-range fallback count |
| l1Fail | L1SW route lookup/port selection failure count |
| l2Fail | L2SW route lookup/port selection failure count |
| dstL1Fail | Destination L1SW lookup failure count |
| revNpuFail | Reverse NPU port selection failure count |
| revDstL1Fail | Reverse destination L1SW failure count |
| revL2Fail | Reverse L2SW failure count |
| revSrcL1Fail | Reverse source L1SW failure count |

> Diagnostic counters are used for test and production fault localization; in normal SUCCESS results, all counters should be 0 or only jettyIdFallback non-0 (old topology input scenario).

### 8.4 Route Convergence Algorithm (RouteConvergeService)

> **Corresponds to `route/service/RouteConvergeService.java` in the §3.2 package structure**

#### 8.4.1 Algorithm Overview

After link up/down event trigger, BFS propagates reachability changes between interconnected forwarding nodes: starting from the event port's chip, locate affected route prefixes, propagate along peer forwarding links to downstream chip routing tables, refresh corresponding OutPortInfo.convergedFlag and RoutingEntry.reachable.

#### 8.4.2 Convergence Steps

1. **Locate event port**: In SuperNode, find DeviceEntity by `deviceName`, iterate its forwardingChips, find chip C containing `portName`.
2. **Refresh local chip routing table**: Iterate all RoutingEntry in the `"deviceName#C"` routing table, for each entry.outPortInfos where portName == eventPortName's OutPortInfo:
   - down event: `setFlag(FLAG_PASSIVE_CONVERRGED)`
   - up event: `clearFlag(FLAG_PASSIVE_CONVERRGED)`
3. **Refresh reachable**: Call `refreshReachable()` on RoutingEntry modified in step 2, record prefixes with reachable changes (true→false or false→true) as `changedPrefixes` set.
4. **BFS propagation**: If `changedPrefixes` is non-empty:
   - Iterate other ports P with `linkStatus == up` on chip C;
   - Locate peer forwarding node N's in-interface P' via `P.remoteDevice` / `P.remotePort`;
   - Find chip C' to which P' belongs on N;
   - Query prefixes in `changedPrefixes` in the `"N#C'"` routing table;
   - For RoutingEntry with hit prefixes, locate OutPortInfo where portName == P'.portName in outPortInfos, setFlag/clearFlag `FLAG_PASSIVE_CONVERRGED` (consistent with event direction), refreshReachable;
   - If N's reachable also changed, add N to BFS queue and continue propagation.
5. **Termination condition**: BFS queue is empty (no more reachable changes need propagation).

#### 8.4.3 Key Constraints

- Forwarding isolation: Different forwardingChips of the same device have independent routing tables; convergence propagates only within the port's chip routing table.
- Target: SNCService's `instantiationRouteMap` (populated by `makeRoutes`); does not modify SuperNode topology data's `routingTableMap` itself.
- ECMP handling: If a RoutingEntry has multiple out ports, down event only marks the hit out port; reachable is determined by all out ports' convergedFlag jointly (any one == 0 means reachable=true).
- Idempotency: Repeatedly sending the same down event does not repeatedly set flags (bit operation idempotent).

### 8.5 Route MSP Calculation and Instantiation Algorithm

#### 8.5.1 RouteMspService (Template Route MSP Calculation)

> **Corresponds to `route/service/RouteMspService.java`**

Based on topology templates (`128_npu_rack.json`, `128_npu_inter_rack.json`), uses BFS to compute the shortest path from each forwarding node to other nodes, generates template routing table `RouteTable` (`Prefix → RouteEntry`, each RouteEntry contains NhpSet + path classification) by path policy (shortest / secondShortest / other).

**BFS Shortest Path Policy:**
- Each hop cost = 1, BFS queue ensures first arrival is shortest;
- shortest: next hop out port set for shortest path;
- secondShortest: next hop out port set for second shortest path (one more hop than shortest);
- other: out ports for other longer paths, used for ECMP multi-path scenarios.

#### 8.5.2 RouteInstantiationService (Template Route Instantiation)

> **Corresponds to `route/service/RouteInstantiationService.java`**

Instantiate template routing table into `Map<String, RoutingEntry>` (key = route prefix IP) per SuperNode's actual chassis/slot/index, store in `instantiationRouteMap` (key = `"deviceName#chipIndex"`).

**Instantiation Rules:**
- NPU: Match template nodes by `chassis/slot/ubpu/die` labels; each NPU device generates one routing table copy.
- L1SW: Match by `chassis/index` labels; L1SW routing table's out port names are remapped per actual ports.
- L2SW: Match by `index/chip` labels; 4-chassis instantiation remaps L2SW out port index/name per inter-chassis topology.
- Deep copy: `deepCopyRoutingEntry` ensures `instantiationRouteMap` and return value do not affect each other.

#### 8.5.3 TopoTemplateService (Template Parsing)

> **Corresponds to `route/topo/template/service/TopoTemplateService.java`**

Parse built-in topology template JSON files, construct `SncTopology` model (including SncNode, SncPort, Label, Address, Prefix, Bitmap, PolicyPath, PolicyPrefix, etc.). Deserialization is completed collaboratively by `TemplateLoader`, `NodeLoader`, `PortLoader`, `PrefixLoader`, etc.

### 8.6 HashUtils (hash wrapper)

> **Corresponds to `util/HashUtils.java`, `util/UbSwitchHash.java`, `util/DllLoader.java`**

#### 8.6.1 Dual JNA Bindings

HashUtils loads two native library interfaces via JNA:

| Interface | Native Function | Algorithm | Usage |
|:-----|:---------|:-----|:-----|
| `UbSwitchEcmpLibrary` | `ubswitch_Hash_ecmp` | ECMP hash (corresponds to `ubswitch_hash.c`) | L1SW/L2SW route selection (H3~H7) |
| `UbSwitchDieLibrary` | `ubswitch_Hash_dieEcmp` | CRC-8/ATM hash (corresponds to `ubswitch_dieHash.c`) | NPU→L1SW route selection (H1/H2, tuple `(DstCNA, jettyId)`) |

**JNA Loading Flow:**
1. `DllLoader` searches native library files in order of jar sibling directory, classpath extraction, etc.;
2. `Native.load("ubswitch_hash", UbSwitchEcmpLibrary.class)` loads ECMP library;
3. `Native.load("ubswitch_dieHash", UbSwitchDieLibrary.class)` loads die library;
4. Falls back to `UbSwitchHash` (pure Java implementation, corresponds 1:1 to the two C files logic) when any loading fails.

#### 8.6.2 Java Fallback (UbSwitchHash)

`UbSwitchHash` provides `hashEcmp` and `hashDieEcmp` two static methods, logic fully consistent with native library, used for:
- Test environment without native library;
- Automatic fallback when JNA loading fails;
- Dual-path consistency test verification (call native and Java implementations simultaneously to compare results).

#### 8.6.3 Key API

```java
public class HashUtils {
    public static final int JETTY_ID_MIN = 32;
    public static final int JETTY_ID_MAX = 1023;

    /** ECMP hash (L1SW/L2SW route selection) */
    public static int nativeHash(String dstCna, int ecmpCnt, int hashFunc);

    /** die hash (NPU→L1SW route selection, tuple (DstCNA, jettyId)) */
    public static int nativeHashDstCnaJetty(String dstCna, int jettyId, int ecmpCnt, int hashFunc);

    /** Validate jettyId value range [32, 1023] */
    public static boolean isValidJettyId(int jettyId);
}
```

### 8.7 Coverage Planning Key Design Decisions

> This section is merged from the original "SNC NPU-L1 Coverage Path Planning Design" document's §12 Open Questions and §13 Implementation Supplementary Notes, recording design decisions landed on 2026-09-13.

#### 8.7.1 Interface Naming (Q1)

| Decision | Options | Final Adoption |
|:---|:---|:---|
| Extended interface naming | `planPathsCoverageEx` / `planPathsCoverageWithNpuL1` / `planPathsFullCoverage` | **`planPathsCoverageEx`** (concise, retains original interface name prefix) |

#### 8.7.2 SCNA Semantics (Q2)

| Decision | Options | Final Adoption |
|:---|:---|:---|
| SCNA used by NPU out port hash | Flow's source CNA / NPU port-level CNA | **Flow's source CNA** (follows existing convention; if hardware implementation uses out port CNA for hash, adjust per actual behavior) |

#### 8.7.3 REDUNDANT Coverage Granularity (Q3)

| Decision | Options | Final Adoption |
|:---|:---|:---|
| REDUNDANT's "≥2" application granularity | Unified configuration per layer / Fine-grained configuration per sub-layer | **Unified configuration per layer** (all NPU_L1 ≥ 2, all L1_L2 ≥ 2); if finer granularity needed, can configure per layer |

#### 8.7.4 CoverageLinkScope Values (Q4)

| Decision | Options | Final Adoption |
|:---|:---|:---|
| Whether to support only NPU↔L1 (excluding L1↔L2) | Add `NPU_L1` enum value / Not add | **Not add** (currently only `L1_L2` / `NPU_L1_L2`; can be extended later if needed) |

#### 8.7.5 Diagnostic Counter Instantiation (Q5)

| Decision | Options | Final Adoption |
|:---|:---|:---|
| Whether failure counters are `static` or instance fields | `static` (global shared) / Instance fields (independent per construction) | **Instance fields** (`CoveragePlanEngine.ExDiagnostics`, reset each time engine is constructed; concurrency-safe) |

#### 8.7.6 CoverageLink Field Naming (Q6)

| Decision | Options | Final Adoption |
|:---|:---|:---|
| Whether to rename `CoverageLink.switchDevice` to `deviceName` | Rename / Keep original name | **Rename to `deviceName`** (consistent with other DTO field naming; JSON contract updated synchronously) |

#### 8.7.7 Route Scope Extension and Reception Semantics

**Reception Semantics (Key Premise):** The destination CNA belongs to a certain NPU device, and that NPU can receive the packet, even if the packet arrives at a port that is not the CNA's own corresponding physical port. Therefore the route/port selection constraint is relaxed from "CNA ↔ port one-to-one correspondence" to "**the NPU device owning the CNA is reachable**".

| Location | Old Definition | Extended Definition |
|:---|:---|:---|
| L1SW routing | Only build /32 routes for CNAs of "physically connected ports" | For **every NPU with ports**, build /32 routes for **each of its CNAs**, out port = all ports from this L1SW to that NPU |
| L2SW→L1SW port selection | Fixed use of `dst.remoteL1sw` (L1SW where destination port is located) | Any "L1SW that can reach the destination NPU device" |
| L1SW→NPU port selection | Route has only 1 out port (no ECMP) | All ports from this L1SW to destination NPU (≥2 → hash selectable) |

**Side Effect (forward):** The ECMP member sets for L1SW→NPU and L2SW→L1SW two hops no longer degenerate; coverage planning can truly "step on" these out ports, and NPU↔L1SW layer coverage rate can reach 100%.

#### 8.7.8 EID and Out Port Relationship

- `srcPort` / `srcCna` / `srcEid` identify **endpoint identity** (which device's which logical port initiates/receives the flow), **do not constrain** the packet's physical out port;
- After the source NPU receives the packet, it selects the real out port among its uplink ports (all ports to the L1SW traversed for the destination) by **CRC8 `(DstCNA, jettyId)`**; **the selected port's CNA is the SCNA used by subsequent L1/L2 port selection**;
- Therefore `CoveredEidPair.srcPort` (selected endpoint identity) and `coveredLinks[0].outPort` (real out port) **can be different**, which is intentional by design;
- ACK direction is similar: `destPort` is the ACK sending endpoint identity, real out port is determined by `(srcCna, source port jettyId)` (jettyId taken from source NPU port, same as forward).

#### 8.7.9 Native Library CRC8 Algorithm Details

`ubswitch.c` (repository root directory) exports symbols:

```c
int ubswitch_Hash_dieEcmp(const char *dst_cna, int jetty_id, int ecmp_cnt);
/* CRC-8/ATM: poly 0x07, init 0x00, no reflection, no final XOR
   byte stream = DstCNA's ASCII (excluding trailing NUL) + jettyId low byte + jettyId high byte
   ecmp_cnt == 0 → return raw CRC (0..255); ecmp_cnt > 0 → CRC % ecmp_cnt */
```

| Usage | Native Symbol | Java Entry |
|:---|:---|:---|
| Inter-chassis L1SW↔L2SW port selection, L1SW→NPU port selection | `ubswitch_Hash_ecmp` | `HashUtils.nativeHash(...)` |
| **NPU→L1SW port selection (CRC8)** | **`ubswitch_Hash_dieEcmp`** | **`HashUtils.nativeHashDstCnaJetty(dstCna, jettyId, ecmpCnt, hashFunc)`** |

Binary build: `build_ubswitch.ps1` (MinGW `gcc -O2 -shared` produces `libubswitch.dll`; `clang --target={x86_64,aarch64}-unknown-linux-gnu -fuse-ld=lld -nostdlib -shared` produces two `.so` files), artifacts land in `umdk/src/snc/src/main/resources/`. CRC8 correctness verified by `HashUtilsJettyTest.crc8MatchesReference` using Java reference implementation bit-by-bit comparison (including `ecmpCnt` modulo).

#### 8.7.10 Real Test Results (2026-09-13 Landed)

| Scenario | Interface | status | Inter-chassis Pairs | Intra-chassis Pairs | NPU_L1 Coverage Rate | L1_L2 Coverage Rate | Report |
|:---|:---|:---|--:|--:|--:|--:|:---|
| **Full rack 4 chassis** (148 devices) | `planPathsCoverageEx` | **SUCCESS** | **598** | 0 | **100.00% (2048/2048)** | **100.00% (2048/2048)** | `target/coverage-rack4-report.md` (≈189s) |
| 2 chassis subset | `planPathsCoverage` (inter-chassis only) | see `PlanPathsCoverageIntegrationTest` | — | — | — | — | console output (`CoverageMainSuccessTest`) |
| Single chassis (no L2SW) | `planPathsCoverageEx` | SUCCESS | 0 | 18 | 100% (64/64) | 0/0 | `target/coverage-intra-chassis-report.md` |

> Full rack 4 chassis = `FullRackTopologyGenerator` generated content (128 NPU × 8 ports + 16 L1SW + 4 L2SW), coverage link domain 4096 (NPU_L1 2048 = NPU→L1 1024 + L1→NPU 1024; L1_L2 2048 = L1→L2 1024 + L2→L1 1024), **all 4096 links covered by 598 inter-chassis EID pairs**, 10 engine diagnostic counters all 0, `jettyIdFallback` is 0.

#### 8.7.11 Test Conventions (2026-09-13)

**2-chassis scenario is only used for old interface `planPathsCoverage` regression testing** (`PlanPathsCoverageIntegrationTest`, `CoverageMainSuccessTest`); new interface `planPathsCoverageEx` automated tests are all based on topology generated by `FullRackTopologyGenerator`, trimmed to **single chassis** subset:

- `PlanPathsCoverageExIntegrationTest` (northbound `SncService`, analogous to old interface integration tests): MIN/REDUNDANT coverage rate + state machine/null parameter/SuperNode not exists/uninit four contract test cases;
- `CoverageIntraChassisTest` (`PathService` layer): intra-chassis 2-hop + CRC8 port selection + SCNA chaining + layer statistics + route scope end-to-end validation, and produces intra-chassis coverage report.
- `FullRackTopologyJettyIdTest`: `FullRackTopologyGenerator` uses fixed allocation `JETTY_ID_BASE + portIndex` (32..39, fully consistent each generation).

#### 8.7.12 Inter-chassis Flow Example (4-hop + ACK)

> Example data is from 2-chassis topology planning output. Per §8.7.11 test conventions, 2-chassis scenario is only for old interface regression, so this example serves as **flow walkthrough**; new interface automated assertions see §8.7.13 (single chassis).

Topology: 2-chassis subset (8 NPU + 8 L1SW + 4 L2SW). EID pair: `rack2#board1#npu1:400GUB 1/2/1` ↔ `rack1#board1#npu2:400GUB 1/4/1`.

| # | Direction | Device | Out Port | Peer | Peer Port | layer |
|--:|:---|:---|:---|:---|:---|:---|
| 0 | forward | rack2#board1#npu1 | 400GUB 1/2/1 | rack2#l1sw1 | 400GUB 1/0/1 | NPU_L1 |
| 1 | forward | rack2#l1sw1 | 400GUB 1/0/78 | l2sw1 | 400GUB 1/0/7:2 | L1_L2 |
| 2 | forward | l2sw1 | 400GUB 1/0/7:2 | rack1#l1sw1 | 400GUB 1/0/78 | L1_L2 |
| 3 | forward | rack1#l1sw1 | 400GUB 1/0/3 | rack1#board1#npu2 | 400GUB 1/4/1 | NPU_L1 |
| 4 | ACK | rack1#board1#npu2 | 400GUB 1/4/2 | rack1#l1sw1 | 400GUB 1/0/4 | NPU_L1 |
| 5 | ACK | rack1#l1sw1 | 400GUB 1/0/94 | l2sw1 | 400GUB 1/0/15:2 | L1_L2 |
| 6 | ACK | l2sw1 | 400GUB 1/0/47:2 | rack2#l1sw1 | 400GUB 1/0/94 | L1_L2 |
| 7 | ACK | rack2#l1sw1 | 400GUB 1/0/1 | rack2#board1#npu1 | 400GUB 1/2/1 | NPU_L1 |

**Flow Key Points:**
1. Source NPU uses **CRC8 `(DstCNA, jettyId)`** to select out port among "uplink ports to the L1SW traversed for the destination" (hop 0);
2. The selected port's **CNA becomes SCNA**, participating in L1SW→L2SW (hop 1) and L2SW→L1SW (hop 2) port selection;
3. Destination-side L1SW looks up table by `DstCNA`, selects out port by hash among "all ports to the destination NPU" (hop 3);
4. ACK direction (hop 4~7): `DstCNA = source CNA`, **jettyId = source NPU port jettyId** (same jettyId as forward).

#### 8.7.13 Intra-chassis Flow Example (2-hop + ACK, Real Test Output)

Topology: single chassis (rack1: 4 NPU + 4 L1SW, no L2SW) → Phase 1 has no available EID pairs, all covered by Phase 2.
EID pair: `rack1#board1#npu2:400GUB 1/4/1` ↔ `rack1#board1#npu1:400GUB 1/2/1`.

| # | Direction | Device | Out Port | Peer | Peer Port | layer |
|--:|:---|:---|:---|:---|:---|:---|
| 0 | forward | rack1#board1#npu2 | 400GUB 1/4/1 | rack1#l1sw1 | 400GUB 1/0/3 | NPU_L1 |
| 1 | forward | rack1#l1sw1 | 400GUB 1/0/2 | rack1#board1#npu1 | 400GUB 1/2/2 | NPU_L1 |
| 2 | ACK | rack1#board1#npu1 | 400GUB 1/2/1 | rack1#l1sw1 | 400GUB 1/0/1 | NPU_L1 |
| 3 | ACK | rack1#l1sw1 | 400GUB 1/0/4 | rack1#board1#npu2 | 400GUB 1/4/2 | NPU_L1 |

#### 8.7.14 Key Invariants

| No. | Invariant |
|:---:|:---|
| I1 | NPU↔L1 member set only comes from **routing table LPM hit entries**, not from physical connection full enumeration (consistent with hardware forwarding) |
| I2 | When member set `size == 1`, hash degenerates to deterministic port selection, consistent with old interface same-scenario results |
| I3 | `linkMap` key remains `deviceName:outPortName`, no cross-layer conflict; same key deduplication takes the one with larger `totalOutPorts` |
| I4 | Under `L1_L2` domain, link domain, hash points, `CoveredPair` link count, statistics are all bit-by-bit consistent with old implementation |
| I5 | `sum(layerStats[*].totalLinks) == stats.totalLinks`, `sum(layerStats[*].coveredCount) == stats.coveredCount` |
| I6 | Each EID pair's forward/reverse coverage link count is equal (CROSS_L2 4 each, 8 total; LOCAL_L1 2 each, 4 total), jettyId is the same in both directions (both taken from source port) |
| I7 | Greedy and statistics logic do not introduce layer branches; layering only appears in `collectBidirectionalLinks` (domain name) and `buildResult` (statistics) |

#### 8.7.15 Thread Safety

- `CoveragePlanEngine` itself is stateless; `hashFunc` / `fixedDataUdpPort` / `fixedAckUdpPort` / `hashTuple` are final fields.
- `ExDiagnostics` diagnostic counters are **instance fields** (internal objects of `CoveragePlanEngine`), reset each time engine is constructed; the same engine instance is not safe for concurrent invocation, but each `planPathsCoverage` / `planPathsCoverageEx` call constructs a new engine, so the northbound interface level is concurrency-safe.
- `SncService.routeCalculate` / `makeRoutes` protect `routeCalculated` flag and `instantiationRouteMap` writes via `synchronized`; `getNodeRoute` is read-only and concurrent; `notifyLinkEvent` modifies `instantiationRouteMap` and requires serialization.
- `SuperNode` / `SuperNodeStore` concurrency safety is ensured by the caller (existing constraints unchanged).

#### 8.7.16 Configuration Compatibility

| Configuration | New | Description |
|:---|:---:|:---|
| `SNCConfig.hashFunc` | No | NPU segment hash reuses same function selector |
| `SNCConfig.dieHashFunctionSelect` | Yes | NPU→L1SW die hash function selector (for planPathsCoverageEx) |
| `SNCConfig.fixedDataUdpPort` / `fixedAckUdpPort` | No | NPU segment reuses fixed ports (effective when four/five-tuple participates in hash) |
| `SNCConfig.hashTuple` | No | NPU segment reuses same tuple width |
| New NPU segment switch | **Not added** | Whether to enable is determined by which interface is called (`planPathsCoverage` vs `planPathsCoverageEx`) |

---
## 9 Detailed Path Planning Flow

### 9.1 Flow Overview

Path planning uses a **two-phase loop (forward → reverse) + direct connection short-circuit** as the overall control structure, with a total of 11 steps (Step 0 ~ Step 10):

```
                                      Phase 1
                                  ┌──────────────┐
                                  │ Step 0 ~ 2    │
                                  │ Device check/ │
                                  │ Node check    │
                                  └───────┬──────┘
                                          │
                              ┌───────────┴───────────┐
                              ▼                       ▼
                     ┌────────────────┐     ┌──────────────────┐
                     │ interDevices   │     │ interDevices     │
                     │ empty (direct) │     │ non-empty (multi)│
                     └───────┬────────┘     └────────┬─────────┘
                             │ Step 4               │ Step 5
                             ▼                      ▼
                     ┌────────────────┐     ┌──────────────────┐
                     │ Direct path    │     │ Multi-hop path   │
                     │ validation     │     │ resolution       │
                     │ (terminal step,│     │ → InternalPathInfo│
                     │ no routing)    │     └────────┬─────────┘
                     └───────┬────────┘              │
                             │ Success return         │
                             │ (code 0)               │
                             │                        ▼
                             │              ┌──────────────────┐
                             │              │ Step 6           │
                             │              │ Forward init     │
                             │              │ dst=dev2         │
                             │              └────────┬─────────┘
                             │                       ▼
                             │              ╔══════════════════╗
                             │              ║ Forward loop     ║
                             │              ║ Step 8→9 × n     ║
                             │              ╚══════╤═══════════╝
                             │                       ▼
                             │              ┌──────────────────┐
                             │              │ Step 10          │
                             │              │ dst==dev2?       │──→ Step 7 (Reverse)
                             │              │ Yes (forward done)│     dst=dev1
                             │              └──────────────────┘         │
                             │                                          ▼
                             │                                 ╔════════════════════╗
                             │                                 ║ Reverse loop       ║
                             │                                 ║ Step 8→9 × n       ║
                             │                                 ╚══════╤═════════════╝
                             │                                          ▼
                             │                                 ┌──────────────────┐
                             │                                 │ Step 10          │
                             │                                 │ dst==dev1?       │──→ §9.5 (construct output)
                             │                                 │ Yes (reverse done)│
                             │                                 └──────────────────┘
                             │                                          │
                             │                                          ▼
                             │                                 ┌──────────────────┐
                             │                                 │ Step 9~10        │
                             │                                 │ UDP port compute │
                             └─────────────────────────────────┴──────────────────┘
```

**Two-phase Loop Description:**

| Phase | Direction | Target Address (targetAddr) | Destination Device | Execution Path |
|:-----|:-----|:----------------------|:---------|:---------|
| Forward (Step 6) | dev1 → dev2 | CNA2 (= dev2 port IP) | dev2 | Step 6 → [8 → 9]^n → 10 |
| Reverse (Step 7) | dev2 → dev1 | CNA1 (= dev1 port IP) | dev1 | Step 7 → [8 → 9]^n → 10 → §9.5 (construct output) |

**Direct Connection Short-circuit Description:**
- Step 4 is a **terminal step** — after direct path validation passes, it **returns success directly** (code 0), skipping Phase 3 (route planning Step 6~8) and Phase 4 (output construction Step 9~10).
- In direct connection scenarios, two devices' NPU ports are directly connected; the path does not pass through any switch devices, therefore **no routing table lookup is needed**. The communication path is guaranteed by physical port connection relationships.

---

### 9.2 Phase 1: Device Judgment and Source/Destination Info Lookup (Step 0 ~ 2)

**Step 0 - superNodeName Locating and Source/Destination Device Judgment:**
1. **Super node locating:** Locate the target super node's `SuperNode` (§4.1) in `SuperNodeStore.superNodeMap` (§7.9) based on `request.superNodeName` (§6.1).
   - If `superNodeName` is empty or the corresponding `SuperNode` does not exist → return error code **1012** (`TOPO_NOT_FOUND`, §6.2 PlanStatus), flow terminates.
2. **Source and destination device judgment:** Look up source device `dev1` and destination device `dev2` in the target `SuperNode.getNpuDevices()` (§4.1). Path planning only handles NPU devices; SW devices do not participate in src/dest lookup.
3. If either device does not exist → return error code **1007** (`TOPO_INCOMPLETE`, §6.2 PlanStatus), flow terminates.
   > **Note:** In Step 0, `superNodeName` not existing and device not found in `SuperNode.getNpuDevices()` are two different levels of errors. `superNodeName` not existing means super node data was not provisioned, returning `TOPO_NOT_FOUND`(1012); device not found in the loaded super node means topology data is incomplete, returning `TOPO_INCOMPLETE`(1007). Error code definitions see §6.2 PlanStatus.
4. Both device types must be `NPU` (`DeviceType.NPU`, §4.3.1).
5. If not NPU → return error code **3002** (`SRC_AND_DST_MUST_BE_NPU`, §6.2 PlanStatus).
6. **UPI consistency validation:** Validate whether the `upi` (§4.5.1 `NpuPortEntity.upi`, 32 bit) of source device port `port1` and destination device port `port2` are consistent. If inconsistent → return error code **3003** (`UPI_MISMATCH`, §6.2 PlanStatus), flow terminates.
7. Success → record current `superNodeName` for subsequent Step use, proceed to Step 1.

**Step 1 - Lookup Source Information:**
Look up and record the following information for source device `dev1`:
- `EID1` (port-associated EID), from `NpuPortEntity.eid` (§4.5.1)
- `CNA1` (port-associated CNA), from `PortEntity.cna` (§4.5)
- `port1` connection info (`remoteDevice`, `remotePort`), from `PortEntity` (§4.5)

If any information is missing → return error code **1003** (`SRC_INFO_ERR`, §6.2), flow terminates.
Success → proceed to Step 2.

**Step 2 - Lookup Destination Information:**
Look up and record the following information for destination device `dev2`:
- `EID2` (port-associated EID), from `NpuPortEntity.eid` (§4.5.1)
- `CNA2` (port-associated CNA), from `PortEntity.cna` (§4.5)
- `port2` connection info (`remoteDevice`, `remotePort`), from `PortEntity` (§4.5)

If any information is missing → return error code **1004** (`DST_INFO_ERR`, §6.2), flow terminates.
Success → proceed to Step 3.

---

### 9.3 Phase 2: Path Resolution (Step 3 ~ 5)

> **Data Structure Reference:** §4.3 DeviceEntity (with getForwardingChips() abstract method), §4.4 ForwardingChip (with getPorts() abstract method), §4.5 PortEntity, §5.1 InternalPathInfo/InternalPathHop, §6.1 PathPlanRequest

**Step 3 - Determine Intermediate Nodes:**
Check whether `request.interDevices` (§6.1) is empty:
- No intermediate nodes → jump to Step 4 (direct connection scenario).
  > **V1 Behavior Note:** The current version V1 does not implement auto-routing algorithm. When `interDevices` is empty, the engine only handles direct connection scenarios:
  > - First execute Step 4 direct connection validation: if port connection relationship validation passes → return direct connection result (success).
  > - If direct connection validation fails → return error code **1008** (`TOPO_CONNECTION_ERROR`, §6.2), flow terminates. The engine will not attempt to auto-discover multi-hop paths.
  > - The caller must ensure: if source and destination devices are not directly connected, intermediate devices and out ports must be explicitly specified in `interDevices`.
- Has intermediate nodes → jump to Step 5 (multi-hop scenario, must explicitly specify intermediate devices and out ports).

**Step 4 - Direct Path Validation (Terminal Step):**
Validate bidirectional connection relationships:
- `port1.remoteDevice == dev2.deviceName` and `port1.remotePort == port2.portName`
- `port2.remoteDevice == dev1.deviceName` and `port2.remotePort == port1.portName`

If validation passes → construct return result per `PathPlanResult` (two-hop path, §6.2), **return success directly (code 0)**, no further execution of Phase 3 and Phase 4.

If validation fails → return error code **1008** (`TOPO_CONNECTION_ERROR`, §6.2).

> **Direct Connection Short-circuit Semantics:** Step 4 is a terminal step. In direct connection scenarios, the communication path is guaranteed by physical port connection relationships, without relying on routing table (§4.7) forwarding, therefore **Phase 3** (Step 6~8, route planning) and **Phase 4** (Step 9~10, UDP port computation and output construction) are **not executed**. This is intentional by design.

**Step 5 - Multi-hop Path Resolution:**
Use `request.interDevices` and real topology data to construct the complete `InternalPathInfo` (§5.1).

**5.1 Topology Data Validation:**
Iterate each `{deviceName → outPort}` entry in `interDevices`, check in `SuperNode.devices`:
- Device existence: if `superNode.devices.get(deviceName)` returns null → return error code **1007** (`TOPO_INCOMPLETE`), flow terminates.
- Port existence: if `outPort` cannot be found in any forwarding chip's `ports` of that device (iterate all chips via `device.getForwardingChips()`, then call `chip.getPorts()` to find port) → return error code **1007** (`TOPO_INCOMPLETE`), flow terminates.

**5.2 Path Construction:**
Assemble the complete `InternalPathInfo.hops` list in order:

```
hops[0]   = dev1           (inPort=null, outPort=port1)
hops[1]   = interDevices[0] (inPort=port1.remotePort, outPort=interDevices[0].outPort)
hops[2]   = interDevices[1] (inPort=previous hop remotePort, outPort=interDevices[1].outPort)
...
hops[n]   = interDevices[k] (inPort=previous hop remotePort, outPort=interDevices[k].outPort)
hops[n+1] = dev2           (inPort=last hop remotePort, outPort=null)
```

- **Source node (hops[0]):** `inPort=null`, `outPort=request.srcPort`, `cna`/`eid` taken from source port.
- **Intermediate nodes (hops[1] ~ hops[n]):** `inPort` taken from previous hop's `remotePort`, `outPort` specified in `interDevices`.
  - For SW devices: `cna` may be null (SW port cna is optional, §4.5.2), note this during route lookup.
  - **Connection validation:** For each hop, verify `currentHop.remoteDevice == nextHop.deviceName` and `currentHop.remotePort == nextHop.inPort` to ensure path continuity.
- **Destination node (hops[n+1]):** `outPort=null`, `inPort` taken from previous hop's `remotePort`.

**5.3 Connection Relationship Validation:**
Each hop's `remoteDevice` / `remotePort` must be consistent with the next hop's `deviceName` / `inPort`. If inconsistent → return error code **1009** (`TOPO_CONNECTION_NOT_FOUND`, §6.2).

> **Implementation Note:** Device lookup uses the unified view returned by `superNode.getAllDevices()` (merged npuDevices + swDevices), with HashMap O(1) locating; port lookup via `NpuDevice.findNpuPort()` (NPU device, directly uses `NpuForwardingChip.getNpuPorts()`, no instanceof/cast needed) or iterating forwarding chips' `getPorts()` Map (SW devices) (§4.4, §4.5). The port's belonging chip (`chipIndex`) is automatically covered in Step 8 route lookup by iterating all `ForwardingChip` (via `device.getForwardingChips()`) of the device, without needing to be separately recorded in Step 5.

---

### 9.4 Phase 3: Path Planning Loop (Step 6 ~ 8)

> **Data Structure Reference:** §4.7 RoutingTable (with maskLengths), §4.8 RoutePrefix, §4.9 RoutingEntry/OutPortInfo, §5.2 RouteSelectionRecord, §8 Indexed Mask Match algorithm

The core structure of Phase 3 is a **two-phase loop**, distinguished by `currentPhase` state flag for forward/reverse:

```
Forward (Step 6)          Reverse (Step 7)
     │                       │
     ▼                       ▼
┌─────────────────────────────────────┐
│ Step 8: Path planning loop (execute for each intermediate device) │
│   for each intermediate device:     │
│     1. Iterate all ForwardingChips of the device │
│     2. For each chip, do indexed mask match (targetAddr) │
│     3. Take best result from all chips          │
│     4. Validate route out port consistency with topology connection │
│     5. If ECMP → record RouteSelectionRecord │
│   After loop:                          │
│     if FORWARD → switch to reverse (Step 7) │
│     if REVERSE → construct output (§9.5) │
└─────────────────────────────────────┘
```

#### 9.4.1 Forward Phase (Step 6 → 8)

**Step 6 - Forward Path Planning Initial Setup:**
- Set current phase flag `currentPhase = FORWARD`
- Destination device = `dev2`, destination port = `port2`, destination address = `CNA2` (32 bit), source address = `CNA1` (32 bit)
- Proceed to Step 8

#### 9.4.2 Reverse Phase (Step 7 → 8)

**Step 7 - Reverse Path Planning Initial Setup:**
- Set current phase flag `currentPhase = REVERSE`
- **Path reversal:** Reverse the current `InternalPathInfo.hops` list (`Collections.reverse()`)

  | Attribute | Reversal Rule |
  |:-----|:---------|
  | Element order | Original hops[i] → New hops[n-1-i] |
  | inPort / outPort | Swap: original inPort → new outPort, original outPort → new inPort |
  | cna/eid | Forward takes out port cna/eid; after reversal takes in port cna/eid (forward outPort = reverse inPort, semantically consistent) |
  | remoteDevice/remotePort | Points to previous hop's device/port, maintaining topology connection semantics |
  | hopIndex | Renumber (0 ~ hops.size()-1) |

- Destination device = `dev1`, destination port = `port1`, destination address = `CNA1` (32 bit), source address = `CNA2` (32 bit)
- Proceed to Step 8

#### 9.4.3 Step 8 - Path Planning Loop (Core)

From the current `InternalPathInfo.hops` list, **exclude head and tail nodes** (head = current source device, tail = current destination device), and execute path planning for each remaining intermediate device.

> **Head-tail Exclusion Rule (direction-dependent):**
> - Forward phase (FORWARD): exclude hops[0] (dev1, source) and hops[last] (dev2, destination)
> - Reverse phase (REVERSE): exclude hops[0] (original dev2, now reversed as path starting point) and hops[last] (original dev1, now reversed as path endpoint)
> - Intermediate device criterion: **DeviceType == SW** switch devices. If NPU devices appear in reverse phase (unreasonable path), their ports have no routing table (SW ports have no CNA), the algorithm will fail in subsequent steps.

**Processing flow for each intermediate device:**

**① Address Determination:**
- `targetAddr` = current phase's destination address (forward = `CNA2`, reverse = `CNA1`), 32-bit CNA address.
- `prevHop` = previous hop (the device already processed in the loop), used for Step 8 ⑤ next-hop validation.

**② Cross-chip Route Lookup:**
Routing tables are stored per chip (§4.7); the inbound port's chip may not contain the route to the destination. Therefore, **iterate all `ForwardingChip` of the current device** (via `device.getForwardingChips()` abstract method, §4.3), and for each chip execute the following steps:

```
for each (ForwardingChip chip in device.getForwardingChips().values()):
    1. Construct RoutingTableKey(superNodeName, deviceName, chip.chipIndex)
       → Get RoutingTable via superNodeStore.getRoutingTable(rtKey)
       → If null returned (no routing table for this chip), skip this chip, continue to next

    2. Indexed mask match (§8.1):
       maskLengths = routingTable.getMaskLengths()  // already deduplicated descending
       for each maskLen in maskLengths:
            netAddr = AddressUtils.applyMask(targetAddr, maskLen)
            prefix = RoutePrefix(netAddr, maskLen)
            entry = routingTable.routes.get(prefix)
            if entry != null:
                Record (chipIndex, entry, maskLen) as candidate
                break  // Skip subsequent masks for this chip (current maskLen is already longest match)

    3. Chip has no routing table (getRoutingTable returns null) → skip
```

After iteration, select the `RoutingEntry` with the largest `maskLen` from all chips' candidate results as the final result:
- **No chip matched successfully →** Current device has no route to `targetAddr` → return error code **1010** (`ROUTE_NOT_REACHABLE`, §6.2).

> **Design Notes:**
> - In multi-chip devices, inbound port and routing table may not be on the same chip. For example: inbound port is on chip 0, but routing table is on chip 1. Iterating all chips ensures cross-chip scenarios can also find routes.
> - The same chip's `maskLengths` may contain multiple masks (e.g., [32, 20]), searched from longest to shortest level by level.
> - If a chip has no routing table (`getRoutingTable` returns null), skip directly — no error, results from chips with routing tables are used.

**③ Route Out Port Resolution:**
The found `RoutingEntry` contains `outPortInfos` Map (§4.9):
- If `outPortInfos` is empty → no out port → return error code **1010** (`ROUTE_NOT_REACHABLE`).
- Each `OutPortInfo`'s `portName` in `outPortInfos` is the route-directed out port.

**④ Out Port and Next-hop Consistency Validation:**
Compare the route-matched `outPort` (or the first port among ECMP candidates) with the current hop's `outPort` (from `InternalPathHop.outPort`):
- The route's `outPort` must be able to connect to the next-hop device in path planning. That is: `chip.getPorts().get(outPort).getRemoteDevice() == nextHop.deviceName`.
- If inconsistent → return error code **1010** (`ROUTE_NOT_REACHABLE`), indicating routing table and topology connection inconsistency.

> **Validation Significance:** `interDevices` specifies path topology (which device connects to which), routing tables specify forwarding decisions. Both must be consistent — the out port pointed to by the routing table should connect to the next-hop device in the path. This validation captures routing configuration misalignment issues.

**⑤ Result Summary then proceed to Step 9:**
Pass the final `RoutingEntry` and current device information to Step 9 for out port judgment.

> **Next-hop Relationship:** For the currently processing intermediate device `currentHop`:
> - Forward phase: `currentHop`'s next hop has a larger index in the path (closer to destination device)
> - Reverse phase: `currentHop`'s next hop has a larger index in the path (closer to original dev1, i.e., reversed destination)

If current loop has processed all intermediate devices → skip Step 9, proceed to Step 10.

#### 9.4.4 Step 9 - Out Port Judgment and Route Selection Recording

Judge the out port for `RoutingEntry.outPortInfos` returned by Step 8:

| Condition | Handling |
|:-----|:-----|
| `outPortInfos.size() == 1` | Use this out port normally, proceed to next hop |
| `outPortInfos.size() > 1` | Create a `RouteSelectionRecord` (§5.2), record route selection info, proceed to next hop; simultaneously `HopInfo.multiPath=true`, `PathPlanResult.spray=true` marks this path contains ECMP multi-path, caller decides per-flow strategy |

**RouteSelectionRecord Creation Rules (ECMP Scenario):**

```
RouteSelectionRecord record = new RouteSelectionRecord();
record.setDeviceName(currentHop.deviceName);
record.setPrefix(matchedPrefix);                           // Matched RoutePrefix
record.setCandidateOutPorts(candidateList);                // All candidate OutPortInfo
record.setScna(CNA1);                                      // Source CNA (unchanged)
record.setDcna(CNA2);                                      // Destination CNA (unchanged)
record.setDirection(currentPhase == FORWARD ? Direction.FORWARD : Direction.REVERSE);
// hashInfo records tuple identifier (SCNA:DCNA), for §9.5 Step 9 hash computation
record.setHashInfo(CNA1 + ":" + CNA2);
```

- `candidateOutPorts`: All candidate `OutPortInfo` are added; the port consistent with `interDevices` specified out port is marked as `selected=true` (i.e., path-specified target port), others as `false`.
- This record is appended to the end of `RouteSelectionRecord` list for §9.5 Step 9 use.

> **Inter-chassis Multi-path Route Selection Note:** When multiple ECMP segments exist on the path (e.g., L1SW0→L2SW and L2SW→L1SW1 are both multi-path), Step 9 only records candidate out port list and the path-specified target port (`selected=true`). The detailed flow of hash algorithm searching UDP port numbers satisfying all ECMP segment constraints is in §9.5 Step 9.

#### 9.4.5 Step 10 - Direction Switch Judgment

Determine the flow direction based on current phase flag `currentPhase`:

```
if currentPhase == FORWARD:
    // Forward phase has completed route lookup for all intermediate devices
    // Switch to reverse phase
    → Jump to Step 7 (reverse path setup)

if currentPhase == REVERSE:
    // Reverse phase also completed
    // Restore path to forward order (reverse again)
    → Execute path reversal (same rules as Step 7), restore to forward order
    → Enter output construction phase (§9.5, Step 9~10)
```

---

### 9.5 Phase 4: Output Construction (Step 9 ~ 10)

> **Data Structure Reference:** §5.2 RouteSelectionRecord, §6.2 PathPlanResult/PathInfo/HopInfo

**Step 9 - UDP Port Computation (Inter-chassis Multi-path Scenario):**

When `RouteSelectionRecord` list is non-empty, a 8-bit source UDP port number (0~255) needs to be computed for forward and reverse directions separately, so that the hash algorithm selects the `interDevices` specified path on each ECMP segment.

> **Bit-width Constraint Note:** `dataUdpSrcPort` and `ackUdpSrcPort` are both strictly limited to 8 bits (0~255), determined by hardware offload register bit width. All algorithms involving UDP port search operate within this space.

> **Background:** In inter-chassis multi-path scenarios (e.g., NPU0↔L1SW0↔L2SW↔L1SW1↔NPU1), routing tables on intermediate devices L1SW0 and L2SW may simultaneously have multiple out ports (ECMP). The same source UDP port number must simultaneously satisfy hash route selection constraints on all ECMP segments, ensuring the entire path connects according to `interDevices` specified ports.

**9.1 Hash Algorithm Definition:**

```
Selected port index = hash(SCNA, DCNA, srcUdpPort) % candidateOutPorts.size()
```

- **Input tuple**: `SCNA` (source CNA, 32 bit) + `DCNA` (destination CNA, 32 bit) + `srcUdpPort` (source UDP port number, 8 bit)
- **Output**: Integer hash value, modulo candidate port count to get selected out port index
- **Stubbable**: Hash function can be stub injected during testing, precisely controlling output values for specific tuples, bypassing multi-segment coupled search complexity

**9.2 Forward Path Port Computation (dataUdpSrcPort):**

The forward path's UDP source port corresponds to `PathPlanResult.dataUdpSrcPort`, computed as follows:

```
Filter: RouteSelectionRecord list L_fwd where direction == FORWARD

For each record r ∈ L_fwd:
    N_r     = r.candidateOutPorts.size()         // Candidate port count
    idx_r   = Index of selected=true in r.candidateOutPorts  // Target port position
    SCNA_r  = CNA1                                 // Source CNA
    DCNA_r  = CNA2                                 // Destination CNA

Iterate port ∈ [0, 255]:
    If ∀ r ∈ L_fwd: hash(SCNA_r, DCNA_r, port) % N_r == idx_r:
        dataUdpSrcPort = port
        break
```

- Condition satisfied: All FORWARD direction ECMP segments selected target port → record `dataUdpSrcPort`
- No solution (no port value in 0~255 range satisfies all constraints) → return error code **1** (`FAILED`)

**9.3 Reverse Path Port Computation (ackUdpSrcPort):**

The reverse path's UDP source port corresponds to `PathPlanResult.ackUdpSrcPort`, computed similarly to forward but with SCNA/DCNA swapped:

```
Filter: RouteSelectionRecord list L_rev where direction == REVERSE

For each record r ∈ L_rev:
    N_r     = r.candidateOutPorts.size()
    idx_r   = Index of selected=true in r.candidateOutPorts
    SCNA_r  = CNA2                                 // Reverse: source CNA = CNA2
    DCNA_r  = CNA1                                 // Reverse: destination CNA = CNA1

Iterate port ∈ [0, 255]:
    If ∀ r ∈ L_rev: hash(SCNA_r, DCNA_r, port) % N_r == idx_r:
        ackUdpSrcPort = port
        break
```

**9.4 Forward-Reverse Relationship Description:**

| Attribute | Forward (dataUdpSrcPort) | Reverse (ackUdpSrcPort) |
|:-----|:----------------------|:----------------------|
| Hash input SCNA | CNA1 (source port CNA) | CNA2 (destination port CNA) |
| Hash input DCNA | CNA2 (destination port CNA) | CNA1 (source port CNA) |
| Source UDP port | `dataUdpSrcPort` (8 bit) | `ackUdpSrcPort` (8 bit) |
| Corresponding result field | `PathPlanResult.dataUdpSrcPort` | `PathPlanResult.ackUdpSrcPort` |

- Forward and reverse paths pass through the same devices and out ports (guaranteed by `interDevices`), but SCNA/DCNA are swapped in hash input, therefore `dataUdpSrcPort` and `ackUdpSrcPort` are **computed independently** and can have different values.
- When only one ECMP segment exists on the path, typically multiple UDP port values satisfy the constraint, with ample search space.
- When multiple ECMP segments exist on the path (e.g., both L1SW0 and L2SW have multi-path), the same UDP port must simultaneously satisfy multi-segment constraints, narrowing search space. Since hash is stub-implemented, testing can inject precise mappings to bypass multi-segment coupling.

**9.5 No ECMP Scenario:**

If `RouteSelectionRecord` list is empty (all device out ports on the path are unique), this step is skipped; `dataUdpSrcPort` and `ackUdpSrcPort` use default values or are left empty.

**9.6 RouteSelectionRecord Lifecycle Review:**

| Phase | Operation | Record Direction |
|:-----|:-----|:---------|
| Forward (Step 6→8→9→10) | Forward path ECMP nodes → append records | FORWARD |
| Reverse (Step 7→8→9→10) | Reverse path ECMP nodes → append records | REVERSE |
| §9.5 Step 9 | Consume by direction group, independently compute dataUdpSrcPort / ackUdpSrcPort | Both directions |

**Step 10 - Fill PathPlanResult:**
Fill the following information into `PathPlanResult` object (§6.2):
- `sourceEid` / `destEid`: EID pair information (from Step 1/2)
- `path`: Path hop-by-hop information (`PathInfo` → `List<HopInfo>`), converted from `InternalPathInfo.hops` (§5.1) to external `HopInfo` (§6.2.2)
- `ackUdpSrcPort` / `dataUdpSrcPort`: UDP port pair information (if §9.5 Step 9 has computed)

Return success (code **0**), with complete `PathPlanResult` information.

---

### 9.6 Error Code and Step Mapping

| Error Code | Name | Trigger Step | Description |
|:-------|:-----|:---------|:-----|
| 0 | SUCCESS | Step 4 / 10 | Success (direct connection success or complete path planning success) |
| 1003 | SRC_INFO_ERR | Step 1 | Source information missing |
| 1004 | DST_INFO_ERR | Step 2 | Destination information missing |
| 1007 | TOPO_INCOMPLETE | Step 0 / 5 | Topology incomplete (device not found in SuperNode) |
| 1008 | TOPO_CONNECTION_ERROR | Step 4 | Direct connection validation failed (port connection relationship mismatch) |
| 1009 | TOPO_CONNECTION_NOT_FOUND | Step 5 | Multi-hop path resolution failed (connection relationship error) |
| 1010 | ROUTE_NOT_REACHABLE | Step 8 | Route unreachable (no route, no out port, or out port inconsistent with topology) |
| 1011 | COVERAGE_INCOMPLETE | Coverage planning phase | Coverage planning did not reach 100% (only planPathsCoverage/planPathsCoverageEx) |
| 1012 | TOPO_NOT_FOUND | Step 0 | Super node does not exist |
| 3002 | SRC_AND_DST_MUST_BE_NPU | Step 0 | Source and destination must be NPU devices |
| 3003 | UPI_MISMATCH | Step 0 | Source and destination port UPI mismatch |

---

### 9.7 Flow Data Flow Overview

```
PathPlanRequest (§6.1)
    │ superNodeName, srcDevice, srcPort, destDevice, destPort, interDevices
    │
┌──────────────────────────────────────────────────────────────────────────┐
│ Phase 1 (Step 0~2): Device Judgment and Info Lookup                    │
│   SuperNode.getNpuDevices() → NpuDevice → NpuDevice.findNpuPort()        │
│   findNpuPort uses NpuForwardingChip.getNpuPorts(), no instanceof/cast │
│   Extract: EID1, CNA1, EID2, CNA2, port1/port2 connection info        │
│   Error codes: 3002, 3003, 1003, 1004, 1007, 1012                      │
└─────────────────────────┬────────────────────────────────────────────────┘
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
┌─────────────────────────┐  ┌──────────────────────────────────────────────┐
│ Phase 2: interDevices empty │  │ Phase 2: interDevices non-empty              │
│ Step 4: Direct validation │  │ Step 5: Multi-hop resolution → InternalPathInfo│
│ (terminal)                │  │   Validate: device existence, port existence, │
│ Error code: 1008          │  │   connection continuity                      │
│ Success: Return directly  │  │   Error codes: 1007, 1009                    │
│ (code 0)                  │  └─────────────────────┬────────────────────────┘
┌─────────────────────────┐  │                       │
                            │
┌──────────────────────────────────────────────────────────────────────────┐
│ Phase 3 (Step 6→7→8→9→10): Path Planning Loop (Forward + Reverse)    │
│   Step 6: Forward setup (target=CNA2, dst=dev2, phase=FORWARD)          │
│   Step 7: Reverse setup (reverse path, target=CNA1, dst=dev1, phase=REVERSE) │
│                                                                           │
│   Step 8 (for each intermediate device):                                 │
│     ┌─────────────────────────────────────────────────────────────────┐  │
│     │ ① Iterate device.getForwardingChips() all chips                    │  │
│     │ ② For each chip: RoutingTableKey → superNodeStore.getRoutingTable│  │
│     │ ③ Indexed mask match: maskLengths[0..n] → RoutePrefix → O(1) hit │  │
│     │ ④ Cross-chip selection: take RoutingEntry with largest maskLen    │  │
│     │ ⑤ Out port and next-hop consistency validation                   │  │
│     │ ⑥ Result forwarded to Step 9                                   │  │
│     └─────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│   Step 9: Out Port Judgment                                             │
│     1 out port → proceed to next hop normally                           │
│     Multiple out ports → append RouteSelectionRecord + multiPath=true/spray=true │
│                                                                           │
│   Error codes: 1010                                                      │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
┌──────────────────────────────────────────────────────────────────────────┐
│ Phase 4 (Step 9~10): Output Construction                              │
│   Step 9: UDP port computation (based on forward + reverse RouteSelectionRecord list) │
│   Step 10: InternalPathInfo → PathPlanResult [§6.2]                     │
│   Return success (code 0)                                                │
└──────────────────────────────────────────────────────────────────────────┘
```

---

---

