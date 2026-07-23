# SNC (Supernode Network Controller) Design Document

> This document defines the class design for the SNC module, including the domain model, computation model, northbound data structures, northbound interfaces, path planning algorithm, and detailed path planning flow.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Northbound Mechanism](#2-northbound-mechanism)
3. [File Directory Design](#3-file-directory-design)
4. [Data Structure Definitions (Domain Model Entity)](#4-data-structure-definitions)
5. [Pure Internal Data Structures (Computation Model)](#5-pure-internal-data-structures)
6. [Northbound Data Structures (DTO)](#6-northbound-data-structures)
   - [6.1 PathPlanRequest (Path Planning Request)](#61-pathplanrequest)
   - [6.2 PathPlanResult (Path Planning Response)](#62-pathplanresult)
   - [6.3 Relationship Between Northbound and Internal Data Structures](#63-relationship-between-northbound-and-internal-data-structures)
7. [Northbound Interface](#7-northbound-interface)
   - [7.1 Interface Overview](#71-interface-overview)
   - [7.2 SNCService Interface Definition](#72-sncservice-interface-definition)
   - [7.3 Invocation Sequence](#73-invocation-sequence)
   - [7.4 State Machine](#74-state-machine)
   - [7.5 Error Handling](#75-error-handling)
   - [7.6 Parameter Validation Rules](#76-parameter-validation-rules)
   - [7.7 Interface Implementation Mapping](#77-interface-implementation-mapping)
   - [7.8 Invalid Invocation Order Description](#78-invalid-invocation-order-description)
   - [7.9 SuperNodeStore (Topology Storage)](#79-supernodestore)
   - [7.10 AclStore (ACL Storage)](#710-aclstore)
8. [Path Planning Algorithm — Indexed Mask Match](#8-path-planning-algorithm--indexed-mask-match)
9. [Detailed Path Planning Flow](#9-detailed-path-planning-flow)

---

## 1. Overview

### 1.1 Business Background

SNC (Supernode Network Controller) is a super node controller responsible for managing network topology, ACL, and routing information, and providing path planning functionality that returns the parameters required for communication path coverage.

### 1.2 Core Functional Requirements

| Functional Module | Description | Priority |
|:----------------:|:-------------------------------|:------:|
| Initialization/Deinitialization | SNC service startup and shutdown | P0 |
| SuperNode Data Management | Network topology structure provisioning, querying, and deletion | P1 |
| TP-ACL Data Management | Transport policy access control list provisioning, querying, and deletion | P1 |
| Path Planning | Path planning based on EID pairs and ACL validation | P2 |

---

## 2. Northbound Mechanism

### 2.1 Northbound Overview

**Northbound Data Flow:**
```
┌──────────────────────────────────────────────────┐
│         Upper-layer Orchestrator/Management System│ (Northbound caller) │
│   - Topology data entry (including routing info) │             │
│   - ACL policy provisioning                     │             │
│   - Path planning request                       │             │
└──────────────┬───────────────────────────────────┘
               │ API Call
┌──────────────▼──────────────────────────────────┐
│        SNC Module (this module)                  │             │
│   - Data persistence and indexing               │             │
│   - Path planning and path resolution           │             │
│   - ACL validation                              │             │
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

- **Configuration operations (topology/ACL provisioning):** Synchronous calls; the caller provides complete data snapshots.
- **Query operations (path planning):** Synchronous calls; request-response mode; the caller sends a PathPlanRequest, SNC returns a PathPlanResult.
- **Initialization/Deinitialization:** Synchronous calls; SNC loads data from the northbound at startup or receives full synchronization; deinitialization clears in-memory data.

### 2.3 Data Consistency Guarantee

- Topology data (including routing information) and ACL data are provisioned as full snapshots; SNC does not maintain incremental change logs.
- All data uses in-memory HashMap indexing, ensuring O(1) lookup efficiency.
- Path planning is computed in real-time based on in-memory data, with no dependency on external storage.

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
│   ├── PortEntity.java                # Port abstract base class
│   ├── NpuPortEntity.java             # NPU port (§4.5.1)
│   ├── SwPortEntity.java              # Switch port (§4.5.2)
│   ├── LogicPortEntity.java           # Logical port (§4.6)
│   ├── RoutingTable.java              # Routing table (§4.7)
│   ├── RoutingEntry.java              # Routing entry (§4.9)
│   ├── RoutePrefix.java               # Route prefix structure (§4.8)
│   ├── RoutingTableKey.java           # Routing table composite key (superNodeName + deviceName + chipIndex, §4.7.1)
│   ├── OutPortInfo.java               # Out port information (§4.9.1)
│   ├── AclData.java                   # ACL data container (§4.10)
│   ├── AclKey.java                    # ACL composite key (§4.11)
│   ├── TpAclEntity.java               # TP-ACL entity (§4.12)
│   ├── TransportType.java             # Transport type enum (RMTP/RCTP/CTP/UTP) (§4.10)
│   ├── InternalPathInfo.java          # §5.1 Internal path information (engine computation context)
│   ├── InternalPathHop.java           # §5.1 Internal path hop
│   └── RouteSelectionRecord.java      # §5.2 Internal route selection record
│
├── dto/                               # §6 Northbound API DTO (decoupled from domain model)
│   ├── PathPlanRequest.java           # Path planning request (§6.1)
│   ├── PathPlanResult.java            # Path planning response + PlanStatus enum (§6.2)
│   ├── PathInfo.java                  # Path information (§6.2.1)
│   └── HopInfo.java                   # Hop information (§6.2.2)
│
├── service/                           # Business logic layer (orchestration)
│   ├── SuperNodeService.java               # Topology data management
│   ├── AclService.java                # ACL data management
│   └── PathService.java               # Path planning orchestration (calls engine layer)
│
├── store/                             # Data storage layer (HashMap indexing)
│   ├── SuperNodeStore.java               # Topology index (superNodeName→SuperNode / routingTableMap)
│   └── AclStore.java                  # ACL index (superNodeName→AclData / tpAclMap)
│
├── engine/                            # Algorithm engine layer
│   ├── PathEngine.java                # Path resolution engine (Step 5~7)
│   ├── RouteLookupEngine.java         # Path planning engine / Indexed Mask Match (Step 8~12, §8)
│   └── AclCheckEngine.java            # ACL validation engine (Step 3~4)
│
├── exception/                         # Exception definitions (§7.5.2)
│   ├── SNCException.java              # Base exception
│   ├── SNCStateException.java         # State exception
│   ├── SuperNodeNotFoundException.java     # Topology data not found
│   ├── AclNotFoundException.java      # ACL data not found
│   └── PathPlanException.java         # Path planning failure (contains PlanStatus)
│
└── util/                              # Utility classes
    └── AddressUtils.java              # CNA mask calculation, address format validation
```

### 3.3 Dependency Relationships

```
                    ┌──────────┐
                    │   dto    │ (§6 Northbound API DTO, no internal dependencies, pure data structures)
                    └────▲─────┘
                         │uses
                    ┌────┴─────┐
                    │ service  │ (Orchestration layer: SuperNodeService / AclService / PathService)
                    └─┬──┬──┬─┘
                      │  │  │
            ┌─────────┘  │  └─────────┘
            │            │            │
       ┌────────┐  ┌─────────┐  ┌────────┐
       │ store  │  │ engine  │  │ entity │
       │(index) │  │(algo)   │  │(model) │
       └───┬────┘  └────┬────┘  └────────┘
           │            │
           └─────┬──────┘
                 │query/write
           ┌────────┐
           │ entity │ (§4 Domain Model + §5 Computation Model, shared dependency of store/engine/service)
           └────────┘
```

| Layer | Can Depend On | Cannot Depend On | Description |
|:---|:-------|:--------|:-----|
| `dto` | - | entity / service / store / engine | API contract layer, independent of internal implementation |
| `entity` | util | dto / service / store / engine | Pure data structure layer |
| `store` | entity / util | dto / service / engine | Index storage, directly operates on domain model |
| `engine` | entity / util | dto / service / store | Algorithm engine, reads entity and outputs §5 computation model |
| `service` | entity / dto / store / engine / util | - | Orchestration layer, completes DTO-to-domain-model mapping |
| `exception` | dto.PathPlanResult.PlanStatus | - | Exceptions can reference error code enum (PlanStatus defined inside §6.2 PathPlanResult) |
| `util` | - | entity / dto / service / store / engine | Pure utility class |

### 3.4 Interface Layer to Internal Layer Conversion Mapping

`SNCServiceImpl` is located at the package root, responsible for connecting `dto` with internal `entity`/`service`.

```
SNCServiceImpl
    │
    ├── init(SNCConfig)
    │     └→ SuperNodeStore.init() + AclStore.init()
    │     └→ Only operates on config and store, does not involve dto
    │
    ├── setSuperNode(SuperNode)          // entity.SuperNode (§4.1 Domain Model)
    │     └→ SuperNodeService.importSuperNode(superNode)
    │              └→ SuperNodeStore.replace(superNode)
    │
    ├── setAclData(AclData)            // entity.AclData (§4.12 Domain Model)
    │     └→ AclService.importAclData(aclData)
    │              └→ AclStore.replace(aclData)
    │
    ├── planPath(PathPlanRequest)      // dto.PathPlanRequest (§6.1 DTO)
    │     └→ PathService.planPath(request)
    │              ├→ superNode.getNpuDevices().get(srcDevice/destDevice)  // Step 0: NPU device lookup
    │              ├→ srcNpuDevice.findNpuPort() + destNpuDevice.findNpuPort() // Step 1~2: Port lookup (directly uses NpuForwardingChip.getNpuPorts(), no instanceof/cast)
    │              ├→ AclCheckEngine.check()                        // Step 3~4: ACL bidirectional validation (reads entity.TpAclEntity)
    │              ├→ PathEngine.resolveDirectPath/resolveMultiHopPath(→ InternalPathInfo) // Step 5~7: Path resolution
    │              │    Signature: (NpuDevice, NpuPortEntity, NpuDevice, NpuPortEntity, ...)
    │              ├→ superNode.getAllDevices() + RouteLookupEngine.lookup() // Step 8~12: Path planning
    │              └→ Assemble dto.PathPlanResult                       // Step 13~15: Output construction (§6.2 DTO)
    │
    └── uninit()
            └→ SuperNodeStore.clear() + AclStore.clear()
```

> `setSuperNode` / `setAclData` input parameters directly use `entity.SuperNode` / `entity.AclData` (domain model) because they originate from JSON deserialization of the raw structure and correspond 1:1 to topology files, requiring no additional DTO wrapping. `planPath` input/output uses `dto.PathPlanRequest` / `dto.PathPlanResult` because they are oriented toward northbound callers and require stable API contracts.

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

    public NpuPortEntity(String portName, Integer id, Integer chipIndex,
                         String remoteDevice, String remotePort, String cna,
                         String eid, String upi) {
        super(portName, id, chipIndex, remoteDevice, remotePort, cna);
        this.eid = eid;
        this.upi = upi;
    }
}
```

**Field Constraints:**
- `eid`: 128-bit EID identifier, string format. Only NPU ports carry EID information.
- NpuPortEntity is stored in `NpuForwardingChip.ports` (`Map<String, NpuPortEntity>`, §4.4.1), accessed directly via `getNpuPorts()` for the precise type, without instanceof/cast.

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
- Switch device ports have no CNA/EID/UPI concept; the `cna` field in switch port scenarios is **optional** (can be null) and does not participate in ACL validation or CNA matching in path planning.
- `remoteDevice` / `remotePort` are core fields for switch ports, used for multi-hop topology path resolution.
- SwPortEntity is stored in `SwForwardingChip.ports` (`Map<String, SwPortEntity>`, §4.4.2), accessed directly via `getSwPorts()` for the precise type, without instanceof/cast.

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
- `RoutingTable`: Stored independently in `SuperNodeStore.routingTableMap`, keyed by `RoutingTableKey` (`superNodeName + deviceName + chipIndex`) (`Map<RoutingTableKey, RoutingTable>`, §4.7.1), supporting global O(1) lookup. Under multiple super nodes, deviceName may be duplicated, distinguished by superNodeName. `RoutingTable` is not used as a HashMap key; `equals()`/`hashCode()` is generated by Lombok `@EqualsAndHashCode` (all fields participate, consistent with `RoutePrefix` §4.8 and `AclKey` §4.11).
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
- `equals()` and `hashCode()` are automatically generated by Lombok `@EqualsAndHashCode` (all three fields participate), ensuring HashMap lookup correctness. This approach is consistent with `AclKey` (§4.11) and `RoutePrefix` (§4.8).

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
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class RoutingEntry {
    /** Target prefix structure -- includes destination address (dstAddress) and mask length (maskLength) */
    private RoutePrefix prefix;

    /** Out port information Map -- supports multiple out ports (ECMP), Map key is portName, required field */
    private Map<String, OutPortInfo> outPortInfos;
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| prefix | RoutePrefix | Target prefix structure, includes destination address and mask length |
| outPortInfos | Map\<String, OutPortInfo\> | Out port information Map, key is portName, supports multiple out ports (ECMP), required field |

**Notes:**
- `RoutingEntry` is stored in `RoutingTable.routes`, keyed by `RoutePrefix` object.
- During path planning, CNA is padded to a 32-bit `targetAddr` (see §4.8.1), and known masks are taken from `RoutingTable.maskLengths` for level-by-level O(1) lookup by constructing keys (§8).
- For example, `1.1.1.0/24` and `1.1.1.0/20` are different routes because different masks result in different `RoutePrefix`.

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
    private String portName;         // Out interface name -- Required field
    private String nextHop;          // Next hop IP
    private Integer preference;      // Route priority (1-255, default 60)
    private Integer tag;             // Route tag
    private String protocol;         // Route protocol type
}
```

| Field | Type | Description |
|:-----|:-----|:-----|
| portName | String | Out interface name -- Required field |
| nextHop | String | Next hop IP |
| preference | Integer | Route priority (1-255, default 60) |
| tag | Integer | Route tag |
| protocol | String | Route protocol type |

**Notes:**
- Mask length has been migrated to the `RoutePrefix` structure; `OutPortInfo` no longer contains a `maskLength` field.
- The above five fields are uniformly encapsulated in `OutPortInfo`, serving as the value in `RoutingEntry.outPortInfos` Map; Map key is `portName`, supporting O(1) lookup and traversal, covering ECMP scenarios.

---

### 4.10 AclData (ACL Data)

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class AclData {
    /** ACL identifier, corresponding to SuperNode.name, indicating which super node this ACL data belongs to -- Required field */
    private String superNodeName;

    /** ACL Map -- Required field, Map key is AclKey (composite object) */
    private Map<AclKey, TpAclEntity> tpAcls;
}
```

**Key Notes:**
- `superNodeName`: ACL identifier, corresponding to `SuperNode.name` (superNodeName), used for per-super-node differentiated storage in `AclStore`. External ACL data for multiple super nodes can be provisioned, each stored with `superNodeName` as the `AclStore.store` Map key (see §7.9).
- `tpAcls`: Map key is `AclKey` (composite object, including sourceEid + destEid + transportType), used for O(1) ACL rule lookup.

---

### 4.11 AclKey (ACL Composite Key)

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class AclKey {
    /** Source EID -- 128 bit */
    private String sourceEid;

    /** Destination EID -- 128 bit */
    private String destEid;

    /** Transport type */
    private TransportType transportType;
}
```

**Constraints:**
- `equals()` and `hashCode()` are automatically generated by Lombok `@EqualsAndHashCode` (based on three fields: sourceEid, destEid, transportType), ensuring HashMap lookup correctness.
- The three fields (sourceEid, destEid, transportType) jointly uniquely identify one ACL rule.
- **AclKey** stores the triple (sourceEid + destEid + transportType), serving as a HashMap index key for O(1) ACL rule lookup.
- **TpAclEntity** stores validation fields (sourceCna + destCna + templateId), without redundantly storing the EID triple. During ACL validation, after locating TpAclEntity via AclKey, the CNA consistency between the entry's CNA and the port's CNA is verified (see §9.3 Step 3~4).

---

### 4.12 TpAclEntity (TP-ACL Entity)

```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class TpAclEntity {
    /** Source address (only supports CNA) -- 32 bit -- Required field */
    private String sourceCna;

    /** Destination address (only supports CNA) -- 32 bit -- Required field */
    private String destCna;

    /** Template ID (1-19) */
    private Integer templateId;
}
```

**Transport Type Enum:**

```java
public enum TransportType {
    RMTP,  // Reliable Transfer Protocol (Reliable Connection) -- supported in current version
    RCTP,  // Reliable Transfer Protocol (Reliable Messaging) -- reserved, to be enabled in future versions
    CTP,   // Connection-oriented Transport Protocol -- reserved, to be enabled in future versions
    UTP    // Unreliable Transfer Protocol -- reserved, to be enabled in future versions
}
```

> **Usage Note:** The current version (V1) ACL validation and path planning only supports `RCTP`; `RMTP`, `UTP`, `CTP` are reserved enum values. A `transportType` field will be added to `PathPlanRequest` in future versions, enabled once the caller specifies the transport type. Currently the `planPath()` flow hardcodes `RCTP` (see §9.3).
>
> **Enum Definition Location Note:** The `TransportType` enum is defined in §4.12 (adjacent to `TpAclEntity`), but §4.11 `AclKey`'s `transportType` field already references this enum type; readers can refer forward to §4.12 for enum value definitions.

**ACL Validation Rules:**
- During path planning, lookup uses `(sourceEid, destEid, transportType)` in HashMap.
- After finding the entry, verify `sourceCna` matches the source device port CNA, and `destCna` matches the destination device port CNA.
- Bidirectional check: first check forward (EID1→EID2), then check reverse (EID2→EID1); both must pass for ACL validation to succeed.


## 5 Pure Internal Data Structures

### 5.1 InternalPathInfo (Internal Path Information)

> **Design Basis:** Refer to §9.4 Phase 3 Step 7 — Multi-hop path resolution flow.

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

Encapsulates the complete internal path, constructed in Step 7 and consumed in subsequent Steps 8~12.

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
Step 7 (Multi-hop path resolution):
    Input:  PathPlanRequest (srcDevice, srcPort, destDevice, destPort, interDevices)
    Output: InternalPathInfo (hop-by-hop populated with topology consistency validation)
    
Step 8~12 (Path planning loop):
    Input:  InternalPathInfo (constructed from Phase 3)
    Process: Iterate InternalPathInfo.hops, perform path planning for each intermediate device
    Output: RouteSelectionRecord list (produced from Step 11)
    
Step 14 (Populate PathPlanResult):
    Input:  InternalPathInfo.hops
    Output: PathPlanResult.paths (converted to external HopInfo list)
```

---

### 5.2 RouteSelectionRecord (Internal Route Selection Record)

> **Design Basis:** Refer to §9.5 Phase 4 Step 11 — Out port determination and route selection recording.

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
     *  source UDP port number (8 bit, calculated and filled in by Step 13).
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

| Field | Source | Corresponding Item in Step 11 Pseudocode |
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
- Out port count > 1 and device does not support per-flow → Do not record, return error code **1011**.
- Out port count > 1 and device supports per-flow → Record one `RouteSelectionRecord`, where `candidateOutPorts` contains all candidate out interfaces (all ECMP paths), the port consistent with `interDevices` specified out port is marked as `selected=true` (target port), others as `false`. Proceed to next hop.

**Consumption Relationship:**
```
Step 11 (Record):
    For each intermediate device with ECMP → generate RouteSelectionRecord
    → candidateOutPorts records all candidate out interfaces + selected marker
    
Step 13 (UDP port computation):
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

**Field Description:**

| Field | Type | Description |
|:-----|:-----|:-----|
| sourceEid | String | Source EID (128 bit), from source NPU port, see §4.5.1 NpuPortEntity.eid |
| destEid | String | Destination EID (128 bit), from destination NPU port, see §4.5.1 NpuPortEntity.eid |
| path | PathInfo | Path details, containing hop-by-hop information |
| status | PlanStatus | Query status, 0=success, non-0=failure (error codes see table above) |
| errorMessage | String | Failure reason description, filled when status is not SUCCESS |
| ackUdpSrcPort | Integer | Ack UDP source port (8 bit), computed by Step 13, for hardware offload |
| dataUdpSrcPort | Integer | Data UDP source port (8 bit), computed by Step 13, for hardware offload |
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

### 6.3 Relationship Between Northbound and Internal Data Structures

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

The SNC module exposes a unified northbound interface `SNCService`, located in package `com.huawei.umdk.snc`. The caller (upper-layer orchestrator/management system) uses this interface to perform four phases of operations: **initialization, data provisioning, path planning, and deinitialization**.

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
    ├── setAclData(AclData) → void                 // ACL full provisioning
    ├── addAclRules(String, Map<AclKey, TpAclEntity>) → void  // ACL incremental: batch add/update rules
    ├── removeAclRules(String, List<AclKey>) → void          // ACL incremental: batch remove rules
    ├── getAclData(String) → AclData               // ACL data query
    ├── removeAclData(String) → void               // ACL data deletion
    │
    ├── planPath(PathPlanRequest) → PathPlanResult     // Path planning (single path)
    └── uninit() → void                                // Deinitialization
```

> **Data Structure Reference:** For complete definitions of northbound data structures involved in the interface such as `PathPlanRequest`, `PathPlanResult`, `PathInfo`, `HopInfo`, `PlanStatus`, etc., see [§6 Northbound Data Structures](#6-northbound-data-structures).

---

### 7.2 SNCService Interface Definition

```java
package com.huawei.umdk.snc;

import java.util.List;
import java.util.Map;

import com.huawei.umdk.snc.entity.*;
import com.huawei.umdk.snc.config.SNCConfig;

/**
 * SNC main service interface — Northbound entry point
 *
 * <h3>Invocation Order Constraints</h3>
 * <pre>{@code
 *   sncService.init(config);                    // 1. Initialization
 *   sncService.setSuperNode(superNode);           // 2. Provision topology data (can be called multiple times to update)
 *   sncService.setAclData(aclData);             // 3. Provision ACL data (can be called multiple times to update)
 *   sncService.addNpuDevices("A5-superPod-1", List.of(npuDevice));  // 4. Incremental: batch add NPU devices
 *   sncService.addSwDevices("A5-superPod-1", List.of(swDevice));    // 5. Incremental: batch add SW devices
 *   sncService.removeDevices("A5-superPod-1", List.of("rack1#os0#npu1")); // 6. Incremental: batch remove devices
 *   sncService.addRoutingEntries("A5-superPod-1", "rack1#os0#npu1", 0, List.of(entry)); // 6. Incremental: batch add routes
 *   sncService.addAclRules("A5-superPod-1", Map.of(aclKey, aclEntity)); // 7. Incremental: batch add ACL rules
 *   sncService.planPath(request);               // 8. Path planning (can be called concurrently multiple times)
 *   SuperNode td = sncService.getSuperNode("A5-superPod-1");   // 9. Topology data query
 *   AclData ad = sncService.getAclData("A5-superPod-1");     // 10. ACL data query
 *   sncService.removeSuperNode("A5-superPod-1");              // 11. Topology data deletion
 *   sncService.removeAclData("A5-superPod-1");               // 12. ACL data deletion
 *   sncService.uninit();                       // 13. Deinitialization
 * }</pre>
 *
 * <h3>State Constraints</h3>
 * - Calling other interfaces without init(): throws SNCStateException
 * - Calling other interfaces after uninit(): throws SNCStateException
 * - Repeated init(): idempotent handling or throws SNCStateException
 *
 * @see PathPlanRequest
 * @see PathPlanResult
 * @see SuperNode
 * @see AclData
 */
public interface SNCService {

    // ============ Lifecycle Management ============

    /**
     * Initialize SNC service
     *
     * Load configuration, initialize internal HashMaps (topology index, ACL index).
     *
     * @param config SNC configuration (logging strategy, indexing strategy, etc.), can be null (uses default configuration)
     * @throws SNCStateException State exception (duplicate initialization, etc.)
     */
    void init(SNCConfig config);

    /**
     * Deinitialize SNC service
     *
     * Clear all in-memory data (topology Map, ACL Map), release resources.
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

    /**
     * Provision ACL data (full replacement)
     *
     * Parse and index AclData into in-memory HashMap.
     * - Uses full replacement (replace) strategy.
     * - Can be called multiple times; each call fully replaces all ACL entries.
     * - Topology and ACL provisioning order can be swapped.
     *
     * @param aclData ACL data container (§4.12)
     * @throws IllegalArgumentException aclData is null
     * @throws SNCStateException SNC not initialized
     */
    void setAclData(AclData aclData);

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

    // ============ Incremental Update - ACL ============

    /**
     * Incrementally batch add/update ACL rules
     *
     * Batch add or update TP-ACL rules in the specified ACL data.
     *
     * @param superNodeName ACL identifier (corresponding to AclData.superNodeName, §4.10)
     * @param rules ACL rules Map (key=AclKey, value=TpAclEntity), each entry's key and value non-null
     * @throws IllegalArgumentException Any parameter is null
     * @throws SNCStateException SNC not initialized
     */
    void addAclRules(String superNodeName, Map<AclKey, TpAclEntity> rules);

    /**
     * Incrementally batch remove ACL rules
     *
     * Batch remove TP-ACL rules from the specified ACL data.
     *
     * @param superNodeName ACL identifier (corresponding to AclData.superNodeName, §4.10)
     * @param keys ACL composite key list (§4.11), each element non-null
     * @throws IllegalArgumentException Any parameter is null, or AclData does not exist
     * @throws SNCStateException SNC not initialized
     */
    void removeAclRules(String superNodeName, List<AclKey> keys);

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

    /**
     * Query ACL data
     *
     * Get the corresponding AclData object from AclStore by superNodeName.
     *
     * @param superNodeName ACL identifier (corresponding to AclData.superNodeName, §4.10)
     * @return AclData object, returns null if ACL data for the specified superNodeName does not exist
     * @throws IllegalArgumentException superNodeName is null or empty string
     * @throws SNCStateException SNC not initialized
     */
    AclData getAclData(String superNodeName);

    /**
     * Delete ACL data
     *
     * Remove the corresponding ACL data from AclStore by superNodeName.
     *
     * @param superNodeName ACL identifier (corresponding to AclData.superNodeName, §4.10)
     * @throws IllegalArgumentException superNodeName is null or empty string
     * @throws SNCStateException SNC not initialized
     */
    void removeAclData(String superNodeName);

    // ============ Path Planning ============

    /**
     * Path planning (synchronous request-response mode)
     *
     * Based on source/destination device and port information, execute path planning and path resolution,
     * returning complete communication path parameters.
     * Internally executes Step 0 ~ Step 15 flow.
     *
     * <table>
     *   <tr><th>Phase</th><th>Step</th><th>Description</th></tr>
     *   <tr><td>Phase 1</td><td>Step 0~2</td><td>Device judgment and source/destination info lookup §9.2</td></tr>
     *   <tr><td>Phase 2</td><td>Step 3~4</td><td>ACL bidirectional validation §9.3</td></tr>
     *   <tr><td>Phase 3</td><td>Step 5~7</td><td>Path resolution (direct/multi-hop) §9.4</td></tr>
     *   <tr><td>Phase 4</td><td>Step 8~12</td><td>Path planning loop (forward/reverse) §9.5</td></tr>
     *   <tr><td>Phase 5</td><td>Step 13~15</td><td>Output construction (UDP port computation + PathPlanResult filling) §9.6</td></tr>
     * </table>
     *
     * <h3>Prerequisites</h3>
     * - init() has been completed
     * - setSuperNode() has been called (topology data exists)
     * - setAclData() has been called (ACL data exists)
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
| setAclData | AclData | void | Synchronous | No (write operations require serialization) | Full replacement of ACL data |
| addAclRules | String, Map\<AclKey, TpAclEntity\> | void | Synchronous | No (write operations require serialization) | Incremental batch add/update ACL rules |
| removeAclRules | String, List\<AclKey\> | void | Synchronous | No (write operations require serialization) | Incremental batch remove ACL rules |
| getSuperNode | String | SuperNode | Synchronous | Yes (read-only, concurrent) | Query topology data by superNodeName |
| removeSuperNode | String | void | Synchronous | No (write operations require serialization) | Delete topology data and associated routing tables by superNodeName |
| getAclData | String | AclData | Synchronous | Yes (read-only, concurrent) | Query ACL data by superNodeName |
| removeAclData | String | void | Synchronous | No (write operations require serialization) | Delete ACL data by superNodeName |
| planPath | PathPlanRequest | PathPlanResult | Synchronous | Yes (read-only, concurrent) | Single path planning |

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
   │── setAclData(aclData) ───────────────────────────▶│  Phase 3: ACL provisioning
   │◀── void ────────────────────────────────────────│
   │                                                   │
│── planPath(request1) ────────────────────────────▶│  Phase 4: Path planning
│◀── PathPlanResult { status=0, path=... } ───────│ (can be called concurrently multiple times)
│                                                   │
│── planPath(request2) ────────────────────────────▶│
│◀── PathPlanResult { status=1005, ... } ─────────│
│                                                   │
│── getSuperNode("A5-superPod-1") ──────────────────▶│  Phase 5: Data query
│◀── SuperNode { name="A5-superPod-1", ... } ──────│
│                                                   │
│── getAclData("A5-superPod-1") ───────────────────▶│
│◀── AclData { superNodeName="A5-superPod-1", ... } ──────│
│                                                   │
│── removeSuperNode("A5-superPod-1") ───────────────▶│  Phase 6: Data deletion
│◀── void ────────────────────────────────────────│
│                                                   │
│── removeAclData("A5-superPod-1") ────────────────▶│
│◀── void ────────────────────────────────────────│
│                                                   │
│── uninit() ──────────────────────────────────────▶│  Phase 7: Deinitialization
│◀── void ────────────────────────────────────────│
   │                                                   │
```

> **Note:** The provisioning order of setSuperNode and setAclData can be swapped, but both must be completed before planPath.

---

### 7.4 State Machine

The SNC service internally maintains the following lifecycle states:

```
         init()                                 uninit()
  INIT ──────────▶ READY ──(setSuperNode & setAclData both completed)──▶ DATAREADY
   │                                │                                 │
   │                                │ Incremental operations (add/remove/get/…) │
   │                                │ setSuperNode / setAclData         │ planPath (can be called concurrently)
   │                                │ uninit()                         │ setSuperNode / setAclData (can update)
   │                                │ Incremental operations (add/remove/get/…) │
   │                                │                                 │
   └──── uninit() ───▶ UNINIT ◀───────────────────────────────────────┘
```

| State | Description | Allowed Operations |
|:-----|:-----|:----------|
| INIT | Initial state (not initialized) | init(), uninit() |
| READY | Ready state (initialized, data not ready) | setSuperNode, setAclData; all incremental operations (addNpuDevices, addSwDevices, removeDevices, addRoutingEntries, removeRoutingEntries, addAclRules, removeAclRules); all query operations (getSuperNode, getAclData); removeSuperNode, removeAclData; uninit |
| DATAREADY | Data ready state (topology + ACL both provisioned) | Same as READY, plus planPath |
| UNINIT | Deinitialized | (None, calling any operation throws SNCStateException) |

**State Transition Rules:**
- `init()`: INIT → READY (non-idempotent, repeated init rebuilds all internal objects)
- `uninit()`: INIT / READY / DATAREADY → UNINIT (calling in INIT state only clears state flag, no side effects)
- `setSuperNode()` + `setAclData()`: READY → DATAREADY (auto-transitions when both are provisioned)
- `setSuperNode()` / `setAclData()`: DATAREADY → DATAREADY (data ready state can continue updating data)
- `planPath()`: Only available in **DATAREADY** state; returns SNCStateException when not in DATAREADY

---

### 7.5 Error Handling

#### 7.5.1 Return Status Codes

All path planning error codes are returned via `PathPlanResult.status` (`PlanStatus` enum):

| Error Code | Enum Constant | Description | Trigger Phase |
|:------:|:--------|:-----|:--------|
| 0 | `SUCCESS` | Success | - |
| 1 | `FAILED` | General failure | - |
| 1001 | `SRC_EID_NOT_FOUND` | Source EID not found | Step 0 |
| 1002 | `DEST_EID_NOT_FOUND` | Destination EID not found | Step 0 |
| 1003 | `SRC_INFO_ERR` | Source info missing or incorrect | Step 1 |
| 1004 | `DST_INFO_ERR` | Destination info missing or incorrect | Step 2 |
| 1005 | `ACL_CHECK_FAILED` | ACL check failed (including ACL data not existing and ACL entry mismatch) | Step 3/4 |

| 1007 | `TOPO_INCOMPLETE` | Topology incomplete (device not found in super node devices) | Step 0 / Step 5~7 |
| 1008 | `TOPO_CONNECTION_ERROR` | Topology connection error (direct connection validation failed) | Step 6 |
| 1009 | `TOPO_CONNECTION_NOT_FOUND` | Topology connection not found (multi-hop path resolution failed) | Step 7 |
| 1010 | `ROUTE_NOT_REACHABLE` | Route not reachable (indexed mask match missed or route entry has no out port) | Step 10 |
| 1011 | `MULTI_PATH_NOT_SUPPORTED` | Multiple paths exist and device does not support per-flow | Step 11 |
| 1012 | `TOPO_NOT_FOUND` | Topology data not found (superNodeName is empty or corresponding SuperNode does not exist) | Step 0 |
| 1013 | `ACL_NOT_FOUND` | ACL data not found (setAclData not called or superNodeName has no corresponding AclData) | Step 3 |
| 3002 | `SRC_AND_DST_MUST_BE_NPU` | Source and destination must be NPU | Step 0 |
| 3003 | `UPI_MISMATCH` | Source and destination port UPI mismatch | Step 0 |

> **Complete Enum Definition:** [§6.2 PathPlanResult.PlanStatus](#62-pathplanresult-path-planning-response).

**Error Code Encoding Rules:**
- `0`: Success
- `1xxx`: Path planning phase errors (device/port/ACL/route/topology related)
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
├── AclNotFoundException     // ACL data not found
└── PathPlanException        // Path planning failure (contains PlanStatus error code and description)
```

| Exception Class | Usage Scenario | Handling Method |
|:-------|:--------|:--------|
| `SNCStateException` | Illegal invocation order (calling planPath without init, calling after uninit, etc.) | Throw directly, northbound caller catches and handles |
| `IllegalArgumentException` | Input parameter is null, required fields missing | Entry validation, throw directly |
| `SuperNodeNotFoundException` | setSuperNode not called or topology data incomplete (including superNodeName not existing and device not found) | Service layer converts to error code 1012/1001/1002/1007 |
| `AclNotFoundException` | setAclData not called or ACL data incomplete | Service layer converts to error code 1013/1005 |
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
| `aclData` non-null | `setAclData(AclData)` input parameter | Throw `IllegalArgumentException` |
| `request` non-null | `planPath(PathPlanRequest)` input parameter | Throw `IllegalArgumentException` |
| `request.superNodeName` non-empty | Super node name is required (§6.1), used for multi-super-node scenario positioning | Throw `IllegalArgumentException` |
| `request.srcDevice` non-empty | Source device is required (§6.1) | Throw `IllegalArgumentException` |
| `request.destDevice` non-empty | Destination device is required (§6.1) | Throw `IllegalArgumentException` |
| `request.srcPort` non-empty | Source port is required (§6.1) | Throw `IllegalArgumentException` |
| `request.destPort` non-empty | Destination port is required (§6.1) | Throw `IllegalArgumentException` |
| `superNodeName` non-empty | `getSuperNode(String)` / `removeSuperNode(String)` input parameter | Throw `IllegalArgumentException` |
| `superNodeName` non-empty | `getAclData(String)` / `removeAclData(String)` input parameter | Throw `IllegalArgumentException` |
| deviceName format | `rack#os#npu` or `rack#l1sw0` format | Engine layer validation, returns error code 1003/1004 |

> **Business rule validation** (device type must be NPU, EID/CNA completeness, etc.) is performed in the engine layer, not at the entry point.

---

### 7.7 Interface Implementation Mapping

The `SNCServiceImpl` implementation class delegates interface methods to internal components:

```
SNCServiceImpl
    │
    ├── init(SNCConfig)
    │     └→ SuperNodeStore.init() + AclStore.init()  // Initialize HashMaps
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
    ├── setAclData(AclData)
    │     └→ AclService.importAclData(aclData)
    │              └→ AclStore.replace(aclData)    // Full replacement of ACL index
    │
    ├── addAclRules(String, Map<AclKey, TpAclEntity>)
    │     └→ AclService.addAclRules(superNodeName, rules)              // Loop calls store.addAclRule()
    │              └→ AclStore.addAclRule(superNodeName, key, entity)  // Incremental add/update ACL rule (single entry)
    │
    ├── removeAclRules(String, List<AclKey>)
    │     └→ AclService.removeAclRules(superNodeName, keys)                  // Loop calls store.removeAclRule()
    │              └→ AclStore.removeAclRule(superNodeName, key)  // Incremental delete ACL rule (single entry)
    │
    ├── getSuperNode(String)
    │     └→ SuperNodeStore.getSuperNode(superNodeName)        // Query topology data
    │
    ├── removeSuperNode(String)
    │     └→ SuperNodeStore.removeSuperNode(superNodeName)     // Delete topology data and associated routing tables
    │
    ├── getAclData(String)
    │     └→ AclStore.getAclData(superNodeName)             // Query ACL data
    │
    ├── removeAclData(String)
    │     └→ AclStore.removeAclData(superNodeName)          // Delete ACL data
    │
    ├── planPath(PathPlanRequest)
    │     └→ PathService.planPath(request)
    │              ├→ AclCheckEngine.check()        // ACL validation (Step 3~4)
    │              ├→ PathEngine.resolvePath()      // Path resolution (Step 5~7)
    │              ├→ RouteLookupEngine.lookup()    // Path planning (Step 8~12)
    │              └→ Assemble PathPlanResult            // Output construction (Step 13~15)
    │
    └── uninit()
            └→ SuperNodeStore.clear() + AclStore.clear()  // Clear data
```

### 7.8 Invalid Invocation Order Description

The following invocation sequences are illegal, and SNC should return an error:

| Invalid Sequence | Error Reason | Suggested Handling |
|:--------------------------------------|:----------------------------------|:--------------------|
| Calling other interfaces without `init()` | Internal data structures not initialized | Throw SNCException |
| Calling other interfaces after `uninit()` | Already deinitialized, in-memory data cleared | Throw SNCException |
| Calling `planPath()` without provisioning topology data | Cannot find device information | Return error code 1001/1002 |
| Calling `planPath()` without provisioning ACL data | ACL validation fails | Return error code 1005 |
| Repeated `init()` without calling `uninit()` | State machine duplicate initialization | Idempotent handling or throw exception |



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

// Step 10: Lookup routing table
RoutingTableKey rtKey = new RoutingTableKey(superNodeName, deviceName, chipIndex);
RoutingTable rt = superNodeStore.getRoutingTable(rtKey);
```

---

### 7.10 AclStore (ACL Storage)

The core storage layer for ACL data, maintaining the super node → ACL data primary index.

```java
public class AclStore {
    /** ACL data primary index -- Map key is AclData.superNodeName (corresponding to superNodeName, §4.10), supporting multi-super-node scenarios */
    private Map<String, AclData> store;

    // ========== Lifecycle Methods ==========

    /**
     * Initialize storage
     * <p>Create an empty HashMap instance.
     */
    public void init() {
        this.store = new HashMap<>();
    }

    /**
     * Full replacement of ACL data
     * <p>Store AclData object in store Map with aclData.superNodeName as key.
     * Old data with the same superNodeName is overwritten.
     *
     * @param aclData ACL data container (§4.10), requires superNodeName non-empty
     */
    public void replace(AclData aclData) {
        store.put(aclData.getSuperNodeName(), aclData);
    }

    /**
     * Clear all ACL data
     */
    public void clear() {
        if (store != null) {
            store.clear();
        }
    }

    /**
     * Delete ACL data for the specified superNodeName
     *
     * <p>Remove the AclData corresponding to the specified superNodeName from store.
     *
     * @param superNodeName ACL identifier (§4.10 AclData.superNodeName)
     */
    public void removeAclData(String superNodeName) {
        store.remove(superNodeName);
    }

    // ========== Query Methods ==========

    /**
     * Get ACL data by superNodeName
     *
     * @param superNodeName ACL identifier (§4.10 AclData.superNodeName)
     * @return AclData object, returns null if not exists
     */
    public AclData getAclData(String superNodeName) {
        return store.get(superNodeName);
    }
}
```

**Design Notes:**

| Feature | Description |
|:-----|:-----|
| Primary index `store` | Keyed by `superNodeName`, O(1) locate super node's ACL data |
| `replace()` strategy | Full replacement: old data with the same superNodeName is overwritten |
| `clear()` strategy | Map.clear() to clear |
| ACL rule lookup | Secondary O(1) lookup via `AclData.tpAcls` (`Map<AclKey, TpAclEntity>`, §4.10) |

**Query Flow Example:**
```
// Step 3/4: ACL validation
AclData aclData = aclStore.getAclData(request.getSuperNodeName());
AclKey key = new AclKey(sourceEid, destEid, TransportType.RCTP);
TpAclEntity acl = aclData.getTpAcls().get(key);
```

---

## 8 Path Planning Algorithm — Indexed Mask Match

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
 * PathService → RouteLookupEngine, corresponding to §9.5 Phase 4 Step 10.
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

---
## 9 Detailed Path Planning Flow

### 9.1 Flow Overview

Path planning uses a **two-phase loop (forward → reverse) + direct connection short-circuit** as the overall control structure, with a total of 16 steps (Step 0 ~ Step 15):

```
                                      Phase 1+2
                                  ┌──────────────┐
                                  │ Step 0 ~ 5    │
                                  │ Device check/ │
                                  │ ACL/Node check│
                                  └───────┬──────┘
                                          │
                              ┌───────────┴───────────┐
                              ▼                       ▼
                     ┌────────────────┐     ┌──────────────────┐
                     │ interDevices   │     │ interDevices     │
                     │ empty (direct) │     │ non-empty (multi)│
                     └───────┬────────┘     └────────┬─────────┘
                             │ Step 6               │ Step 7
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
                             │              │ Step 8           │
                             │              │ Forward init     │
                             │              │ dst=dev2         │
                             │              └────────┬─────────┘
                             │                       ▼
                             │              ╔══════════════════╗
                             │              ║ Forward loop     ║
                             │              ║ Step 10→11 × n   ║
                             │              ╚══════╤═══════════╝
                             │                       ▼
                             │              ┌──────────────────┐
                             │              │ Step 12          │
                             │              │ dst==dev2?       │──→ Step 9 (Reverse)
                             │              │ Yes (forward done)│     dst=dev1
                             │              └──────────────────┘         │
                             │                                          ▼
                             │                                 ╔════════════════════╗
                             │                                 ║ Reverse loop       ║
                             │                                 ║ Step 10→11 × n     ║
                             │                                 ╚══════╤═════════════╝
                             │                                          ▼
                             │                                 ┌──────────────────┐
                             │                                 │ Step 12          │
                             │                                 │ dst==dev1?       │──→ Step 14 (Output construction)
                             │                                 │ Yes (reverse done)│
                             │                                 └──────────────────┘
                             │                                          │
                             │                                          ▼
                             │                                 ┌──────────────────┐
                             │                                 │ Step 13~15       │
                             │                                 │ UDP port compute │
                             └─────────────────────────────────┴──────────────────┘
```

**Two-phase Loop Description:**

| Phase | Direction | Target Address (targetAddr) | Destination Device | Execution Path |
|:-----|:-----|:----------------------|:---------|:---------|
| Forward (Step 8) | dev1 → dev2 | CNA2 (= dev2 port IP) | dev2 | Step 8 → [10 → 11]^n → 12 |
| Reverse (Step 9) | dev2 → dev1 | CNA1 (= dev1 port IP) | dev1 | Step 9 → [10 → 11]^n → 12 → 14 |

**Direct Connection Short-circuit Description:**
- Step 6 is a **terminal step** — after direct path validation passes, it **returns success directly** (code 0), skipping Phase 4 (route planning Step 8~12) and Phase 5 (output construction Step 13~15).
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

### 9.3 Phase 2: ACL Bidirectional Validation (Step 3 ~ 4)

> **Data Structure Reference:** §4.10 AclData, §4.11 AclKey, §4.12 TpAclEntity

**Step 3 - Forward ACL Validation:**
Construct `AclKey` (§4.11) using `(sourceEid=EID1, destEid=EID2, transportType=RCTP)` and look up in TP-ACL HashMap (`AclData.tpAcls`, §4.10).
- If `AclData` object does not exist → return error code **1013** (`ACL_NOT_FOUND`, §6.2).
- Lookup failed (key does not exist) → return error code **1005** (`ACL_CHECK_FAILED`, §6.2).
- Lookup successful: verify that `sourceCna == CNA1` and `destCna == CNA2` in the ACL entry (`TpAclEntity`, §4.12).
  - CNA mismatch → return error code **1005** (`ACL_CHECK_FAILED`).
- Validation passed → proceed to Step 4.

**Step 4 - Reverse ACL Validation:**
Construct `AclKey` using `(sourceEid=EID2, destEid=EID1, transportType=RCTP)` and look up in TP-ACL HashMap.
- If `AclData` object does not exist → return error code **1013** (`ACL_NOT_FOUND`, §6.2).
- Lookup failed (key does not exist) → return error code **1005** (`ACL_CHECK_FAILED`).
- Lookup successful: verify that `sourceCna == CNA2` and `destCna == CNA1` in the ACL entry.
  - CNA mismatch → return error code **1005** (`ACL_CHECK_FAILED`).
- Validation passed → proceed to Step 5.

> **Transport Type Note:** The current version only supports `RCTP` (Reliable Transfer Protocol — Reliable Messaging); ACL validation hardcodes `transportType=RCTP`. `RMTP` (Reliable Connection), `UTP` (Unreliable Transfer Protocol) and `CTP` (Connection-oriented Transport Protocol) are reserved enum values, to be enabled in future versions when `PathPlanRequest` adds a `transportType` field. See §4.12 TransportType enum.

---

### 9.4 Phase 3: Path Resolution (Step 5 ~ 7)

> **Data Structure Reference:** §4.3 DeviceEntity (with getForwardingChips() abstract method), §4.4 ForwardingChip (with getPorts() abstract method), §4.5 PortEntity, §5.1 InternalPathInfo/InternalPathHop, §6.1 PathPlanRequest

**Step 5 - Determine Intermediate Nodes:**
Check whether `request.interDevices` (§6.1) is empty:
- No intermediate nodes → jump to Step 6 (direct connection scenario).
  > **V1 Behavior Note:** The current version V1 does not implement auto-routing algorithm. When `interDevices` is empty, the engine only handles direct connection scenarios:
  > - First execute Step 6 direct connection validation: if port connection relationship validation passes → return direct connection result (success).
  > - If direct connection validation fails → return error code **1008** (`TOPO_CONNECTION_ERROR`, §6.2), flow terminates. The engine will not attempt to auto-discover multi-hop paths.
  > - The caller must ensure: if source and destination devices are not directly connected, intermediate devices and out ports must be explicitly specified in `interDevices`.
- Has intermediate nodes → jump to Step 7 (multi-hop scenario, must explicitly specify intermediate devices and out ports).

**Step 6 - Direct Path Validation (Terminal Step):**
Validate bidirectional connection relationships:
- `port1.remoteDevice == dev2.deviceName` and `port1.remotePort == port2.portName`
- `port2.remoteDevice == dev1.deviceName` and `port2.remotePort == port1.portName`

If validation passes → construct return result per `PathPlanResult` (two-hop path, §6.2), **return success directly (code 0)**, no further execution of Phase 4 and Phase 5.

If validation fails → return error code **1008** (`TOPO_CONNECTION_ERROR`, §6.2).

> **Direct Connection Short-circuit Semantics:** Step 6 is a terminal step. In direct connection scenarios, the communication path is guaranteed by physical port connection relationships, without relying on routing table (§4.7) forwarding, therefore **Phase 4** (Step 8~12, route planning) and **Phase 5** (Step 13~15, UDP port computation and output construction) are **not executed**. This is intentional by design.

**Step 7 - Multi-hop Path Resolution:**
Use `request.interDevices` and real topology data to construct the complete `InternalPathInfo` (§5.1).

**7.1 Topology Data Validation:**
Iterate each `{deviceName → outPort}` entry in `interDevices`, check in `SuperNode.devices`:
- Device existence: if `superNode.devices.get(deviceName)` returns null → return error code **1007** (`TOPO_INCOMPLETE`), flow terminates.
- Port existence: if `outPort` cannot be found in any forwarding chip's `ports` of that device (iterate all chips via `device.getForwardingChips()`, then call `chip.getPorts()` to find port) → return error code **1007** (`TOPO_INCOMPLETE`), flow terminates.

**7.2 Path Construction:**
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

**7.3 Connection Relationship Validation:**
Each hop's `remoteDevice` / `remotePort` must be consistent with the next hop's `deviceName` / `inPort`. If inconsistent → return error code **1009** (`TOPO_CONNECTION_NOT_FOUND`, §6.2).

> **Implementation Note:** Device lookup uses the unified view returned by `superNode.getAllDevices()` (merged npuDevices + swDevices), with HashMap O(1) locating; port lookup via `NpuDevice.findNpuPort()` (NPU device, directly uses `NpuForwardingChip.getNpuPorts()`, no instanceof/cast needed) or iterating forwarding chips' `getPorts()` Map (SW devices) (§4.4, §4.5). The port's belonging chip (`chipIndex`) is automatically covered in Step 10 route lookup by iterating all `ForwardingChip` (via `device.getForwardingChips()`) of the device, without needing to be separately recorded in Step 7.

---

### 9.5 Phase 4: Path Planning Loop (Step 8 ~ 12)

> **Data Structure Reference:** §4.7 RoutingTable (with maskLengths), §4.8 RoutePrefix, §4.9 RoutingEntry/OutPortInfo, §5.2 RouteSelectionRecord, §8 Indexed Mask Match algorithm

The core structure of Phase 4 is a **two-phase loop**, distinguished by `currentPhase` state flag for forward/reverse:

```
Forward (Step 8)          Reverse (Step 9)
     │                       │
     ▼                       ▼
┌─────────────────────────────────────┐
│ Step 10: Path planning loop (execute for each intermediate device) │
│   for each intermediate device:     │
│     1. Iterate all ForwardingChips of the device │
│     2. For each chip, do indexed mask match (targetAddr) │
│     3. Take best result from all chips          │
│     4. Validate route out port consistency with topology connection │
│     5. If ECMP → record RouteSelectionRecord │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Step 12: Direction switch judgment   │
│   if currentPhase == FORWARD:        │
│       → Step 9 (switch to reverse)   │
│   if currentPhase == REVERSE:        │
│       → Step 14 (construct output)   │
└─────────────────────────────────────┘
```

#### 9.5.1 Forward Phase (Step 8 → 10 → 11 → 12)

**Step 8 - Forward Path Planning Initial Setup:**
- Set current phase flag `currentPhase = FORWARD`
- Destination device = `dev2`, destination port = `port2`, destination address = `CNA2` (32 bit), source address = `CNA1` (32 bit)
- Proceed to Step 10

#### 9.5.2 Reverse Phase (Step 9 → 10 → 11 → 12)

**Step 9 - Reverse Path Planning Initial Setup:**
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
- Proceed to Step 10

#### 9.5.3 Step 10 - Path Planning Loop (Core)

From the current `InternalPathInfo.hops` list, **exclude head and tail nodes** (head = current source device, tail = current destination device), and execute path planning for each remaining intermediate device.

> **Head-tail Exclusion Rule (direction-dependent):**
> - Forward phase (FORWARD): exclude hops[0] (dev1, source) and hops[last] (dev2, destination)
> - Reverse phase (REVERSE): exclude hops[0] (original dev2, now reversed as path starting point) and hops[last] (original dev1, now reversed as path endpoint)
> - Intermediate device criterion: **DeviceType == SW** switch devices. If NPU devices appear in reverse phase (unreasonable path), their ports have no routing table (SW ports have no CNA), the algorithm will fail in subsequent steps.

**Processing flow for each intermediate device:**

**① Address Determination:**
- `targetAddr` = current phase's destination address (forward = `CNA2`, reverse = `CNA1`), 32-bit CNA address.
- `prevHop` = previous hop (the device already processed in the loop), used for Step 10 ⑤ next-hop validation.

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

**⑤ Result Summary then proceed to Step 11:**
Pass the final `RoutingEntry` and current device information to Step 11 for out port judgment.

> **Next-hop Relationship:** For the currently processing intermediate device `currentHop`:
> - Forward phase: `currentHop`'s next hop has a larger index in the path (closer to destination device)
> - Reverse phase: `currentHop`'s next hop has a larger index in the path (closer to original dev1, i.e., reversed destination)

If current loop has processed all intermediate devices → skip Step 11, proceed to Step 12.

#### 9.5.4 Step 11 - Out Port Judgment and Route Selection Recording

Judge the out port for `RoutingEntry.outPortInfos` returned by Step 10:

| Condition | Handling |
|:-----|:-----|
| `outPortInfos.size() == 1` | Use this out port normally, proceed to next hop |
| `outPortInfos.size() > 1 && device does not support autonomous per-flow` | Return error code **1011** (`MULTI_PATH_NOT_SUPPORTED`, §6.2) |
| `outPortInfos.size() > 1 && device supports autonomous per-flow` | Create a `RouteSelectionRecord` (§5.2), record route selection info, proceed to next hop |

**RouteSelectionRecord Creation Rules (ECMP Scenario):**

```
RouteSelectionRecord record = new RouteSelectionRecord();
record.setDeviceName(currentHop.deviceName);
record.setPrefix(matchedPrefix);                           // Matched RoutePrefix
record.setCandidateOutPorts(candidateList);                // All candidate OutPortInfo
record.setScna(CNA1);                                      // Source CNA (unchanged)
record.setDcna(CNA2);                                      // Destination CNA (unchanged)
record.setDirection(currentPhase == FORWARD ? Direction.FORWARD : Direction.REVERSE);
// hashInfo records tuple identifier (SCNA:DCNA), for Step 13 hash computation
record.setHashInfo(CNA1 + ":" + CNA2);
```

- `candidateOutPorts`: All candidate `OutPortInfo` are added; the port consistent with `interDevices` specified out port is marked as `selected=true` (i.e., path-specified target port), others as `false`.
- This record is appended to the end of `RouteSelectionRecord` list for Step 13 use.

> **Inter-chassis Multi-path Route Selection Note:** When multiple ECMP segments exist on the path (e.g., L1SW0→L2SW and L2SW→L1SW1 are both multi-path), Step 11 only records candidate out port list and the path-specified target port (`selected=true`). The detailed flow of hash algorithm searching UDP port numbers satisfying all ECMP segment constraints is in Step 13.

#### 9.5.5 Step 12 - Direction Switch Judgment

Determine the flow direction based on current phase flag `currentPhase`:

```
if currentPhase == FORWARD:
    // Forward phase has completed route lookup for all intermediate devices
    // Switch to reverse phase
    → Jump to Step 9 (reverse path setup)

if currentPhase == REVERSE:
    // Reverse phase also completed
    // Restore path to forward order (reverse again)
    → Execute path reversal (same rules as Step 9), restore to forward order
    → Jump to Step 14 (construct output)
```

---

### 9.6 Phase 5: Output Construction (Step 13 ~ 15)

> **Data Structure Reference:** §5.2 RouteSelectionRecord, §6.2 PathPlanResult/PathInfo/HopInfo

**Step 13 - UDP Port Computation (Inter-chassis Multi-path Scenario):**

When `RouteSelectionRecord` list is non-empty, a 8-bit source UDP port number (0~255) needs to be computed for forward and reverse directions separately, so that the hash algorithm selects the `interDevices` specified path on each ECMP segment.

> **Bit-width Constraint Note:** `dataUdpSrcPort` and `ackUdpSrcPort` are both strictly limited to 8 bits (0~255), determined by hardware offload register bit width. All algorithms involving UDP port search operate within this space.

> **Background:** In inter-chassis multi-path scenarios (e.g., NPU0↔L1SW0↔L2SW↔L1SW1↔NPU1), routing tables on intermediate devices L1SW0 and L2SW may simultaneously have multiple out ports (ECMP). The same source UDP port number must simultaneously satisfy hash route selection constraints on all ECMP segments, ensuring the entire path connects according to `interDevices` specified ports.

**13.1 Hash Algorithm Definition:**

```
Selected port index = hash(SCNA, DCNA, srcUdpPort) % candidateOutPorts.size()
```

- **Input tuple**: `SCNA` (source CNA, 32 bit) + `DCNA` (destination CNA, 32 bit) + `srcUdpPort` (source UDP port number, 8 bit)
- **Output**: Integer hash value, modulo candidate port count to get selected out port index
- **Stubbable**: Hash function can be stub injected during testing, precisely controlling output values for specific tuples, bypassing multi-segment coupled search complexity

**13.2 Forward Path Port Computation (dataUdpSrcPort):**

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

**13.3 Reverse Path Port Computation (ackUdpSrcPort):**

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

**13.4 Forward-Reverse Relationship Description:**

| Attribute | Forward (dataUdpSrcPort) | Reverse (ackUdpSrcPort) |
|:-----|:----------------------|:----------------------|
| Hash input SCNA | CNA1 (source port CNA) | CNA2 (destination port CNA) |
| Hash input DCNA | CNA2 (destination port CNA) | CNA1 (source port CNA) |
| Source UDP port | `dataUdpSrcPort` (8 bit) | `ackUdpSrcPort` (8 bit) |
| Corresponding result field | `PathPlanResult.dataUdpSrcPort` | `PathPlanResult.ackUdpSrcPort` |

- Forward and reverse paths pass through the same devices and out ports (guaranteed by `interDevices`), but SCNA/DCNA are swapped in hash input, therefore `dataUdpSrcPort` and `ackUdpSrcPort` are **computed independently** and can have different values.
- When only one ECMP segment exists on the path, typically multiple UDP port values satisfy the constraint, with ample search space.
- When multiple ECMP segments exist on the path (e.g., both L1SW0 and L2SW have multi-path), the same UDP port must simultaneously satisfy multi-segment constraints, narrowing search space. Since hash is stub-implemented, testing can inject precise mappings to bypass multi-segment coupling.

**13.5 No ECMP Scenario:**

If `RouteSelectionRecord` list is empty (all device out ports on the path are unique), this step is skipped; `dataUdpSrcPort` and `ackUdpSrcPort` use default values or are left empty.

**13.6 RouteSelectionRecord Lifecycle Review:**

| Phase | Operation | Record Direction |
|:-----|:-----|:---------|
| Forward (Step 8→10→11→12) | Forward path ECMP nodes → append records | FORWARD |
| Reverse (Step 9→10→11→12) | Reverse path ECMP nodes → append records | REVERSE |
| Step 13 | Consume by direction group, independently compute dataUdpSrcPort / ackUdpSrcPort | Both directions |

**Step 14 - Fill PathPlanResult:**
Fill the following information into `PathPlanResult` object (§6.2):
- `sourceEid` / `destEid`: EID pair information (from Step 1/2)
- `path`: Path hop-by-hop information (`PathInfo` → `List<HopInfo>`), converted from `InternalPathInfo.hops` (§5.1) to external `HopInfo` (§6.2.2)
- `ackUdpSrcPort` / `dataUdpSrcPort`: UDP port pair information (if Step 13 has computed)

**Step 15 - Return Success:**
Return success (code **0**), with complete `PathPlanResult` information.

---

### 9.7 Error Code and Step Mapping

| Error Code | Name | Trigger Step | Description |
|:-------|:-----|:---------|:-----|
| 0 | SUCCESS | Step 6 / 15 | Success (direct connection success or complete path planning success) |
| 1003 | SRC_INFO_ERR | Step 1 | Source information missing |
| 1004 | DST_INFO_ERR | Step 2 | Destination information missing |
| 1005 | ACL_CHECK_FAILED | Step 3 / 4 | ACL validation failed (key not existing or CNA mismatch) |
| 1007 | TOPO_INCOMPLETE | Step 0 / 7 | Topology incomplete (device not found in SuperNode) |
| 1008 | TOPO_CONNECTION_ERROR | Step 6 | Direct connection validation failed (port connection relationship mismatch) |
| 1009 | TOPO_CONNECTION_NOT_FOUND | Step 7 | Multi-hop path resolution failed (connection relationship error) |
| 1010 | ROUTE_NOT_REACHABLE | Step 10 | Route unreachable (no route, no out port, or out port inconsistent with topology) |
| 1011 | MULTI_PATH_NOT_SUPPORTED | Step 11 | Multiple paths (ECMP) and device does not support autonomous per-flow |
| 1012 | TOPO_NOT_FOUND | Step 0 | Super node does not exist |
| 1013 | ACL_NOT_FOUND | Step 3 / 4 | AclData object does not exist (supplementary check) |
| 3002 | SRC_AND_DST_MUST_BE_NPU | Step 0 | Source and destination must be NPU devices |
| 3003 | UPI_MISMATCH | Step 0 | Source and destination port UPI mismatch |

---

### 9.8 Flow Data Flow Overview

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
┌──────────────────────────────────────────────────────────────────────────┐
│ Phase 2 (Step 3~4): ACL Bidirectional Validation                       │
│   AclData.tpAcls → AclKey(EID1, EID2, RCTP) → TpAclEntity               │
│   Validate: sourceCna == CNA1, destCna == CNA2 (forward + reverse)     │
│   Error codes: 1005, 1013                                               │
└─────────────────────────┬────────────────────────────────────────────────┘
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
┌─────────────────────────┐  ┌──────────────────────────────────────────────┐
│ Phase 3: interDevices empty │  │ Phase 3: interDevices non-empty              │
│ Step 6: Direct validation │  │ Step 7: Multi-hop resolution → InternalPathInfo│
│ (terminal)                │  │   Validate: device existence, port existence, │
│ Error code: 1008          │  │   connection continuity                      │
│ Success: Return directly  │  │   Error codes: 1007, 1009                    │
│ (code 0)                  │  └─────────────────────┬────────────────────────┘
┌─────────────────────────┐  │                       │
                            │
┌──────────────────────────────────────────────────────────────────────────┐
│ Phase 4 (Step 8→9→10→11→12): Path Planning Loop (Forward + Reverse)    │
│   Step 8: Forward setup (target=CNA2, dst=dev2, phase=FORWARD)          │
│   Step 9: Reverse setup (reverse path, target=CNA1, dst=dev1, phase=REVERSE) │
│                                                                           │
│   Step 10 (for each intermediate device):                                 │
│     ┌─────────────────────────────────────────────────────────────────┐  │
│     │ ① Iterate device.getForwardingChips() all chips                    │  │
│     │ ② For each chip: RoutingTableKey → superNodeStore.getRoutingTable│  │
│     │ ③ Indexed mask match: maskLengths[0..n] → RoutePrefix → O(1) hit │  │
│     │ ④ Cross-chip selection: take RoutingEntry with largest maskLen    │  │
│     │ ⑤ Out port and next-hop consistency validation                   │  │
│     │ ⑥ Result forwarded to Step 11                                   │  │
│     └─────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│   Step 11: Out Port Judgment                                             │
│     1 out port → proceed to next hop normally                           │
│     Multiple out ports (no ECMP support) → 1011                        │
│     Multiple out ports (ECMP supported) → append RouteSelectionRecord  │
│                                                                           │
│   Error codes: 1010, 1011                                               │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
┌──────────────────────────────────────────────────────────────────────────┐
│ Phase 5 (Step 13~15): Output Construction                              │
│   Step 13: UDP port computation (based on forward + reverse RouteSelectionRecord list) │
│   Step 14: InternalPathInfo → PathPlanResult [§6.2]                     │
│   Step 15: Return success (code 0)                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

---

