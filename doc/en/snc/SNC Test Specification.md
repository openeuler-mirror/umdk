# SNC Module Test Specification

## 1. Test Architecture Overview

### 1.1 Layered Strategy

A test strategy aligned with the development layering is adopted, using real instances (no mocking) and injecting dependencies via constructor parameters:

| Layer | Test Type | Strategy |
|:---|:---------|:-----|
| entity | Unit test | Pure data classes; cover constructor/Getter/Setter/equals/hashCode/toString |
| dto | Unit test | Pure data classes; same pattern as entity layer |
| config | Unit test | Configuration class; cover default values/all-args/Getter/Setter |
| exception | Unit test | Exception classes; cover constructor/error codes |
| util | Unit test | Utility classes; cover algorithm correctness (mask/IP conversion/CNA padding) |
| store | Unit test | In-memory storage; cover init/replace/get/remove/clear |
| engine | Unit test | Algorithm engines; cover LPM/ACL validation/path resolution |
| service | Unit test | Business orchestration; validate store/engine flow |
| SNCServiceImpl | Integration test | Full end-to-end path; combined with JSON test fixtures |

### 1.2 Test Package Structure

```
src/test/java/com/huawei/umdk/snc/
├── SNCServiceIntegrationTest.java    # Integration test (main entry point)
├── TestDataLoader.java               # Test data loading utility
├── entity/                           # Entity layer unit tests (25 classes)
│   ├── AclDataTest.java
│   ├── AclKeyTest.java
│   ├── DeviceEntityTest.java
│   ├── DeviceTypeTest.java
│   ├── ForwardingChipTest.java
│   ├── InternalPathHopTest.java
│   ├── InternalPathInfoTest.java
│   ├── LogicPortEntityTest.java
│   ├── MgmtInfoTest.java
│   ├── NpuDeviceTest.java
│   ├── NpuForwardingChipTest.java
│   ├── NpuPortEntityTest.java
│   ├── OutPortInfoTest.java
│   ├── RoutePrefixTest.java
│   ├── RouteSelectionRecordTest.java
│   ├── RoutingEntryTest.java
│   ├── RoutingTableKeyTest.java
│   ├── RoutingTableTest.java
│   ├── SwDeviceTest.java
│   ├── SwForwardingChipTest.java
│   ├── SwitchLevelTest.java
│   ├── SwPortEntityTest.java
│   ├── SuperNodeTest.java
│   ├── TpAclEntityTest.java
│   └── TransportTypeTest.java
├── dto/                              # DTO layer unit tests
│   ├── PathPlanRequestTest.java
│   ├── PathPlanResultTest.java
│   ├── PathInfoTest.java
│   └── HopInfoTest.java
├── config/                           # Config layer unit tests
│   └── SNCConfigTest.java
├── exception/                        # Exception layer unit tests
│   ├── SNCExceptionTest.java
│   ├── SNCStateExceptionTest.java
│   ├── SuperNodeNotFoundExceptionTest.java
│   ├── AclNotFoundExceptionTest.java
│   └── PathPlanExceptionTest.java
├── util/                             # Util layer unit tests
│   └── AddressUtilsTest.java
├── store/                            # Store layer unit tests
│   ├── SuperNodeStoreTest.java
│   └── AclStoreTest.java
├── engine/                           # Engine layer unit tests
│   ├── RouteLookupEngineTest.java
│   ├── AclCheckEngineTest.java
│   └── PathEngineTest.java
└── service/                          # Service layer unit tests
    ├── SuperNodeServiceTest.java
    ├── AclServiceTest.java
    └── PathServiceTest.java
```

---

## 2. Test Layers and Case Statistics

### 2.1 Unit Tests

| Layer | Test Class | Class Under Test | Case Count |
|------|--------|--------|--------|
| Service | `SuperNodeServiceTest` | `SuperNodeService` | 35 |
| Service | `AclServiceTest` | `AclService` | 16 |
| Service | `PathServiceTest` | `PathService` | 65 |
| Engine | `PathEngineTest` | `PathEngine` | 20 |
| Engine | `RouteLookupEngineTest` | `RouteLookupEngine` | 8 |
| Engine | `AclCheckEngineTest` | `AclCheckEngine` | 7 |
| Store | `SuperNodeStoreTest` | `SuperNodeStore` | 24 |
| Store | `AclStoreTest` | `AclStore` | 10 |
| Entity | 25 test files | Various Entity classes | ~174 |
| DTO | 4 test files | DTO classes | 29 |
| Exception | 5 test files | Exception classes | 22 |
| Config | `SNCConfigTest` | `SNCConfig` | 7 |
| Util | `AddressUtilsTest` | `AddressUtils` | 31 |

### 2.2 Integration Tests

| Test Class | Case Count | Data Source |
|--------|--------|---------|
| `SNCServiceIntegrationTest` | 28+ | JSON files (`topo_data_2npu_1port.json`, `topo_data_4npu_8port.json`, `topo_data_2box_16l2sw.json`, `acl_data_2npu_1port.json`, `acl_data_4npu_8port.json`) |

---

## 3. Test Design per Layer

### 3.1 Entity Layer

26 entity classes + 1 inner class, totaling 25 test files and approximately 174 test cases.

| Category | Class Name | Test File |
|:-----|:-----|:---------|
| Enum | DeviceType | DeviceTypeTest.java |
| Enum | SwitchLevel | SwitchLevelTest.java |
| Enum | TransportType | TransportTypeTest.java |
| Enum | RouteSelectionRecord.Direction | Embedded in RouteSelectionRecordTest.java |
| Abstract base | DeviceEntity | DeviceEntityTest.java |
| Abstract base | ForwardingChip | ForwardingChipTest.java |
| Domain class | SuperNode | SuperNodeTest.java |
| Domain class | MgmtInfo | MgmtInfoTest.java |
| Domain class | NpuDevice | NpuDeviceTest.java |
| Domain class | SwDevice | SwDeviceTest.java |
| Domain class | NpuForwardingChip | NpuForwardingChipTest.java |
| Domain class | SwForwardingChip | SwForwardingChipTest.java |
| Domain class | NpuPortEntity | NpuPortEntityTest.java |
| Domain class | SwPortEntity | SwPortEntityTest.java |
| Domain class | LogicPortEntity | LogicPortEntityTest.java |
| Domain class | RoutingTable | RoutingTableTest.java |
| Domain class | RoutingTableKey | RoutingTableKeyTest.java |
| Domain class | RoutePrefix | RoutePrefixTest.java |
| Domain class | RoutingEntry | RoutingEntryTest.java |
| Domain class | OutPortInfo | OutPortInfoTest.java |
| Domain class | AclData | AclDataTest.java |
| Domain class | AclKey | AclKeyTest.java |
| Domain class | TpAclEntity | TpAclEntityTest.java |
| Computation model | InternalPathInfo | InternalPathInfoTest.java |
| Computation model | InternalPathHop | InternalPathHopTest.java |
| Computation model | RouteSelectionRecord | RouteSelectionRecordTest.java |

**Test Pattern:** Each entity class follows a uniform 7-step template:
1. `testDefaultConstructor()` → Verify all fields are null/false
2. `testAllArgsConstructor()` → Verify all-args constructor assigns fields correctly
3. `testSettersAndGetters()` → Verify Setter/Getter correctness
4. `testEquals()` → Equivalence (equal for same object, unequal for different, non-nullity, reflexivity)
5. `testHashCode()` → hashCode consistency
6. `testToString()` → toString includes key fields
7. Enums: additionally verify `values()` array and `valueOf()` conversion

**Specialized Patterns:**
- Abstract base classes (ForwardingChip/DeviceEntity): Test parent methods via anonymous subclasses
- `RoutePrefix`/`RoutingTableKey`/`AclKey` (HashMap key classes): Additional coverage for null field boundaries
- `SuperNode`: Additional coverage for `getNpuDevices`/`getSwDevices`/`getAllDevices` merge logic
- `NpuDevice`: Additional coverage for `findNpuPort` cross-chip search, null chip/null port boundaries

### 3.2 DTO Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| PathPlanRequest | 8+ | Constructor/Getter/Setter/equals/hashCode/toString; `interDevices` null scenario |
| PathPlanResult | 10+ | Same as above + `PlanStatus` enum coverage (11 status values) + success/failure constructors |
| PathInfo | 6+ | Constructor/Getter/Setter/equals/hashCode/toString; `hops` null scenario |
| HopInfo | 8+ | Constructor + `multiPath`/`deviceType` fields + source/destination/intermediate node field constraints |

### 3.3 Config Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| SNCConfig | 7 | Default constructor (logLevel=INFO), all-args constructor, Getter/Setter, equals/hashCode/toString |

### 3.4 Exception Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| SNCException | 4 | Message constructor, Cause constructor |
| SNCStateException | 4 | Inheritance relationship verification, constructor |
| SuperNodeNotFoundException | 4 | Inheritance relationship verification |
| AclNotFoundException | 4 | Inheritance relationship verification |
| PathPlanException | 6 | Error code constructor, Detail constructor, getStatus() |

### 3.5 Util Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| AddressUtils | 31 | `cnaToTargetAddr`, `applyMask`, `ipToInt`, `intToIp`, `isValidCna`, `isValidEid` |

### 3.6 Store Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| SuperNodeStore | 24 | init/replace/getSuperNodeData/getRoutingTable/removeSuperNode/clear; addNpuDevice/addSwDevice; multiple superNodeName coexistence; routing table extraction; empty devices/null parameters/beforeInit operations |
| AclStore | 10 | init/replace/getAclData/removeAclData/clear; null values/null parameters |

**SuperNodeStore Key Scenarios:**
1. **Basic lifecycle**: init → replace → get → clear
2. **Routing table indexing**: ForwardingChip containing routingTable → routingTableMap correctly indexed after replace
3. **Multiple super nodes coexistence**: SuperNodes with different names can be queried independently
4. **Deletion**: removeSuperNode clears corresponding entries in both superNodeMap and routingTableMap
5. **Incremental addition**: addNpuDevice/addSwDevice add to npuDevices/swDevices respectively and index routing tables
6. **Implicit Map creation**: addNpuDevice automatically creates a new HashMap if npuDevices is null

### 3.7 Engine Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| RouteLookupEngine | 8 | LPM match/no-match/default route/empty route/ECMP multiple out-ports; maskLengths=[0] no match |
| AclCheckEngine | 7 | Forward validation/reverse validation/bidirectional validation/CNA mismatch/Key not found/forward match but dest mismatch |
| PathEngine | 20 | Direct path (NpuDevice/NpuPortEntity overload)/multi-hop path/cross-chip route lookup/path reversal/port lookup exception/null chip/half-connection |

**RouteLookupEngine LPM Core Algorithm:**

| Routing Table | targetAddr | Expected |
|:-------|:-----------|:-----|
| {/24: eth0, /16: eth1, /0: wan} | "170.170.170.17" | eth0 (/24) |
| {/24: eth0, /16: eth1, /0: wan} | "171.170.170.17" | wan (/0) |
| {} | "1.2.3.4" | null |

**AclCheckEngine Validation:**

| Scenario | Expected |
|:-----|:-----|
| Complete match (EID + CNA consistent) | true |
| CNA mismatch | false |
| Key not found | false |
| Bidirectional check | Both forward and reverse must pass for true |

**PathEngine Path Resolution:**

| Scenario | Expected |
|:-----|:-----|
| 2 NPU ports direct connection | InternalPathInfo.hops.size() == 2 |
| 1 intermediate L1SW | hops.size() == 3 |
| Intermediate device not found | Throws SuperNodeNotFoundException |
| Cross-chip route lookup | Returns longest prefix match entry |

### 3.8 Service Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| SuperNodeService | 35 | importSuperNode validation, addNpuDevices/addSwDevices, getDevice, getRoutingTable, exception handling; null/empty string/empty collection parameter validation |
| AclService | 16 | importAclData validation, getAclData, exception handling; null/empty string/empty collection parameter validation |
| PathService | 65 | Complete planPath flow (16 steps), various error code branches, reflection tests (null fields), routePhase exception branches, NpuDevice.findNpuPort boundary |

**PathService Flow Coverage (corresponding to design document §9):**

| Step | Scenario | Expected PlanStatus |
|:-----|:-----|:----------------|
| 0 | superNodeName not found | TOPO_NOT_FOUND (1012) |
| 0 | Device not found | TOPO_INCOMPLETE (1007) |
| 1 | srcPort not found/CNA/EID empty | SRC_INFO_ERR (1003) |
| 2 | destPort not found/CNA/EID empty | DST_INFO_ERR (1004) |
| 3 | ACL data not found/CNA mismatch | ACL_CHECK_FAILED (1005) |
| 6 | Direct connection validation failed | TOPO_CONNECTION_ERROR (1008) |
| 7 | Multi-hop path resolution failed | TOPO_CONNECTION_NOT_FOUND (1009) |
| 10 | Route unreachable | ROUTE_NOT_REACHABLE (1010) |
| 14 | Success | SUCCESS (0) |

### 3.9 SNCServiceImpl

| Test Category | Test Case Count | Key Test Points |
|:---------|:----------|:-----------|
| Lifecycle state machine | 8 | INIT→READY→DATAREADY→UNINIT state transitions |
| Parameter validation | 16 | All input parameter null/empty string checks |
| Exception handling | 6 | Calling methods before init / after uninit |
| Full end-to-end | 6 | From init → setSuperNodeData → setAclData → addNpuDevices → addSwDevices → planPath → uninit |

**State Machine Tests:**

| Test Scenario | Call Sequence | Expected Result |
|:---------|:---------|:---------|
| Call setSuperNode without init | setSuperNode(...) | SNCStateException |
| Normal call after init | init → setSuperNode → setAclData | Normal execution |
| Call after uninit | init → ... → uninit → getSuperNode | SNCStateException |
| Repeated init | init → init | Idempotent, no exception thrown |

---

## 4. Test Data Management

### 4.1 JSON Test Data

```
src/test/resources/
├── topo_data_2npu_1port.json     # 2 NPU + 1 L1 SW topology (single port)
├── topo_data_4npu_8port.json     # 4 NPU + 2 L1 SW topology (multi-port)
├── topo_data_2box_16l2sw.json    # 2 chassis + 16 L2SW topology (cross-chassis path)
├── acl_data_2npu_1port.json      # ACL data corresponding to 2npu
└── acl_data_4npu_8port.json      # ACL data corresponding to 4npu
```

### 4.2 TestDataLoader Utility Class

`TestDataLoader` is responsible for parsing JSON files into Java objects:
- `loadSuperNode(resourcePath)` — Parse topology JSON into `SuperNode` (including npuDevices, swDevices, chips, ports, routing tables)
- `loadAclData(resourcePath, superNodeName)` — Parse ACL JSON into `AclData`

### 4.3 2npu_1port Data (Minimal Validation)

- **NPU1**: 1 port `400GE 0/0/1`, CNA=`170.170.170.18`, EID=`AAAAAA12000000000000000000000002`, UPI=`0A0A0A01`
- **NPU2**: 1 port `400GE 0/1/1`, CNA=`221.221.221.66`, EID=`DDDDDD42000000000000000000000002`, UPI=`0A0A0A01`
- **L1SW0**: 2 ports connected to NPU1/NPU2
- **Routes**: NPU1→target 221.221.221.68, L1SW has two routes (170.170.170.17→NPU1 side, 221.221.221.68→NPU2 side)
- **ACL**: Two bidirectional rules (AAAAAA11...↔DDDDDD44...)

### 4.4 4npu_8port Data (Full Validation)

- 4 NPUs each with 8 ports (32 ports total), each port has independent CNA/EID
- 4 L1SWs each with 8 ports, no L2SW
- Each NPU's 8 ports evenly distributed across 4 L1SWs (2 ports per L1SW)
- Routing table: Each NPU has 8 routes to other NPUs (ECMP 2-way), each L1SW has 4 routes to each NPU (single-way)
- ACL: 6 NPU pairs × 8 ports × 2 directions = 96 bidirectional rules

### 4.5 Port Naming and Encoding Rules

| Device Type | Port Format | Example |
|:---------|:---------|:-----|
| NPU | `400GE 0/{chipIndex}/{portIndex}` | `400GE 0/0/1` |
| L1SW | `400GE 1/{chipIndex}/{portIndex}` | `400GE 1/0/2` |

| NPU | EID Prefix | CNA Range | UPI |
|:----|:---------|:---------|:------------|
| npu1 | AAAAAA | 170.170.170.x | 0A0A0A01 |
| npu2 | DDDDDD | 221.221.221.x | 0A0A0A01 |
| npu3 | EEEEEE | 238.238.238.x | 0A0A0A01 |
| npu4 | FFFFFF | 255.255.255.x | 0A0A0A01 |

---

## 6. Test Tools and Dependencies

| Tool | Version | Purpose |
|------|------|------|
| JUnit Jupiter | 5.9.2 | Test framework |
| JaCoCo | 0.8.12 | Coverage statistics |
| Maven Surefire | 3.2.2 | Test execution |
| Lombok | 1.18.36 | POJO simplification |

---

## 7. Test Naming Conventions

- Test class name: `{ClassUnderTest}Test.java`
- Test method name: `{scenario}_{expectedResult}` (camelCase)
- Use `@DisplayName` to annotate descriptions
- Entity/DTO tests uniformly follow the 7-step template: default → allArgs → setters → equalsEqual → equalsNotEqual → hashCode → toString
