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
| engine | Unit test | Algorithm engines; cover LPM/path resolution |
| service | Unit test | Business orchestration; validate store/engine flow |
| SNCServiceImpl | Integration test | Full end-to-end path; combined with JSON test fixtures |

### 1.2 Test Package Structure

```
src/test/java/com/huawei/umdk/snc/
├── SNCServiceIntegrationTest.java    # Integration test (main entry point)
├── TestDataLoader.java               # Test data loading utility
├── entity/                           # Entity layer unit tests (22 classes, including LinkEvent)
│   ├── DeviceEntityTest.java
│   ├── DeviceTypeTest.java
│   ├── ForwardingChipTest.java
│   ├── InternalPathHopTest.java
│   ├── InternalPathInfoTest.java
│   ├── LinkEventTest.java            # New: link event entity
│   ├── LogicPortEntityTest.java
│   ├── MgmtInfoTest.java
│   ├── NpuDeviceTest.java
│   ├── NpuForwardingChipTest.java
│   ├── NpuPortEntityTest.java        # Updated: includes jettyId field tests
│   ├── OutPortInfoTest.java          # Updated: includes convergedFlag/setFlag/clearFlag/isConverged tests
│   ├── RoutePrefixTest.java
│   ├── RouteSelectionRecordTest.java
│   ├── RoutingEntryTest.java         # Updated: includes reachable field + refreshReachable tests
│   ├── RoutingTableKeyTest.java
│   ├── RoutingTableTest.java
│   ├── SwDeviceTest.java
│   ├── SwForwardingChipTest.java
│   ├── SwitchLevelTest.java
│   ├── SwPortEntityTest.java
│   └── SuperNodeTest.java
├── dto/                              # DTO layer unit tests
│   ├── PathPlanRequestTest.java
│   ├── PathPlanResultTest.java       # Updated: includes COVERAGE_INCOMPLETE status
│   ├── PathInfoTest.java
│   ├── HopInfoTest.java
│   ├── CoveragePathsRequestTest.java          # New
│   ├── CoveragePathsResultTest.java           # New
│   ├── CoverageStatsTest.java                 # New
│   ├── CoverageLayerStatsTest.java            # New
│   ├── CoverageLinkTest.java                  # New
│   ├── CoverageLinkScopeTest.java             # New
│   ├── CoverageLinkLayerTest.java             # New
│   ├── CoveragePathTypeTest.java              # New
│   ├── CoverageRequirementTest.java           # New
│   ├── CoveredEidPairTest.java                # New
│   └── CoveredEidPairRefTest.java             # New
├── config/                           # Config layer unit tests
│   └── SNCConfigTest.java
├── exception/                        # Exception layer unit tests
│   ├── SNCExceptionTest.java
│   ├── SNCStateExceptionTest.java
│   ├── SuperNodeNotFoundExceptionTest.java
│   └── PathPlanExceptionTest.java
├── util/                             # Util layer unit tests
│   ├── AddressUtilsTest.java
│   ├── HashUtilsTest.java                    # New: nativeHash/nativeHashDstCnaJetty/isValidJettyId
│   ├── UbSwitchHashTest.java                 # New: Java fallback correctness
│   └── DllLoaderTest.java                    # New: JNA search path
├── store/                            # Store layer unit tests
│   └── SuperNodeStoreTest.java
├── engine/                           # Engine layer unit tests
│   ├── RouteLookupEngineTest.java
│   ├── PathEngineTest.java
│   └── CoveragePlanEngineTest.java           # New: findCoverage/findCoverageEx + two-phase coverage + getExDiagnostics
├── route/                            # Route layer unit tests (new)
│   ├── model/
│   │   ├── RouteTableTest.java
│   │   ├── RouteEntryTest.java
│   │   ├── InboundTest.java
│   │   ├── NextHopPortTest.java
│   │   └── OriginNodeTest.java
│   ├── service/
│   │   ├── RouteMspServiceTest.java          # BFS shortest path + path policy
│   │   ├── RouteInstantiationServiceTest.java # Template instantiation + deepCopyRoutingEntry
│   │   └── RouteConvergeServiceTest.java     # BFS route convergence + setFlag/clearFlag/refreshReachable
│   └── topo/
│       └── template/
│           ├── model/TemplateModelTest.java   # SncTopology/SncNode/SncPort/Label etc.
│           └── service/TopoTemplateServiceTest.java # Template parsing
└── service/                          # Service layer unit tests
    ├── SuperNodeServiceTest.java
    ├── PathServiceTest.java                  # Updated: includes planPathsCoverage/planPathsCoverageEx
    └── LinkEventServiceTest.java             # New: handleLinkEvent + trigger convergence
```

---

## 2. Test Layers and Case Statistics

### 2.1 Unit Tests

| Layer | Test Class | Class Under Test | Case Count |
|------|--------|--------|--------|
| Service | `SuperNodeServiceTest` | `SuperNodeService` | 35 |
| Service | `PathServiceTest` | `PathService` (incl. planPathsCoverage/Ex) | 95+ |
| Service | `LinkEventServiceTest` | `LinkEventService` | 25+ |
| Engine | `PathEngineTest` | `PathEngine` | 20 |
| Engine | `RouteLookupEngineTest` | `RouteLookupEngine` | 8 |
| Engine | `CoveragePlanEngineTest` | `CoveragePlanEngine` (findCoverage/Ex + two-phase) | 80+ |
| Route | `RouteMspServiceTest` | `RouteMspService` | 20+ |
| Route | `RouteInstantiationServiceTest` | `RouteInstantiationService` | 25+ |
| Route | `RouteConvergeServiceTest` | `RouteConvergeService` | 30+ |
| Route | `TopoTemplateServiceTest` | `TopoTemplateService` | 12+ |
| Route | `TemplateModelTest` | SncTopology/SncNode/SncPort/Label etc. | 40+ |
| Route | `RouteTableTest`/`RouteEntryTest`/`InboundTest`/`NextHopPortTest`/`OriginNodeTest` | route.model classes | 35+ |
| Store | `SuperNodeStoreTest` | `SuperNodeStore` | 24 |
| Entity | 22 test files (incl. LinkEventTest) | Various Entity classes | ~170 |
| DTO | 15 test files (incl. 11 new DTOs) | DTO classes | 80+ |
| Exception | 4 test files | Exception classes | 18 |
| Config | `SNCConfigTest` | `SNCConfig` | 7 |
| Util | `AddressUtilsTest` + `HashUtilsTest` + `UbSwitchHashTest` + `DllLoaderTest` | AddressUtils + HashUtils + UbSwitchHash + DllLoader | 60+ |

### 2.2 Integration Tests

| Test Class | Case Count | Data Source |
|--------|--------|---------|
| `SNCServiceIntegrationTest` | 60+ | JSON files (`topo_data_2npu_1port.json`, `topo_data_4npu_8port.json`, `topo_data_2box_16l2sw.json`) |
| `PlanPathsCoverageExIntegrationTest` | 30+ | Landed (delivered together with NPU-L1 design) |
| `FullRackTopologyJettyIdTest` | 5+ | `FullRackTopologyGenerator` fixed jettyId allocation (32..39) |

---

## 3. Test Design per Layer

### 3.1 Entity Layer

22 entity classes + 1 inner class, totaling 22 test files and approximately 170 test cases.

| Category | Class Name | Test File |
|:-----|:-----|:---------|
| Enum | DeviceType | DeviceTypeTest.java |
| Enum | SwitchLevel | SwitchLevelTest.java |
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
| Domain class | LinkEvent | LinkEventTest.java |
| Domain class | RoutingTable | RoutingTableTest.java |
| Domain class | RoutingTableKey | RoutingTableKeyTest.java |
| Domain class | RoutePrefix | RoutePrefixTest.java |
| Domain class | RoutingEntry | RoutingEntryTest.java |
| Domain class | OutPortInfo | OutPortInfoTest.java |
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
- `RoutePrefix`/`RoutingTableKey` (HashMap key classes): Additional coverage for null field boundaries
- `SuperNode`: Additional coverage for `getNpuDevices`/`getSwDevices`/`getAllDevices` merge logic
- `NpuDevice`: Additional coverage for `findNpuPort` cross-chip search, null chip/null port boundaries
- `NpuPortEntity`: Additional coverage for the `jettyId` field (including extended constructor); out-of-range jettyId triggers `HashUtils.isValidJettyId` throwing `IllegalArgumentException`
- `OutPortInfo`: Additional coverage for `convergedFlag` bit operations: `setFlag`/`clearFlag`/`isConverged`; FLAG_PASSIVE_CONVERRGED / FLAG_ACTIVE_CONVERRGED bit combinations
- `RoutingEntry`: Additional coverage for the `reachable` field; `refreshReachable()` state transitions under 0/1/multi outPort scenarios; `RoutingEntry.copy(src)` deep-copy semantics
- `LinkEvent`: Additional coverage that `eventType` accepts only "up"/"down"; other values throw `IllegalArgumentException`; all-args constructor + Getter/Setter/equals/hashCode/toString

### 3.2 DTO Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| PathPlanRequest | 8+ | Constructor/Getter/Setter/equals/hashCode/toString; `interDevices` null scenario |
| PathPlanResult | 12+ | Same as above + `PlanStatus` enum coverage (11 status values, incl. COVERAGE_INCOMPLETE/TOPO_NOT_FOUND) + success/failure constructors; `spray` field |
| PathInfo | 6+ | Constructor/Getter/Setter/equals/hashCode/toString; `hops` null scenario |
| HopInfo | 8+ | Constructor + `multiPath`/`deviceType` fields + source/destination/intermediate node field constraints |
| CoveragePathsRequest | 6+ | Constructor + `superNodeName`/`coverageRequirement`; null coverageRequirement defaults to MIN_COVERAGE |
| CoveragePathsResult | 15+ | All-fields constructor + `scope`/`status`/`eidPairs`/`coverageLinks`/`totalStats`/`layerStats`; layerStats null (planPathsCoverage) vs non-null (planPathsCoverageEx) |
| CoverageStats | 10+ | All fields + coverage rate/duplicate rate calculation fields + eidUniformity |
| CoverageLayerStats | 6+ | Constructor + `layer` enum + `stats` nesting |
| CoverageLink | 10+ | All fields + `layer`/`deviceType` null vs non-null scenarios |
| CoverageLinkScope | 4+ | Enum values() + valueOf(): L1_L2 / NPU_L1_L2 |
| CoverageLinkLayer | 4+ | Enum values() + valueOf(): NPU_L1 / L1_L2 |
| CoveragePathType | 4+ | Enum values() + valueOf(): CROSS_L2 / LOCAL_L1 |
| CoverageRequirement | 4+ | Enum values() + valueOf(): MIN_COVERAGE / REDUNDANT |
| CoveredEidPair | 8+ | All fields + `coveredLinks` list + `type` null vs non-null scenarios |
| CoveredEidPairRef | 6+ | All fields + `srcEid`/`dstEid` |

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
| PathPlanException | 6 | Error code constructor, Detail constructor, getStatus() |

### 3.5 Util Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| AddressUtils | 31 | `cnaToTargetAddr`, `applyMask`, `ipToInt`, `intToIp`, `isValidCna`, `isValidEid` |
| HashUtils | 18+ | `nativeHash` (ECMP), `nativeHashDstCnaJetty` (die hash), `JETTY_ID_MIN`/`JETTY_ID_MAX`, `isValidJettyId` (inside/outside [32,1023] / null); falls back to UbSwitchHash when native unavailable |
| UbSwitchHash | 15+ | `hashEcmp` and `hashDieEcmp` pure Java implementations; dual-path consistency tests against the native library (`hashEcmp` ↔ `ubswitch_Hash_ecmp`, `hashDieEcmp` ↔ `ubswitch_Hash_dieEcmp`) |
| DllLoader | 8+ | JNA search path: jar sibling directory, classpath extraction, temp directory; returns null when not found |

### 3.6 Store Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| SuperNodeStore | 24 | init/replace/getSuperNodeData/getRoutingTable/removeSuperNode/clear; addNpuDevice/addSwDevice; multiple superNodeName coexistence; routing table extraction; empty devices/null parameters/beforeInit operations |

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
| PathEngine | 20 | Direct path (NpuDevice/NpuPortEntity overload)/multi-hop path/cross-chip route lookup/path reversal/port lookup exception/null chip/half-connection |
| CoveragePlanEngine | 80+ | findCoverage (L1↔L2 domain); findCoverageEx (two-phase CROSS_L2 + LOCAL_L1); hash usage points H1~H7b; jettyIdOf fallback (missing/out-of-range/null port.id); getExDiagnostics all 10 diagnostic counters; MIN_COVERAGE / REDUNDANT coverageRequirement; COVERAGE_INCOMPLETE and SUCCESS termination conditions; EID uniformity statistics |

**RouteLookupEngine LPM Core Algorithm:**

| Routing Table | targetAddr | Expected |
|:-------|:-----------|:-----|
| {/24: eth0, /16: eth1, /0: wan} | "170.170.170.17" | eth0 (/24) |
| {/24: eth0, /16: eth1, /0: wan} | "171.170.170.17" | wan (/0) |
| {} | "1.2.3.4" | null |

**PathEngine Path Resolution:**

| Scenario | Expected |
|:-----|:-----|
| 2 NPU ports direct connection | InternalPathInfo.hops.size() == 2 |
| 1 intermediate L1SW | hops.size() == 3 |
| Intermediate device not found | Throws SuperNodeNotFoundException |
| Cross-chip route lookup | Returns longest prefix match entry |

**CoveragePlanEngine Coverage Planning Core Tests:**

| Test Class | Scenario | Expected |
|:-------|:-----|:-----|
| CoveragePlanEngineTest | findCoverage: 4npu_8port + MIN_COVERAGE | SUCCESS, scope=L1_L2, layerStats=null, coverageRate=1.0 |
| CoveragePlanEngineTest | findCoverage: 4npu_8port + REDUNDANT | SUCCESS, coverageRate=1.0, redundantLinks > 0 |
| CoveragePlanEngineTest | findCoverage: incomplete topology | COVERAGE_INCOMPLETE, coverageRate < 1.0 |
| CoveragePlanEngineTest | findCoverageEx: cross-chassis + same-chassis + MIN_COVERAGE | SUCCESS, scope=NPU_L1_L2, layerStats=[NPU_L1, L1_L2], both layers coverageRate=1.0 |
| CoveragePlanEngineTest | findCoverageEx: jettyId missing | SUCCESS + exJettyFallback > 0 |
| CoveragePlanEngineTest | findCoverageEx: jettyId out of range (< 32 or > 1023) | SUCCESS + exJettyFallback > 0 (fallback 32 + portId) |
| CoveragePlanEngineTest | findCoverageEx: CROSS_L2 EID pair coveredLinks.size()==8 | 4 forward + 4 reverse |
| CoveragePlanEngineTest | findCoverageEx: LOCAL_L1 EID pair coveredLinks.size()==4 | 2 forward + 2 reverse |
| CoveragePlanEngineTest | findCoverageEx: all diagnostic counters 0 | SUCCESS + all exDiagnostics fields 0 |
| CoveragePlanEngineTest | findCoverageEx: NPU route LPM miss | npuRouteFail > 0 |
| CoveragePlanEngineTest | findCoverageEx: L1SW route lookup failure | l1Fail > 0 |
| CoveragePlanEngineTest | findCoverageEx: reverse NPU/L1SW/L2SW failure | revNpuFail / revDstL1Fail / revL2Fail / revSrcL1Fail > 0 |

### 3.8 Service Layer

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| SuperNodeService | 35 | importSuperNode validation, addNpuDevices/addSwDevices, getDevice, getRoutingTable, exception handling; null/empty string/empty collection parameter validation |
| PathService | 95+ | Complete planPath flow (65) + planPathsCoverage (15+) + planPathsCoverageEx (15+); various error code branches, reflection tests (null fields), routePhase exception branches, NpuDevice.findNpuPort boundary; CoveragePlanEngine constructor injection; two-phase flow triggering; scope/layerStats validation |
| LinkEventService | 25+ | handleLinkEvent normal down/up flow; port state update (linkStatus/updateAt); triggers RouteConvergeService.converge; invalid eventType throws IllegalArgumentException; device/port not found throws IllegalStateException; null SuperNode throws IllegalArgumentException |

**PathService Flow Coverage (corresponding to design document §9):**

| Step | Scenario | Expected PlanStatus |
|:-----|:-----|:----------------|
| 0 | superNodeName not found | TOPO_NOT_FOUND (1012) |
| 0 | Device not found | TOPO_INCOMPLETE (1007) |
| 1 | srcPort not found/CNA/EID empty | SRC_INFO_ERR (1003) |
| 2 | destPort not found/CNA/EID empty | DST_INFO_ERR (1004) |
| 4 | Direct connection validation failed | TOPO_CONNECTION_ERROR (1008) |
| 5 | Multi-hop path resolution failed | TOPO_CONNECTION_NOT_FOUND (1009) |
| 6-7 | Route unreachable | ROUTE_NOT_REACHABLE (1010) |
| 9-10 | Success | SUCCESS (0) |

**PathService Coverage Planning Tests (new):**

| Scenario | Expected |
|:-----|:-----|
| planPathsCoverage: 4npu_8port + MIN_COVERAGE | SUCCESS, scope=L1_L2 |
| planPathsCoverage: 4npu_8port + REDUNDANT | SUCCESS, redundantLinks > 0 |
| planPathsCoverage: incomplete topology | COVERAGE_INCOMPLETE |
| planPathsCoverage: superNodeName not found | TOPO_NOT_FOUND |
| planPathsCoverage: state not DATAREADY | SNCStateException |
| planPathsCoverage: request is null | IllegalArgumentException |
| planPathsCoverageEx: 4npu_8port + jettyId + MIN_COVERAGE | SUCCESS, scope=NPU_L1_L2, layerStats=[NPU_L1, L1_L2] |
| planPathsCoverageEx: jettyId missing | SUCCESS + exJettyFallback > 0 |
| planPathsCoverageEx: incomplete topology | COVERAGE_INCOMPLETE |
| planPathsCoverageEx: CROSS_L2 path length verification | coveredLinks.size() == 8 |
| planPathsCoverageEx: LOCAL_L1 path length verification | coveredLinks.size() == 4 |

**LinkEventService Test Scenarios:**

| Scenario | Expected |
|:-----|:-----|
| handleLinkEvent: normal down event | port.linkStatus = LINK_DOWN + port.updateAt updated + converge triggered |
| handleLinkEvent: normal up event | port.linkStatus = LINK_UP + port.updateAt updated + converge triggered |
| handleLinkEvent: duplicate down event | Idempotent, routing state unchanged |
| handleLinkEvent: eventType not up/down | IllegalArgumentException |
| handleLinkEvent: deviceName not found | IllegalStateException |
| handleLinkEvent: portName not found | IllegalStateException |
| handleLinkEvent: superNode is null | IllegalArgumentException |
| handleLinkEvent: event is null | IllegalArgumentException |
| handleLinkEvent: eventTime is 0 or negative | Allowed (only written to updateAt, no range validation) |

### 3.9 SNCServiceImpl

| Test Category | Test Case Count | Key Test Points |
|:---------|:----------|:-----------|
| Lifecycle state machine | 12+ | INIT→READY→DATAREADY→UNINIT state transitions; routeCalculate/makeRoutes/getNodeRoute/notifyLinkEvent available in both READY/DATAREADY; planPathsCoverage/Ex only in DATAREADY |
| Parameter validation | 20+ | All input parameter null/empty string checks; CoveragePathsRequest/LinkEvent field validation |
| Exception handling | 10+ | Calling methods before init / after uninit; routeCalculate not called before makeRoutes throws IllegalStateException; makeRoutes not called before getNodeRoute throws exception |
| Full end-to-end | 10+ | From init → setSuperNodeData → addNpuDevices → addSwDevices → planPath → planPathsCoverage → planPathsCoverageEx → routeCalculate → makeRoutes → getNodeRoute → notifyLinkEvent → uninit |
| Coverage planning chain | 8+ | planPathsCoverage/planPathsCoverageEx full flow; scope/layerStats/type validation |
| Route calculation chain | 8+ | routeCalculate idempotency (two calls); makeRoutes instantiation; getNodeRoute query; notifyLinkEvent reachable changes after converge verified via getNodeRoute |

**State Machine Tests:**

| Test Scenario | Call Sequence | Expected Result |
|:---------|:---------|:---------|
| Call setSuperNode without init | setSuperNode(...) | SNCStateException |
| Normal call after init | init → setSuperNode | Normal execution, state enters DATAREADY |
| Call after uninit | init → ... → uninit → getSuperNode | SNCStateException |
| Repeated init | init → init | Idempotent, no exception thrown |
| Call planPath in READY state | init → planPath | SNCStateException (not yet DATAREADY) |
| Call routeCalculate in READY state | init → routeCalculate | Normal execution |
| Call makeRoutes in READY state | init → makeRoutes | Throws IllegalStateException (routeCalculate not called) |
| Call notifyLinkEvent in READY state | init → notifyLinkEvent | Throws IllegalStateException (makeRoutes not called, instantiationRouteMap empty) |
| Call planPathsCoverage in DATAREADY state | init → setSuperNode → planPathsCoverage | Normal execution |
| Call planPathsCoverageEx in DATAREADY state | init → setSuperNode → planPathsCoverageEx | Normal execution |

### 3.10 Route Layer (new)

| Class | Test Case Count | Key Test Points |
|:---|:----------|:-----------|
| RouteMspService | 20+ | BFS shortest path calculation; shortest/secondShortest/other path classification; template routing table generation; single-chassis/cross-chassis topology; cost=1 consistency; unreachable scenarios |
| RouteInstantiationService | 25+ | instantiateXpodRoute expands per chassis; NPU/L1SW/L2SW label matching; L2SW out-port remapping when instantiating 4 chassis; buildRouteTableKey; deepCopyRoutingEntry deep-copy semantics (modifying the returned value does not affect internals); empty SuperNode / no forwardingChips boundaries |
| RouteConvergeService | 30+ | converge BFS propagation; FLAG_PASSIVE_CONVERRGED setFlag/clearFlag; refreshReachable state transitions (true→false / false→true); ECMP multi-out-port only marks the hit one; same-device different-chip forwarding isolation; idempotency (repeated down events); up event clears PASSIVE then reverse BFS propagation |
| TopoTemplateService | 12+ | parseTemplateFile parses 128_npu_rack.json + 128_npu_inter_rack.json; SncTopology model construction; NodeLoader/PortLoader/PrefixLoader collaboration; throws exception when template file not found |
| TemplateModel | 40+ | SncTopology/SncNode/SncPort/Label/Address/Prefix/Bitmap/PolicyPath/PolicyPrefix/AddrType constructor + Getter/Setter/equals/hashCode/toString |
| RouteTable / RouteEntry / Inbound / NextHopPort / OriginNode | 35+ | route.model class constructor + field constraints; RouteEntry's NhpSet + path classification; Inbound's inPortId/parentNode/cost/outIfSet; NextHopPort's pathType |

**RouteConvergeService Key Test Scenarios:**

| Scenario | Expected |
|:-----|:-----|
| Single-port down: single out-port RoutingEntry | reachable=false + convergedFlag!=0 + BFS propagation to peer |
| Single-port down: ECMP multi-out-port RoutingEntry | Only the hit outPort setFlag, reachable=true (other out-ports still effective), no BFS propagation |
| Single-port up: clear PASSIVE | convergedFlag==0 + reachable=true + reverse BFS propagation clears peer |
| Repeated down event | Idempotent, state unchanged |
| Same-device different-chip convergence | Forwarding isolated, only chip C routing table affected, chip C' unaffected |
| Cross-multi-hop propagation | chip C → N → N' → N'' chained reachable changes |
| Target object verification | Modifies instantiationRouteMap, does not modify SuperNode.routingTableMap |
| Device not found | Throws IllegalStateException |
| Port not found | Throws IllegalStateException |

---

## 4. Test Data Management

### 4.1 JSON Test Data

```
src/test/resources/
├── topo_data_2npu_1port.json     # 2 NPU + 1 L1 SW topology (single port)
├── topo_data_4npu_8port.json     # 4 NPU + 2 L1 SW topology (multi-port)
└── topo_data_2box_16l2sw.json    # 2 chassis + 16 L2SW topology (cross-chassis path)
```

### 4.2 TestDataLoader Utility Class

`TestDataLoader` is responsible for parsing JSON files into Java objects:
- `loadSuperNode(resourcePath)` — Parse topology JSON into `SuperNode` (including npuDevices, swDevices, chips, ports, routing tables)

### 4.3 2npu_1port Data (Minimal Validation)

- **NPU1**: 1 port `400GE 0/0/1`, CNA=`170.170.170.18`, EID=`AAAAAA12000000000000000000000002`, UPI=`0A0A0A01`
- **NPU2**: 1 port `400GE 0/1/1`, CNA=`221.221.221.66`, EID=`DDDDDD42000000000000000000000002`, UPI=`0A0A0A01`
- **L1SW0**: 2 ports connected to NPU1/NPU2
- **Routes**: NPU1→target 221.221.221.68, L1SW has two routes (170.170.170.17→NPU1 side, 221.221.221.68→NPU2 side)

### 4.4 4npu_8port Data (Full Validation)

- 4 NPUs each with 8 ports (32 ports total), each port has independent CNA/EID
- 4 L1SWs each with 8 ports, no L2SW
- Each NPU's 8 ports evenly distributed across 4 L1SWs (2 ports per L1SW)
- Routing table: Each NPU has 8 routes to other NPUs (ECMP 2-way), each L1SW has 4 routes to each NPU (single-way)

### 4.5 Port Naming and Encoding Rules

| Device Type | Port Format | Example |
|:---------|:---------|:-----|
| NPU | `400GE 0/{chipIndex}/{portIndex}` | `400GE 0/0/1` |
| L1SW | `400GE 1/{chipIndex}/{portIndex}` | `400GE 1/0/2` |

| NPU | EID Prefix | CNA Range | UPI | jettyId Range |
|:----|:---------|:---------|:------------|:-------------|
| npu1 | AAAAAA | 170.170.170.x | 0A0A0A01 | [32, 1023]; FullRackTopologyGenerator uses 32..39 |
| npu2 | DDDDDD | 221.221.221.x | 0A0A0A01 | [32, 1023]; FullRackTopologyGenerator uses 32..39 |
| npu3 | EEEEEE | 238.238.238.x | 0A0A0A01 | [32, 1023]; FullRackTopologyGenerator uses 32..39 |
| npu4 | FFFFFF | 255.255.255.x | 0A0A0A01 | [32, 1023]; FullRackTopologyGenerator uses 32..39 |

**jettyId Test Data Sources:**
- SuperNode JSON `jettyId` field: parsed by `TestDataLoader`;
- Template JSON `jetty_id` field: `128_npu_rack.json`, carried by `PortLoader`/`SncPort`;
- `FullRackTopologyGenerator` allocates `JETTY_ID_BASE + portIndex` (32..39) deterministically, pinned by `FullRackTopologyJettyIdTest`.

---

## 5. Test Tools and Dependencies

| Tool | Version | Purpose |
|------|------|------|
| JUnit Jupiter | 5.9.2 | Test framework |
| JaCoCo | 0.8.12 | Coverage statistics |
| Maven Surefire | 3.2.2 | Test execution |
| Lombok | 1.18.36 | POJO simplification |

---

## 6. Test Naming Conventions

- Test class name: `{ClassUnderTest}Test.java`
- Test method name: `{scenario}_{expectedResult}` (camelCase)
- Use `@DisplayName` to annotate descriptions
- Entity/DTO tests uniformly follow the 7-step template: default → allArgs → setters → equalsEqual → equalsNotEqual → hashCode → toString
