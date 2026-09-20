# SNC Module Test Execution Guide

## 1. Runtime Environment

| Item | Version |
|------|------|
| JDK | 21+ |
| Maven | 3.8+ |
| Operating System | Windows / Linux |
| Build Tool | Maven (pom.xml configured with JUnit 5.9.2 / JaCoCo 0.8.12 / Surefire 3.2.2) |

---

## 2. Run All Tests

Execute in the `src/snc` directory:

```bash
mvn test
```

Output example:

```
Tests run: 477, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

> 477 is the expected total after adding tests for planPathsCoverage/Ex, notifyLinkEvent, routeCalculate/makeRoutes/getNodeRoute, CoveragePlanEngine, route services, LinkEventService, HashUtils/UbSwitchHash/DllLoader, and new DTOs; the actual execution result prevails.

---

## 3. Run a Single Test Class

```bash
# Full test suite + coverage report
mvn clean test

# Specify a test class
mvn test -Dtest=SNCServiceIntegrationTest

# Coverage planning tests
mvn test -Dtest=CoveragePlanEngineTest
mvn test -Dtest=PlanPathsCoverageExIntegrationTest

# Route service tests
mvn test -Dtest=RouteConvergeServiceTest
mvn test -Dtest=RouteInstantiationServiceTest
mvn test -Dtest=RouteMspServiceTest
mvn test -Dtest=TopoTemplateServiceTest

# HashUtils tests (including Java fallback consistency)
mvn test -Dtest=HashUtilsTest
mvn test -Dtest=UbSwitchHashTest

# Link event service tests
mvn test -Dtest=LinkEventServiceTest

# jettyId fixed allocation pinning tests
mvn test -Dtest=FullRackTopologyJettyIdTest

# Wildcard matching
mvn test -Dtest=*Service*
mvn test -Dtest=Coverage*
mvn test -Dtest=Route*

# All tests under a specific package
mvn test -Dtest="com.huawei.umdk.snc.service.*"
mvn test -Dtest="com.huawei.umdk.snc.route.*"
mvn test -Dtest="com.huawei.umdk.snc.dto.*"

# Skip test compilation
mvn compile -DskipTests
```

---

## 4. Generate Coverage Report

JaCoCo coverage report is automatically generated after running tests:

```bash
mvn test
```

Report path:
```
target/site/jacoco/index.html
```

Open `index.html` directly in a browser to view coverage details.

---

## 5. Skip Tests (Packaging Scenarios)

```bash
# Skip test compilation and package
mvn package -DskipTests

# Skip test execution but compile tests
mvn package -Dmaven.test.skip=true
```

---

## 6. Common Troubleshooting

### 6.1 Test Failure — Checklist

- Check whether JSON test resource files exist (`src/test/resources/`)
- Verify that port EID/CNA in topology JSON are complete
- Verify that port names are defined in topology data
- Verify that route prefixes match the results of `cnaToTargetAddr()` (requires `/32` exact match)
- If planPathsCoverageEx fails, check whether the NPU port `jettyId` field is within `[32, 1023]`; if missing, it triggers the `exJettyFallback` diagnostic counter (not a failure, still SUCCESS)
- If route convergence tests fail, check whether `instantiationRouteMap` is filled via `makeRoutes`; `notifyLinkEvent` requires `routeCalculate` + `makeRoutes` first
- If CoveragePlanEngine tests fail, check the counters from `getExDiagnostics()` to locate whether the NPU/L1SW/L2SW layer route/port lookup failed
- If HashUtils tests fail, check whether the native library loaded successfully; if loading fails, it automatically falls back to `UbSwitchHash` (pure Java), which does not affect test passing, but `DllLoaderTest` reports the search paths
- If template parsing tests fail, check whether the `128_npu_rack.json` / `128_npu_inter_rack.json` resource files are in the classpath

### 6.2 Compilation Failure

```bash
mvn clean compile test-compile
```

Clear the target directory and recompile.

### 6.3 JaCoCo Report Not Generated

Confirm that the jacoco plugin configuration exists in `pom.xml`:
```xml
<plugin>
    <groupId>org.jacoco</groupId>
    <artifactId>jacoco-maven-plugin</artifactId>
    <version>0.8.12</version>
    ...
</plugin>
```

### 6.4 Notes

1. **Test order independence**: Each test class is independent and does not rely on side effects from other tests
2. **Test data independence**: Each test method creates its own test data and does not share mutable objects
3. **No Mock framework**: The current stage uses pure JUnit 5; store/engine is injected via constructor
4. **JSON fixtures are read-only**: JSON test data cannot be modified by tests
