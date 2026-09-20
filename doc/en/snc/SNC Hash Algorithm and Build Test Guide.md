# SNC Hash Algorithm and Build Test Guide

## 1. Document Purpose and Scope

This document describes the design of the ECMP port-selection hash algorithms in the SNC module, the collaboration between the pure-Java implementation and the native-library implementation, and the detailed build, packaging, test, and deployment workflows for the following scenarios:

- Source build without native executables
- Source build with native executables
- JAR packaging workflow
- Test workflow for testers who only have the JAR (with / without native libraries)
- CI pipeline scenarios

Intended audience: developers, testers, CI pipeline maintainers, production deployment engineers.

---

## 2. Hash Algorithm Design

The SNC module exposes two ECMP port-selection hash entry points used for load-balancing at different device layers:

### 2.1 `ubswitch_Hash_ecmp` — Inter-Chassis Port Selection Hash

**Purpose**: L1SW↔L2SW (inter-chassis) and L1SW→NPU port selection, based on the 5-tuple `(dip, sip, dport, sport, protocol)`.

**Algorithm branches** (selected by the `hash_func` parameter):

| `hash_func` | Algorithm | Description |
|---|---|---|
| `1` | FNV-1a | offset basis `2166136261` (`0x811C9DC5`), prime `16777619`; per-byte `(h^=b)*=p` for dip/sip, then `mix` for dport/sport/protocol/hash_func |
| other | Simple accumulator | `h = h*31 + b` accumulated byte-by-byte over dip/sip/ports/protocol/hash_func |

**Modulo rule**:
- `ecmp_cnt == 0` returns the raw hash value (signed 32-bit)
- `ecmp_cnt > 0` returns `floorMod(h, ecmp_cnt)`, result is non-negative

**Constant semantics**: All numeric values (`0x811C9DC5`, `16777619`, `0x9e3779b9`, `31`) are public algorithm constants, **not cryptographic salts**. `0x9e3779b9` is the golden-ratio constant (Knuth multiplicative hash); `31` is the prime multiplier used by Java's `String.hashCode()`.

### 2.2 `ubswitch_Hash_dieEcmp` — NPU Uplink Port Selection Hash

**Purpose**: NPU→L1SW uplink port selection, based on the 2-tuple `(dst_cna, jetty_id)`.

**Algorithm**: CRC-8/ATM (polynomial `0x07`, init `0x00`, no reflection, no final XOR) over the 9-byte stream `{src_cna[4 BE], dst_cna[4 BE], lb[1]}`, where `src_cna` is fixed to 0 and `lb` is the low 8 bits of the jetty id.

**Parameter constraints**:
- `function_select ∈ {0, 1}` both select CRC-8/ATM; other values return `-1`
- `ecmp_cnt == 0` returns the raw CRC (0..255)
- `ecmp_cnt > 0` returns `crc % ecmp_cnt`; result is non-negative (CRC is already non-negative, no correction needed)

### 2.3 Dual-Implementation Equivalence

Each algorithm has two implementations: the native library (C-compiled `.dll`/`.so`) and the pure-Java implementation (`UbSwitchHash.java`). **The two are bit-for-bit equivalent**, verified by unit tests (`UbSwitchHashTest` includes an independent reference implementation for comparison).

---

## 3. Collaboration Between Native Library and Pure-Java Implementation

### 3.1 Overall Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HashUtils.java (entry)                    │
│                                                             │
│  nativeHash(...) ──────┐                                    │
│                        ▼                                    │
│              ┌──────────────────────┐                       │
│              │ LIB_ECMP != null ?   │                       │
│              └──────────┬───────────┘                       │
│                    │        │                              │
│                   yes       no                             │
│                    ▼        ▼                              │
│         ┌─────────────┐  ┌─────────────────────┐            │
│         │ JNA native   │  │ UbSwitchHash        │ (fallback)│
│         │ ubswitch_    │  │ .ubswitchHashEcmp() │            │
│         │ Hash_ecmp()  │  │                     │            │
│         └─────────────┘  └─────────────────────┘            │
│                                                             │
│  nativeHashDstCnaJetty(...) ──────┐                         │
│                                   ▼                         │
│                         ┌──────────────────────┐            │
│                         │ LIB_DIE != null ?    │            │
│                         └──────────┬───────────┘            │
│                              │        │                     │
│                             yes       no                     │
│                              ▼        ▼                     │
│                   ┌─────────────┐  ┌─────────────────────┐  │
│                   │ JNA native   │  │ UbSwitchHash        │ │
│                   │ ubswitch_    │  │ .ubswitchHashDieEcmp│ │
│                   │ Hash_dieEcmp │  │ ()                  │ │
│                   └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Design Principles

1. **Native library takes priority**: If JNA successfully loads the native library, the native implementation is used (consistent with historical behavior, convenient for native-library replacement debugging)
2. **Java fallback**: If native library loading fails, automatically falls back to the `UbSwitchHash` pure-Java implementation; results are equivalent
3. **Silent degradation**: No exception is thrown on fallback; load-failure diagnostics are emitted to stderr only
4. **Zero behavioral difference**: Both paths return identical results for the same input (`mapHashMode` is applied uniformly before both paths)

### 3.3 Importance of `mapHashMode`

`HashUtils.mapHashMode()` is a 1↔6 swap mapping:

```java
private static int mapHashMode(int hashFunc) {
    if(hashFunc == 1) return 6;
    if(hashFunc == 6) return 1;
    return hashFunc;
}
```

**Key constraint**: `mapHashMode` must be applied **before both paths are invoked**, not only on the native path. The current implementation honors this:

```java
int mappedFunc = mapHashMode(hashFunc);   // ← map first
if (LIB_ECMP != null) {
    LIB_ECMP.ubswitch_Hash_ecmp(..., mappedFunc, ...);    // native path uses mappedFunc
}
return UbSwitchHash.ubswitchHashEcmp(..., mappedFunc, ...); // fallback path also uses mappedFunc
```

### 3.4 `DllLoader` Native Library Search Order

`DllLoader.buildSearchPaths()` searches for native libraries in the following order:

| # | Search Path | Source | Description |
|---|---|---|---|
| 1 | `jna.library.path` | `-D` JVM arg | Explicit user override; highest priority |
| 2 | `src/main/resources` | Hard-coded | Development / unit-test scenario |
| 3 | `user.dir` | System property | Current working directory |
| 4 | **JAR sibling directory** | `getApplicationDir()` | **Key path for testers / production** |
| 5 | `target` | Hard-coded | Maven build output |
| 6 | `target/classes` | Hard-coded | Maven class output |
| 7 | Classpath extraction | `extractFromClasspath()` | Extract from inside JAR to temp dir |
| 8 | Bare-name load | `Native.load(name)` | Delegate to JNA system-path search |

**Key logic of `getApplicationDir()`**:
```java
URL location = DllLoader.class.getProtectionDomain().getCodeSource().getLocation();
File file = new File(location.toURI());
if (file.isFile()) {
    return file.getParent();   // ← when running from JAR, returns JAR's parent directory
}
return file.getAbsolutePath();  // ← when running from class directory, returns that directory
```

---

## 4. Source Build Without Native Executables

### 4.1 Applicable Scenarios

- Standard development workflow where the developer does not need native libraries locally
- CI pipeline that pulls source and runs tests
- Any environment that does not depend on native libraries

### 4.2 Directory Layout

```
umdk/
└── src/
    └── snc/
        ├── pom.xml
        ├── src/main/java/.../util/
        │   ├── HashUtils.java
        │   ├── UbSwitchHash.java        ← pure-Java implementation
        │   ├── DllLoader.java
        │   └── AddressUtils.java
        ├── src/main/resources/
        │   ├── 128_npu_inter_rack.json  ← retained (topology data)
        │   └── 128_npu_rack.json        ← retained (topology data)
        └── test/...                     ← test code
```

**Note**: `src/main/resources/` does **not** contain any native library files (`.dll`/`.so`).

### 4.3 Build Command

```bash
cd umdk/src/snc
mvn clean test
```

### 4.4 Execution Principle

1. **JVM startup**: Maven Surefire launches the JVM and loads SNC classes
2. **`HashUtils` static initializer runs**:
   - `DllLoader.load("libubswitch.dll", ...)` is invoked
   - `buildSearchPaths()` searches in order: `jna.library.path` (unset) → `src/main/resources` (no library) → `user.dir` (no library) → `getApplicationDir()` = `target/classes` (no library) → `target` / `target/classes` (no library) → `extractFromClasspath` (no library) → `Native.load("libubswitch.dll")` (system path, likely fails)
   - Load failure → stderr outputs `[HashUtils] Failed to load native library 'libubswitch.dll': ...`
   - `LIB_ECMP = null`, `LIB_DIE = null`
3. **Test calls `HashUtils.nativeHash(...)`**:
   - Detects `LIB_ECMP == null` → invokes `UbSwitchHash.ubswitchHashEcmp(...)`
4. **Test calls `HashUtils.nativeHashDstCnaJetty(...)`**:
   - Detects `LIB_DIE == null` → invokes `UbSwitchHash.ubswitchHashDieEcmp(...)`

### 4.5 Expected Output

```
[HashUtils] Failed to load native library 'libubswitch.dll': ...
[HashUtils] Failed to load native library 'libubswitch-die.dll': ...
...
[INFO] Tests run: 496, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

The "Failed to load" messages on stderr are **expected behavior** and do not affect test pass/fail.

### 4.6 Advantages

- ✅ No need to maintain multi-platform native libraries
- ✅ No environment differences (results are fully determined by Java code)
- ✅ CI stability (does not depend on whether the machine has native libraries pre-installed)
- ✅ Cross-platform consistency (Windows/Linux/x86_64/aarch64 produce identical results)

---

## 5. Source Build With Native Executables

### 5.1 Applicable Scenarios

- Verifying the behavior of a new native-library version
- Performance comparison tests
- Native-library feature debugging

### 5.2 Preparing Native Libraries

Place the platform-appropriate native libraries in any directory, e.g. `umdk/native-libs/`:

```
umdk/
├── native-libs/
│   ├── libubswitch.dll              (Windows)
│   ├── libubswitch-die.dll          (Windows)
│   ├── libubswitch-x86_64.so        (Linux x86_64)
│   ├── libubswitch-die-x86_64.so    (Linux x86_64)
│   ├── libubswitch-aarch64.so       (Linux aarch64)
│   └── libubswitch-die-aarch64.so   (Linux aarch64)
└── src/snc/
    └── pom.xml
```

### 5.3 Native Library File Naming Convention

`HashUtils.detectNativeLibraryName()` selects the file name automatically based on the platform:

| Platform | ECMP library name | DIE library name |
|---|---|---|
| Windows | `libubswitch.dll` | `libubswitch-die.dll` |
| Linux x86_64 | `libubswitch-x86_64.so` | `libubswitch-die-x86_64.so` |
| Linux aarch64 | `libubswitch-aarch64.so` | `libubswitch-die-aarch64.so` |

**The exact file names above must be used**, otherwise JNA will not find them.

### 5.4 Build Commands

**Option A: Specify via `-D` parameter** (recommended):

```bash
cd umdk/src/snc
mvn clean test -Djna.library.path=../../native-libs
```

The `pom.xml` configures a `jna.library.path` system-property bridge (`<jna.library.path>${native.lib.dir}</jna.library.path>`); the Maven property can also be used:

```bash
mvn clean test -Dnative.lib.dir=../../native-libs
```

**Option B: Place in the working directory**:

```bash
cd umdk/native-libs
mvn -f ../src/snc clean test
# user.dir=umdk/native-libs; DllLoader will find the native libraries
```

**Option C: Place in `src/main/resources`** (restores historical behavior):

```bash
cp native-libs/* umdk/src/snc/src/main/resources/
cd umdk/src/snc
mvn clean test
```

### 5.5 Execution Principle

Using Option A as an example:

1. **JVM startup**: `-Djna.library.path=../../native-libs` sets the system property
2. **`HashUtils` static initializer runs**:
   - `DllLoader.load()` is invoked
   - The first entry of `buildSearchPaths()` is `jna.library.path` = `../../native-libs`
   - `findDllPath()` finds `libubswitch.dll` in that directory → returns the absolute path
   - Sets `jna.library.path` to that directory (ensures JNA can also find transitive dependencies)
   - `Native.load(absolutePath, ...)` loads successfully
   - `LIB_ECMP != null`, `LIB_DIE != null`
3. **Test calls `HashUtils.nativeHash(...)`**:
   - Detects `LIB_ECMP != null` → invokes JNA interface `LIB_ECMP.ubswitch_Hash_ecmp(...)`
4. **Test calls `HashUtils.nativeHashDstCnaJetty(...)`**:
   - Detects `LIB_DIE != null` → invokes JNA interface `LIB_DIE.ubswitch_Hash_dieEcmp(...)`

### 5.6 Expected Output

```
[INFO] Tests run: 496, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

**No** "Failed to load" output on stderr (because loading succeeded).

### 5.7 Verifying Whether the Native Library Is Used

```bash
mvn test 2>stderr.log
grep "Failed to load" stderr.log
# no output = native library loaded successfully, native path is used
# output present = load failed, fallback is used
```

---

## 6. JAR Packaging Workflow

### 6.1 Standard Packaging Command

```bash
cd umdk/src/snc
mvn clean package
```

### 6.2 Artifacts

```
umdk/src/snc/target/
├── snc-1.0.0.jar              ← main JAR (does not contain native libraries)
├── snc-1.0.0.jar.sha256
└── original-snc-1.0.0.jar      ← pre-shade original JAR (if shade plugin is used)
```

### 6.3 JAR Contents

```
snc-1.0.0.jar
├── com/huawei/umdk/snc/
│   ├── util/
│   │   ├── HashUtils.class
│   │   ├── UbSwitchHash.class    ← pure-Java fallback implementation is compiled into the JAR
│   │   ├── DllLoader.class
│   │   └── AddressUtils.class
│   └── ... other business classes
└── 128_npu_inter_rack.json       ← topology data resource (retained)
    128_npu_rack.json             ← topology data resource (retained)
```

**Key properties**:
- ✅ JAR does **not** contain native libraries (`.dll`/`.so`)
- ✅ JAR **does** contain `UbSwitchHash.class` (pure-Java fallback is compiled in)
- ✅ JAR **does** contain topology JSON resources

### 6.4 Skip Tests for Fast Packaging

```bash
mvn clean package -DskipTests
```

### 6.5 Verify the JAR Loads Standalone

```bash
cd umdk/src/snc/target
# List JAR contents; confirm UbSwitchHash.class and topology JSON resources are compiled in
jar tf snc-1.0.0.jar | grep -E "UbSwitchHash|128_npu"
# Expected output:
#   com/huawei/umdk/snc/util/UbSwitchHash.class
#   128_npu_inter_rack.json
#   128_npu_rack.json

# Confirm the JAR contains no native libraries (.dll/.so)
jar tf snc-1.0.0.jar | grep -E "\.(dll|so)$"
# Expected output: (empty — no native libraries)
```

> **Note**: `snc-1.0.0.jar` is a **library JAR** (the manifest has no `Main-Class`); it cannot be run with `java -jar`. At runtime it must be loaded via `-cp` and driven by caller code (a main class), with third-party dependencies (JNA, etc.) provided by the caller's environment. See Chapter 7 for details.

### 6.6 Packaging With Native Libraries (Optional)

If the JAR and native libraries need to be distributed together, use either of the following:

**Option A: ZIP packaging**

```bash
cd umdk/src/snc/target
mkdir -p dist
cp snc-1.0.0.jar dist/
cp /path/to/native-libs/libubswitch*.dll dist/   # per platform
cp /path/to/native-libs/libubswitch-die*.dll dist/
zip -r snc-dist.zip dist/
```

**Option B: Maven Assembly Plugin** (requires `maven-assembly-plugin` configuration in `pom.xml`)

### 6.7 Recommended Distribution Methods

- **JAR-only distribution**: Simplest; testers can run without native libraries (via fallback)
- **JAR + native-libs directory distribution**: Testers can optionally use native libraries (see Chapter 7)

---

## 7. Tester Workflow for Using the JAR

### 7.1 Scenario A: JAR Alone (No Native Libraries)

#### 7.1.1 Directory Layout

```
/opt/test/
└── snc-1.0.0.jar
```

#### 7.1.2 Execution Command

`snc-1.0.0.jar` is a **library JAR** (the manifest has no `Main-Class`); it cannot be run directly with `java -jar`. It must be loaded via `-cp` by caller code (a test program / application) which then invokes the SNC API:

```bash
cd /opt/test
# Caller test program (provides its own main method and calls SncService APIs)
java -cp ".:snc-1.0.0.jar:jna-5.14.0.jar" MyTestDriver
```

Here `MyTestDriver` is a main class prepared by the tester (compiled against `snc-1.0.0.jar`) that drives SNC via `new SncService().init(...)` → `setSuperNode(...)` → `planPathsCoverage(...)` etc. Third-party dependencies such as `jna-5.14.0.jar` are supplied by the caller environment (preinstalled on the device or distributed alongside).

> **Note**: Wherever `java -jar snc-1.0.0.jar` appears in the sections below, treat it as shorthand for `java -cp ".:snc-1.0.0.jar:<deps>" <MainClass>`; the key point is that native libraries are loaded automatically by `DllLoader` from the JAR's sibling directory, regardless of how the JVM is launched.

#### 7.1.3 Execution Principle

1. JVM loads `snc-1.0.0.jar` and initializes the `HashUtils` class
2. `HashUtils` static initializer invokes `DllLoader.load("libubswitch.dll", ...)`:
   - `getApplicationDir()` returns `/opt/test/` (JAR's parent directory)
   - `buildSearchPaths()` searches in order: `jna.library.path` (unset) → `src/main/resources` (no such path inside JAR) → `user.dir` = `/opt/test/` (no library) → **`/opt/test/`** (JAR sibling, no library) → `target` / `target/classes` (do not exist) → `extractFromClasspath` (no native-library resource inside JAR) → `Native.load("libubswitch.dll")` (no library on system path)
   - Load failure → `LIB_ECMP = null`, `LIB_DIE = null`
3. Business code calls `HashUtils.nativeHash(...)`:
   - Detects `LIB_ECMP == null` → invokes `UbSwitchHash.ubswitchHashEcmp(...)`
4. Business code calls `HashUtils.nativeHashDstCnaJetty(...)`:
   - Detects `LIB_DIE == null` → invokes `UbSwitchHash.ubswitchHashDieEcmp(...)`

#### 7.1.4 Expected Behavior

- ✅ Program runs normally
- ✅ Hash results are **identical** to the native library (algorithms are bit-for-bit equivalent)
- ⚠️ stderr outputs "Failed to load native library" diagnostics (**expected, not an error**)
- ⚠️ Performance is slightly lower than the native library (pure-Java interpreted execution, but imperceptible in ECMP port-selection scenarios)

### 7.2 Scenario B: JAR + Native Libraries

#### 7.2.1 Directory Layout

```
/opt/test/
├── snc-1.0.0.jar
├── libubswitch.dll              ← per platform (Windows)
└── libubswitch-die.dll          ← per platform (Windows)
```

Or Linux x86_64:

```
/opt/test/
├── snc-1.0.0.jar
├── libubswitch-x86_64.so
└── libubswitch-die-x86_64.so
```

#### 7.2.2 Execution Command

```bash
cd /opt/test
java -cp ".:snc-1.0.0.jar:jna-5.14.0.jar" MyTestDriver
```

No `-D` parameter is needed; `DllLoader` automatically finds the native libraries in the JAR's sibling directory.

#### 7.2.3 Execution Principle

1. JVM loads `snc-1.0.0.jar`
2. `HashUtils` static initializer invokes `DllLoader.load("libubswitch.dll", ...)`:
   - `getApplicationDir()` returns `/opt/test/` (JAR's parent directory)
   - Entry 4 of `buildSearchPaths()` is `/opt/test/`
   - `findDllPath()` finds `libubswitch.dll` in `/opt/test/` → returns `/opt/test/libubswitch.dll`
   - Sets `jna.library.path` = `/opt/test/`
   - `Native.load("/opt/test/libubswitch.dll", ...)` loads successfully
   - `LIB_ECMP != null`, `LIB_DIE != null`
3. Business code calls `HashUtils.nativeHash(...)`:
   - Detects `LIB_ECMP != null` → invokes JNA interface `LIB_ECMP.ubswitch_Hash_ecmp(...)`

#### 7.2.4 Expected Behavior

- ✅ Program runs normally
- ✅ Hash results are identical to Scenario A
- ✅ No "Failed to load" output on stderr (load succeeded)
- ✅ Performance is slightly higher than Scenario A (native-library execution, but practically imperceptible)

### 7.3 Scenario C: Native Libraries in an Arbitrary Directory

#### 7.3.1 Directory Layout

```
/home/tester/
├── snc-1.0.0.jar
└── libs/                       ← custom directory
    ├── libubswitch.dll
    └── libubswitch-die.dll
```

#### 7.3.2 Execution Command

```bash
cd /home/tester
java -Djna.library.path=/home/tester/libs -jar snc-1.0.0.jar
```

#### 7.3.3 Execution Principle

`-Djna.library.path` has the highest priority (entry 1 of `buildSearchPaths()`); `DllLoader` searches that path first and loads on hit.

### 7.4 Replacing Native Libraries

When a tester wants to verify a new native-library version:

1. Back up the existing native libraries (optional)
2. Place the new native libraries in the JAR's sibling directory, **overwriting** the old files
3. Confirm the file names match the platform (see §5.3)
4. Restart the JVM and run the program
5. Verify that loading succeeded: check stderr for "Failed to load" output

### 7.5 Verifying Whether the Test Uses Native Libraries

```bash
# Run the program, redirecting stderr
java -cp ".:snc-1.0.0.jar:jna-5.14.0.jar" MyTestDriver 2>stderr.log

# Check
grep "Failed to load" stderr.log
# no output = native library loaded successfully
# output present = load failed, fallback is used
```

### 7.6 Test Scenario Comparison Table

| Test Purpose | Directory Layout | Command | Expected |
|---|---|---|---|
| Verify Java fallback | JAR only | `java -cp ".:snc-1.0.0.jar:<deps>" MyTestDriver` | stderr has "Failed to load", results correct |
| Verify native library | JAR + native libs | `java -cp ".:snc-1.0.0.jar:<deps>" MyTestDriver` | stderr has no error, results correct |
| Verify replaced native lib | JAR + new native libs (overwrite old) | `java -cp ".:snc-1.0.0.jar:<deps>" MyTestDriver` | stderr has no error, results per new lib |
| Dual-path equivalence | Same machine, run both scenarios | Compare results | Results identical |

> `<deps>` denotes third-party dependencies supplied by the caller environment (e.g. `jna-5.14.0.jar`); `MyTestDriver` is the caller-provided main class.

---

## 8. CI Pipeline Scenario

### 8.1 Standard CI Command

```bash
# After pulling source
cd umdk/src/snc
mvn clean test
```

### 8.2 Execution Principle

Identical to Chapter 4 "Source Build Without Native Executables":
1. CI machine has no native libraries
2. All `DllLoader` search paths fail to find native libraries
3. `LIB_ECMP = null`, `LIB_DIE = null`
4. Automatically falls back to Java fallback

### 8.3 Key Advantages

- ✅ **CI environment consistency**: Does not depend on whether the CI machine has native libraries pre-installed
- ✅ **Cross-platform consistency**: CI runs on x86_64 / aarch64 / Windows / Linux produce identical results
- ✅ **Stable reproducibility**: Results are determined by source code and are comparable with historical builds

### 8.4 CI Verifying Native Libraries (Optional)

If CI needs to regression-test native-library behavior:

```bash
# Pre-stage native libraries in native-libs/ directory in the CI script
mvn clean test -Djna.library.path=native-libs
```

---

## 9. Production Deployment Scenario

### 9.1 Recommended Approach: JAR-Only Deployment

```bash
# Production server
/opt/app/
└── snc-1.0.0.jar

java -cp ".:snc-1.0.0.jar:<deps>" com.example.App
```

**Rationale**:
- Simplified deployment (single JAR)
- Cross-platform consistency
- No native-library dependency; upgrading JDK/OS does not require recompiling native libraries
- Java fallback performance is sufficient for ECMP port-selection scenarios

### 9.2 High-Performance Scenario: JAR + Native Libraries

```bash
/opt/app/
├── snc-1.0.0.jar
├── libubswitch-x86_64.so       # per production platform
└── libubswitch-die-x86_64.so

java -cp ".:snc-1.0.0.jar:<deps>" com.example.App
```

`DllLoader` automatically loads from the JAR's sibling directory.

---

## 10. Native Library File Inventory and Naming Convention

### 10.1 Native Library Inventory

| File Name | Purpose | Platform |
|---|---|---|
| `libubswitch.dll` | ECMP port-selection hash | Windows |
| `libubswitch-die.dll` | NPU uplink port-selection hash | Windows |
| `libubswitch-x86_64.so` | ECMP port-selection hash | Linux x86_64 |
| `libubswitch-die-x86_64.so` | NPU uplink port-selection hash | Linux x86_64 |
| `libubswitch-aarch64.so` | ECMP port-selection hash | Linux aarch64 |
| `libubswitch-die-aarch64.so` | NPU uplink port-selection hash | Linux aarch64 |

### 10.2 Source C Files

| C Source File | Corresponding Native Library | Corresponding Java Method |
|---|---|---|
| `ubswitch_ecmp.c` | `libubswitch.{dll,so}` | `UbSwitchHash.ubswitchHashEcmp()` |
| `ubswitch_dieEcmp.c` | `libubswitch-die.{dll,so}` | `UbSwitchHash.ubswitchHashDieEcmp()` |

### 10.3 Compiling Native Libraries (Reference)

**Windows (MinGW)**:
```bash
x86_64-w64-mingw32-gcc -shared -o libubswitch.dll ubswitch_ecmp.c -Wl,--kill-at
x86_64-w64-mingw32-gcc -shared -o libubswitch-die.dll ubswitch_dieEcmp.c -Wl,--kill-at
```

**Linux x86_64**:
```bash
gcc -shared -fPIC -o libubswitch-x86_64.so ubswitch_ecmp.c
gcc -shared -fPIC -o libubswitch-die-x86_64.so ubswitch_dieEcmp.c
```

**Linux aarch64 (cross-compile)**:
```bash
aarch64-linux-gnu-gcc -shared -fPIC -o libubswitch-aarch64.so ubswitch_ecmp.c
aarch64-linux-gnu-gcc -shared -fPIC -o libubswitch-die-aarch64.so ubswitch_dieEcmp.c
```

---

## 11. Key Java File Descriptions

### 11.1 `HashUtils.java`

**Path**: `src/snc/src/main/java/com/huawei/umdk/snc/util/HashUtils.java`

**Responsibilities**:
- Provides two public entry points: `nativeHash(...)` and `nativeHashDstCnaJetty(...)`
- Static initializer loads native libraries (success or failure does not affect class initialization)
- At runtime, selects native library or fallback based on whether `LIB_ECMP`/`LIB_DIE` is null

**Key method**:

```java
public static int nativeHash(String dip, String sip, int dport, int sport,
                             int ethertype, int protocol, int offset,
                             int ecmpCnt, int hashFunc, int hashSeed) {
    int mappedFunc = mapHashMode(hashFunc);              // map first for dual-path consistency
    if (LIB_ECMP != null) {
        int rawHash = LIB_ECMP.ubswitch_Hash_ecmp(...);  // native library
        return (ecmpCnt == 0) ? rawHash : Math.floorMod(rawHash, ecmpCnt);
    }
    return UbSwitchHash.ubswitchHashEcmp(...);            // Java fallback
}
```

### 11.2 `UbSwitchHash.java`

**Path**: `src/snc/src/main/java/com/huawei/umdk/snc/util/UbSwitchHash.java`

**Responsibilities**:
- Provides two static methods: `ubswitchHashEcmp()` and `ubswitchHashDieEcmp()`
- Pure-Java implementation of the C source algorithm logic
- Bit-for-bit equivalent to the native library

**Key porting pitfalls**:

| C Construct | Java Equivalent | Note |
|---|---|---|
| `unsigned int h` overflow | `int h` natural overflow | Java int overflow wraparound matches C uint32 low 32 bits |
| `unsigned int >> 2` | `int >>> 2` | **Must use `>>>`**; `>>` is arithmetic shift and sign-extends |
| `unsigned char crc` truncation | `(crc << 1) & 0xFF` | C's unsigned char auto-truncates; Java needs explicit `& 0xFF` |
| `uint32_t >> 24` | `int >>> 24` | Must also use `>>>` |
| `int h % ecmp_cnt` negative correction | `r < 0 ? r + ecmpCnt : r` | Java `%` may return negative; correction needed |
| `const char *` iterated to `\0` | `String.charAt` iteration | C uses NUL termination; Java uses length |

### 11.3 `DllLoader.java`

**Path**: `src/snc/src/main/java/com/huawei/umdk/snc/util/DllLoader.java`

**Responsibilities**:
- Provides the `load(dllName, interfaceClass)` static method
- Searches for native libraries in order; loads via JNA if found, returns null if not (caller falls back)
- Supports extracting native libraries from the classpath to a temp directory (for JAR-embedded scenarios; currently not enabled)

### 11.4 `UbSwitchHashTest.java`

**Path**: `test/snc/java/com/huawei/umdk/snc/util/UbSwitchHashTest.java`

**Responsibilities**:
- 10 unit tests covering all branches of both hash algorithms
- Includes independent reference implementations (CRC-8/ATM, FNV-1a, simple accumulator) for comparison
- Verifies boundaries: `ecmpCnt=0`, `functionSelect` not 0/1, null inputs, etc.

---

## 12. Troubleshooting

### 12.1 Symptom: stderr outputs "Failed to load native library"

**Cause**: Native library not found, or loading failed (architecture mismatch, missing dependencies, etc.)

**Troubleshooting steps**:
1. Confirm whether the native library is needed (if not, ignore this output and use fallback)
2. If needed, check that the file name matches the platform (see §10.1)
3. Check that the file is in a `DllLoader` search path (see §3.4)
4. View the full stack trace: `t.printStackTrace(System.err)` output

### 12.2 Symptom: JAR run reports `UnsatisfiedLinkError`

**Cause**: JNA found the native library but the symbol does not exist (not exported at compile time, or function name is wrong)

**Troubleshooting**:
- Windows: use `dumpbin /exports libubswitch.dll` to check exported symbols
- Linux: use `nm -D libubswitch-x86_64.so` to check exported symbols
- `ubswitch_Hash_ecmp` and `ubswitch_Hash_dieEcmp` should be present

### 12.3 Symptom: Native library results differ from Java fallback

**Expected**: The two should be identical. If they differ, possible causes:
1. Native library version does not match the C source (recompile the native library)
2. `mapHashMode` was not applied uniformly before both paths (check `HashUtils` code)
3. Java port has a bug (run `UbSwitchHashTest` unit tests to verify)

### 12.4 Symptom: Test fails but no "Failed to load" output

**Explanation**: Native library loaded successfully; the test failure is unrelated to native libraries. Troubleshoot as a normal test failure (see `SNC Test Execution Guide.md` Chapter 6).

---

## 13. Appendix

### 13.1 Change Inventory (This De-dependency Refactor)

| Operation | File | Description |
|---|---|---|
| Created | `src/snc/src/main/java/com/huawei/umdk/snc/util/UbSwitchHash.java` | Pure-Java hash implementation |
| Modified | `src/snc/src/main/java/com/huawei/umdk/snc/util/HashUtils.java` | Added fallback branches |
| Deleted | `src/snc/src/main/resources/libubswitch*.dll` | Windows native libraries |
| Deleted | `src/snc/src/main/resources/libubswitch*.so` | Linux native libraries |
| Created | `test/snc/java/com/huawei/umdk/snc/util/UbSwitchHashTest.java` | Unit tests |
| Unchanged | `src/snc/src/main/java/com/huawei/umdk/snc/util/DllLoader.java` | Search paths already support JAR sibling |

### 13.2 Test Verification Results

```
[INFO] Tests run: 496, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

Includes 10 `UbSwitchHashTest` unit tests covering:
- ECMP hash: simple branch, FNV-1a branch, modulo, null inputs
- DIE hash: functionSelect boundary, CRC8 reference comparison, modulo

### 13.3 Reference Documents

- `SNC Test Execution Guide.md` — SNC module test execution guide
- `SNC Framework Architecture Design.md` — SNC framework architecture design
- `SNC Test Specification.md` — SNC test specification

### 13.4 Glossary

| Term | Meaning |
|---|---|
| ECMP | Equal-Cost Multi-Path; load balancing across equal-cost paths |
| CNA | Customer Network Address |
| L1SW | Level 1 Switch |
| L2SW | Level 2 Switch |
| NPU | Network Processing Unit |
| JNA | Java Native Access; access native code without writing JNI |
| FNV-1a | Fowler-Noll-Vo 1a hash algorithm |
| CRC-8/ATM | 8-bit CRC using the ATM HEC polynomial (0x07) |
| fallback | Fallback mechanism; uses an alternate implementation when the primary is unavailable |
