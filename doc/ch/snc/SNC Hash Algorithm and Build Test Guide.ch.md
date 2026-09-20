# SNC Hash 算法与构建测试指南

## 1. 文档目的与适用范围

本文件描述 SNC 模块中 ECMP 选口哈希算法的设计、纯 Java 实现与原生库实现的协同关系，并详细说明在以下场景中的构建、打包、测试流程与底层原理：

- 不带原生可执行文件的源码构建
- 带原生可执行文件的源码构建
- 打 jar 包流程
- 测试人员拿到 jar 包后的使用流程（带 / 不带原生库两种子场景）
- CI 流水线场景

适用读者：开发者、测试人员、CI 流水线维护人员、生产部署人员。

---

## 2. 哈希算法设计

SNC 模块包含两个 ECMP 选口哈希入口，用于在不同设备层做负载均衡选口：

### 2.1 `ubswitch_Hash_ecmp` — 跨机箱选口哈希

**用途**：L1SW↔L2SW（跨机箱）和 L1SW→NPU 选口，基于五元组 `(dip, sip, dport, sport, protocol)`。

**算法分支**（由 `hash_func` 参数选择）：

| `hash_func` | 算法 | 说明 |
|---|---|---|
| `1` | FNV-1a | offset basis `2166136261`（`0x811C9DC5`），prime `16777619`，对 dip/sip 逐字节 `(h^=b)*=p`，对 dport/sport/protocol/hash_func 调用 `mix` 混合 |
| 其他 | 简单累加 | `h = h*31 + b` 逐字节累加 dip/sip/ports/protocol/hash_func |

**取模规则**：
- `ecmp_cnt == 0` 返回原始哈希值（32 位带符号）
- `ecmp_cnt > 0` 返回 `floorMod(h, ecmp_cnt)`，结果非负

**常量含义**：所有数值（`0x811C9DC5`、`16777619`、`0x9e3779b9`、`31`）均为公开算法常量，不是密码学盐。`0x9e3779b9` 是黄金分割常数（Knuth multiplicative hash），`31` 是 Java `String.hashCode()` 使用的素数乘子。

### 2.2 `ubswitch_Hash_dieEcmp` — NPU 上行选口哈希

**用途**：NPU→L1SW 上行选口，基于 `(dst_cna, jetty_id)` 二元组。

**算法**：CRC-8/ATM（polynomial `0x07`，init `0x00`，无反射，无最终 XOR），对 9 字节流 `{src_cna[4 BE], dst_cna[4 BE], lb[1]}` 计算 CRC，其中 `src_cna` 固定为 0，`lb` 是 jetty id 低 8 位。

**参数约束**：
- `function_select ∈ {0, 1}` 均选择 CRC-8/ATM；其他值返回 `-1`
- `ecmp_cnt == 0` 返回原始 CRC（0..255）
- `ecmp_cnt > 0` 返回 `crc % ecmp_cnt`，结果非负（CRC 本身非负，无需补正）

### 2.3 双实现等价性

两个算法各有两种实现：原生库（C 编译的 `.dll`/`.so`）与纯 Java（`UbSwitchHash.java`）。**两者算法逻辑逐位等价**，已通过单元测试验证（`UbSwitchHashTest` 含独立参考实现对比）。

---

## 3. 原生库与纯 Java 实现的协同设计

### 3.1 总体架构

```
┌─────────────────────────────────────────────────────────────┐
│                    HashUtils.java（入口）                    │
│                                                             │
│  nativeHash(...) ──────┐                                    │
│                        ▼                                    │
│              ┌──────────────────────┐                       │
│              │ LIB_ECMP != null ?  │                       │
│              └──────────┬───────────┘                       │
│                    │        │                              │
│                   是        否                              │
│                    ▼        ▼                              │
│         ┌─────────────┐  ┌─────────────────────┐            │
│         │ JNA 原生库   │  │ UbSwitchHash        │（fallback）│
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
│                             是        否                     │
│                              ▼        ▼                     │
│                   ┌─────────────┐  ┌─────────────────────┐  │
│                   │ JNA 原生库   │  │ UbSwitchHash        │ │
│                   │ ubswitch_    │  │ .ubswitchHashDieEcmp│ │
│                   │ Hash_dieEcmp │  │ ()                  │ │
│                   └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 设计原则

1. **原生库优先**：若 JNA 成功加载原生库，优先使用原生实现（与历史行为一致，便于原生库替换调试）
2. **Java fallback**：若原生库加载失败，自动回落到 `UbSwitchHash` 纯 Java 实现，结果等价
3. **静默降级**：fallback 时不抛异常，仅向 stderr 输出加载失败诊断信息
4. **零行为差异**：两条路径对同一输入返回相同结果（`mapHashMode` 在两条路径前统一应用）

### 3.3 `mapHashMode` 的重要性

`HashUtils.mapHashMode()` 是个 1↔6 互换映射：

```java
private static int mapHashMode(int hashFunc) {
    if(hashFunc == 1) return 6;
    if(hashFunc == 6) return 1;
    return hashFunc;
}
```

**关键约束**：`mapHashMode` 必须在 **两条路径调用前** 统一应用，不能只在原生路径应用。当前实现已遵守此约束：

```java
int mappedFunc = mapHashMode(hashFunc);   // ← 先映射
if (LIB_ECMP != null) {
    LIB_ECMP.ubswitch_Hash_ecmp(..., mappedFunc, ...);    // 原生路径用 mappedFunc
}
return UbSwitchHash.ubswitchHashEcmp(..., mappedFunc, ...); // fallback 路径也用 mappedFunc
```

### 3.4 `DllLoader` 原生库搜索顺序

`DllLoader.buildSearchPaths()` 按以下顺序搜索原生库：

| 序号 | 搜索路径 | 来源 | 说明 |
|---|---|---|---|
| 1 | `jna.library.path` | `-D` JVM 参数 | 用户显式指定，优先级最高 |
| 2 | `src/main/resources` | 硬编码 | 开发期 / 单元测试场景 |
| 3 | `user.dir` | 系统属性 | 当前工作目录 |
| 4 | **jar 同级目录** | `getApplicationDir()` | **测试人员/生产部署的关键路径** |
| 5 | `target` | 硬编码 | Maven 构建产物目录 |
| 6 | `target/classes` | 硬编码 | Maven class 输出目录 |
| 7 | classpath 提取 | `extractFromClasspath()` | 从 jar 内提取到临时目录 |
| 8 | 裸名加载 | `Native.load(name)` | 委托 JNA 系统路径搜索 |

**`getApplicationDir()` 的关键逻辑**：
```java
URL location = DllLoader.class.getProtectionDomain().getCodeSource().getLocation();
File file = new File(location.toURI());
if (file.isFile()) {
    return file.getParent();   // ← 从 jar 运行时返回 jar 父目录
}
return file.getAbsolutePath();  // ← 从 class 目录运行时返回该目录
```

---

## 4. 不带原生可执行文件的源码构建

### 4.1 适用场景

- 标准开发流程，开发者本地不需要原生库
- CI 流水线从源码拉取并跑测试
- 任何不依赖原生库的环境

### 4.2 目录布局

```
umdk/
└── src/
    └── snc/
        ├── pom.xml
        ├── src/main/java/.../util/
        │   ├── HashUtils.java
        │   ├── UbSwitchHash.java        ← 纯 Java 实现
        │   ├── DllLoader.java
        │   └── AddressUtils.java
        ├── src/main/resources/
        │   ├── 128_npu_inter_rack.json  ← 保留（拓扑数据）
        │   └── 128_npu_rack.json        ← 保留（拓扑数据）
        └── test/...                     ← 测试代码
```

**注意**：`src/main/resources/` 下**不含**任何原生库文件（`.dll`/`.so`）。

### 4.3 构建命令

```bash
cd umdk/src/snc
mvn clean test
```

### 4.4 执行原理

1. **JVM 启动**：Maven Surefire 启动 JVM，加载 SNC 类
2. **`HashUtils` 静态块执行**：
   - `DllLoader.load("libubswitch.dll", ...)` 被调用
   - `buildSearchPaths()` 顺序搜索：`jna.library.path`(未设) → `src/main/resources`(无库) → `user.dir`(无库) → `getApplicationDir()`=target/classes(无库) → `target`/`target/classes`(无库) → `extractFromClasspath`(无库) → `Native.load("libubswitch.dll")`(系统路径，大概率失败)
   - 加载失败 → stderr 输出 `[HashUtils] Failed to load native library 'libubswitch.dll': ...`
   - `LIB_ECMP = null`、`LIB_DIE = null`
3. **测试调用 `HashUtils.nativeHash(...)`**：
   - 检测到 `LIB_ECMP == null` → 调用 `UbSwitchHash.ubswitchHashEcmp(...)` 执行
4. **测试调用 `HashUtils.nativeHashDstCnaJetty(...)`**：
   - 检测到 `LIB_DIE == null` → 调用 `UbSwitchHash.ubswitchHashDieEcmp(...)` 执行

### 4.5 预期输出

```
[HashUtils] Failed to load native library 'libubswitch.dll': ...
[HashUtils] Failed to load native library 'libubswitch-die.dll': ...
...
[INFO] Tests run: 496, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

stderr 中的"Failed to load"是**预期行为**，不影响测试通过。

### 4.6 优势

- ✅ 无需维护多平台原生库
- ✅ 无环境差异（结果完全由 Java 代码决定）
- ✅ CI 稳定（不依赖机器是否预装原生库）
- ✅ 跨平台一致（Windows/Linux/x86_64/aarch64 结果相同）

---

## 5. 带原生可执行文件的源码构建

### 5.1 适用场景

- 需要验证新版本原生库行为
- 性能对比测试
- 原生库特性调试

### 5.2 准备原生库

将对应平台的原生库放在任意目录，例如 `umdk/native-libs/`：

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

### 5.3 原生库文件命名规则

`HashUtils.detectNativeLibraryName()` 根据平台自动选择文件名：

| 平台 | ECMP 库名 | DIE 库名 |
|---|---|---|
| Windows | `libubswitch.dll` | `libubswitch-die.dll` |
| Linux x86_64 | `libubswitch-x86_64.so` | `libubswitch-die-x86_64.so` |
| Linux aarch64 | `libubswitch-aarch64.so` | `libubswitch-die-aarch64.so` |

**必须使用上述精确文件名**，否则 JNA 找不到。

### 5.4 构建命令

**方式 A：通过 `-D` 参数指定**（推荐）：

```bash
cd umdk/src/snc
mvn clean test -Djna.library.path=../../native-libs
```

`pom.xml` 已配置 `jna.library.path` 系统属性桥接（`<jna.library.path>${native.lib.dir}</jna.library.path>`），也可使用 Maven 属性：

```bash
mvn clean test -Dnative.lib.dir=../../native-libs
```

**方式 B：放工作目录**：

```bash
cd umdk/native-libs
mvn -f ../src/snc clean test
# user.dir=umdk/native-libs，DllLoader 会搜索到原生库
```

**方式 C：放 `src/main/resources`**（恢复历史行为）：

```bash
cp native-libs/* umdk/src/snc/src/main/resources/
cd umdk/src/snc
mvn clean test
```

### 5.5 执行原理

以方式 A 为例：

1. **JVM 启动**：`-Djna.library.path=../../native-libs` 设置系统属性
2. **`HashUtils` 静态块执行**：
   - `DllLoader.load()` 调用
   - `buildSearchPaths()` 第一项就是 `jna.library.path` = `../../native-libs`
   - `findDllPath()` 在该目录找到 `libubswitch.dll` → 返回绝对路径
   - 设置 `jna.library.path` 为该目录（确保 JNA 后续加载依赖也能找到）
   - `Native.load(absolutePath, ...)` 成功加载
   - `LIB_ECMP != null`、`LIB_DIE != null`
3. **测试调用 `HashUtils.nativeHash(...)`**：
   - 检测到 `LIB_ECMP != null` → 调用 JNA 接口 `LIB_ECMP.ubswitch_Hash_ecmp(...)` 执行
4. **测试调用 `HashUtils.nativeHashDstCnaJetty(...)`**：
   - 检测到 `LIB_DIE != null` → 调用 JNA 接口 `LIB_DIE.ubswitch_Hash_dieEcmp(...)` 执行

### 5.6 预期输出

```
[INFO] Tests run: 496, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

stderr 中**无** "Failed to load" 输出（因为加载成功）。

### 5.7 验证是否走了原生库

```bash
mvn test 2>stderr.log
grep "Failed to load" stderr.log
# 无输出 = 原生库加载成功，走原生路径
# 有输出 = 加载失败，走 fallback
```

---

## 6. 打 jar 包流程

### 6.1 标准打包命令

```bash
cd umdk/src/snc
mvn clean package
```

### 6.2 产物

```
umdk/src/snc/target/
├── snc-1.0.0.jar              ← 主 jar 包（不含原生库）
├── snc-1.0.0.jar.sha256
└── original-snc-1.0.0.jar      ← shade 前的原始 jar（如有 shade 插件）
```

### 6.3 jar 包内容

```
snc-1.0.0.jar
├── com/huawei/umdk/snc/
│   ├── util/
│   │   ├── HashUtils.class
│   │   ├── UbSwitchHash.class    ← 纯 Java fallback 实现已编译进 jar
│   │   ├── DllLoader.class
│   │   └── AddressUtils.class
│   └── ... 其他业务类
└── 128_npu_inter_rack.json       ← 拓扑数据资源（保留）
    128_npu_rack.json             ← 拓扑数据资源（保留）
```

**关键特性**：
- ✅ jar 包**不含**原生库（`.dll`/`.so`）
- ✅ jar 包**包含** `UbSwitchHash.class`（纯 Java fallback 已编入）
- ✅ jar 包**包含** 拓扑 JSON 资源

### 6.4 跳过测试快速打包

```bash
mvn clean package -DskipTests
```

### 6.5 验证 jar 包可独立加载

```bash
cd umdk/src/snc/target
# 列出 jar 内容，确认 UbSwitchHash.class 与拓扑 JSON 资源已编入
jar tf snc-1.0.0.jar | grep -E "UbSwitchHash|128_npu"
# 预期输出：
#   com/huawei/umdk/snc/util/UbSwitchHash.class
#   128_npu_inter_rack.json
#   128_npu_rack.json

# 确认 jar 内不含原生库（.dll/.so）
jar tf snc-1.0.0.jar | grep -E "\.(dll|so)$"
# 预期输出：（空，不含原生库）
```

> **说明**：`snc-1.0.0.jar` 是库 jar 包（manifest 无 `Main-Class`），不能 `java -jar` 直接运行。运行时需以 `-cp` 方式加载并由调用方代码（main 类）驱动，第三方依赖（JNA 等）由调用方环境提供。详见第 7 章。

### 6.6 打包时附带头原生库（可选）

若需要 jar 包与原生库一起分发，使用以下任一方式：

**方式 A：zip 打包**

```bash
cd umdk/src/snc/target
mkdir -p dist
cp snc-1.0.0.jar dist/
cp /path/to/native-libs/libubswitch*.dll dist/   # 按平台
cp /path/to/native-libs/libubswitch-die*.dll dist/
zip -r snc-dist.zip dist/
```

**方式 B：Maven Assembly 插件**（需要 `pom.xml` 配置 `maven-assembly-plugin`）

### 6.7 推荐分发方式

- **jar 包单独分发**：最简单，测试人员无原生库也能跑（走 fallback）
- **jar + native-libs 目录一起分发**：测试人员可选用原生库（见第 7 章）

---

## 7. 测试人员使用 jar 包流程

### 7.1 场景 A：jar 包单独使用（无原生库）

#### 7.1.1 目录布局

```
/opt/test/
└── snc-1.0.0.jar
```

#### 7.1.2 执行命令

`snc-1.0.0.jar` 是**库 jar 包**（manifest 无 `Main-Class`），不能直接 `java -jar` 运行，需通过调用方代码（测试程序 / 业务应用）以 `-cp` 方式加载后调用 SNC API：

```bash
cd /opt/test
# 调用方测试程序（自带 main 方法，引用 SncService API）
java -cp ".:snc-1.0.0.jar:jna-5.14.0.jar" MyTestDriver
```

其中 `MyTestDriver` 是测试人员自备的 main 类（编译时引用 `snc-1.0.0.jar`），通过 `new SncService().init(...)` → `setSuperNode(...)` → `planPathsCoverage(...)` 等方法驱动 SNC；`jna-5.14.0.jar` 等第三方依赖由调用方环境提供（设备已预装或一并分发）。

> **说明**：以下章节中若出现 `java -jar snc-1.0.0.jar` 形式，应理解为 `java -cp ".:snc-1.0.0.jar:<deps>" <MainClass>` 的简写；重点是原生库由 `DllLoader` 自动从 jar 同级目录加载，与启动方式无关。

#### 7.1.3 执行原理

1. JVM 加载 `snc-1.0.0.jar`，初始化 `HashUtils` 类
2. `HashUtils` 静态块执行 `DllLoader.load("libubswitch.dll", ...)`：
   - `getApplicationDir()` 返回 `/opt/test/`（jar 父目录）
   - `buildSearchPaths()` 顺序搜索：`jna.library.path`(未设) → `src/main/resources`(jar 内无此路径) → `user.dir`=`/opt/test/`(无库) → **`/opt/test/`**(jar 同级，无库) → `target`/`target/classes`(不存在) → `extractFromClasspath`(jar 内无原生库资源) → `Native.load("libubswitch.dll")`(系统路径无库)
   - 加载失败 → `LIB_ECMP = null`、`LIB_DIE = null`
3. 业务代码调用 `HashUtils.nativeHash(...)`：
   - 检测 `LIB_ECMP == null` → 调用 `UbSwitchHash.ubswitchHashEcmp(...)` 执行
4. 业务代码调用 `HashUtils.nativeHashDstCnaJetty(...)`：
   - 检测 `LIB_DIE == null` → 调用 `UbSwitchHash.ubswitchHashDieEcmp(...)` 执行

#### 7.1.4 预期行为

- ✅ 程序正常运行
- ✅ 哈希结果与原生库**完全一致**（算法逐位等价）
- ⚠️ stderr 输出 "Failed to load native library" 诊断信息（**预期行为，非错误**）
- ⚠️ 性能略低于原生库（纯 Java 解释执行，但 ECMP 选口场景无感知差异）

### 7.2 场景 B：jar 包 + 原生库

#### 7.2.1 目录布局

```
/opt/test/
├── snc-1.0.0.jar
├── libubswitch.dll              ← 按平台选择（Windows）
└── libubswitch-die.dll          ← 按平台选择（Windows）
```

或 Linux x86_64：

```
/opt/test/
├── snc-1.0.0.jar
├── libubswitch-x86_64.so
└── libubswitch-die-x86_64.so
```

#### 7.2.2 执行命令

```bash
cd /opt/test
java -cp ".:snc-1.0.0.jar:jna-5.14.0.jar" MyTestDriver
```

无需任何 `-D` 参数，`DllLoader` 自动从 jar 同级目录找到原生库。

#### 7.2.3 执行原理

1. JVM 加载 `snc-1.0.0.jar`
2. `HashUtils` 静态块执行 `DllLoader.load("libubswitch.dll", ...)`：
   - `getApplicationDir()` 返回 `/opt/test/`（jar 父目录）
   - `buildSearchPaths()` 第 4 项就是 `/opt/test/`
   - `findDllPath()` 在 `/opt/test/` 找到 `libubswitch.dll` → 返回 `/opt/test/libubswitch.dll`
   - 设置 `jna.library.path` = `/opt/test/`
   - `Native.load("/opt/test/libubswitch.dll", ...)` 成功加载
   - `LIB_ECMP != null`、`LIB_DIE != null`
3. 业务代码调用 `HashUtils.nativeHash(...)`：
   - 检测 `LIB_ECMP != null` → 调用 JNA 接口 `LIB_ECMP.ubswitch_Hash_ecmp(...)` 执行

#### 7.2.4 预期行为

- ✅ 程序正常运行
- ✅ 哈希结果与场景 A 完全一致
- ✅ stderr 无 "Failed to load" 输出（加载成功）
- ✅ 性能略高于场景 A（原生库执行，但实际无感知差异）

### 7.3 场景 C：原生库放任意目录

#### 7.3.1 目录布局

```
/home/tester/
├── snc-1.0.0.jar
└── libs/                       ← 自定义目录
    ├── libubswitch.dll
    └── libubswitch-die.dll
```

#### 7.3.2 执行命令

```bash
cd /home/tester
java -Djna.library.path=/home/tester/libs -jar snc-1.0.0.jar
```

#### 7.3.3 执行原理

`-Djna.library.path` 优先级最高（`buildSearchPaths()` 第 1 项），`DllLoader` 首先在该路径搜索，找到即加载。

### 7.4 替换原生库的流程

测试人员想验证新版本原生库时：

1. 备份现有原生库（可选）
2. 将新原生库放到 jar 同级目录，**覆盖**旧文件
3. 确认文件名与平台匹配（见 5.3 节）
4. 重启 JVM 运行程序
5. 验证加载是否成功：检查 stderr 是否有 "Failed to load" 输出

### 7.5 验证测试是否使用原生库

```bash
# 运行程序，将 stderr 重定向
java -cp ".:snc-1.0.0.jar:jna-5.14.0.jar" MyTestDriver 2>stderr.log

# 检查
grep "Failed to load" stderr.log
# 无输出 = 原生库加载成功
# 有输出 = 加载失败，走 fallback
```

### 7.6 测试场景对照表

| 测试目的 | 目录布局 | 命令 | 预期 |
|---|---|---|---|
| 验证 Java fallback | 仅 jar 包 | `java -cp ".:snc-1.0.0.jar:<deps>" MyTestDriver` | stderr 有 "Failed to load"，结果正确 |
| 验证原生库 | jar + 原生库 | `java -cp ".:snc-1.0.0.jar:<deps>" MyTestDriver` | stderr 无错误，结果正确 |
| 验证替换原生库 | jar + 新原生库（覆盖旧） | `java -cp ".:snc-1.0.0.jar:<deps>" MyTestDriver` | stderr 无错误，结果按新库 |
| 双路径一致性 | 同机器先后跑 | 对比两次结果 | 结果完全一致 |

> `<deps>` 为调用方环境提供的第三方依赖（如 `jna-5.14.0.jar`），`MyTestDriver` 为调用方自带 main 类。

---

## 8. CI 流水线场景

### 8.1 标准 CI 命令

```bash
# 拉取源码后执行
cd umdk/src/snc
mvn clean test
```

### 8.2 执行原理

与第 4 章"不带原生可执行文件的源码构建"完全相同：
1. CI 机器无原生库
2. `DllLoader` 所有搜索路径都找不到原生库
3. `LIB_ECMP = null`、`LIB_DIE = null`
4. 自动走 Java fallback

### 8.3 关键优势

- ✅ **CI 环境一致性**：不依赖 CI 机器是否预装原生库
- ✅ **跨平台一致**：CI 跑在 x86_64 / aarch64 / Windows / Linux 结果完全相同
- ✅ **稳定可复现**：结果由源码决定，与历史构建可对比

### 8.4 CI 验证原生库（可选）

若 CI 需要回归验证原生库行为：

```bash
# CI 脚本中预先准备原生库到 native-libs/ 目录
mvn clean test -Djna.library.path=native-libs
```

---

## 9. 生产部署场景

### 9.1 推荐方式：jar 包单独部署

```bash
# 生产服务器
/opt/app/
└── snc-1.0.0.jar

java -cp ".:snc-1.0.0.jar:<deps>" com.example.App
```

**理由**：
- 简化部署（单个 jar 包）
- 跨平台一致
- 无原生库依赖，升级 JDK/OS 无需重新编译原生库
- Java fallback 性能在 ECMP 选口场景完全够用

### 9.2 高性能场景：jar + 原生库

```bash
/opt/app/
├── snc-1.0.0.jar
├── libubswitch-x86_64.so       # 按生产平台
└── libubswitch-die-x86_64.so

java -cp ".:snc-1.0.0.jar:<deps>" com.example.App
```

`DllLoader` 自动从 jar 同级目录加载。

---

## 10. 原生库文件清单与命名规范

### 10.1 原生库清单

| 文件名 | 用途 | 平台 |
|---|---|---|
| `libubswitch.dll` | ECMP 选口哈希 | Windows |
| `libubswitch-die.dll` | NPU 上行选口哈希 | Windows |
| `libubswitch-x86_64.so` | ECMP 选口哈希 | Linux x86_64 |
| `libubswitch-die-x86_64.so` | NPU 上行选口哈希 | Linux x86_64 |
| `libubswitch-aarch64.so` | ECMP 选口哈希 | Linux aarch64 |
| `libubswitch-die-aarch64.so` | NPU 上行选口哈希 | Linux aarch64 |

### 10.2 源 C 文件

| C 源文件 | 对应原生库 | 对应 Java 方法 |
|---|---|---|
| `ubswitch_ecmp.c` | `libubswitch.{dll,so}` | `UbSwitchHash.ubswitchHashEcmp()` |
| `ubswitch_dieEcmp.c` | `libubswitch-die.{dll,so}` | `UbSwitchHash.ubswitchHashDieEcmp()` |

### 10.3 编译原生库（参考）

**Windows（MinGW）**：
```bash
x86_64-w64-mingw32-gcc -shared -o libubswitch.dll ubswitch_ecmp.c -Wl,--kill-at
x86_64-w64-mingw32-gcc -shared -o libubswitch-die.dll ubswitch_dieEcmp.c -Wl,--kill-at
```

**Linux x86_64**：
```bash
gcc -shared -fPIC -o libubswitch-x86_64.so ubswitch_ecmp.c
gcc -shared -fPIC -o libubswitch-die-x86_64.so ubswitch_dieEcmp.c
```

**Linux aarch64（交叉编译）**：
```bash
aarch64-linux-gnu-gcc -shared -fPIC -o libubswitch-aarch64.so ubswitch_ecmp.c
aarch64-linux-gnu-gcc -shared -fPIC -o libubswitch-die-aarch64.so ubswitch_dieEcmp.c
```

---

## 11. 关键 Java 文件说明

### 11.1 `HashUtils.java`

**路径**：`src/snc/src/main/java/com/huawei/umdk/snc/util/HashUtils.java`

**职责**：
- 提供两个公开入口 `nativeHash(...)` 和 `nativeHashDstCnaJetty(...)`
- 静态块加载原生库（成功或失败都不影响类初始化）
- 运行时根据 `LIB_ECMP`/`LIB_DIE` 是否为 null 选择走原生库或 fallback

**关键方法**：

```java
public static int nativeHash(String dip, String sip, int dport, int sport,
                             int ethertype, int protocol, int offset,
                             int ecmpCnt, int hashFunc, int hashSeed) {
    int mappedFunc = mapHashMode(hashFunc);              // 先映射，保证双路径一致
    if (LIB_ECMP != null) {
        int rawHash = LIB_ECMP.ubswitch_Hash_ecmp(...);  // 原生库
        return (ecmpCnt == 0) ? rawHash : Math.floorMod(rawHash, ecmpCnt);
    }
    return UbSwitchHash.ubswitchHashEcmp(...);            // Java fallback
}
```

### 11.2 `UbSwitchHash.java`

**路径**：`src/snc/src/main/java/com/huawei/umdk/snc/util/UbSwitchHash.java`

**职责**：
- 提供 `ubswitchHashEcmp()` 和 `ubswitchHashDieEcmp()` 两个静态方法
- 纯 Java 实现 C 源码的算法逻辑
- 与原生库逐位等价

**移植关键陷阱**：

| C 构造 | Java 等价 | 注意点 |
|---|---|---|
| `unsigned int h` 溢出 | `int h` 自然溢出 | Java int 溢出回绕与 C uint32 低 32 位一致 |
| `unsigned int >> 2` | `int >>> 2` | **必须用 `>>>`**，`>>` 是算术右移会补符号位 |
| `unsigned char crc` 截断 | `(crc << 1) & 0xFF` | C 的 unsigned char 自动截断，Java 需手动 `& 0xFF` |
| `uint32_t >> 24` | `int >>> 24` | 同样必须用 `>>>` |
| `int h % ecmp_cnt` 负数补正 | `r < 0 ? r + ecmpCnt : r` | Java `%` 可能返回负数，需补正 |
| `const char *` 遍历到 `\0` | `String.charAt` 遍历 | C 用 NUL 结尾，Java 用 length |

### 11.3 `DllLoader.java`

**路径**：`src/snc/src/main/java/com/huawei/umdk/snc/util/DllLoader.java`

**职责**：
- 提供 `load(dllName, interfaceClass)` 静态方法
- 按搜索顺序查找原生库，找到则 JNA 加载，找不到返回 null（由调用方走 fallback）
- 支持从 classpath 提取原生库到临时目录（用于 jar 内打包场景，当前未启用）

### 11.4 `UbSwitchHashTest.java`

**路径**：`test/snc/java/com/huawei/umdk/snc/util/UbSwitchHashTest.java`

**职责**：
- 10 个单元测试覆盖两个哈希算法的所有分支
- 含独立参考实现（CRC-8/ATM、FNV-1a、simple 累加）用于对比
- 验证边界：`ecmpCnt=0`、`functionSelect` 非 0/1、null 入参等

---

## 12. 故障排查

### 12.1 现象：stderr 输出 "Failed to load native library"

**原因**：原生库未找到，或加载失败（架构不匹配、依赖缺失等）

**排查步骤**：
1. 确认是否需要原生库（不需要则忽略此输出，走 fallback 即可）
2. 如需原生库，检查文件名是否匹配平台（见 10.1 节）
3. 检查文件是否在 `DllLoader` 搜索路径中（见 3.4 节）
4. 查看完整堆栈：`t.printStackTrace(System.err)` 输出

### 12.2 现象：jar 包运行报 `UnsatisfiedLinkError`

**原因**：JNA 找到了原生库但符号不存在（编译时未导出，或函数名错误）

**排查**：
- Windows：用 `dumpbin /exports libubswitch.dll` 检查导出符号
- Linux：用 `nm -D libubswitch-x86_64.so` 检查导出符号
- 应存在 `ubswitch_Hash_ecmp` 和 `ubswitch_Hash_dieEcmp`

### 12.3 现象：原生库结果与 Java fallback 不一致

**预期**：两者应完全一致。若不一致，可能原因：
1. 原生库版本与 C 源码不一致（重新编译原生库）
2. `mapHashMode` 未在两条路径前统一应用（检查 `HashUtils` 代码）
3. Java 移植存在 bug（运行 `UbSwitchHashTest` 单测验证）

### 12.4 现象：测试失败但无 "Failed to load" 输出

**说明**：原生库加载成功，测试失败与原生库无关，按常规测试失败排查（见 `SNC Test Execution Guide.ch.md` 第 6 章）。

---

## 13. 附录

### 13.1 改动清单（本次去依赖改造）

| 操作 | 文件 | 说明 |
|---|---|---|
| 新建 | `src/snc/src/main/java/com/huawei/umdk/snc/util/UbSwitchHash.java` | 纯 Java 哈希实现 |
| 修改 | `src/snc/src/main/java/com/huawei/umdk/snc/util/HashUtils.java` | 加 fallback 分支 |
| 删除 | `src/snc/src/main/resources/libubswitch*.dll` | Windows 原生库 |
| 删除 | `src/snc/src/main/resources/libubswitch*.so` | Linux 原生库 |
| 新建 | `test/snc/java/com/huawei/umdk/snc/util/UbSwitchHashTest.java` | 单元测试 |
| 不改 | `src/snc/src/main/java/com/huawei/umdk/snc/util/DllLoader.java` | 搜索路径已支持 jar 同级 |

### 13.2 测试验证结果

```
[INFO] Tests run: 496, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

含 10 个 `UbSwitchHashTest` 单元测试，覆盖：
- ECMP 哈希：simple 分支、FNV-1a 分支、取模、null 入参
- DIE 哈希：functionSelect 边界、CRC8 参考实现对比、取模

### 13.3 参考文档

- `SNC Test Execution Guide.ch.md` — SNC 模块测试执行指南
- `SNC Framework Architecture Design.ch.md` — SNC 框架架构设计
- `SNC Test Specification.ch.md` — SNC 测试规范

### 13.4 术语表

| 术语 | 含义 |
|---|---|
| ECMP | Equal-Cost Multi-Path，等价多路径负载均衡 |
| CNA | Customer Network Address，客户网络地址 |
| L1SW | Level 1 Switch，一级交换机 |
| L2SW | Level 2 Switch，二级交换机 |
| NPU | Network Processing Unit，网络处理单元 |
| JNA | Java Native Access，Java 原生访问（无需 JNI 编写） |
| FNV-1a | Fowler-Noll-Vo 1a 哈希算法 |
| CRC-8/ATM | 8 位 CRC，ATM HEC 使用的多项式（0x07） |
| fallback | 回退机制，主实现不可用时使用备选实现 |
