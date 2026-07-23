# SNC 模块测试执行

## 1. 运行环境

| 项目 | 版本 |
|------|------|
| JDK | 21+ |
| Maven | 3.8+ |
| 操作系统 | Windows / Linux |
| 构建工具 | Maven (pom.xml 已配置 JUnit 5.9.2 / JaCoCo 0.8.12 / Surefire 3.2.2) |

---

## 2. 执行全部测试

在 `src/snc` 目录下执行：

```bash
mvn test
```

输出示例：

```
Tests run: 498, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

---

## 3. 执行单个测试类

```bash
# 全量测试 + 覆盖率报告
mvn clean test

# 指定测试类
mvn test -Dtest=SNCServiceIntegrationTest

# 通配符匹配
mvn test -Dtest=*Service*

# 指定包下所有测试
mvn test -Dtest="com.huawei.umdk.snc.service.*"

# 跳过测试编译
mvn compile -DskipTests
```

---

## 4. 生成覆盖率报告

执行测试后自动生成 JaCoCo 覆盖率报告：

```bash
mvn test
```

报告路径：
```
target/site/jacoco/index.html
```

直接在浏览器打开 `index.html` 即可查看覆盖率详情。

---

## 5. 跳过测试（打包场景）

```bash
# 跳过测试编译打包
mvn package -DskipTests

# 跳过测试执行但编译测试
mvn package -Dmaven.test.skip=true
```

---

## 6. 常见问题排查

### 6.1 测试失败 — 检查点

- JSON 测试资源文件是否存在（`src/test/resources/`）
- ACL JSON 中的 EID/CNA 是否与拓扑 JSON 匹配
- 端口名称是否在拓扑数据中定义
- 路由前缀是否与 `cnaToTargetAddr()` 结果一致（`/32` 精确匹配要求）

### 6.2 编译失败

```bash
mvn clean compile test-compile
```

清除 target 目录后重新编译。

### 6.3 JaCoCo 报告未生成

确认 `pom.xml` 中存在 jacoco 插件配置：
```xml
<plugin>
    <groupId>org.jacoco</groupId>
    <artifactId>jacoco-maven-plugin</artifactId>
    <version>0.8.12</version>
    ...
</plugin>
```

### 6.4 注意事项

1. **测试顺序无关**：每个测试类独立，不依赖其他测试的副作用
2. **测试数据独立**：每个测试方法创建自己的测试数据，不共享可变对象
3. **无 Mock 框架**：当前阶段使用纯 JUnit 5，store/engine 通过构造器注入
4. **JSON 工具只读**：JSON 测试数据不可被测试修改
