---
name: urma-ut-generator
description: Generate and maintain stable URMA GTest unit tests in umdk.
---

# URMA UT 用例生成 Skill

本文件是 URMA GTest 用例生成指导。遇到下面任务时按本 skill 执行：

- 给已有 URMA 代码补充 UT。
- 给新增 URMA 代码同步补充 UT。
- 扩展 URMA mock 数据或 fixture。
- 检查 URMA UT phase 覆盖率和新增行覆盖率。

目标是生成稳定、可维护、可复用的接口级 UT，而不是为了覆盖率进入真实设备路径。

## 基线要求

所有 URMA UT 工作在本地 `master` 分支上处理。开始前先确认：

```bash
git status --short --branch
git branch --show-current
```

要求：

- 当前分支是 `master`。
- 本地 `master` 已包含正式 GTest UT 基线。
- 工作区没有未确认的其他改动。
- 如果本地 `master` 落后 `origin/master`，先同步上游再补用例。

## 通用生成规则

先判断测试对象类型，再选择对应测试边界：

- common 纯工具函数：直接构造输入并断言输出、边界、非法输入。
- core TLV/ioctl wrapper：使用 `-Wl,--wrap=ioctl` 捕获命令，不访问真实 ioctl。
- core public API：使用内存态 `urma_context_t`、`urma_device_t`、`urma_ops_t` 覆盖参数校验和 ops 返回传播。
- bond 纯逻辑：构造内存态 context、target、segment、WR、CR。
- bond 对外 API：优先覆盖非法输入、非法状态、引用计数保护、空成员集合和失败回收。

新增用例必须先查已有数据：

- command/TLV 数据优先复用 `test/urma/include/urma_cmd_mock.h`。
- bonding 路径优先复用 `BondPathFixture` 或 `BondPublicApiFixture`。
- core API 优先在 `test/urma/core/core_test.cpp` 复用或扩展本地 fixture。
- 只有已有 mock/fixture 无法表达可复用场景时，才补共享数据集。
- 一次性非法输入留在单个 test 文件内，例如 `nullptr`、`UINT32_MAX`、`dev_fd=-1`、空数组。

硬约束：

- 不 include `.c` 文件测试 static 函数。
- 不依赖 `/dev/uburma`、sysfs、netlink、真实 provider、UDMA 硬件或 `/lib64/urma/*`。
- 不为覆盖率修改生产默认行为。
- 不比较运行时绝对地址值。
- 不把不稳定真实系统路径纳入强门禁。

## 已有代码补 UT

适用场景：生产代码已经存在，需要扩大 UT 覆盖面。

执行流程：

1. 运行 `bash test/urma/script/urma_UT.sh`，查看 `phase_common`、`phase_urma_core`、`phase_urma_bond`、`phase_uvs` 摘要。
2. 优先选择低覆盖且可稳定 UT 的 public/internal header 暴露接口。
3. 先补稳定 contract：正常路径、非法输入、边界值、错误传播、引用计数、状态保护。
4. 若路径进入真实设备、sysfs、netlink、provider 或 health thread，停在外层 contract；需要更深覆盖时先设计 wrap/seam。
5. 补完用例后运行完整脚本和 `git diff --check`。

输出要求：

- 新增或修改 GTest 用例。
- 必要时补充共享 mock 数据或 fixture。
- 记录对应 phase 覆盖率变化。
- 说明仍未覆盖的真实系统边界。

## 新增代码补 UT

适用场景：本次变更新增或修改了 `src/urma` 下的生产代码。

执行流程：

1. 写生产代码前先确认新增逻辑是否可通过现有 fixture 表达。
2. 新增生产代码时同步新增或更新 UT，不允许先只提交生产逻辑。
3. 对新增分支至少覆盖：成功路径、主要失败路径、非法输入、边界值、状态不变性。
4. 对新增错误传播路径断言返回码和关键输出字段。
5. 运行 `bash test/urma/script/urma_UT.sh`，新增可执行源码行覆盖率必须 `>=90%`。

新增行覆盖率门禁：

- 脚本使用 `test/urma/script/check_diff_coverage.py` 检查新增行覆盖率。
- 默认 base 是 `git merge-base HEAD origin/master`。
- 可用 `URMA_UT_DIFF_BASE=<commit>` 覆盖 base。
- 统计范围只包含：
  - `src/urma/common`
  - `src/urma/lib/urma/core`
  - `src/urma/lib/urma/bond`
  - `src/urma/lib/uvs`
- 只统计 LCOV 可识别的新增可执行行。
- 新增行没有 LCOV 可执行记录时输出 `Diff coverage: no instrumented added lines` 并通过。
- 可执行新增行覆盖率低于 `90%` 时脚本失败，并打印未覆盖行。

## 用例模式

### 普通接口

```cpp
TEST(UrmaCommonTest, FunctionNameCoversNormalAndInvalidInput)
{
    InputType input = MakeReusableInput();

    EXPECT_EQ(EXPECTED_OK, function_under_test(&input));
    EXPECT_EQ(EXPECTED_ERR, function_under_test(nullptr));
}
```

要求：

- 测试名描述行为，不描述实现细节。
- 同一 test 只覆盖一组强相关路径。
- 断言返回值后，再断言关键输出字段或状态变化。

### TLV/ioctl wrapper

```cpp
TEST(UrmaCmdTlvTest, XxxTlvAttrsMatchExpected)
{
    urma_cmd_xxx_t arg = urma_test::MakeXxxCmd();

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_ioctl_xxx(urma_test::MOCK_IOCTL_FD, &arg));
    ExpectCapturedCommand(URMA_CMD_XXX, urma_test::ExpectedXxxAttrs(&arg));
}
```

断言稳定字段：

- command id。
- `args_len`。
- attr 顺序。
- attr `type`。
- attr `field_size`。
- array metadata。
- attr data 是否指向原始字段。

如果暂时没有完整 attr 预期，只允许用 header 级断言作为过渡：

```cpp
EXPECT_URMA_IOCTL_WRAPPER(urma_ioctl_xxx, URMA_CMD_XXX, urma_cmd_xxx_t);
```

后续补 mock 数据时，必须升级为完整 attr 断言。

### Bonding public API

```cpp
TEST(UrmaBondTest, PublicApiRejectsInvalidState)
{
    BondPublicApiFixture fixture;

    EXPECT_EQ(URMA_EAGAIN, bondp_delete_jfs(&fixture.jfs.v_jfs));
}
```

要求：

- 优先覆盖外层 contract。
- 不伪造不完整对象强行进入深层正常路径。
- 真实 provider、netlink、sysfs 或 health thread 路径先停在稳定失败点。

### Core public API

```cpp
TEST(UrmaCoreTest, CpApiXxxValidatesInputsAndDispatchesOps)
{
    CoreApiFixture fixture;
    urma_xxx_attr_t attr = {};

    EXPECT_EQ(URMA_EINVAL, urma_modify_xxx(nullptr, &attr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_xxx(&fixture.xxx, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_xxx(&fixture.xxx, &attr));

    fixture.ops.modify_xxx = MockModifyXxx;
    EXPECT_EQ(URMA_SUCCESS, urma_modify_xxx(&fixture.xxx, &attr));
}
```

要求：

- 先测 NULL、状态错误、缺失 ops，再测 ops 返回传播。
- batch delete 必须断言 `bad_xxx` 回填。
- 引用计数路径必须断言成功变化和失败不误改。

## Mock 数据扩展

### Command/TLV

在 `test/urma/include/urma_cmd_mock.h` 中按同一模式补：

```cpp
inline urma_cmd_xxx_t MakeXxxCmd()
{
    urma_cmd_xxx_t arg = {};
    arg.in.some_field = MOCK_VALUE;
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedXxxAttrs(urma_cmd_xxx_t *arg)
{
    return {
        { XXX_IN_FIELD, sizeof(arg->in.some_field), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.some_field) },
    };
}
```

### Bonding

优先扩展已有 fixture：

- `BondPathFixture`：datapath convert/schedule、WR/CR、target/segment/path 映射。
- `BondPublicApiFixture`：`bondp_api.h`、`bondp_datapath.h`、`bondp_segment.h`、`bondp_provider_ops.h` 的无设备 public API。

新增字段必须保持 fixture 为纯内存对象，不引入真实 fd、真实 context 创建或真实 provider 依赖。

## 覆盖率和验收

`bash test/urma/script/urma_UT.sh` 的阻断条件：

- URMA 构建失败。
- GTest 构建失败。
- GTest 执行失败。
- 新增可执行源码行覆盖率低于 `90%`。

当前只作为观察报告、不阻断的内容：

- phase function coverage。
- phase line coverage。
- 某个 phase 暂时没有覆盖数据。

Phase 分组：

- `phase_common`: `src/urma/common`
- `phase_urma_core`: `src/urma/lib/urma/core`
- `phase_urma_bond`: `src/urma/lib/urma/bond`
- `phase_uvs`: `src/urma/lib/uvs`

恢复 phase 强门禁前必须满足：

1. 不依赖真实硬件或真实系统状态。
2. 主要外部边界已有 mock、wrap 或 seam。
3. 本地和 CI 稳定通过。
4. phase 覆盖率目标可以持续达成。

## 完成检查

提交前逐项确认：

1. 新用例能稳定构建和运行。
2. 已优先复用现有 mock/fixture。
3. 只有通用场景才新增共享数据。
4. 没有真实设备、sysfs、netlink、安装库或 UDMA provider 依赖。
5. `bash test/urma/script/urma_UT.sh` 通过。
6. 新增生产代码时 diff coverage `>=90%`。
7. phase 覆盖率报告已生成。
8. `git diff --check` 通过。
