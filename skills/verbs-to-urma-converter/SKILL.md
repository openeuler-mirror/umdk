---
name: verbs-to-urma-converter
description: 将 RDMA verbs 代码迁移到 URMA API。当用户想要将 infiniband verbs 代码转换为 URMA，或在进行 RDMA/InfiniBand 迁移时，或用户提到 verbs API、ibv_*、rdma，或想要使用 URMA 替代传统 RDMA 时使用此 skill。此 skill 处理完整的迁移，包括 API 映射、数据结构转换和 URMA 特定优化。
---

# Verbs 到 URMA 迁移 skill

> 版本: 1.0 | URMA API 版本: 25.12.0

此 skill 将 RDMA Verbs (libibverbs) 代码迁移到 URMA (统一远程内存访问) API。

## 何时使用此 skill

在以下情况触发此 skill：
- 用户提到 "verbs"、"libibverbs"、"ibv_*" 函数
- 用户提到 "RDMA"、"InfiniBand"、"RoCE"
- 用户想要将 infiniband 代码迁移到 URMA
- 用户提到 "urma" 和 "迁移"、"转换"、"移植"、"翻译"
- 用户想要将 RDMA 应用程序转换为使用 URMA

---

## 迁移硬约束（全过程适用）

以下约束贯穿迁移全过程，任何阶段不得违反：

1. **原始文件不可变** — 所有输出放入 `urma_output/`，保留原始目录结构，原始文件不得修改
2. **4 阶段不可跳过** — 阶段 4 捕获编译无法发现的运行时语义错误，跳过会导致资源泄漏、逻辑错误等
3. **系统头文件是最高权威** — API 签名、类型定义以 `urma_api.h` / `urma_types.h` 为准，与参考文档冲突时以头文件为准
4. **结构体必须零初始化** — 使用 `{0}` 或 `{.field = value}` 指定初始化，未初始化字段导致未定义行为
5. **验证不可跳过** — 每个文件的 patterns/pitfalls 逐项检查，FAIL 不可遗留
6. **无头文件不可继续** — 缺乏权威 API 来源时 Agent 会编造不存在的函数，必须先找到头文件

### URMA vs Verbs 概览

| RDMA Verbs 概念 | URMA 等价物 |
|---|---|
| PD (保护域) | URMA 中隐式存在 |
| MR (内存区域) | `urma_target_seg_t` 通过 `urma_register_seg()` |
| CQ (完成队列) | `urma_jfc_t` 通过 `urma_create_jfc()` |
| QP (队列对) | `urma_jetty_t` 或 `urma_jfs_t` + `urma_jfr_t` |
| SRQ (共享接收队列) | `urma_jfr_t` 带 `share_jfr=1` 标志 |
| 完成通道 | `urma_jfce_t` 通过 `urma_create_jfce()` |
| LID + GID | `urma_eid_t` (16字节端点ID，LID 已移除) |
| QPN | JPN (Jetty 对编号) |
| PSN | PSN (包序列号) |

### 快速参考（完整列表见 `mapping.md §1`）

| Verbs | URMA |
|-------|------|
| `ibv_open_device()` | `urma_create_context()` |
| `ibv_reg_mr()` | `urma_register_seg()` |
| `ibv_create_cq()` | `urma_create_jfc()` |
| `ibv_create_qp()` | `urma_create_jetty()` |
| `ibv_modify_qp(RTR/RTS)` | `urma_import_jetty()` + `urma_bind_jetty()` |
| `ibv_post_send()` | `urma_post_jetty_send_wr()` |

---

## 迁移工作流程

### 阶段 1: 准备

**目标**: 理解源代码并建立完整的 API 映射。

**必须交付物**（阶段结束时必须产出）:
1. 源文件分类清单：哪些含 verbs API（需转换），哪些不含（原样复制）
2. Verbs API 清单与 URMA 映射表：每个 API 的处理方式（替换/删除/待确认）
3. 传输模式与连接模型判断（RC/RM/UM, import+bind 等）
4. 用户确认（展示上述交付物，获得许可后方可进入阶段 2）

**必须完成**（阶段过程中的硬约束）:
- 系统头文件（urma_api.h / urma_types.h / urma_opcode.h）已找到并读取，作为权威来源
  - 常见位置：`/usr/include/ub/umdk/urma/`
  - 若未找到：要求用户安装或提供路径，不可在没有头文件的情况下继续
- 每个 verbs API 均已在 mapping.md 中查找过等价物
- 无法映射的 API 已在 mapping.md §无URMA等价物 中确认删除，或标注为待确认
- 已了解 URMA 完整资源生命周期（参考 patterns.md §1）

**参考查阅路径**（建议，非强制）:
- patterns.md §1 → 理解 URMA 完整生命周期
- mapping.md → 逐 API 查找映射
- pitfalls.md → 了解常见错误概览

---

### 阶段 2: 转换

**目标**: 在 `urma_output/` 目录中创建转换后的代码，原始文件保持不变。

**必须交付物**（阶段结束时必须产出）:
1. `urma_output/` 目录，包含所有转换后的文件，保留原始目录结构
2. 每个文件的验证结果（见验证要求）
3. 每个文件的映射项执行追溯（见映射追溯）
4. 项目级映射追溯汇总（见映射追溯）
5. 编译配置已更新

**转换约束**（必须满足）:
- 所有转换后的代码放入 `urma_output/`，原始文件不可修改
- 头文件的类型定义变更必须与所有引用它的源文件保持一致
- 构建文件（Makefile）在所有代码文件转换完成后再更新
- 含 verbs API 最多的文件建议优先转换，以尽早发现映射问题

**每个文件的转换内容**:
- `#include <infiniband/verbs.h>` → `#include <ub/umdk/urma/urma_api.h>`
- Verbs API 调用 → URMA 等价物（查 mapping.md）；无等价物的调用直接删除（查 mapping.md §无URMA等价物）
- 结构体字段名更新（如 `wc.qp_num` → `cr.local_id`）
- 枚举值更新（如 `IBV_MTU_1024` → `URMA_MTU_1024`）
- 连接建立流程更新（查 mapping.md §连接建立决策树，按 RC/RM/UM 选择正确操作）
- 地址交换格式更新（`lid:qpn:psn:gid` → `jpn:eid`，查 mapping.md §地址交换格式决策）
- 清理顺序更新（查 mapping.md §清理顺序决策，按传输模式选择正确顺序）

**构建配置必须更新**:
- 链接库：`-libverbs` → `-lurma -lurma_common`
- 头文件路径：`infiniband/verbs.h` → `ub/umdk/urma/urma_api.h`
- 若原项目无 Makefile，需创建（链接 `-lurma -lurma_common`）

#### 映射追溯（防止遗漏映射项）

> **问题**：阶段 1 产出映射计划后，阶段 2 逐文件转换时容易遗漏非核心路径的映射项（如 `ibv_create_comp_channel → urma_create_jfce`），因为验证只对照 patterns/pitfalls（通用知识），不对照阶段 1 的映射计划（项目特定清单）。

**两层追溯机制**：

**文件级追溯**（每个文件转换后立即核对）：
- 核对该文件中直接出现的每个 verbs API 是否已处理
- 不得遗漏：包括条件分支内、辅助函数中、初始化/清理路径中的调用
- 核对结果作为该文件验证的一部分

**项目级追溯**（所有文件转换后汇总核对）：
- 核对阶段 1 映射表中的每一项是否至少在一个文件中被处理过
- 不得有映射项处于"未处理"状态
- 输出追溯汇总：每项映射的状态（已转换/已删除）及处理所在的文件

---

#### 验证要求（每个文件转换后必须满足）

**必须验证**:
- patterns.md 的每个章节：此文件的代码是否符合该 pattern
- pitfalls.md 的每个章节：此文件的代码是否踩了该 pitfall
- 编号对应：P-XX 对应 patterns.md 章节号，PIT-XX 对应 pitfalls.md 章节号
- 文件级映射追溯：该文件中的每个 verbs API 是否已处理

**必须达到的状态**:
- 每项判断为**符合**（对应 pattern / 未踩 pitfall）或**不适用**（N/A，需说明原因，如"此文件无 RDMA 操作"）
- **不符合项**(FAIL) 必须修复后重新验证，不得遗留
- **不得跳过任何章节** — 遍历参考文件的实际章节编号
- 编号来源于参考文件的实际章节，当参考文件新增章节时自动包含

**输出方式**: 逐项列出每章节的验证结果与判断依据，确保可审计。不得以"已验证"等笼统表述替代逐项检查。

---

### 阶段 3: 验证

**目标**: 编译、链接并验证转换后的代码。

**必须交付物**（阶段结束时必须产出）:
1. 编译成功（无错误）
2. 链接正确（依赖 `liburma.so` 和 `liburma_common.so`）

**必须完成**（阶段过程中的硬约束）:
- 编译通过，无未定义引用、类型不匹配等错误
- 链接验证确认依赖正确的 URMA 库
- 编译错误已排查并修复

**常见编译错误与排查方向**:

| 错误类型 | 可能原因 | 排查方向 |
|---------|---------|---------|
| 未定义引用 | API 名称错误 | 查 urma_api.h 中的正确函数签名 |
| 没有名为 'jetty_id' 的成员 | 字段名错误 | `cr.local_id` 而非 `cr.jetty_id`（见 mapping.md） |
| 宏重定义 | 头文件中已存在该宏 | 删除自己定义的宏 |
| 类型不匹配 | 参数类型错误 | 匹配 urma_api.h 中的确切签名 |
| 缺少头文件 | 未包含正确头文件 | 添加 `#include <ub/umdk/urma/urma_api.h>` |

---

### 阶段 4: 审查和优化（强制性）

**目标**: 以项目视角检查跨文件语义问题，验证编译之外的正确性。

> **为什么不能只看单个文件**: 资源生命周期跨文件（A 文件创建、B 文件销毁）、类型声明在 .h 中修改但 .c 引用未同步、Verbs 残留可能仅出现在"原样复制"的工具文件中——这些都不是单文件视角能发现的问题。

**必须交付物**（阶段结束时必须产出）:
1. 跨文件一致性确认：头文件类型定义与源文件引用同步、共享变量声明一致
2. 资源生命周期完整性：每个 URMA 资源的创建→销毁链无遗漏
3. Verbs 残留为零：`urma_output/` 中无任何 `ibv_*` / `verbs.h` / `infiniband` 引用
4. 运行时语义正确性：import/unimport 配对、wait/ack 配对、清理路径完整
5. 用户确认的审查结果摘要

**必须完成**（阶段过程中的硬约束）:

1. **头文件→源文件一致性**：.h 中修改的类型定义，确认所有引用该 .h 的 .c 文件均已同步更新，无残留旧类型
2. **共享变量一致性**：跨文件共享的变量（如全局 `ibv_cq *g_cq` → `urma_jfc_t *g_jfc`），确认 .h 声明和所有 .c 使用一致
3. **资源归属与生命周期**：梳理每个 URMA 资源（context、jfc、jfr、jetty、tseg、tjetty、import_seg）在哪个文件创建、哪个文件销毁，确认创建→销毁链完整无遗漏
4. **Verbs 残留扫描**：确认 `urma_output/` 中无任何 Verbs 残留引用
5. **重新审视 N/A 项**：阶段 2 中标记 N/A 但跨文件看可能适用的项（例如单文件不含 RDMA 代码，但其他文件会触发 import_seg 要求）
6. **清理路径完整性**：每个成功路径是否都有对应的完整清理序列（unbind→unimport→delete）
7. **资源泄漏检查**：每个 `urma_import_*` 是否都有对应的 `urma_unimport_*`；每个 `urma_wait_jfc` 是否都有 `urma_ack_jfc`

修复并重编译，直到干净。

#### 阶段 4 检查点

向用户展示以下信息：
- 阶段 4 中发现并修复的问题
- 遗留风险（已知但无法在迁移中解决的问题）
- 新增知识（迁移中发现的新映射/patterns/pitfalls）
- 是否将新增知识添加到参考文件（需用户同意）

---

## 输出格式

**强制性**: 所有转换后的代码放入新目录。原始文件保持不变。

**最终输出结构**:
```
project/
├── (原始文件 - 不变)
└── urma_output/
    ├── (转换后的 .c 文件)
    ├── (转换后的 .h 文件)
    ├── (原样复制的非 verbs 文件)
    └── Makefile
```

---

## 贡献新知识

成功迁移后，你可能会发现新的映射、patterns 或 pitfalls。

**步骤**:

1. **收集新发现**:
   - 新 API 映射 (verbs → urma)
   - 新结构体字段映射
   - 新代码 patterns
   - 新 pitfalls

2. **向用户展示发现**:
   ```
   我在迁移过程中发现了以下新信息:

   [清晰列出发现]

   是否要将这些添加到参考文件中？
   ```

3. **如果用户同意**:
   - **新 API 映射**: 添加到 `references/mapping.md`
   - **新代码 Patterns**: 添加到 `references/patterns.md`
   - **新 Pitfalls**: 添加到 `references/pitfalls.md`

4. **如果用户拒绝**:
   - 跳过更新参考文件

这确保 skill 随着实际使用不断改进，但仅在用户同意时进行。

---

## 参考文件概览

| 文件 | 用途 | Agent 使用场景 |
|------|------|---------------|
| `mapping.md` | Verbs → URMA 查找表 | "X 的 URMA 等价物是什么？" |
| `patterns.md` | 完整代码模式 | "展示如何编写 X" |
| `pitfalls.md` | 已知问题和修复 | "为什么 X 失败？" |
| `urma_sample.md` | 完整工作示例 (~1280 行) | 仅当 patterns.md 不够详细时按需阅读 |

**推荐阅读顺序**:
1. `mapping.md` - 学习 API 等价物
2. `patterns.md` - 查看完整工作代码
3. `pitfalls.md` - 避免常见错误
4. `urma_sample.md` - 仅当需要完整参考实现时阅读（~1280 行，按需加载）