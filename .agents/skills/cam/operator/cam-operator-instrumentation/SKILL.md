---
name: cam-operator-instrumentation
description: 昇腾算子 TRACE_POINT / MoeTracing 打点、profiling GM、point_map 与 Chrome trace。Agent 先读 G1–G5。用户提到打点、MoeTracing、TRACE_POINT、Chrome trace 时使用；或 cam-operator-debug / cam-operator-optimization 明确需要阶段 timing evidence 时使用。正确性未过时由 cam-operator-debug 主导，不自行解释根因。
---

# Instrumentation Skill

status: **accepted**

本 Skill 是 **打点工序 + 工具链**。决定「该不该测、测完怎么解释」走 [cam-operator-optimization](../cam-operator-optimization/SKILL.md)。完整步骤、MoeTracing 规格、脚本用法见 [references/procedure.md](references/procedure.md)。脚本在 [scripts/](scripts)。

本 Skill 初始由个人打点工具链导入；当前唯一 canonical 路径是
`.agents/skills/cam/operator/cam-operator-instrumentation/`。它没有抽成
Knowledge——这是流程，不是 API 合同。

```text
打点能看到 stage
  ≠
该 stage 就是端到端瓶颈

instrumented build
  ≠
报加速比用的 production build

MoeTracing 默认 PipeBarrier<PIPE_ALL>
  ≠
生产路径的跨流水合同

忠实记时：PIPE_ALL 后再 GetSystemCycle
  ≠
MoeTracingWithCycle(data, GetSystemCycle())
```

`PIPE_ALL` 打点屏障仍读 [pipeline Card](../../../../knowledge/cam/synchronization/pipeline-events-and-ordering.md)。不要用打点宏覆盖 accepted API，也不要把测量用 barrier 当成生产路径合同。

---

## 什么时候用

- 用户要 **TRACE_POINT / MoeTracing / profiling 张量 / Chrome trace**
- [cam-operator-optimization](../cam-operator-optimization/SKILL.md) 需要阶段 Cycle 做 localization
- [cam-operator-debug](../cam-operator-debug/SKILL.md) 连续步骤无信息增益，明确要阶段 timing / event evidence

```text
correctness 未过
  → 不把本 Skill 当 primary route
  → cam-operator-debug 主导诊断
  → debug 点名要阶段证据时，本 Skill 只供 evidence
```

不要当 primary route，当：

- 还没跑完或返回码非 0，且 debug **没有**点名要打点证据
- 只想听「开 double buffer 快 30%」且无测量合同
- 用户明确只要改字符串、不要 GM / 不要改 Op 输出（缩范围，回复里写未完成项）

蓝区无 NPU：可以插桩、接 hook、静态校验；Runtime / Chrome 标 **未测**。

---

## 门禁 G1–G5

G1–G5 是 **本仓这套 TRACE_POINT / MoeTracing toolchain** 的 integration gates，不是所有 AscendC profiling（PRINTF / PMU / msprof / 其它 runtime）的通用 API 合同。

用户未缩小范围、且走这套工具链时，缺一条就不得宣称闭环。细则在 procedure。

| | 必须 |
| --- | --- |
| **G1** | 当次编译的 `trace_preprocessor` 产出 **`point_map.json`**，与正在跑的核同源 |
| **G2** | `profiling_data` 是全部 Tensor 数据输出的 **最后一个**；host / infer / 核 / aclnn / pybind **同序** |
| **G3** | 项目常用整条命令编过 OPP（及若有的 pybind）。**不等于**只过 `validate_trace_points` / `check_compile_safety` |
| **G4** | 既有 sample/UT：设备 **synchronize 之后** `save_profiling_data`；Chrome 用 **同源** `point_map` + `trace_collector` |
| **G5** | `profiling_dir` / `chrome_trace` / `point_map` 在 spawn 前 **`Path.resolve()` 绝对路径** |

禁止注册 `xxx_profiling` / `*_with_profiling`。同一 `torch.ops` 名；模式 A 不改返回个数，模式 B 只在同一名下多一路 profiling。

---

## 流程（1–7）

1. 从入口 **递归** 扫该算子 `op_kernel/`（含 `#include` 子树），AIC/AIV 分开看  
2. 打点树：L1 = `processing`  
3. 薄 helper 合并；`wait` / `sync` / `copy` 等边界保留  
4. 成对 B/E；`MoeTracing` 内必须 **`PIPE_ALL` 后再 `GetSystemCycle`**（禁止把 cycle 当实参先求值）；**不要**打 tile 内层 K 循环  
5. `validate_trace_points.py` + `check_compile_safety.py`（不替代完整编译）  
6. 改 **已有** `compile_*.sh` 插入 preprocessor hook；少新建 sh  
7. 改 **已有** sample/UT 解包与落盘  

命令与陷阱（相对路径落到 `trace_utils.py` 旁、错 `point_map`、冷启动第一次 combine）只在 procedure 里查，不要在本页复制 UMDK 路径当默认。

Chrome 的 `clock-divisor` 是 **instrumentation toolchain 配置**，按目标平台和 `trace_collector` 版本读 procedure 里 **已验证** 的那一行。不要跨平台复用旧值。

```text
validated tool configuration
  ≠
hardware invariant
```

---

## 和 Weaver 其它层

| 要做的事 | 走 |
| --- | --- |
| 该不该优化、active vs exposed | `cam-operator-optimization` |
| 507035 / 结果错 / hang | `cam-operator-debug`（需要阶段证据时再叫本 Skill） |
| copy / tile 合同 | 已有 Knowledge / Case |
| 查官方/头文件 | `cam-operator-docs-search` |
| 无文档时重建算子语义 | `cam-operator-spec-reconstruction` |

打点 Skill **不**解释 pingpong，也 **不**把 Chrome 里最长的条当成根因。

---

## 输出

回复必须逐条写 G1–G5：**已满足 / 未满足 + 风险**。再列改了哪些文件（含 `op_kernel` 子树）、校验跑了没有、sample 是否 sync 后落盘。
