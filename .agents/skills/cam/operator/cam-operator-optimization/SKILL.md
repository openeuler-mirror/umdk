---
name: cam-operator-optimization
description: 基于正确性已通过的 CAM AscendC 算子源码、Cycle 与 profiling 证据定位性能瓶颈并规划优化。用户要求提速、解释性能差异或分析计算/搬运/通信/同步等待时使用；正确性失败先走 cam-operator-debug。
---

# Operator Optimization Skill

status: **accepted**

本 Skill 是 **路由器**。正确性通过之后，按判断循环决定测什么、假说怎么排、改哪一处。不要把它当成各族性能百科，也不要无测量报加速比。

API / 资源事实只读已 `accepted` 的 Knowledge 和 Case。优化排序是 `recommendation`，不能覆盖 Card。

```text
debug / perf heuristic
  cannot override
accepted API / hardware contract
```

错的走 [cam-operator-debug](../cam-operator-debug/SKILL.md)。上板还没做完 Functional + **无 profiler 的 Stability**：先回 [cam-operator-run](../cam-operator-run/SKILL.md)，不要把 msprof 当第一趟。跨域搬运走 [correctness-debug](../../../../workflows/cam/operator/correctness-debug/README.md)。

第一版不该写成纯串行 / 满屏 PIPE_ALL：那是 [cam-operator-development](../cam-operator-development/SKILL.md) 的 **P1–P5 + PAC**，不是等正确性过了再当优化题。
PAC 冻结的 L1 可以带着 L2 candidate；本 Skill 入口仍是 correctness passed 之后的测量循环，不得把未测的 L2 候选直接当本轮必改项。

```text
P-gate 结构问题
  ≠
measured bottleneck
```

---

## 1. 诊断循环

```text
correctness passed
  → measure
  → localize stage（active vs exposed）
  → classify bottleneck family
  → ranked hypotheses
  → smallest evidence-backed change
  → correctness retest
  → compare under the same performance contract
```

还没有测量：只许静态假说，Perf 标 **未测**。  
检查区分不了两条假说：换更小的改动或补一次测量，不要同时改 tile、同步和 API。

---

## 2. 六条边界

```text
慢的感觉              ≠ 瓶颈
指标                   ≠ 根因
stage duration         ≠ exposed bottleneck
hypothesis             ≠ Knowledge fact
改一处                 ≠ 验证
无证据重写             ≠ 优化
```

```text
stage active cycles
  ≠
exposed latency
  ≠
critical-path contribution

存在 overlap 时
  T_total ≠ Σ T_stage

code identity must be known
  ≠
code identity must be the same
```

优化优先瞄准 **exposed latency / stall / critical-path contribution**，不要机械选 active cycles 最大的阶段。

打点能测 stage，不代表 stage 最大的就是端到端目标。  
`num=2` 只是 overlap eligibility，不是“一定更快”。

---

## 3. Performance contract

和 failure contract 对应：比的是哪两版、什么负载、怎么测。

| 块 | 至少固定 |
| --- | --- |
| workload | shape / dtype / input 特征；batch / token / seq（若有）；rank / world size（若分布式） |
| environment | SOC / CANN；critical env；topology |
| measurement protocol | warmup；iterations；metric / statistic；打点 / profiling 开还是关 |
| code | **baseline identity A**；**candidate identity B** |
| observation | latency / cycles / throughput；若有，再附 stage evidence |

```text
instrumented build
  ≠
production performance build
```

阶段打点若改变了 kernel：只用于 localization。报收益回到可比较的 benchmark configuration。

---

## 4. 瓶颈族

入口已是 correctness passed。

```text
missing required ordering   → cam-operator-debug
extra / exposed wait        → 本 Skill
```

| 族 | 升权条件（够用就停） | 先读 |
| --- | --- | --- |
| movement / copy | Copy **暴露**在 critical path；小 DMA；aligned 膨胀 | [copy](../../../../knowledge/cam/memory/memory-copy-and-alignment.md) |
| pipeline overlap / exposed wait | 合同合法但仍过度同步、tile 太小叠不上、可见 stall | [pipeline](../../../../knowledge/cam/synchronization/pipeline-events-and-ordering.md)、[TQue](../../../../knowledge/cam/memory/ub-tque-tbuf-and-double-buffer.md) |
| occupancy / load balance | 核不满；尾核拖时间 | [tiling-from-shape](../../../../knowledge/cam/engineering/tiling-from-shape.md) |
| tile / buffer | UB 装不下或装太浅；`num=2` 没回传预算 | tiling + [hierarchy](../../../../knowledge/cam/hardware/ascend950/core-and-memory-hierarchy.md) |
| vector instruction efficiency | Compute 在 critical path 上且指令碎、中间落 GM | [mask-repeat](../../../../knowledge/cam/ascendc/vector/mask-repeat-and-kernel-limits.md) |
| other | scalar / host / cube / comm | GEMM K、MC2、FA、MoE Case；无文就承认 |

提问顺序（有适用条件，不是门禁）：

```text
切分 / occupancy 是否离谱
  → MC2 且已有 T_comm / T_compute：卡间 overlap
  → 确实有核间同步：核间等待
  → 单核：exposed movement vs compute vs wait vs scalar
```

普通 Vector 经常直接进单核。不要为 Add 先走通算。  
MTE2 busy 在 MC2 上先排除通信等待污染，再谈搬运。

---

## 5. 测量怎么接

```text
本 Skill
  决定测什么、假说怎么排、改哪一处

instrumentation
  阶段 Cycle / timing：走 [instrumentation](../cam-operator-instrumentation/SKILL.md)（G1–G5）
  hidden vs exposed 需要 overlap / wait / boundary evidence
  只有各阶段独立 duration 时：只能 localize active cost，
    不能直接推出 critical-path contribution
  不解释该开 pingpong

msprof / profiling-analysis
  已有采集目录 → 分析现有数据
  没有 → 本 Skill 可以设计 / 请求下一轮采集
  指标仍只是 hypothesis evidence，不是补丁
```

蓝区无 NPU：可以排静态假说、设计内网测量。不要要求 `npu-smi`。不要用 cannbot 收益表填数。

---

## 6. Decision Rules

```text
MUST     正确性同一 test contract 过了再谈性能
MUST     上板时 L8（无 profiler）已过，再开 L9 / msprof
MUST     先测量（阶段或 kernel），再改
MUST     记录 baseline A 与 candidate B
MUST     一次只改有证据支持的一处
MUST     改完先 correctness retest，再在同一 performance contract 下比 A/B
MUST NOT 无测量报加速比
MUST NOT 把 active 最大的阶段自动当成端到端瓶颈
MUST NOT 用收益表 / A2 数字 / 512B / 256KB 覆盖 accepted Card
MUST NOT 为普通 Vector 强制走卡间 / 核间
MUST NOT 把缺 readiness 当成性能目标
MUST NOT 为 N 轮去 launch N 次进程；一轮脚本用 `warm_iter`/`test_iter`（或仓内等价）。只有 weight-init 的 `op_summary` 不是 fused 性能

IF 只有“感觉慢”
THEN 只许静态假说 + 设计测量，Perf 标未测

IF Copy active 高
THEN 先问是否暴露在 critical path；暴露才升权 movement

IF 三段几乎不重叠且 num=1
THEN overlap eligibility 升权；num=2 仍要回传 UB

IF 核不满或尾核拖时间
THEN 回到 tiling revise，不要先改 Vector API

IF 无新测量还在换实现
THEN 停优化，回去补打点 / msprof
```

msprof 命令、Dump 步骤、Softmax / matmul 模板不进本文件。没有对应 Case 或 Knowledge 就说暂无，不要编加速比。
