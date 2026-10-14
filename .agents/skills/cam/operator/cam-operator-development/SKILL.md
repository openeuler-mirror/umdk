---
name: cam-operator-development
description: >-
  AscendC 算子开发主路由。先分 NEW OPERATOR 与 EXISTING OPERATOR FEATURE。新算子走
  workflows/cam/operator/new-operator（Design+Gate A，禁止直接写核）。已有算子 Feature
  走 workflows/cam/operator/existing-operator-feature（先重建 Baseline，禁止带着方案读源码）。
  无可靠 Contract 不得写核；写核前打开 performance-by-construction 走 Gate A/PAC；Gate B
  宣称 L1。上板走 cam-operator-run。Triggers: 新算子, 增加 Feature, Baseline
  Reconstruction, Gate A, Design Proposal, Batch Completion.
---

# Operator Development

status: **accepted**（主路由。P-gate 细则在 reference，不在本页展开。）

本 Skill 只编排开发链。不讲 API 合同，不做测后优化，不重建算子语义。

**日常开发先定任务类型，再打开对应 workflow + 本页 + [performance-by-construction](references/performance-by-construction.md)。**  
新算子：[new-operator](../../../../workflows/cam/operator/new-operator/workflow.md)。  
已有 Feature：[existing-operator-feature](../../../../workflows/cam/operator/existing-operator-feature/workflow.md)。  
上板：[cam-operator-run](../cam-operator-run/SKILL.md)。

```text
NEW OPERATOR
    Requirement → Design → Gate A → Implementation

EXISTING OPERATOR FEATURE
    Existing Source → Baseline Freeze → Delta Design → Implementation
```

未声明类型：先问，不得默认当成新算子。没有用户批准，不得自动跨 Gate。

```text
performance-aware baseline
  ≠
performance-optimal implementation

L1 — production-correct first version
  semantic correct · physical legal · compile · closed sync
  reasonable locality · no obvious asymptotic disaster
  simple production hot path

L2 — performance-mature version
  communication minimization · SIMT/vector specialization
  serial-island decomposition · adaptive resource path
  reduced barriers · profiling-driven pipeline

Gate A + PAC freeze 的是 L1（可带 L2 candidate 标注）
Gate B 通过 = L1 不是明显低质量结构
       且 Implementation Adversarial Challenge 未留下未分类缺陷
L2 走 cam-operator-optimization，或 PAC 已证明必须进入本轮 L1
```

```text
Gate A PAC
  Assume the design is correct.
  How would a performance engineer defeat it?

Gate B IAC
  Assume the implementation faithfully follows the design.
  How could actual statements still violate it?
```

P-gates 保证第一版不是明显低质量结构。没有 profiling，不得声称「这就是最优方案」。
物理成立 **不等于** 可以 freeze。Gate A 之后必须再挑战一次：资深性能工程师为什么还会推翻这个正确方案。
第一版写完之后必须再攻击一次实现：假定代码忠实于 Design，实际语句仍可能怎样违例。

```text
correct and affordable
  ≠
best justified production baseline
```

---

## Input mutation policy

写任何文件前，把相关路径分成三类。

```text
A. immutable human input          （文件默认不可改）
B. mutable Agent task artifact
C. generated implementation output
```

默认不可改（除非用户**点名授权该文件**）：

- `docs/*` 人工设计 / 架构说明 / 参考图
- 用户粘贴或指定的 spec / 决策
- 已经 review 过的 `operator-contract.md`（semantic freeze）

```text
Immutable human *file*
  ≠
every sentence is a frozen design constraint
```

人工文档里可以同时有：ABI / 语义冻结、implementation sketch、示例、历史 CUDA 笔记。
Contract 必须给每条声称分级（fact vs sketch vs example）。
sketch（例如「跨卡用 mapped DataCopyPad」）坐在不可改文件里，**不等于** ABI。
不得为了「和实现一致」去改该文件；偏离记进 Design Proposal，实现向 **已分级的 fact** 收敛，不向 sketch 收敛。

默认可改（目标仓 `.ascendweaver/`）：

- NEW：`operator-design.md` · `gate-a.md`（旧名 `design-proposal.md` 视为同一 Design）
- EXISTING FEATURE：`baseline-*.md` · `change-contract-*.md` · `blast-radius-*.md` · `delta-design-*.md` · `gate-a-delta-*.md` · `frozen-clause-traceability.md`
- `development-status.md`
- 本轮 generated reports

实现输出：kernel / host / test / build integration（仍受 write set 约束）。

```text
Agent MUST NOT edit an immutable human input
unless the user explicitly authorizes that file.

If implementation evidence conflicts with an immutable design:
  1. report the conflict
  2. cite implementation / API evidence
  3. propose a design-document patch separately
  4. stop structural implementation if the conflict is blocking

Implementation must converge toward the design,
not rewrite the design to match the implementation.
```

**Implementation 开始前必须打印：**

```text
READ-ONLY INPUTS:
WRITEABLE DESIGN ARTIFACTS:
IMPLEMENTATION WRITE SET:
```

write set 保护 sibling；本政策保护人工输入。二者都要。

---

## 1. Entry / Scope

进这里：要开发 AscendC——**从 0 的新算子**，或 **已有算子上的 Feature**。

| 用户说的 | 任务类型 | 第一轮打开 |
| --- | --- | --- |
| 新算子 / 从 0 / 没有现成 kernel | `NEW OPERATOR` | [new-operator](../../../../workflows/cam/operator/new-operator/workflow.md) |
| 给已有算子加 Feature / 改协议 / 加开关 | `EXISTING OPERATOR FEATURE` | [existing-operator-feature](../../../../workflows/cam/operator/existing-operator-feature/workflow.md) |
| 没说 | **先问** | 不得开写 |

立刻转走：

| 情况 | 走 |
| --- | --- |
| 无可靠设计文档；参数/数据流不清；存在 **blocking unknown** | [cam-operator-spec-reconstruction](../cam-operator-spec-reconstruction/SKILL.md) |
| 只问某个 CANN API / overload / 头文件 | [cam-operator-docs-search](../cam-operator-docs-search/SKILL.md) |
| 写完 / 改完核，要上板编译安装跑 | [cam-operator-run](../cam-operator-run/SKILL.md) |
| 已经在跑且失败（编译、返回码、结果错、hang） | 先有 ITERATION 卡再 [cam-operator-debug](../cam-operator-debug/SKILL.md) |
| 正确性已过、要解释快慢 / 报加速比 | [cam-operator-optimization](../cam-operator-optimization/SKILL.md) |
| 要阶段 Cycle / TRACE_POINT | [instrumentation](../cam-operator-instrumentation/SKILL.md) |

用户已给出完整可开发语义且与调用一致 → 把已给语义写成 Contract，不必再跑 reconstruction。

---

## 2. Development Loop

按任务类型选一条。不要把 Feature 做成“从 0 再设计一遍”。

**NEW OPERATOR** — 细节 [workflow](../../../../workflows/cam/operator/new-operator/workflow.md)：

```text
Requirement → Freeze → Retrieval → Design → Gate A
    → STOP
    → PAC + FC → Implementation → Gate B → iteration
```

第一轮只交 `.ascendweaver/operator-design.md` + `gate-a.md`。禁止改 production source。

**EXISTING OPERATOR FEATURE** — 细节 [workflow](../../../../workflows/cam/operator/existing-operator-feature/workflow.md)：

```text
Existing Source → Baseline Reconstruction → Baseline Freeze
    → STOP
    → Change Contract → Blast Radius → Delta Design → Gate A-Delta
    → STOP
    → Implementation（只实现 delta）→ Traceability → Gate B → iteration
```

第一轮隐藏未来方案：只重建 production 实际怎么工作。禁止提 Feature 实现、改代码、顺手优化。

共同的 Gate / PAC / Gate B 规则仍在本页后文与 PBC。Existing Feature 的 Gate A 是 **Delta Gate**（`DA01`–`DA18`），不是整算子重过一遍 GA01–GA18。

```text
无 Operator Contract（或仍有 blocking unknown）
  → 不允许进入 kernel implementation

Gate A 未执行
  → 不允许写 kernel

PAC 未执行，或七条未回答
  → 不允许 freeze Design / 写 kernel

Gate B 未执行，或 Frozen-Clause mismatch 且无 first-party 等价证明，或存在 present+unjustified，或 Gate B.5 仍有未攻击项
  → 不允许宣称 L1 baseline complete
```

non-blocking unknown 可带着 assumption / scope 继续，不得当成 fact。

### Target environment resolution

写 Design Proposal / Gate A 之前，target SOC / CANN / runtime environment 必须已经是任务合同，不是仓库现状。

权威来源：

```text
1. 用户明确需求
2. 本任务明确设计文档 / Plan
3. 当前目标分支针对该任务的显式 build / CI contract
```

不能单独冻结 target：

```text
- repo 默认 SOC
- sibling operator 的 SOC / UB / AIC/AIV
- 当前 shell 默认 CANN
- 历史实现环境
- 可用的某个 container
```

```text
repo supports X
  ≠
this operator targets X
```

细则在 [cam-operator-spec-reconstruction R0](../cam-operator-spec-reconstruction/SKILL.md)。本 Skill 只挡门：环境未冻结且会影响实现，就停。

```text
IF target SOC / CANN 会影响
   API legality / memory hierarchy / synchronization /
   tiling / compile path
AND target environment 仍 unknown
THEN environment 是 blocking
     不得进入 Design Proposal / Gate A
```

---

## 3. Design Proposal

写核前必须书面回答这些轴。这里只规定 **必须回答什么**；怎么切、容量多少、API 怎么填，打开对应资产，不要在本 Skill 展开教程。

启发式写成绝对规则会把 Agent 带偏（Combine v2：`S < AIV` → 必须切 H 填满 AIV）。本页规则的形状是：

```text
enumerate candidates
  → cost model
  → preserve locality
  → justify choice

heuristic
  ≠
absolute rule
```

少写 must split / must double-buffer / must fuse / must manual UB。
要的是比较和 justification，不是 occupancy / 框架 API 的自动策略。

| 轴 | 必须能回答 | 打开 |
| --- | --- | --- |
| semantic axes | 哪些轴有语义、不能 flatten | Contract；Vector 再读 [tiling-from-shape](../../../../knowledge/cam/engineering/tiling-from-shape.md) |
| ownership / parallelization | 谁拥有哪段数据；**先证 logical worker-space（physical launch index ≠ worker ID；不能从 `<<<block_dim>>>` 直接等于 `GetBlockIdx()`）**；**primary + secondary** 轴；`work_items / AIV`；切或不切的 **cost model**；**phase 内 serial island vs 被连带 serial 的 node** | tiling（含 launch topology）；本页 **parallel-axis exploration** / **serial-island**；PBC **Logical Worker Topology Gate**；Cube 读 [43](../../../../cases/cam/operators/compute/gemm/ascend950-basic-matmul/case.md)；K 切分读 [GEMM K](../../../../knowledge/cam/engineering/gemm-k-partition-strategies.md) |
| **partition locality** | contiguous chunk vs cyclic vs 2D；metadata bulk DMA vs per-item GetValue；**batch/window 从 core-local range / UB 推出，禁止无容量账的魔法 batch**；**已证明的 compact/monotonic invariant 必须消扫描（头尾求 span），不能只换成 bulk DMA** | 本页 **partition locality**；PBC **Locality Work-Elimination** |
| tiling | tile / tail / 对齐；proposal 过不过容量与 API；**common-case 可 full inner axis 则 hot path 不引入 h_tile；DMA 切块 ≠ 算法 tile；exceptional fallback 不得改语义** | tiling → capacity → revise；本页 **hot-path vs exceptional shape**；PBC **Hot-path vs Exceptional Shape Gate** |
| memory residency | 中间结果下一消费者；reuse vs UB footprint | Gate A 的 P2；硬件读 [950 hierarchy](../../../../knowledge/cam/hardware/ascend950/core-and-memory-hierarchy.md) |
| pipeline / buffering | `none \| single \| double \| other` + 理由；**每个**含 MTE2/V/MTE3/comm 中任两 pipe 的 phase 交 2-iteration timeline，不得只画 main；**intended concurrent stages → buffer / event credit 数量（闭环 ≠ 够飞）**；**每个 dominant phase 比较 E1/E2/E3；一阶段 ping-pong ≠ kernel pipeline PASS**；**dominant + small high-frequency side path 必须交联合 timeline** | [TQue](../../../../knowledge/cam/memory/ub-tque-tbuf-and-double-buffer.md)；Gate A 的 P3；PBC **Steady-state** / **pipeline resource depth** / **Side-path Integration Gate** |
| **UB orchestration** | 先 physical UB map，再决定是否用 TQue/TBuf 表达一部分；**overlay = lifetime 不重叠 + max-footprint closure + alignment + leftover identity（下一发不得把 handshake leftover 认成 ready）** | 本页 **UB orchestration**；PBC **Memory Orchestration Gate**；[adversarial statics](../../../../knowledge/cam/engineering/implementation-adversarial-statics.md) |
| **physical realizability** | 热路径每个 **运算**（不只每个 named buffer）落到 src/dst 物理对象 + dtype/bytes + lifetime + alias/API；width-change 禁止口头 in-place；每个 DMA 填 dest 对齐与 landing footprint | PBC **Physical Realizability**；[copy](../../../../knowledge/cam/memory/memory-copy-and-alignment.md) |
| synchronization | 每条边的 producer/consumer；**HardEvent 类型从 writer/reader/next-writer 推出，禁止 sibling 熟名**；**每个跨 mechanism / 跨 phase 的 producer→consumer 都要 visibility 证明**；**每个同步原语必须对应一条尚未被后续更强原语覆盖的 dependency edge**；**kernel boundary / 全 rank barrier 禁止了哪段 overlap**；manual event 的 Set/Wait/startup/drain；**phase A→barrier→phase B 必须冻结 Event ID 交接状态**；**device collective 必须证明 participant set ≠ 仅凭 launched cores 假设** | [pipeline](../../../../knowledge/cam/synchronization/pipeline-events-and-ordering.md)；P4 **Event protocol closure** / **Phase-transition closure** / **Publication graph** / **Synchronization minimality** / participation-set 表；[adversarial statics](../../../../knowledge/cam/engineering/implementation-adversarial-statics.md) |
| **phase / kernel boundary** | 紧耦合融合算子 **default = 单 device launch**；拆 launch 须过 1/2/3 证明并枚举同步机制；Host wrapper 个数 ≠ `__global__` 个数；**in-kernel collective 还须冻结 participation set（launched vs physical vs team）** | 本页 **phase / kernel boundary** |
| tail / dynamic shape | tail 怎么处理；动态维怎么进 tiling | tiling Card |
| **tiling field provenance** | 每个 tiling 字段 launch 前 Host 怎么得到；device runtime 值默认不 D2H | 本页 **Host/device provenance check** |
| **project integration** | 这个算子如何接进 **目标仓库** 的 OpDef / tiling / ABI / build / binding / test；**写核前声明 write set；sibling 实现默认只读** | 本页 **project integration** |
| **repo-native API idiom** | 性能关键路径冻结前搜仓内成功实现；**same-repo/SOC/role idiom 是 default baseline**；搜过 ≠ 已选；合法 API ≠ 本仓惯用 idiom；偏离须证明 contract/成本/envelope；**sibling 资源上限 path-scoped：provenance tuple 不一致不得继承；「更小更安全」不是证据** | 本页 **Performance-critical mechanism selection**；PBC **Repo-native API Search Gate**；cam-operator-docs-search 只回答合法性 |
| **API invocation contract** | 冻结 API 后仍须证明 overload / 单位 / source·dest extent / padding / stride / completion；默认 `{}` 不是证据 | PBC **API Invocation Contract Gate**；[copy](../../../../knowledge/cam/memory/memory-copy-and-alignment.md) |
| **hot-loop traversal** | UB 驻留 metadata 必须重建实际遍历复杂度；逻辑单遍不得因 helper 退化成 O(N²)；**按完整 call graph 相乘**（outer × helper × nested × helper-of-helper），不得只给 caller 主循环贴复杂度标签 | PBC **Hot-loop Traversal Gate**；[adversarial statics](../../../../knowledge/cam/engineering/implementation-adversarial-statics.md) |
| **launch admission** | kernel 声明 supported domain；Host 必须覆盖 **每一个物理不等式**（含 overlay max-footprint），再与 semantic/API/layout 求交；unsupported 必须有可执行 launch guard | PBC **Launch Admission Gate**；[adversarial statics](../../../../knowledge/cam/engineering/implementation-adversarial-statics.md) |
| **execution mapping** | 不规则 metadata / control-heavy 工作必须 **独立** 评估 Scalar / Vector / SIMT；一个 phase 允许混用；不能 Vector ≠ 必须 Scalar | PBC **P1**；PAC-4 |
| **over-materialization** | 有没有 tensor 只因为以后能重构 consumer state 才被通信 / 落 GM | [sufficient-state](../../../../knowledge/cam/engineering/communicate-sufficient-state.md)；PAC-1 |
| **sufficient state** | producer-side 变换能否减少 cross-rank bytes、replicated workspace、remote scans、synchronization | [sufficient-state](../../../../knowledge/cam/engineering/communicate-sufficient-state.md)；PAC-2 |
| **communication envelope** | bytes/rank、total bytes、remote ops、barriers、replicated state、渐近缩放；对本算子 critical path | PBC **Communication Envelope**；PAC-5 |
| **kernel resource budget** | physical UB ≠ kernel-mode/framework ≠ API-reserved ≠ user-allocatable | PBC **Kernel Resource Budget**；PAC-6 |
| correctness plan | 测什么 shape/dtype；golden 从哪来 | Contract；尺子读 [tolerance-source](../../../../knowledge/cam/engineering/tolerance-source.md) |

搬运单位 / Pad vs Copy → [copy](../../../../knowledge/cam/memory/memory-copy-and-alignment.md)。Mask / repeat → [mask-repeat](../../../../knowledge/cam/ascendc/vector/mask-repeat-and-kernel-limits.md)。合同未知 → cam-operator-docs-search，不要猜 overload。

相似机制先看 [cases/cam/README.md](../../../../cases/cam/README.md)（MoE：[token-expert-rank](../../../../knowledge/cam/engineering/moe-token-expert-rank-data-contracts.md) + [dispatch-combine](../../../../cases/cam/operators/compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md)；融合层：[materialization](../../../../knowledge/cam/engineering/moe-fusion-materialization-and-sync.md)；跨 rank 充分统计：[sufficient-state](../../../../knowledge/cam/engineering/communicate-sufficient-state.md)（**核心 distributed-design principle**）；MC2：[coupling](../../../../knowledge/cam/engineering/mc2-compute-collective-coupling.md)）。Case 是参考，不是复制源。

没有对应 Card / Case → 写 **未找到**，不要编容量或加速比。

### Host/device provenance check

每个写入 `TilingData` / 决定 `block_dim` 的字段，必须标明 provenance。缺一项标 **未回答**：

```text
host shape / attr        tensor.dim / size / stride / dtype 在 Host 已有
compile-time constant    架构常量、本算子冻结的 ALIGN 等
derivable host value     由上述 Host 已知量算出来（例如 S = numel / K）
device runtime value     只存在于 device tensor 内容里（例如 dup_counts[0]）
```

```text
device runtime value
  → 默认保持 device-resident，由 kernel 消费
  → 不得为了填 tiling / 选 block_dim 做 D2H

Host 可以用 device tensor 的 shape / dtype 做 bounds check
（例如 dup_loffs.size(0) >= NvS）
那是 Host-known shape，不是读 payload。

IF 某字段只能从 device payload 得到
AND task contract 没有明确允许 host sync
THEN 不要把它放进 Host tiling
     kernel 自己读 GM scalar / 小块 metadata
```

极少量 control scalar 在 **kernel 内** 读 GM 可以是 P1 的 justified Scalar。
把同样两个 int32 **拉回 Host 再 launch** 是另一件事：它在热路径上插入
device→host synchronization，破坏异步 stage → kernel → barrier。

### phase / kernel boundary

紧耦合、同属一个 fused operator 的逻辑 phase：**single device launch 是 default 候选**。
逻辑 phase 边界不得只因 Host stream barrier 方便就变成独立 `__global__`。
数 device launch：数 `__global__` 和 `*_kernel_do`，不要数 Host `Launch*` wrapper。

每个 launch 边界缺一项标 **未回答**：

```text
why not fused:            为什么不能放进同一个 kernel
mechanism search:         查过哪些 in-kernel / VEC / Host / MIX 同步 API 与仓内先例
boundary semantic:        这次 launch 提供了什么 correctness 语义
exposed global barrier:   是否所有 rank 必须做完 phase A 才开始 phase B
forbids overlap:          禁止了哪一段 producer/consumer overlap
chunk / wave alternative: 能否 phase A chunk i → publish ready → peer consume chunk i
```

拆成多次 device launch 之前，必须证明下列之一：

1. 目标硬件 / API **不能**表达所需的 in-kernel 同步
2. correctness **要求** launch 边界
3. **测量**表明 split launches 更好

淘汰 fused VEC 之前必须枚举机制空间，至少：

```text
scoped HardEvent / TQue
scoped PipeBarrier（非 PIPE_ALL）
VEC-side SHMEM barrier（aclshmemx_barrier_all_vec / aclshmem_barrier_all 等目标版本 API）
Host stream barrier（aclshmemx_barrier_all_on_stream）
MIX + device Barrier
per-PE / per-slot ready（chunk/wave）
```

禁止未查目标版本 SHMEM/Vector barrier 头文件、也未对照仓内成功先例时，
因「跨 rank barrier 必须 MIX/AIC」拒绝 fused VEC。
「单 kernel」≠「必须 MIX + device Barrier」。
仓内单 `__global__` + `ProcessPrologue → VEC barrier → ProcessCombine` 是一等候选，
必须重新验证。不要把该先例里的 `PipeBarrier<PIPE_ALL>()` 抄成合同；PIPE_ALL 仍走 P4。

```text
phase decomposition
  ≠
kernel decomposition

Host stream barrier convenience
  ≠
device launch boundary

2 kernels → 1 kernel
  ≠
pipeline

IF 方案是 prologue → barrier_all → consume
THEN 必须写清：为什么不能单 launch + in-kernel phase transition
     为什么不能 chunk-pipeline
     以及这个 barrier 保护的 publish 集合是什么
     以及 collective 的 participant scope / count / idle-core / rank 集合
     （launch set ≠ 默认等于 participant set）
```

不要求无脑 2→1。一个 kernel 内仍然全 rank barrier，性能结构可以没有本质变化。

### event phase transition

startup / steady / drain 只覆盖一个 phase。单 `__global__` 若有 `phase A → in-kernel barrier → phase B`，缺一项标 **未回答**：

```text
for each (HardEvent, eventID) used in phase A:
  phase A end state:   consumed | signaled/free | in-flight
  phase B action:      inherit | Wait then re-init | disjoint event set
```

```text
startup / steady / drain
  ≠
phase A → barrier → phase B closure

Must NOT SetFlag an already-signaled/free event
without an intervening Wait, unless target-version docs
define double-Set.

Output credits Waited at phase-end may be Set again in phase B.
Leftover input FREE tokens that were Set and never Waited
must be Waited or inherited — not Set again.
```

### parallel-axis exploration

找到第一个合法 ownership 轴之前，必须先过 **Logical Worker Topology Gate**（physical index ≠ logical worker）。
找到第一个合法 ownership 轴之后不得停止。也不得把 occupancy 不够
自动执行成「拆 inner 轴直到填满 AIV」。缺一项标 **未回答**：

```text
primary parallel axis:            保留 natural semantic/locality unit
secondary parallel axis:          none | H-tile | ...   （候选，不是 default）
2D partition candidate:
cost model:                       extra AIV  vs  duplicated metadata /
                                  repeated decode / fragmented DMA /
                                  loss of locality
small-outer / large-inner fallback:
work_items:
available_AIV:
work_items / available_AIV:
```

```text
Primary ownership should preserve the natural semantic/locality unit.

For Combine:
  default = one token per AIV
          = one group per AIV/chunk
  Secondary H partition is NOT the default.

work_items < AIV
  = a smell to investigate
  ≠
  an instruction to manufacture more work items

maximum occupancy
  ≠
optimal partition
```

只在同时满足时才考虑拆 H（或其它 inner 连续轴）：

1. primary work items 不够
2. extra active AIV 的收益超过 metadata 放大、重复 decode、碎 DMA、丢失 token/group reuse
3. shape-specific cost analysis 或测量支持

```text
candidate heuristic
  ≠
baseline policy

Without workload evidence or a hard hardware/API constraint:
  do not turn a threshold (H >= 512, …) into an automatic baseline if.
  Keep it as an optimization candidate / hook until measurement.
```

```text
IF work_items << AIV
THEN 必须审查第二轴，并给出切或不切的 cost model
答不出审查 → PERF-SMELL-10 present + unjustified

IF 为填满 AIV 默认拆 natural unit，而无上面 2/3
THEN PERF-SMELL-10 同样 unjustified

IF Design Proposal / Host tiling 把未经测量的阈值写成 baseline 自动策略
THEN PERF-SMELL-10 present + unjustified
```

不强制任何 shape 都 2D。也不强制 occupancy 不够就 2D。

### serial-island

```text
phase 内有一段必须串行
  ≠
整个 phase 落到 core0 / 单 Scalar 核
```

找到 serial 逻辑之后不得把整段 phase 绑到一个核。缺一项标 **未回答**：

```text
true serial cone:                 最小真正 serial 的依赖锥
nodes serial only by position:    只因写在 serial loop 之后才被标成 serial
producer → island → consumer:     岛前并行 / 岛内串行 / 岛后并行
SIMT remainder:                   不规则 metadata / control 是否独立评估 Scalar/Vector/SIMT
```

```text
serial island
  ≠
serial phase

Ordered identity generation
  ≠
ordered downstream computation

parallel producer
  → serial island
  → parallel consumer
```

只把「身份 / 次序决定」那几步串行。例如 stable ordinal 生成可以 serial；
destination lookup、per-token duplicate detection、DMA materialization 默认仍独立评估并行。

细则走 PBC **Serial-Island Gate**。PAC-3 必须交出 **minimal truly serial dependency cone**。不得因为一个 sub-step serial 就把整个 phase 绑到一个核。

### hot-path vs exceptional shape

不要和 parallel-axis 的跨核 occupancy 混：本条是 **intra-core 主路径抽象**。细则走 PBC **Hot-path vs Exceptional Shape Gate**。

缺一项标 **未回答**：

```text
production / task-contract inner-axis length:
fits UB + API at full length?:     yes | no | unknown
hot-path structure:                full-axis | tiled
DMA burst chunking:                inside copy helper | exposed as h_tile
exceptional fallback:              none | separate path | Host reject
fallback changes Contract semantics?:  no | yes (fail)
```

```text
If production / task-contract shapes fit UB and API
at the full inner axis (typical: H=7168 dual-in/out ≪ 248 KiB):

  baseline = full-H
  no h_tile field
  no h_off loop
  no H-tile scheduling in the hot path

DataCopyPad max burst (e.g. 65504 B)
  ≠
algorithm H tile

IssueCopyPad while-chunk stays inside the copy helper.
It does not belong in the algorithm control flow.

Only when:
  known H still exceeds UB after shrinking metadata windows
  OR the task contract explicitly requires ultra-long hidden
do you add an H-chunk fallback — as a separate path,
not by tiling the common case.

The same rule covers unrequested tail / rare dtype / huge K:
do not pollute the hot path with speculative generality.

Exceptional fallback must not silently weaken semantics.
Resource pressure may shrink a window, revise the map, or Host-reject.
It MUST NOT drop with_weight / optional output / required dtype.
```

### partition locality

分核不能只问 write conflict 和 occupancy。缺一项标 **未回答**：

```text
mapping:          contiguous chunk | cyclic/strided | 2D flattened
why this mapping:
metadata plan:    bulk DMA of a contiguous descriptor range
                  vs per-item GM GetValue
staging size:     batch / window 从 core-local range、UB headroom、
                  metadata footprint、alignment、reuse、DMA/Wait 次数推出
H vs metadata:    metadata outer → H inner
                  vs flatten (id, hTile) and re-read metadata per tile
```

```text
Prefer contiguous chunks on the natural ownership axis
unless load balance evidence requires cyclic partition.

Before choosing strided/cyclic partition, compare:
  contiguous chunk vs round-robin vs 2D split
for GM transactions, metadata reuse, load balance.

禁止未经分析的 flattened work-item round-robin。
```

descriptor 顺序若不保证相邻 id 的 payload 连续（Combine 的 `dup_start`），
对一个 batch 看 span 密度：密则一次 span DMA，稀则缩小 batch。
**若 Contract/Design 已证明 compact + monotonic，span 由头尾推导，禁止整窗 min/max 扫描。**

```text
batching exists
  ≠
batch size is sensible

typical core-local metadata fits UB
  → prefer one-shot staging
otherwise
  → monotonic / windowed staging, or metadata ping-pong
```

禁止没有 capacity/cost 理由的保守魔法 batch（如无账的 `32`）。
「做了 bulk DMA」不等于 locality 已满足。细则走 PBC **Locality Work-Elimination**。

```text
proven locality / producer invariant
  must eliminate work
  not only enable bulk DMA

compact + monotonic contiguous [g0, g1):
  loff0 = groups[g0].dup_start
  loff1 = groups[g1-1].dup_start + groups[g1-1].dup_n
  O(1) head+tail
  NOT window min/max scan
  NOT g_win-- then rescan
  NOT per-group restage of a span the window already covers

window overflow:
  derive / binary-search max g_end from monotonic end(g)
```

### UB orchestration

不得从 `CopyIn→TQue，Compute→TBuf，CopyOut→TQue` 开始设计。
performance-critical 路径的思考顺序：

```text
算法
  → 真实 lifetime
  → physical UB map（地址 / 大小 / 不重叠 reuse）
  → pipeline schedule
  → event ownership（显式 ping/pong，不是 TPipe.AllocEventID 顺带状态）
  → 最后才决定要不要用 TQue/TBuf 帮助表达其中一部分
```

缺一项标 **未回答**：

```text
physical map:  region / offset-or-address / size / owner / stage / lifetime / reusable?
               每个伪码中间值必须出现在某一 region（Cast tmp、DMA landing slot 也算）
dma landing:   每个 DMA edge 的 logical payload vs physical reserved bytes
events:        每个 ping/pong 的 RAW / WAR 是哪条已验证 primitive
strategy:      为何 TQue/TBuf/manual/hybrid 适合表达这份 map 的哪一段
project convention: 目标仓高性能 sibling 是否普遍 manual UB
```

```text
TQue exists
  ≠
TQue is the right orchestration

TPipe.InitBuffer + AllocEventID
  ≠
physical UB orchestration

hybrid
  ≠
把一个 TBuf 切成 ping/pong

AscendC development
  ≠
TPipe + TQue

double buffer
  = 时间 × 空间调度
  ≠
TQue<..., 2>
```

固定 tile、lifetime 可静态分析、强性能目标、多级 ping-pong、
要 V(n+1) || MTE3(n)、跨阶段 reuse：physical map 是第一份交付物。
目标仓高性能实现若普遍 manual UB，默认遵循该 convention，再 justify 例外。

不禁止 TQue。不写 must manual UB。TEventID 本身不一定慢；
问题是 event/UB/protocol 被 allocator 隐式管理。

**project integration** 写核前必须答完（缺一项标 **未找到**）：

```text
existing sibling operator:
call surface:          Python / ACLNN / torch.ops / custom
host registration:
shape / dtype inference:
tiling registration:
kernel entry ABI:
build system:
binding:
test harness:
write set:             本任务允许改的路径（声明后再写）
files NOT to create:
read-only siblings:    无关既有算子实现 / 测试 / 行为
```

```text
existing project
  → preserve its integration conventions
  → 用 sibling 当接入模板，默认不改 sibling 行为

standalone scaffold（operator/src + 新建 build.sh）
  → only when there is no target integration path
     or the user explicitly asks for one

task-local implementation
  ≠
permission to modify sibling operators
```

Allowed by default：新目标算子文件；必要的 registration / build / binding / 本算子测试；
确属 shared infrastructure 且有必要性证据。

Read-only by default：无关既有算子实现、无关测试、无关行为。

write set 之外的编辑必须同时有 necessity evidence、blast-radius、explicit justification，
并回答：为什么不能只改 shared helper？为什么必须改变 sibling operator？

```text
为了目标算子能编译
  → 顺手改 sibling kernel / stub 掉 sibling 符号
```

禁止。

### Performance-critical mechanism selection

对下面每一类性能关键路径，**发明 API 组合之前**先搜目标仓。细则走 PBC **Repo-native API Search Gate**。

```text
GM↔UB movement
remote SHMEM get/put
barrier / signal
atomic
vector reduction
format conversion
communication/computation overlap
```

```text
1. search target repo for successful sibling pattern
2. verify SOC / CANN version applicability
3. inspect exact statement ordering
4. record reusable idiom
5. compare against alternatives
6. the strongest matching idiom is the default baseline
7. justify deviation with contract / cost / envelope / proven-equivalence evidence
```

证据排序：

```text
1. same repo + same SOC + same CANN + same transport direction / pipeline role
2. same repo + same hardware generation + similar dataflow
3. target-version first-party example
4. API documentation
5. generic implementation invented from API legality
```

```text
search complete
  ≠
idiom selected

A legal generic implementation
  must not automatically win
  over a project-proven idiom

same-role sibling idiom
  = default baseline

Deviation requires at least one of:
  API contract does not apply
  extra resource / sync cost
  worse pipeline envelope
  target-version impl proven equivalent AND a named benefit for the lower-level path

Match the transport role, not the sibling operator name:
  remote PUT → look at PUT ops
  remote GET GM→UB→V → look at GET-class ops
  local GM↔UB → mapped Pad may already be the idiom

Reuse the implementation idiom,
not the entire operator architecture.

Do NOT copy:
  unrelated SOC-specific constants
  unrelated protocol
  unrelated tiling
```

若所选 API 与最强本地模式不同，Design Proposal 必须解释 why（上面四条之一）。
只写「搜过、比过、仍选 generic」不够。
换 API 若改变 UB scratch / event / completion 模型，必须重开 UB map 与 pipeline Gate。

### side-path vs dominant pipeline

细则走 PBC **Side-path Integration Gate**。不要和 Steady-state per-phase 混：那条是每个 phase 自己会不会叠；本条是 **dominant ∥ side 联合排程**。

缺一项标 **未回答**：

```text
dominant path:     e.g. hidden row + Vector reduction
side path:         none | weight gather / scale / metadata / flag
side frequency:    per-token / per-k / per-group
joint timeline:    drawn | not drawn
side placement:    interleaved into dominant idle slots | serialized after dominant
```

```text
For an operator with a dominant payload path and a small,
high-frequency side path:

do not review their pipelines only independently.
Build a cross-subpath timeline.

Examine:
  MTE2 side traffic during V-heavy periods
  Scalar side work during V / MTE
  MTE3 side output during next item's MTE2 / V

MTE2 cannot issue hidden and weight at the same instant.
The requirement is: do not dump all tiny MTE2 after hidden completes.

A side path serialized after the dominant path requires
a cost justification or profiling evidence.
```

---

## 4. Gate A — before kernel

**必须打开** [references/performance-by-construction.md](references/performance-by-construction.md)。不要只靠本页摘要。

1. 走 **P1–P5 + Memory Orchestration + Physical Realizability**，以及 PBC 其余具名 Gate（operand graph、Event 拓扑表、overlap envelope、API Invocation Contract、Launch Admission、Hot-loop Traversal、**Logical Worker Topology**、**Frozen-Clause Extraction**）
2. 每个 present smell 写 justification
3. 交 UB map（含 Cast/DMA 中间物理 region 与 landing footprint）**和** 每个实际运算的 operand graph（src/dst 可定位；width-change 禁止口头 in-place）
4. **每个** performance-relevant phase 交 Steady-state 2-iteration timeline，不得只画 main；同时交 pipeline resource depth（stages → buffers → credits）**和** 该 phase 自己的 E1/E2/E3 envelope 比较（一阶段 ping-pong ≠ kernel PASS）
5. 有 side path 时交 **cross-subpath** timeline；跨 phase 时交 Event ID 交接表；manual HardEvent **先**交 writer/reader/next-writer 推导表再冻类型
6. common-case 可 full-axis 则 hot path 不得带 `h_tile`；same-role idiom 是 default；资源上限 path-scoped
7. 性能关键 / 非自然对齐 DMA：冻结 API 后交 **API Invocation Contract**（overload、单位、source/dest extent、padding）；默认 `{}` 不是证据
8. kernel 声明 supported domain；Host 检查必须等价或更严（**Launch Admission**，可执行 guard，不只 Design 散文）

物理项未完成 → **不得**进入 PAC，也 **不得**进入 §5。P-gate 正文不在本 Skill 复述。

### Performance Architecture Challenge

对 **每一个** 已经物理成立的 baseline 走。物理 Gate A PASS 只证明它合法，不证明它该被 freeze。

```text
physical Gate A PASS
  ≠
allowed to freeze

correct and affordable
  ≠
best justified production baseline
```

七条（缺一条标 **未回答** → 不得 freeze）：

```text
1. Over-materialization
   Is any tensor communicated/materialized only because it can later
   reconstruct the actual consumer state?

2. Sufficient-state communication
   Can producer-side transformation reduce cross-rank bytes, replicated
   workspace, remote scans, or synchronization?

3. Serial-island decomposition
   Identify the minimal truly serial dependency cone.
   Do not assign an entire phase to one core merely because one sub-step
   is serial.

4. Execution mapping
   Evaluate Scalar / Vector / SIMT independently for irregular metadata
   and control-heavy work.

5. Communication envelope
   Compare bytes/rank, total bytes, remote operations, barriers,
   replicated state, and asymptotic scaling.

6. Resource budget
   Distinguish physical UB capacity, kernel-mode/framework budget,
   API-reserved regions, and user-allocatable bytes.

7. Challenge the baseline
   A design being correct and affordable is not sufficient evidence that
   it is the best justified production baseline.
```

PAC **不**把更复杂的协议强制成 L1。合法输出包括：当前 candidate 是合法 L1；L2 candidate 写下（可本轮不实现）；七条都有答案。

```text
payload smaller than some other operator
  ≠
this operator's communication choice is justified
```

L1 可以 freeze 较简单、物理闭合的协议，但必须记录被挑战过的 L2 候选，以及为什么现在 freeze 它而不是 L2。
不得把某个 sibling / 外部参考实现的复杂度写成 L1 合同。
原则读 [sufficient-state](../../../../knowledge/cam/engineering/communicate-sufficient-state.md)；
细则走 PBC **PAC-1…7** / **Serial-Island** / **P1** / **Kernel Resource Budget**。

PAC 未完成 → **不得**进入 §5。

---

## 5. Implementation

写第一行代码前交出三张表、**write set** 和 **Frozen-Clause Extraction 表（FC-001…）**：

```text
READ-ONLY INPUTS:
WRITEABLE DESIGN ARTIFACTS:
IMPLEMENTATION WRITE SET:
```

未声明不得改文件。immutable human input 不在 write set 里，即使用户没提 sibling。

只约束行为：

- 实现必须匹配 Operator Contract（fact 当合同；inference 须标明；blocking unknown 仍禁止）
- Design 里的 FROZEN / MUST / exact / selected / do not replace 条款必须按字面落地。不得改成「看起来等价」的更短写法（典型：`GetBlockIdx()/GetSubBlockNum()` → `GetBlockIdx()`），除非给出 **本条 launch** 的 first-party 等价证明
- 资源边界若有 first-party 编译期符号，必须机械绑定（用该符号或 `static_assert`），不要只复制魔法常数
- 遵守 Gate A + PAC 冻结的结构；不要回头写成 bulk Scalar / 无理由 PIPE_ALL / 碎 Vector
- **不要**把不规则 metadata / control-heavy 工作先标 Scalar 再决定要不要看 SIMT；Scalar / Vector / SIMT 必须独立评估（PAC-4）
- **不要**在本 Skill 或回复里重讲 DataCopy / TQue / `num` vs `depth` / UB 容量表
- 不要整份复制不匹配的 Case
- 对照成熟实现时按 [golden-delta-review](../../../../knowledge/cam/engineering/golden-delta-review.md) 分类，不要「和 Golden 不同就改成 Golden」
- 优先沿用目标仓已有 OpDef / CMake / pybind / registration / compile 脚本 / test harness 的 **接入方式**；**不要**在已有接入路径上另起孤立 `operator/` 工程
- 性能关键机制冻结前必须做 **repo-native API search**：先搜仓内成功 idiom；**same-role idiom 是 default baseline**；搜过 ≠ 已选；偏离须 contract/成本/envelope 证据
- sibling 算子实现默认只读。不要为了本算子能链接/编译去改无关 kernel、stub 掉 sibling 符号、或改变无关测试行为
- **不要**用 UB 不够 / 超长 shape fallback 静默改 Contract 语义（关掉 with_weight、丢掉 optional output）。应缩 window、改 map 或 Host reject
- 模仿 API idiom ≠ 模仿整个 sibling operator（协议 / tiling / SOC 常量不抄）
- 必须接到目标仓可重复的构建入口和正确性测试（已有 harness 优先于新建 `build.sh` / `test.py`）
- 不要为「看起来快」加入无测量的极致微优化

蓝区无 NPU：能编则编；Runtime / Correctness 标 **未测**。跨域怎么搬：[correctness-debug workflow](../../../../workflows/cam/operator/correctness-debug/README.md)。

打点代码不进 development baseline。需要阶段证据再走 instrumentation。

---

## 6. Validation / Routing

| 观察 | 走 |
| --- | --- |
| 写完 / 改完，要上板验证 | `cam-operator-run`（禁止直接目标 e2e / msprof） |
| 编译 / 加载失败 | `cam-operator-run` 填卡后 `cam-operator-debug` |
| 跑起来返回码非 0 / hang / crash | `cam-operator-run` 填 FIRST BAD 后 `cam-operator-debug` |
| kernel 跑完但结果错 | `cam-operator-debug` |
| 协议/参数突然对不上 | 可让 spec-reconstruction 取证；诊断仍由 debug 主导 |
| API 单位/overload 不清 | `cam-operator-docs-search` |
| 编译过（或静态完成）且准备收 L1 baseline | **Gate B** |
| 正确性已过、还要更快 | `cam-operator-optimization`（先测） |

不要在本 Skill 里排 507035 假说树。

---

## 7. Gate B — L1 baseline completion

**必须再打开** [performance-by-construction.md](references/performance-by-construction.md)。

顺序固定，不能先填 smell 表：

```text
1. Frozen-Clause Traceability
2. physical → logical worker topology
3. PERF-SMELL-01…12 + whole-call-graph + Gate B.5
```

### 7.1 Frozen-Clause Traceability

在「我重新推理这段代码对不对」之前，先回答：有没有忠实执行 Frozen Design。

每个 Design 中的 FROZEN / MUST / exact / selected / do not replace 条款生成一行：

| Frozen clause | Actual code | Equivalence |
| --- | --- | --- |
| 原文公式 / 约束 | 函数名 + 位置 | exact match / proven equivalent / **mismatch** |

```text
mismatch 且没有对本 launch 的 first-party 等价证明
  → Gate B = FAIL
```

禁止把 target-specific 公式替换成看起来更短的写法后再宣称符合 Design。

### 7.2 Worker topology

`<<<block_dim>>>` 和 `GetBlockIdx()` **不**自动等于 logical worker。必须先写出：

```text
core_ratio / AIC vs AIV / GetBlockIdx / GetBlockNum
/ GetSubBlockNum / GetSubBlockId
        ↓
worker_id ∈ [0, worker_count)
每个参与的 logical worker 恰好一个 worker_id
每个 work item 恰好一个 owner
        ↓
才允许证明 task % worker_count 覆盖
```

不得：假设 worker_id 正确 → 证明 stripe 数学 → PASS。细节见 [tiling-from-shape](../../../../knowledge/cam/engineering/tiling-from-shape.md) §3。

### 7.3 Performance smells / reconstruction / IAC

走 **PERF-SMELL-01…12**。每条：`absent` / `present + justified` / `present + unjustified`。

核对 **write set**：`git diff --name-only` 对照 Design Proposal 声明的路径。
未解释的 sibling-operator / 无关测试修改 = Gate 失败，即使 PERF-SMELL 全过。

声称 pipeline / double buffer / 通信掩盖时，再走
[Steady-state execution review](references/performance-by-construction.md)：
按 **statement ordering** 为 **每个** performance-relevant phase 画至少两个 iteration，
不得用「有 num=2」或「prologue 比较小」代替。
有 small high-frequency side path 时必须再交 **cross-subpath** 联合 timeline。
每个 performance-critical loop 还必须交出 **pipeline resource depth**
（concurrent stages → buffers → event credits）。闭环的 Set/Wait 不够；声称 `MTE2(n+1)||V(n)||MTE3(n-1)` 却只有一套 out / 一个 store credit → PERF-SMELL-04 unjustified。
跨 phase 重复 Set 已 signaled 的 FREE event → PERF-SMELL-05 unjustified。

再走 PBC **Gate B actual-code reconstruction**（Buffer / Operand / Timeline / Traversal / API invocation / Support domain / **whole-call-graph** / **publication graph** / **logical worker** / **integer arithmetic** / **sync minimality**）。
对不上 Gate A 冻结表 → 对应 smell unjustified。

Gate B 必须闭合 **Frozen-Clause Traceability**：extracted count == closure count。
MATCH / PROVEN_EQUIVALENT / 未解释 DEVIATION / MISSING 的规则见 PBC 同名节。
未解释 DEVIATION（含「看起来更快 / 更安全」）→ 不得 PASS。

对照参考实现时走 [golden-delta-review](../../../../knowledge/cam/engineering/golden-delta-review.md)：
different from Golden ≠ change to Golden。

Gate B 必须重建 **whole-call-graph**，不只 helper 内部的 event 链：

```text
writer
  → actual caller statement
  → helper
  → consumer
  → return
  → next writer

helper-local event chain PASS
  ≠
whole-call-graph PASS
```

Wait / reuse / 下一写 必须落在 **caller 的实际语句** 上，不得从 helper 入口倒推。

遍历复杂度必须按 **完整可达 helper 链** 相乘，不能只看 caller 主循环：

```text
Traversal intent ≠ traversal complexity.

outer loop
  × called helper
  × helper nested loop
  × helper-of-helper
  = actual complexity
```

不得只给 `ProcessP*` 主体贴一个复杂度标签。O(B) helper 放进 O(R·E) caller → 实际路径 O(R·E·B)。

复用 buffer 时，lifetime 不重叠不够。必须做 **max-footprint closure**：
`allocated_extent >= max(all phase-specific footprints)`，覆盖整个 Host-admitted domain。
handshake / 完成字还要证 **leftover identity**：下一发不得把上一发 flag 或后级 payload 踩踏认成 ready。

每一条跨 mechanism / 跨 phase 的 producer→consumer 边都要进 **publication graph**。
同一 AIV、ABI tensor、两端都是 SIMT，也不省略 visibility 证明。

### Gate B.5 — Implementation Adversarial Challenge

对称于 Gate A 的 PAC。细则走 PBC 同名节；原则读
[implementation-adversarial-statics](../../../../knowledge/cam/engineering/implementation-adversarial-statics.md)。

```text
Assume implementation faithfully follows the design.
How could actual statements still violate it?
```

宣称 Static PASS **之前**，必须主动搜索（缺一项标 **未攻击**，不得 PASS）：

```text
- frozen-clause rewritten as "looks equivalent"
- GetBlockIdx used as logical worker without topology proof
- helper-introduced extra traversal
- caller/callee ordering mismatch
- buffer reuse before completion
- phase-specific footprint larger than allocation
- one-shot flag leftover / overlay smash looking like next-launch ready
- support-domain inequality missing from Host
- execution-engine transition with no visibility proof
- logical stride vs physical stride mismatch
- identical-looking writes with overlapping padded footprint
- hidden fallback/general path that violates hot-path assumptions
- a comment/proposal claiming something no longer true in source
```

```text
Static PASS
  =
  negative search found no remaining defect
  ≠
  reconstruction checklist filled
```

```text
Frozen-Clause mismatch（无 first-party 等价证明）
  → baseline 未完成

worker topology 未构造就把 stripe 标 PASS
  → baseline 未完成

present + unjustified
  → baseline 未完成
```

Gate B 通过 = L1 忠实于冻结条款，且不是明显低质量结构。**不是** L2 / 性能最优。
Frozen-Clause mismatch（无 first-party 等价证明）或 worker topology 未构造就把 stripe 标 PASS → 不得写 Static PASS。
未完成 B.5 负向搜索 → 不得写 Static PASS / L1 baseline complete。

---

## 8. Decision Rules

```text
MUST     无可靠 Contract / 存在 blocking unknown 时先 reconstruction
MUST     写任何设计/代码前声明任务类型：NEW OPERATOR 或 EXISTING OPERATOR FEATURE
MUST     NEW 第一轮只做 Design + Gate A，不改 production source
MUST     EXISTING FEATURE 第一轮只做 Baseline Reconstruction，隐藏未来方案
MUST     写核前打开 performance-by-construction，完成 Gate A（新算子）或 Gate A-Delta（Feature）
MUST     物理 Gate A 之后、freeze 之前完成 PAC；七条未回答不得写核
MUST     写核前完成 project integration 轴并声明 write set；有现成接入路径则沿用方式，不改 sibling 行为
MUST     宣称 L1 baseline complete 前完成 Gate B：Frozen-Clause Traceability、worker topology、whole-call-graph reconstruction、Gate B.5 Implementation Adversarial Challenge 与 `git diff --name-only` 对照 write set
MUST     Design FROZEN/MUST/exact 条款逐条对到源码；mismatch 无 first-party 等价证明则 FAIL
MUST     工作划分前写出 physical launch index → logical worker；禁止假定 GetBlockIdx()==worker_id
MUST     accepted Knowledge 已覆盖的 API / 硬件事实只链不述
MUST NOT 把纯串行 / bulk Scalar / 满屏 PIPE_ALL / 碎 Vector 当 correctness-first 第一版
MUST NOT 物理成立就 freeze；PAC 七条未交不得写核
MUST NOT 用「相对另一个更大算子 payload 很小」证明本算子通信选择
MUST NOT 把更复杂协议强制成 L1；L1 可保留较简方案，但必须记录被挑战过的 L2 候选
MUST NOT 把 correct and affordable 当成 best justified production baseline（PAC-7）
MUST NOT 把 phase 内一段 serial 逻辑自动写成整个 phase 落 core0；ordered identity generation ≠ ordered downstream computation
MUST NOT 把不能 Vector 的不规则独立工作自动写成必须 Scalar；Scalar / Vector / SIMT 必须独立评估
MUST NOT 把 reconstructible state 当 default 跨 rank / 跨核 materialization（核心原则：Communicate sufficient state, not reconstructible state）
MUST NOT 只审查 helper 内部 event 链；必须重建 writer → caller statement → helper → consumer → return → next writer
MUST NOT 只报 helper 内复杂度或只给 caller 主循环贴标签；outer × helper × nested × helper-of-helper 必须相乘
MUST NOT 只因 lifetime 不重叠就宣布 overlay 合法；必须 max-footprint closure + alignment
MUST NOT 因同一 AIV / ABI tensor / 两端 SIMT 省略 producer→consumer visibility 证明
MUST NOT 用填完的 reconstruction checklist 自证 Static PASS；PASS 必须来自 Gate B.5 负向搜索
MUST NOT 把冻结的 target-specific 公式改成「看起来等价」的更短写法
MUST NOT 对照成熟实现时无分类地改成 Golden
MUST NOT 在已有目标工程接入路径上另起孤立 scaffold
MUST NOT 无测量报加速比或声称最优
MUST NOT 把当次 Contract 升成 Weaver Knowledge
MUST NOT 为过 P-gate 引入无测量的 magic tile / 指令级改写
MUST NOT 把 repo 默认 SOC / sibling 硬件常量升成本次 operator target
MUST NOT 为填 Host tiling / 选 block_dim，无理由把 device runtime metadata D2H
MUST NOT 把逻辑 phase 只因 Host stream barrier 方便就拆成多次 device launch；拆 launch 前必须过 1/2/3 并枚举同步机制
MUST NOT 未查目标版本 SHMEM/Vector barrier API 与仓内先例，就把 fused VEC 等同于「必须 MIX + device Barrier」而淘汰
MUST NOT 用 TQue `num=2` 代替 Steady-state timeline 来声称 pipeline
MUST NOT 只对 dominant/main phase 画 pipeline，而跳过同样含 MTE2/V/MTE3/comm 的 prologue/epilogue
MUST NOT 把闭环 Set/Wait 当成足够的 pipeline 资源；声称 `MTE2(n+1)||V(n)||MTE3(n-1)` 必须配齐独立 buffer / store credit
MUST NOT 把「尽量少用 Event ID」当成目标
MUST NOT 把算法伪码表达式当成已证明的 API 数据通路（如 `Add(acc, Cast(in))`），除非 cam-operator-docs-search 已证明 fused API
MUST NOT 只按 logical payload 填 UB map，而跳过 DMA destination alignment / physical landing footprint
MUST NOT 在 `work_items << AIV` 时只交付第一根合法 ownership 轴而不审查第二轴
MUST NOT 把 `work_items < AIV` 当成必须制造更多 work items / 默认拆 H 的指令
MUST NOT 把未经测量的启发式阈值（如 `H >= 512`）写成 baseline 自动策略
MUST NOT 未比较 contiguous vs cyclic vs 2D 就 flattened round-robin 分核
MUST NOT 用无容量账的魔法 metadata batch 代替 one-shot / windowed staging
MUST NOT 从 TPipe/TQue/TBuf 开始设计 performance-critical UB；不得把 TQue Card 当成「该用 TQue」
MUST NOT 把 heuristic 写成绝对规则（must split / must double-buffer / must fuse / must manual UB）
MUST NOT 在 manual HardEvent 路径上只声明 dependency table、不在 statement schedule 成对 Set/Wait，或 Wait 一个从未 Set 的 `*_FREE`
MUST NOT 在声明的 write set 之外改 sibling 算子实现 / 无关测试 / 无关行为；禁止为编译本算子 stub 掉 sibling
MUST NOT 仅凭 “all launched cores call it” 让 device collective 过 Gate A；必须证明 launch geometry 与 required participation set 一致
MUST NOT 改 immutable human input（docs / 已 review 的 semantic contract / 用户点名的设计资料），除非用户明确授权该文件
MUST NOT 把 immutable human *file* 里的每句话都当成 frozen design constraint；sketch / 示例必须在 Contract 分级，偏离记 Design Proposal，不得改文件去对齐实现
MUST NOT 用改设计文档来消掉实现冲突；冲突要 report + 另提 patch，实现向已分级的 fact 收敛
MUST NOT 只因 API 合法就冻结性能关键路径；必须先搜 target-repo 成功 idiom；**same-role idiom 是 default**；搜过仍选 generic 而无 contract/成本/envelope 证据
MUST NOT 在 Design 已选 metadata staging/windowing 后，overflow 静默退回逐元素 GM GetValue；改 residency/locality class 必须重开对应 performance Gate
MUST NOT 在已证明 compact/monotonic 后仍整窗 min/max 扫描求 span，或 `g_win--` 重扫，或按组补 CopyIn 覆盖本可由头尾推导的 range
MUST NOT 在 production/task-contract 可 full inner axis 时把 `h_tile` / `h_off` 写进 hot path；DMA burst 切块不得升成算法 tile
MUST NOT 用资源不够的 fallback 静默关掉 Contract 要求的 with_weight / optional output / required dtype
MUST NOT 只独立审查 dominant 与 side-path 流水，却不交联合 timeline；side path 默认串在 dominant 之后而无 cost model
MUST NOT 在 phase A 结束后对已 signaled/free、未经 Wait 的 Event ID 再 SetFlag 作为 phase B startup
MUST NOT 按 sibling 熟名挑选 HardEvent 类型；类型必须从 writer/reader/next-writer 推出
MUST NOT 因同一 AIV / 共享 workspace 已重建就跳过 ABI tensor / SIMT→SIMT 等跨 mechanism 边的 visibility 分类
MUST NOT 用「or in-place promote」让 width-change Cast 混过 operand graph；dst 必须可定位且 alias 有 API 证据
MUST NOT 证明当前 schedule 能跑就停；**每个** dominant phase 都要比较 E1/E2/E3；一阶段 ping-pong 不能给整 kernel pipeline PASS
MUST NOT 把 sibling API 的资源上限自动套到 provenance tuple 不一致的路径；不得用「更小更安全」改写 Frozen Design 的 target-specific envelope
MUST NOT 仅因 Host 发射了 N 个 block 就把 `worker_id = GetBlockIdx()`；remainder 证明在错误 worker-space 里自洽仍失败
MUST NOT 让实现 Agent 自选 Frozen-Clause 子集；extracted count ≠ closure count，或未解释 DEVIATION/MISSING，不得 Gate B PASS
MUST NOT 用「更保险」保留已被后续更强原语覆盖的 quiet / PIPE_ALL / extra fence；每个同步原语必须对应一条 distinct unsatisfied edge
MUST NOT 只审计乘法 overflow；整数审计必须覆盖 negation / INT_MIN / sentinel / ceil-div / narrowing / shift
MUST NOT 把 default `{}` / 未证明的 blockLen 单位代替参数级 footprint
MUST NOT 把 UB 驻留的 metadata 当成免费 repeated scan；逻辑单遍消费不得退化成 O(N²) helper；也不得漏掉 helper 把 O(R·E) 乘成 O(R·E·B)
MUST NOT 只在 Design 写 kernel unsupported、Host 却用更弱 sibling cap 放行；Host guard 必须覆盖 kernel domain，且包含每一条物理 footprint 不等式
MUST NOT 在 `SetValue`/`DataCopyPad` 循环里复用同一源 UB，却不证明上一发 MTE3 已消费该 UB；循环尾 `PIPE_MTE3` 不能代替迭代间 `MTE3_S`
MUST NOT 用 consumer 切片 overlap 决定等不等 group-end / per-core 完成字；waiter expected 必须与 publisher grain 同为整 bucket，否则漏等或假死等
MUST NOT 用数学顺序不同的 sibling/dispatch 参照当 golden 来判定 fused kernel 错（漏 smooth、先 quant 再乘、跨 rank 不同 smooth 表）
MUST NOT 把 `export FEATURE=1` 当成 Host tiling 已放行该 path；门控（mask / multi-round / 状态洞）关掉时你在调 baseline
MUST NOT 从旧成功日志整表复制 `HCCL_BUFFSIZE` / 可见卡 / conda 当本次上板合同
MUST NOT 在尚未获得「该 path 已 admitted 且失败发生在 fused 之后」的上板观察前，因静态审查扩 IPC hole、清双 bank 或改 publication
MUST NOT 写完核就跑目标 shape 完整测试或 msprof；上板必须进 cam-operator-run
MUST NOT 把 handshake / 完成字 overlay 在同 kernel 后级会写的 payload 上，却不 consume、不双 bank、也不在下一发 waiter 采样前清平面
MUST NOT 把单次 launch PASS 当成新 flag 协议 leftover-safe；必须再跑至少一发（dataState 翻转或后级 smash 之后）
MUST NOT 在 dest 仍按 plan count 等待时静默丢掉 planned one-shot（cap 超了就 return）
MUST NOT 未声明任务类型就当新算子写
MUST NOT 对已有算子 Feature 跳过 Baseline Freeze，或带着预定方案读源码
MUST NOT 未获用户批准从 Gate A / Baseline Freeze / Gate A-Delta 自动进入下一阶段
MUST NOT 把 Feature Delta 做成整算子重设计；write set 必须是 Blast Radius 投影

IF 任务类型未声明
THEN 先问 NEW OPERATOR 还是 EXISTING OPERATOR FEATURE；不得开写

IF EXISTING OPERATOR FEATURE 且 Baseline 未 Freeze
THEN 只走 Baseline Reconstruction；MUST NOT 提 Feature 方案或改 production source

IF NEW OPERATOR 且用户未批准 Gate A
THEN 停在 Design；MUST NOT Implementation

IF 用户已给出完整可开发语义且与调用一致 且 任务是 NEW OPERATOR
THEN 写成 Contract 后从 Design Proposal 起步

IF target SOC / CANN 会影响 API legality / memory hierarchy / synchronization / tiling / compile path
AND hardware 或 CANN 仍 unknown
THEN 停在 Contract；不得进入 Design Proposal / Gate A

IF Gate A 物理项未完成
THEN 不得进入 PAC / 写 kernel

IF PAC 七条未回答
OR communication envelope 用另一个算子的 byte count 当证明
OR 只证明 correct and affordable 而未挑战 baseline
THEN 不得 freeze Design / 写 kernel

IF 用户要上板测 / 改了 kernel 要验证
THEN 离开本 Skill，进 cam-operator-run；MUST NOT 直接 build + 完整测试

IF compile / runtime / wrong-result
THEN 先有 ITERATION 卡（FIRST BAD），再进 cam-operator-debug

IF correctness passed 且还要更快
THEN 离开本 Skill，进 cam-operator-optimization

IF 需要阶段 timing
THEN instrumentation 只供 evidence

IF Case 的 shape / dtype / hardware / 内存约束对不上
THEN 不得整份复制

IF 目标仓已有 sibling operator / CMake / test harness
THEN 沿用其接入方式，不得新建平行工程
AND 不得把 sibling 实现当成可写集合；sibling 默认只读

```

---

## 9. Output Contract

回复必须能让人 10 秒内看出：当前阶段、下一步、打开了哪个资产、为何能/不能继续。

至少交出：

1. Operator Contract（本轮产出或指向已有）；blocking / non-blocking unknowns
2. Design Proposal（§3 各轴，含 **project integration / write set**、**phase / kernel boundary**（含 mechanism search）、**event phase transition**（含拓扑推导表）、**parallel-axis exploration**、**serial-island**、**hot-path vs exceptional shape**、**partition locality**（含 staging size 与 invariant 消扫描）、**UB orchestration**、**physical realizability**（operand graph）、**API invocation contract**、**launch admission**、**execution mapping（Scalar/Vector/SIMT 独立评估）**、**over-materialization**、**sufficient state**、**communication envelope**、**kernel resource budget**、**side-path vs dominant**、**physical → logical worker**；缺的写 **未重建**）
3. Gate A：P1–P5 + Memory Orchestration + Physical Realizability + justification；UB map（含中间物理 region / DMA landing）**和 operand graph**；**Logical Worker Topology**；每个 performance-relevant phase 的 2-iteration timeline **和** pipeline resource depth **和** 该 phase E1/E2/E3；**dominant+side 联合 timeline**（若有 side path）；Event 拓扑推导表；API Invocation Contract；Launch Admission 对照表；**Frozen-Clause Extraction（FC-001…）**
4. PAC：七条逐条答案；communication envelope（对本算子 critical path）；minimal serial cone；L1 freeze 理由 + L2 candidate（PAC-7：correct and affordable ≠ 已证明该 freeze）
5. 接入目标仓的源码改动（**声明的 write set**）；构建入口 + 测试入口（优先已有 harness）
6. Gate B：Frozen-Clause 表；worker topology 证明；PERF-SMELL-01…12 表；`git diff --name-only` vs write set；按 statement ordering 的 Steady-state review（不得自我总结）；**whole-call-graph reconstruction**（writer → caller statement → helper → consumer → return → next writer；**outer × helper × nested × helper-of-helper**）；**publication graph**；**Frozen-Clause Traceability closure**（count 对齐）；**integer arithmetic audit**；**sync minimality table**；**Gate B.5 IAC**（负向搜索清单；未攻击不得 Static PASS）
7. 状态：`Compile` / `Runtime` / `Correctness` = PASS / FAIL / NOT TESTED
8. 明确：**L1 performance-aware baseline**，不是 L2 / 最优实现

缺 Gate A、PAC 或 Gate B，或 Frozen-Clause mismatch 无等价证明，或存在 `present + unjustified`，或 write set 外有未解释改动，或 Gate B.5 仍有「未攻击」项，不得写「L1 baseline complete」/ Static PASS。
