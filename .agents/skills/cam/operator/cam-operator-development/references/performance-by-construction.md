# Performance-by-Construction

本文件是 [cam-operator-development](../SKILL.md) 的 **第一版结构门禁**。主 Skill **必须**在三个时刻打开本页：Gate A、PAC、Gate B。

```text
Gate A  Design Proposal 完成、写 kernel 前
        → 走 P1–P5（P1 = Scalar / Vector / SIMT）
        → Memory Orchestration Gate
          （含 Kernel Resource Budget：physical ≠ kernel-mode ≠ API reserved ≠ user）
        → Physical Realizability Gate
          （每个实际运算的 operand graph；width-change 禁止口头 in-place）
        → Hot-path vs Exceptional Shape Gate
        → Launch Admission Gate
          （kernel supported domain → 可执行 Host guard）
        → Logical Worker Topology Gate
          （physical launch index ≠ logical worker identity；分核前先证 worker-space）
        → Frozen-Clause Extraction
          （写核前穷举 FC-001…；不得自选 checklist）
        → Repo-native API Search Gate
          （same-role idiom default；资源上限 path-scoped；provenance tuple）
        → API Invocation Contract Gate
          （冻结 API 后仍证 overload / 单位 / pad / dst footprint）
        → Side-path Integration Gate
        → 每个 present smell 给 justification
        → 交 physical UB map（lifetime / reuse / events；allocator 在 map 之后）
        → 热路径每个运算落到 concrete API + 物理 src/dst；每个 DMA 填 landing
        → 每个 performance-relevant phase 交 Steady-state timeline
          （不得只画 dominant/main phase）
        → 每个 performance-critical loop 交 pipeline resource depth
          （intended stages → buffers → event credits；闭环 ≠ 够飞）
        → **每个** dominant phase 比较 E1/E2/E3 overlap envelope
          （一阶段 ping-pong ≠ 整 kernel pipeline PASS）
        → manual HardEvent：先冻结 writer/reader/next-writer 表，再选类型
        → 跨 phase kernel：走 P4 Phase-transition closure
          （phase A 结束时每个 Event ID 的 state + phase B 接手方式）

PAC     物理 Gate A 之后、对每一个 physically valid baseline、Design freeze 之前
        → 1 Over-materialization
        → 2 Sufficient-state communication（producer-side transform）
        → 3 Serial-island：minimal truly serial dependency cone
        → 4 Execution mapping：Scalar / Vector / SIMT 独立评估
        → 5 Communication envelope（bytes/rank、ops、barriers、replicated state、scaling）
        → 6 Resource budget（physical ≠ kernel-mode/framework ≠ API-reserved ≠ user-allocatable）
        → 7 Challenge the baseline：correct and affordable ≠ best justified production baseline
        → 七条全部回答；L1 freeze 可保留较简协议，但必须记录 L2 candidate
        → 未回答 PAC → 不得 freeze / 不得写 kernel

Gate B  第一版 kernel 写完、宣称 L1 baseline complete 前
        → 先 Frozen-Clause Traceability + worker topology
          （工序在 cam-operator-development SKILL §7.1/7.2）
        → 再走 Static Performance Smell Review
        → PERF-SMELL-01…12
        → absent / present+justified / present+unjustified
        → 按 statement ordering 做 Steady-state execution review
          （每个 performance-relevant phase；不得只接受自我总结）
        → actual-code reconstruction：operand graph / Event 类型 /
          envelope / Pad footprint / iterator 复杂度 / Host guard /
          **whole-call-graph**：
            writer → actual caller statement → helper → consumer
            → return → next writer
          **traversal**：outer × helper × nested × helper-of-helper
            （不得只给 caller 主循环贴复杂度标签）
          **overlay**：lifetime ∩ max-footprint ∩ alignment
          **publication graph**：每个跨 mechanism / 跨 phase 边
          **sync minimality**：每个 Wait/barrier/quiet 对应一条未满足边
          **integer arithmetic**：乘法之外含 negation / sentinel / narrowing / shift
          **logical worker reconstruction**：从 actual GetBlockIdx/subblock 重建 ownership
        → Frozen-Clause Traceability closure
          （extracted count == closure count；MISSING/未解释 DEVIATION → 不得 PASS）
        → Gate B.5 Implementation Adversarial Challenge
          （假定实现忠实于 Design，主动搜 helper/reuse/phase-transition 违例）
          静态 PASS 必须来自负向搜索，不是 checklist 自证
        → 实现必须匹配 physical UB map 与 Physical Realizability 表
          （不得把 InitBuffer / AllocEventID 当 orchestration）
        → write set / sibling 只读：见主 Skill Implementation Gate
          （`git diff --name-only`；本页不审查路径）
```

`present + unjustified` → 不得宣称 L1 development baseline complete。
PAC 七条未回答 → 不得 freeze Design / 写 kernel。
correct and affordable → 仍须走 PAC-7，不得直接 freeze。

不是第二份优化百科，也不是硬性能规则。启发式要比较，不要写成绝对指令：

```text
enumerate candidates
  → cost model
  → preserve locality
  → justify choice

work_items < AIV
  = smell to investigate
  ≠
  manufacture more work items

candidate heuristic
  ≠
  baseline policy
```

```text
cam-operator-development  P-gates
  = 第一版就不要犯明显性能结构错误

cam-operator-optimization
  = 已经跑起来之后怎么测、怎么找 exposed bottleneck
```

```text
smell
  → requires justification

smell
  ≠ automatically invalid
```

API / 容量合同仍读已 accepted 的 Knowledge。本页不发明「UB 比 GM 快多少」，也不强制所有算子 double buffer 或 TQue。

---

## P1 Scalar / Vector / SIMT Granularity Gate

不规则 metadata / control-heavy 工作必须 **独立** 评估三条轴，不要先判 Scalar 再决定要不要看 SIMT：

1. **Vector**：是否逐元素重复的 bulk work？粒度够不够大、是否连续、有没有 tiny Vector call？
2. **SIMT**：是否不规则、indexed、彼此独立（lookup / search / per-item branch / atomic）？
3. **Scalar**：是否真 serial control / 少量 metadata / tiling？

PAC-4 在 freeze 前再走一遍这三轴。Gate A 的 P1 不能用「有分支」直接结案。

```text
bulk elementwise work
  → prefer Vector path
  → prefer sufficiently large contiguous Vector work

small control / meta / index / tiling scalar
  → Scalar may be appropriate

irregular indexed independent work
  （lookup / search / per-item branch / atomic update）
  → SIMT is a first-class candidate
  → 不能 Vector ≠ 必须 Scalar

Vector API
  ≠
automatically efficient

cannot Vector
  ≠
must Scalar
```

一个 logical phase 允许混用 Scalar / Vector / SIMT。不得把整段 phase 因其中一处 serial 而全部标成 Scalar。

典型 smell（Scalar bulk）：

```cpp
for (int i = 0; i < 1024; ++i) {
    dst.SetValue(i, src.GetValue(i) * scale);
}
```

典型 smell（碎 Vector）：

```cpp
for (int row = 0; row < M; ++row) {
    AscendC::Mul(... /* tiny count */);
    AscendC::Add(... /* tiny count */);
}
```

典型 smell（本可 SIMT 却全 Scalar）：

```text
for each independent index i:
    irregular lookup / predicate / atomic
  标成「有分支 → Scalar」且未比较 SIMT
```

**不是禁止 Scalar。** loop control、少量 metadata、tiling 计算、真正的 serial 依赖可以留 Scalar。
**也不是命令所有不规则工作必须 SIMT。** 必须比较：真 serial cone vs indexed-independent remainder。

生产 bulk 路径上的 `GetValue` / `SetValue` 见 [copy Card](../../../../../knowledge/cam/memory/memory-copy-and-alignment.md)：合法，但是差的生产搬运（`recommendation`）。

SIMT 选择还接到 PAC-4 与 **Serial-Island Gate**。

---

## Logical Worker Topology Gate

Gate A 必走，**在任何 remainder / strided / 2D partition 公式之前**。
Participation-set review 问 collective **谁必须到齐**。本门问 **谁拥有哪份 work**。二者都依赖 topology，但证明对象不同。

```text
physical launch width
  ≠
logical worker space

GetBlockIdx()
  ≠
logical worker identity

a correct remainder formula
  ≠
a faithful implementation
```

写核 / 写分核公式前，必须重建：

```text
physical launch
  → execution topology
  → subblock topology
  → engine role (AIC / AIV)
  → logical worker identity
  → logical worker count
  → work ownership
```

相关输入（缺则标 **未回答**，不得用 Host `<<<N>>>` 填空）：

```text
core_ratio
launch block_dim
GetBlockIdx / GetBlockNum
GetSubBlockNum / GetSubBlockId
ASCEND_IS_AIC / ASCEND_IS_AIV
target-specific task ratio / GetTaskRation
```

必须证明：

```text
1. every participating logical worker has exactly one logical worker ID
2. those IDs form the intended ownership domain
3. every work item is owned exactly once
4. idle workers remain legal
5. collective participant identity is consistent with this topology
   (cross-check the participation-set review; do not substitute)
```

禁止：

```text
worker_id = GetBlockIdx()
```

仅仅因为 Host 发射了 N 个 block。

```text
A mathematical partition proof is invalid
until the worker-space model itself is proven.

proved cover/union/idle inside the wrong ID space
  → Gate fail, not a successful remainder proof
```

Gate B 从 **actual** `GetBlockIdx` / `GetSubBlockNum` / `ASCEND_IS_*` 重建 logical ID，
对照 Frozen Design 的 worker 公式。不得接受「remainder 数学看起来自洽」。

---

## Serial-Island Gate

PAC 必走（PAC-3）。P1 问一段工作的粒度；本门问 **最小真正 serial 的依赖锥**。

```text
phase has serial logic
  ≠
whole phase on core0 / single Scalar core

one sub-step is serial
  ≠
assign the entire phase to one core
```

缺一项标 **未回答**：

```text
minimal true serial cone:      有真实数据依赖、不能并行的最小节点集合
serial-only-by-position:       只因写在 serial loop 之后才被标 serial 的节点
DAG:                           parallel producer → serial island → parallel consumer
remainder mapping:             岛外不规则独立工作：独立评估 Scalar | SIMT | Vector
```

```text
serial island
  ≠
serial phase

Ordered identity generation
  ≠
ordered downstream computation

must serialize this reduction
  ≠
must serialize the producers and consumers around it
```

禁止：因为 phase 里有 prefix / unique / 全局计数，就把 gather、lookup、per-item write 全部绑到同一个核。
只串行最小顺序锥：stable ordinal / 身份决定可以 serial；destination lookup、
per-token duplicate detection、DMA materialization 默认仍独立评估并行。
岛前可以并行生产；岛内串行；岛后可以并行消费。把整段 phase 丢给 core0 记 PERF-SMELL-10。

不强制任何具体并行分解。要求的是画出 cone，并说明哪些 node 其实只是坐在 serial loop 后面。

---

## P2 GM Residency / Materialization Gate

这个中间 tensor 的 **下一消费者** 是谁？

若仍在当前 tile / 当前核：为什么要落 GM？

若打算常驻 UB：reuse 收益是否盖得过 footprint（tile 变小、挡 buffering、挤掉别的热数据）？

```text
intermediate result
  prefer on-chip residency
  when reuse benefit justifies its footprint
  and lifetime / capacity / dependency allow

on-chip residency
  also consumes UB / register budget
  and may reduce tile size or buffering eligibility

GM materialization
  needs a reason

UB residency
  also needs a footprint justification
```

```text
UB 放得下
  ≠
应该驻留 UB
```

反例（驻留把结构写坏）：大 intermediate 一直留 UB → tile 只能 512 → `num=2` 放不下 → pipeline 叠不上。少量 spill / recompute → tile 2048 + double buffer，可能 overall 更好。这要写进 justification，接到 [tiling-from-shape](../../../../../knowledge/cam/engineering/tiling-from-shape.md) 的 proposal → capacity → revise。

合理落 GM 的例子（需写明）：UB 装不下；驻留会压 tile / 挡住 buffering 且 reuse 不够；跨核 ownership；atomic / 跨核汇合；producer-consumer 边界在核间或通信窗；当前 mode 的协议就要求 GM handoff。

这是 **单 kernel / 单 tile 内** 的 residency 问题。多算子融合时哪些 API-visible GM 能删，读 [MoE fusion materialization](../../../../../knowledge/cam/engineering/moe-fusion-materialization-and-sync.md)。跨 rank / 跨核传的是原始状态还是充分统计，读 [sufficient-state](../../../../../knowledge/cam/engineering/communicate-sufficient-state.md) 与下面 **Sufficient-State Communication Gate**。不要把三层并成一句「少用 GM」。

---

## Sufficient-State Communication Gate

PAC-1 / PAC-2 / PAC-5 必走。P2 问单核内中间结果住哪；本门问 **跨 rank / 跨核 handoff**。

这是 Weaver 的 **核心 distributed-design principle**，不是可选启发式。
原则：[communicate sufficient state](../../../../../knowledge/cam/engineering/communicate-sufficient-state.md)。

一次独立 fused-operator 实现已经回归验证：第一版跨 rank 架构可以保持
sufficient-state exchange + producer-side compact，而不是退回可重构全表 all-gather。
保留现有 Gate A / PAC 搜索；不要把某种 inbox 协议写成配方。

### PAC-1 Over-materialization

```text
needed by a later reconstruction
  ≠
must be transferred as-is
```

缺一项标 **未回答**：

```text
consumer semantic state:     下游真正要消费的状态
transferred object:          拟传输 / 拟落 GM 的 tensor 或 window
materialized only to reconstruct consumer later?:  yes | no | unknown
```

禁止：把「生成时手头有这份表」当成必须发出去 / 落 GM 的理由。
只因为以后能重构 consumer state 才通信 / materialize 的对象记 PERF-SMELL-03。

### PAC-2 Sufficient-state communication

```text
Communicate sufficient state, not reconstructible state.

cheapest to generate locally
  ≠
cheapest to communicate
```

缺一项标 **未回答**：

```text
producer-side transform:     none | compact | prefix | metadata-only | ...
reduces cross-rank bytes?:   yes | no | unknown
reduces replicated workspace?:
reduces remote scans?:
reduces synchronization?:
O(full state) → O(?):
```

不强制某种 compact / flag / all-gather 协议。变换是 candidate，必须进 envelope 再 freeze。

### PAC-5 Communication envelope

每个 distributed / 跨核 candidate 必须比较：

```text
candidate:
bytes / rank:
total bytes:
remote operations:
barriers:
replicated state:
asymptotic scaling:          vs R / S / K / E / ...
critical-path reason:
```

```text
payload smaller than some other operator
  ≠
this operator's communication choice is justified
```

比较必须落在 **本算子 critical path**。禁止用另一个算子的 byte count 当本算子的证明。
L1 可以 freeze 较简方案，但必须写下被挑战过的渐近项和 L2 候选（PAC-7）。

---

## Memory Orchestration Gate

P2 问中间结果住哪。本门问 **UB 由谁切、lifetime 怎么重叠**。
不叫 P6；Gate A 与 P1–P5、Physical Realizability 一起走。

performance-critical 路径 **先设计 physical UB layout**。
不得默认从 TPipe / TQue / TBuf 开始。思考顺序：

```text
算法
  → 真实 lifetime
  → physical UB map
  → pipeline schedule
  → event ownership
  → 最后才决定要不要用 TQue/TBuf 帮助表达其中一部分
```

禁止：

```text
CopyIn  → TQue<VECIN>
Compute → TBuf
CopyOut → TQue<VECOUT>
双缓冲 → num=2
最后再分析 lifetime
```

```text
UB allocation strategy:  在 physical map 之后才选
                         TQue/TBuf | manual partition | hybrid
Reason: ...
physical map:            region / address-or-offset / size /
                         owner / stage / lifetime / reusable?
events:                  每个 ping/pong 的 RAW / WAR primitive
                         （显式设计对象，不是 AllocEventID 顺带状态）
```

```text
TQue exists
  ≠
TQue is the right orchestration abstraction

TPipe.InitBuffer + AllocEventID
  ≠
physical UB orchestration

hybrid
  ≠
把一个 TBuf 切成 ping/pong

TQue / TPipe
  适合 correctness baseline、生命周期难静态分析、普通算子

manual / hybrid
  评估，当：固定 tile、lifetime 可静态分析、强性能目标、
  多级 ping-pong、精细 MTE2/V/MTE3 overlap、跨阶段 reuse
  目标仓高性能 sibling 若普遍 manual UB → 默认遵循 convention
```

不得写成「TQue 性能差，禁止使用」。也不得写成 must manual UB。
TQue 合同仍读 [TQue Card](../../../../../knowledge/cam/memory/ub-tque-tbuf-and-double-buffer.md)。该 Card 不回答「该不该用」。

`TEventID` 本身不一定有显著额外成本。问题是 `TPipe.AllocEventID()`
把 event / UB / protocol 收进 allocator。性能核应直接表达
`UB_ping` / `UB_pong` 地址和 ping/pong event；具体 primitive
跟 A5 / CANN 9.1 已验证 API。

必须交 **physical** UB map（缺一项标 **未回答**）：

```text
region    size    owner     pipeline stage     lifetime        reusable?
A         ...     MTE2      input ping         n → compute n   yes/no
B         ...     MTE2      input pong         n+1 → compute   yes/no
C         ...     Vector    acc                whole reduction no
T         ...     Vector    tmp (Cast dest)    Cast → Add      yes next k
D         ...     MTE3      output ping        Cast → store    maybe
```

conceptual「TQue num=2 + TBuf acc」不是这张表。
伪码中间值（`Cast(in)` 的 dest、4B DMA landing slot）必须有对应 region。见 Physical Realizability。

还要回答：

```text
buffering:  ping / pong / triple？每块在哪个 pipe 上用？
reuse:      哪些 lifetime 不重叠，能否共用同一 UB region？
            lifetime 不重叠 ≠ overlay 合法
overlay:    allocated_extent >= max(all phase-specific footprints)
            覆盖整个 Host-admitted domain；再加 alignment legality
            leftover: 下一发不得把 handshake leftover 认成 ready
pipeline:   这份 layout 是否允许 V(n+1) || MTE3(n)？
            还是 queue transaction 把 output lifetime 锁死了？
events:     每条 RAW/WAR 用哪条已验证 event，id 是否静态可见？
```

```text
Lifetime compatibility is necessary but not sufficient for overlay legality.

phase A uses R * hist_stride
phase B uses E + B on the same physical region
  → Host must admit only shapes where both footprints fit
```

选 TQue 也要填这张表，并说明它只表达 map 的哪一段。
`InitBuffer(inQue, 2, len)` 不是 UB map。
`double buffer` 是时间 × 空间调度，不是模板参数。

### Kernel Resource Budget

PAC-6 必走。physical UB 容量 **不是** kernel 能用的预算，更不是用户可分配字节。

缺一层标 **未回答**：

```text
physical hardware capacity:      芯片 / 模式给出的片上上限
kernel/compiler allocatable:     该 kernel 模式 + compiler 可见剩余
framework-declared budget:       TPipe / runtime 声明的用户预算
API-internal reservation:        Copy / SHMEM helper 自己扣的 scratch / hole
caller-owned resource:           本算子 tiling / window 真正能调的部分
```

```text
physical hardware capacity
  ≠
kernel/compiler allocatable
  ≠
framework-declared budget
  ≠
API-internal reservation
  ≠
caller-owned resource
```

禁止：用芯片宣传容量当 Host `TORCH_CHECK` 上限；把 sibling 另一条 transport path 的 cap 继承过来；把 API 内部 scratch 算进「还能再放大 window」；用「更小更安全」改写 Frozen Design 已选的 target-specific envelope。
Launch Admission 的 Host guard 必须对齐 **caller-owned resource**，不是 physical capacity。

对每一条 API-specific 资源限制，记录 provenance tuple（缺一项不得继承）：

```text
SOC
CANN version
exact API / overload
transfer direction
source address space
destination address space
internal transport path
pipeline role
phase / lifetime context
```

tuple 不一致 → **不得继承**该 cap。first-party 与 Frozen Design 冲突 → **STOP** 并报告，不得静默改 Frozen Design。

---

## Challenge the Baseline Gate

PAC-7 必走。在物理 Gate A 之后、freeze 之前，对每一个 physically valid baseline 再挑战一次。不替代 Physical Realizability。

```text
correct and affordable
  ≠
best justified production baseline
```

缺一项标 **未回答**：

```text
physically valid?:           yes（Gate A）
affordable on critical path?:  PAC-5 envelope
challenged alternatives:     至少一个 L2 / 更强 envelope / producer-side transform
why freeze this L1 now:      ...
L2 candidate (may defer):    ...
```

禁止：Gate A PASS + 通信比某个更大算子小 + UB 放得下 → 直接 freeze。
PAC 可以 freeze 较简 L1，但必须写下被挑战过的候选，以及为什么现在不实现它。

---

## Physical Realizability Gate

P2 问中间结果住 GM 还是 UB。Memory Orchestration 问 UB 怎么切。
本门问：**Proposal 里的运算能不能翻译成指令和物理资源。**
Gate A 与 P1–P5、Memory Orchestration 一起走。不叫新的 P 编号。

```text
abstract dataflow
  ≠
implementable dataflow
```

每个 performance-critical operation 缺一项标 **未回答 / ?**：

```text
Operation:           Cast bf16 → fp32
Concrete API:        ?
Input storage:       in_ping / bf16
Output storage:      tmp_fp32 / fp32
Lifetime:            Cast → Add
Physical bytes:      Align(...)
Pipeline:            V
```

任一 `?` 仍在 → Design 还不能写核。

禁止把概念运算直接当数据通路：

```text
Add(acc, Cast(in))
Reduce(Cast(x))
Mul(Add(x,y), z)
quant(dequant(x))
```

除非 [cam-operator-docs-search](../../cam-operator-docs-search/SKILL.md) 已证明存在对应 fused / mixed-dtype API。
否则嵌套表达式必须拆开，中间值必须出现在 physical UB map 里。
map 只有 input / acc / output / metadata、漏掉 Cast tmp，视为本门失败。

每个 DMA edge 额外填：

```text
DMA:                     remote weight → UB
logical bytes:           4
source alignment:        ?
destination alignment:   ?
physical landing bytes:  ?
```

```text
logical buffer size
  ≠
legal DMA landing layout
```

`?` 未知 → 先 cam-operator-docs-search / 打开 [copy Card](../../../../../knowledge/cam/memory/memory-copy-and-alignment.md)，Gate A 不能过。
不得只写 `wgt: K*4`；必须同时写 logical payload、DMA landing layout、physical reserved bytes。
dest UB base 对齐已在 copy Card（DataCopyPad UB 起址仍要 32B）。不要另写一篇搬运百科。

### Complete operand graph

「主要 tensor 有物理位置」不够。每个 **实际运算** 缺一项标 **未回答**：

```text
Operation:                 Cast | Add | Mul | DataCopyPad | ...
src0 physical object:
src1 physical object:      # 若二元
dst  physical object:
dtype / bytes:
lifetime:
overlap / alias legality:
API legality:
```

全部必须可定位到 UB map 上的 region，或证明的寄存器 / 同 pipe 临时。

```text
logical:   bf16 in → Cast fp32 tmp → Add(acc, tmp)
physical:  in0, in1, acc     // tmp 不存在
  → this Gate fails
```

width-change（`Cast(bf16→fp32)`、量化）必须自动问：

```text
dst 在哪？
能否 alias src？
alias 有 target-version API 证据吗？
```

禁止口头别名：

```text
or in-place promote
Cast into the input buffer
sizeof(bf16) 升级成 fp32 覆盖 in_*
```

除非 cam-operator-docs-search / 头文件已证明该 overload 允许 in-place **且** 元素宽度不变，
或硬件合同明确允许覆盖。bf16→fp32 默认 **不能** alias。

Gate B 从 **实际 Cast/Add/Copy 语句** 重建本图，不能只确认源码出现过 `tmp_*` 字样。

---

## P3 Pipeline / Buffering Gate

第一版 **必须考虑** Copy / Compute 是否可能 overlap，而不是默认：

```text
CopyIn → Wait → Compute → Wait → CopyOut → Wait
```

设计里写清：

```text
Buffering / pipeline proposal:  none | single | double | other
Reason: ...
```

`other` 例如：static local tensor、manual ping-pong、已有 Case 的缓冲模式。必须说明 **为什么这个结构合理**，不是强迫所有 kernel 用 TQue 单/双缓冲。

P3 审查的是 **schedule**。orchestration 已在上一门选完。不要用本门代替 UB map。

```text
必须说明 buffering / pipeline 为何合理
  ≠
所有算子必须 num=2
  ≠
所有算子必须 TQue
  ≠
AscendC 开发 = TPipe/TQue
```

若选 TQue `num=2`，仍要回传 UB 预算。`depth` ≠ double buffer。读 [TQue Card](../../../../../knowledge/cam/memory/ub-tque-tbuf-and-double-buffer.md) 和 [tiling](../../../../../knowledge/cam/engineering/tiling-from-shape.md)。

```text
InitBuffer num=2
  = double-buffer allocation
  ≠
double-buffered execution
```

填 `double` 不够。必须能按语句顺序画出至少两个 iteration 的 MTE2 / Vector / MTE3 timeline，见下面 **Steady-state execution review**。立即 `EnQue → DeQue → CopyOut → Free` 会把 `num=2` 排成串行；`Compute(n)` 之后才 `CopyIn(n+1)` 同样不是 overlap。

不得只对 dominant/main phase 填 buffering。prologue / epilogue / metadata stage 只要含 MTE2、Vector、MTE3、communication 中的任意两个，就要单独填本门，见 Steady-state **per-phase coverage**。

### Pipeline resource depth

P3 的 timeline 证明语句会不会叠；
P4 的 Event Protocol Closure 证明 Set/Wait 成不成对。
本小节问第三层：**闭环之后，独立 buffer / event credit 够不够同时飞**。

```text
closed event protocol
  ≠
sufficient pipeline resources

minimizing Event IDs
  ≠
an objective
```

同号 `EVENT_ID0/1` 在不同 `HardEvent` 类型上是独立池。
不要把「数值上只用了 ID0/ID1」读成「只有两个硬件信号量」。
真正要数的是每个 pipe 上 **in-flight 的独立 buffer 和 credit**。

每个 performance-critical loop 缺一项标 **未回答**：

```text
intended concurrent stages:  e.g. MTE2(n+1) || V(n) || MTE3(n-1)
input buffers / credits:     ping/pong count and which HardEvent IDs
compute occupancy:           acc / tmp that must live across a store
output buffers / credits:    store ping/pong count；drain is per-iter or phase-end
reuse edge:                  which WAR would false-serialize if credits < stages
```

input ping/pong + **single** out 可以让 Event Protocol Closure 全绿，仍把 Cast-to-out
卡在上一次 CopyOut 的 WAR 上。若声称三 stage 共存，就必须给 store 独立
buffer/credit（典型：input ID0/ID1，store ID2/ID3），并且 **不要**在每个
iteration 结束时 drain store——phase 末才收两个 store stage。

不把某一对 ID 写成绝对规则。要的是按 intended concurrency 配资源。
资源不够还填 `double` / 画三线 overlap → PERF-SMELL-04 unjustified。

### Overlap envelope comparison

本小节不只证明「当前 schedule 能跑」。必须比较当前资源预算下
**可实现的最佳合理 overlap envelope**。

缺一项标 **未回答**（名称可本地化，层次不能少）：

```text
E1 serial:              producer → consumer
E2 overlap:             producer(n+1) || consumer(n)
E3 overlap:             producer(n+1) || consumer(n) || writeback(n-1)
```

对 **每一个** dominant phase 各填一行（prologue / scatter / compute / epilogue / local expand / side path 只要含两根 pipe 就算）：

```text
phase:
natural producer engine:
natural consumer engine:
available physical buffers:
available event credits:
best affordable envelope:   E1 | E2 | E3 | N/A
selected envelope:
reason if selected < best:  required; "other phase already pipelines" is not a reason
```

```text
enough to run the chosen schedule
  ≠
best reasonable overlap envelope under the budget

one phase ping-pong
  ≠
kernel pipeline PASS
```

production shape 能轻松放下更强档时，选较弱档 **必须**写成本理由
（省下的字节实际买到了 metadata / 语义 / 另一条热路径）。
「主路径已经能 pipeline」不是 epilogue 停在 E1 的理由。

不把 E3 写成所有算子的绝对规则。Cube / 单 pipe / 无 store 的 kernel
填 N/A 并说明缺哪根 pipe。Gate B 从实际 UB map **分 phase** 重建所选 envelope。

---

## Hot-path vs Exceptional Shape Gate

Gate A 必走。生产 common-case 的最佳路径，不要被未提出的极端 shape 污染。

```text
exceptional-shape generality
  ≠
baseline hot-path structure

DMA max-burst chunking
  ≠
algorithm-axis tile
```

缺一项标 **未回答**：

```text
production / task-contract inner-axis length:
fits UB + API at full length?:     yes | no | unknown
hot-path structure:                full-axis | tiled
DMA burst chunking:                inside copy helper | exposed as h_tile / h_off
exceptional fallback:              none | separate path | Host reject
fallback changes Contract semantics?:  no | yes (Gate fail)
```

若任务合同 / production shapes 在 UB 与 API 下可以走 full inner axis
（典型：H=7168 的 dual-in/out 远小于 248 KiB）：

```text
baseline = full-H (or full natural inner axis)
no h_tile field in the hot path
no h_off loop
no H-tile scheduling
```

`DataCopyPad` 单次上限（如 65504 B）由 copy helper 内部 while-chunk 消化。
那不是把算法维做成 tile 的理由。

只有同时满足才允许 H-chunk **独立 fallback**（不是把主路径 tile 化）：

1. 缩完 metadata window 之后 H 仍超过 UB
2. 或任务合同明确要求超长 hidden / 该 inner axis

同类：不要为未提出的 tail / rare dtype / 超大 K 给 hot path 加抽象。

```text
resource overflow fallback
  ≠
silent semantic downgrade
```

Contract 要求了 `with_weight` / optional output / required dtype 时，
资源压力可以：缩 window、改 physical map、Host reject unsupported shape。
**禁止** kernel 里悄悄丢掉该功能。

本条管 intra-core 主路径抽象。跨核 occupancy 拆 H 走 P3 / parallel-axis，不要混。

---

## Launch Admission Gate

Gate A 必走。Hot-path 可以把 exceptional 写成 **Host reject**；
本门问 reject / supported domain 有没有 **可执行的 launch 边界**。

```text
Every unsupported kernel condition must be enforced
at the launch boundary.

The Host admissible domain must be equal to
or narrower than the kernel-supported domain.
```

```text
Kernel support domain
  ≠
Host launch-admission domain

Design said unsupported
  ≠
Host will refuse the launch
```

每个 kernel 缺一项标 **未回答**：

```text
kernel supported domain:     e.g. full-row E3 footprint <= UB; no H-tile
Host check:                  TORCH_CHECK / equivalent, same or stricter
sibling cap reused?:         no | yes (must prove it covers THIS kernel)
unsupported → fallback?:     none | separate path | Host reject
```

```text
Kernel assumption:
  full-row E3 footprint <= UB
        ↓ must map to
Host:
  TORCH_CHECK(E3Footprint(H, K, ...) <= supported_ub)
```

禁止：kernel 不再 tile、Design 写 large H unsupported，Host 却只检查
sibling 的 `H*2 <= 128 KiB`。那会把 E3-oversize shape 放进 kernel → OOB。

Host domain 也不能只从顶层条件推（整除、`K>=1`、UB 总和）。必须把
**每一个实际物理不等式** 反推进准入域，再求交：

```text
Host admissible domain
  =
  semantic domain
  ∩ API domain
  ∩ physical-layout domain
  ∩ temporary-footprint domain
```

例如 overlay scratch 用 `E+B`，hist 物理容量是 `R * hist_stride`：
Host 必须有 `E+B <= region_X_capacity`（以及其它 region 的同类不等式）。
缺这一条 → Launch Admission 失败，即使「kernel domain 已在 Design 闭合」。

任何「不支持而非 fallback」的决策，都必须在 launch boundary 有 guard。
适用于 H / K / dtype / 对齐 / rank 数 / FP4 / overlay footprint 等。不得只写在 Design 文档里。

Gate B 核对 Host 断言覆盖 kernel 假设，或更严。
Host guard 对齐的是 **Kernel Resource Budget** 的 user-allocatable bytes，不是芯片宣传容量。
Gate B 还要核对：**每个 overlay / scratch 的 max-footprint 不等式是否出现在 Host**。

---

## P4 Synchronization Scope Gate

看到 `PipeBarrier<PIPE_ALL>()` 必须问：到底是哪两个 producer / consumer 之间有 dependency？

能否用 TQue `EnQue`/`DeQue`、具体 HardEvent、或 scoped pipe barrier 表达？

```text
Synchronization should be scoped to
the actual dependency edge.

broad sync
  requires justification
```

PIPE_ALL 可以用于：debug 判别实验、确有全局 ordering 需求、instrumentation 工具链。  
不能当「不知道同步谁就全同步」。

生产路径默认不要留 PIPE_ALL。读 [pipeline Card](../../../../../knowledge/cam/synchronization/pipeline-events-and-ordering.md)。MoeTracing 默认 `PIPE_ALL` ≠ 生产路径合同。

kernel launch 边界和全 rank phase barrier 也是 broad sync：

```text
tightly coupled fused-operator phases
  → single device launch is the default candidate

logical phase
  ≠
kernel boundary

Host Launch* wrappers
  ≠
device __global__ count

Host stream barrier convenience
  ≠
justification for a second kernel
```

拆多次 device launch 之前必须证明 1/2/3 之一，并枚举目标同步机制
（HardEvent / scoped PipeBarrier / VEC-side SHMEM barrier /
Host stream barrier / MIX+device Barrier / per-PE ready）。
禁止未搜 `aclshmemx_barrier_all_vec` 一类 VEC barrier 就把
「单 kernel」等同于「必须 MIX + device Barrier」。

不得把「两个逻辑阶段」自动写成两次 launch + `barrier_all`。
也不得把目标收成「必须合成一个 kernel」：一个 kernel 里仍然
`prologue → barrier_all → consume`，性能结构没有本质变化。
要回答的是：能否单 launch + in-kernel phase transition；
以及 global phase serialization 能否变成 chunk / wave pipeline。
PIPE_ALL 仍按本门审查，不要把仓内先例的 `PipeBarrier<PIPE_ALL>()` 抄成融合合同。

每个 device collective（`aclshmemx_barrier_all_vec` / `aclshmem_barrier_all` /
同类）不得只写 “all launched cores call it”。
缺一项标 **未回答**：

```text
participant scope
participant count
scope kind:     physical cores | launched cores | team members
launch block_dim
idle-core behavior
rank participation
```

证据来自目标版本 first-party header、实现、或成功调用模式。
公共头文件 “all VEC cores” 一句不够。launch geometry 必须与
required participation set 兼容，否则 32-on-64 会 hang。
SKU 支持范围写清（例如 ≥N AIV），不要泛称整个芯片代际。

### Event protocol closure（manual HardEvent）

TQue `EnQue`/`DeQue` 走框架合同，不填本表。

选了手工 `SetFlag`/`WaitFlag` 之后，**声明的 dependency graph ≠ 闭合的 event protocol**。

### Event type derivation

HardEvent **类型**必须从实际 last-writer / next-reader / next-writer 推出，
禁止按 sibling 熟名挑选后再把解释套上去。

```text
Event type must be derived from the actual topology,
never selected by sibling familiarity.
```

Gate A **先**冻结这张表，**然后**才允许代码出现 Event 枚举：

```text
Buffer   Writer   Reader   Next writer   RAW      Reuse WAR
in0      MTE2     V        MTE2          MTE2_V   V_MTE2
out0     V        MTE3     V             V_MTE3   MTE3_V
```

```text
RAW             =  writer_pipe → reader_pipe
WAR / reuse     =  last_reader_pipe → next_writer_pipe
```

`MTE2 writes in → V reads in → MTE2 overwrites in` 却用 `MTE3_MTE2`
（Dispatch/Prefetch 熟名）→ 本门失败，即使 ID 数字成对、phase 表已填。

表未完成 → 不得冻结 HardEvent。Gate B 从 **实际模板实参** 反推类型。

每个 manual UB region 缺一项标 **未回答**：

```text
buffer:        in_ping | out_ping | wgt_slot | ...
producer pipe:
consumer pipe:
RAW event:     e.g. MTE2_V
reuse/WAR:     e.g. V_MTE2
Set site:      which statement
Wait site:     which statement
first-use:     skip Wait | init SetFlag of the FREE/WAR event
drain:         which Wait at kernel/phase end
```

```text
Every declared event edge must appear as a matched Set/Wait pair
in the actual statement schedule.

Every Wait-before-first-Set requires an explicit startup rule.
```

9.1 `SetFlag`/`WaitFlag`（`kernel_operator_block_sync_intf.h`）**没有**把未 Set 的 event 定义成 ready。
禁止 “nop-initialized as free”。合法 startup：

```text
A. first-use skips Wait（以后 reuse 才 Wait）
B. kernel init SetFlag 建立 initial free token
   （sibling dispatch：loop 前 SetFlag<MTE3_MTE2>(ID0/ID1)）
```

AIV `HardEvent` 含 `S_MTE2` / `S_MTE3` / `MTE2_S` / `MTE3_S`（9.1 `kernel_event.h`）。
Scalar pack → CopyOut、Scalar 读完 slot → 下次 MTE2 覆盖，必须画出来；
需要显式边时用这些枚举，不要假设 auto-sync 已闭合手工协议。

声明在 event table、没有出现在 statement schedule → P4 不通过。

### Phase-transition closure

单 `__global__` 含 `phase A → in-kernel barrier → phase B` 时，
startup / steady / drain 只覆盖 **一个** phase，不够。

每个 `(HardEvent, eventID)` 缺一项标 **未回答**：

```text
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
```

phase-end 已 Wait 完的 output `MTE3_V` 可以在 phase B 再 Set（合法 re-init）。
phase A 最后一次 Acc 留下的 `V_MTE2` FREE token 若从未 Wait，phase B 不得再 Set；
必须 Wait 后 re-init，或 inherit，或换一组 ID。

### Publication graph（所有 mechanism / phase-crossing 边）

shared workspace 的 UB→MTE3→`MTE3_MTE2`→SyncAll→MTE2 重建是必要的，**不够**。

```text
Every producer→consumer edge crossing an execution mechanism
or phase boundary requires a visibility/completion proof,
regardless of whether the storage is ABI output, workspace,
or symmetric memory.
```

同一张 publication graph：

```text
producer mechanism
    ↓
physical storage
    ↓
completion / cache visibility
    ↓
consumer mechanism
```

必须分类的边包括（不限于）：

```text
SIMT GM store     → SIMT GM load
Scalar GM store   → MTE2
MTE3              → Scalar GM
remote PUT        → remote MTE2
UB writer         → MTE3 → MTE2 reader
```

```text
same AIV / same-core ownership
  ≠
visibility proof may be omitted

ABI tensor
  ≠
publication is automatic
```

可以证明同一 AIV 的 disjoint slice **不需要**跨核 SyncAll；
不能从 ownership 推出「这条边不用写进 Gate B」。
HardEvent 名（如 `V_MTE2`）等待的是 Vector→MTE2，不是 VF→VF GM visibility。
未分类 → P4 / Gate B 失败。

### Synchronization minimality

publication graph 证明每条边 **有** visibility。本小节问：每个同步原语是否关闭了 **一条尚未被后续更强原语覆盖的边**。

对每一个：

```text
WaitFlag
PipeBarrier
SyncAll
world / team barrier
quiet
cache visibility primitive
Host barrier / stream wait
```

缺一项标 **未回答**：

```text
primitive:
predecessor:
successor:
completion property required:
why a weaker already-issued primitive is insufficient:
```

```text
Every synchronization primitive must justify
one distinct unsatisfied dependency edge.
```

若两个连续原语声称同一 completion / publication 性质 → **标 review**。
不得因为「更保险」保留额外 fence / quiet / PIPE_ALL。
**不要自动删除同步**；缺 distinct-edge justification → PERF-SMELL-05 unjustified。

Drain WaitFlag（last MTE3 / scratch reuse）与 world barrier（rendezvous + documented RMA visibility）是两条边。
若后续 barrier 的 first-party 合同已包含前序 completion，额外 quiet 必须指出 barrier **没有**覆盖的那条边。

---

## P5 Repeated Work / Redundant Access Gate

Loop-invariant / 可复用数据，不得在 **最内层** 无理由重复 GM load / recompute。

```text
一批连续 metadata（scale / index / offset）
  → 优先按 tile / block 搬入 UB
  → 再从 UB 复用（必要时再抽 local scalar / vector register）

极少量 control / meta
  → 单次 scalar load 可接受

每个 H 元素都 GM GetValue
  ≠
每个 token 一次 GetValue 就够了
```

不要把「禁止内层逐元素 GM」收成「每个 token `scaleGm.GetValue(token)`」。T 很大时，那仍是大量 scalar GM access。

```text
explicit GM access
  ≠
compiler will hoist it
```

被后续 Vector 整段覆盖的 `Duplicate` / 清零，也是本条的 redundant work。

Design 已选 bulk / windowed metadata staging 时，overflow 不得静默退回
逐元素 GM `GetValue`。改 residency class 必须重开本门。

### Locality Work-Elimination

bulk DMA 把 descriptor 搬进 UB 之后，**已证明的 producer invariant 必须继续消计算**。

```text
contiguous ownership
  ≠
bulk DMA only

proven locality / compact / monotonic
  →
must eliminate work
```

Contract/Design 已证明 compact + monotonic 时，span / window boundary 从头尾
或单调 `end(g)` 推导：

```text
loff0 = groups[g0].dup_start
loff1 = groups[g1-1].dup_start + groups[g1-1].dup_n
```

禁止：整窗 min/max 扫描、`g_win--` 再重扫、按组补 CopyIn 覆盖本已 staged 的 span。
window 太大：从单调 `end(g)` 推导 / 二分最大 `g_end`，不是线性砍尾。

未证明 compact 时，才允许密度扫描，并写明为何 invariant 不成立。

---

## Hot-loop Traversal Gate

```text
For metadata/control data resident in UB, reconstruct actual
traversal complexity from the written implementation.

Residency does not make repeated scans free.

If logical consumption is single-pass, helper abstractions must not
silently turn it into repeated traversal without measured justification.
```

```text
For every hot-path callsite, reconstruct complexity through
the complete reachable helper chain.

A helper with O(B) traversal invoked inside O(R·E) caller loops
makes the actual path O(R·E·B), regardless of the caller’s
nominal algorithm label.

Traversal intent ≠ traversal complexity.
```

P5 / Locality Work-Elimination 盯 GM reload 和「可由头尾推导的 span 扫描」。
本门问下一层：**数据已在 UB，hot-loop 的 control traversal 是否仍被 helper 退化。**
Gate B 把本门做成 **可执行手续**，不是一句知识原则：

```text
look at ProcessP* body
  → assign a complexity label
  ≠
outer loop
  × called helper
  × helper nested loop
  × helper-of-helper
```

```text
Resident metadata
  ≠
free repeated control work

Traversal intent
  ≠
iterator complexity
```

对 hot loop 中的 metadata / control 访问，Gate B 必须重建实际复杂度。
若逻辑数据只需单遍消费，implementation 不应因 helper abstraction 退化成
repeated scan / O(N²)，即使每次 `GetValue` 都在 UB。

```text
logical:          for k in K: if positive: consume      # O(K)
implementation:   count n; for r in n: scan from 0      # O(K²)
  → this Gate fails unless extra passes are proven necessary
```

```text
outer loop
  × called helper
  × helper nested loop
  × helper-of-helper
  = actual complexity

helper-local O(n)
  ≠
whole-call-graph O(n)

caller-body label O(R·E)
  ≠
actual path if helper itself loops O(B)
```

额外 Scalar 扫描会推迟下一发 MTE2，破坏 pipeline lead time。
正当理由必须写明：为何不能单调 cursor / 单次 walk。
Gate B 必须把 **完整可达 helper 链** 相乘；不得只报 helper 内部复杂度，
不得只给 caller 主循环贴标签，也不得漏掉 helper 里的 find-from-0 / rescan。

可疑热点（不必自动算出所有 C++ 复杂度，但必须列进 review）：

```text
for-loop
  → function call
  → callee has a loop
  → report multiplicative nesting
```

不与 Locality Work-Elimination 混：前者消的是 compact/prefix **span**；本条消的是
**单遍消费意图 vs iterator 复杂度 / call-graph 相乘**。记 PERF-SMELL-08。

---

## Repo-native API Search Gate

性能关键机制不得只证明「API 合法」。

冻结 GM↔UB / remote SHMEM / barrier / 同类路径前：搜 target-repo sibling
成功 idiom → 核对 SOC/CANN → 看 statement ordering → 比较候选。

```text
search complete
  ≠
idiom selected

same repo + same SOC + same CANN
+ same data direction + same pipeline role
  → that idiom is the default baseline
```

偏离须证明：API contract 不适用、多了资源/同步成本、envelope 更差、
或目标版本实现等价且更低层路径有具名收益。只写「搜过仍选 generic」不够。

匹配 **transport role**，不是 sibling 算子名：

```text
remote PUT UB/GM→peer GM     → PUT-class ops
remote GET peer GM→this UB→V → GET-class ops
local GM↔UB                  → mapped Pad 可能就是 idiom
```

合法 generic ≠ 自动胜过本仓已验证写法。
cam-operator-docs-search 只回答 overload / 版本合同；本门回答「这个仓这条路径默认用哪套」。
换 API 若引入 helper-internal UB reservation 或另一套 completion，
重开 Physical Realizability 与 pipeline。

```text
Same-repo idiom transfers positive implementation evidence,
not automatically all of its resource restrictions.

Resource constraints must be scoped to the exact API/path
that consumes the resource.

another SHMEM operator used this UB cap
  ≠
this SHMEM operator should too

a smaller cap is safer
  ≠
this path is proven to require that cap
```

继承一条限制之前，provenance tuple 必须兼容（见 **Kernel Resource Budget**）：

```text
SOC + CANN + exact overload + direction
+ src/dst address space + transport + pipeline role + phase/lifetime
```

任一字段不一致 → 重新证明，不得继承。
Frozen Design 已选更大的 target-specific envelope 时，不得用「更安全的较小 cap」静默改写。
first-party 与 Frozen Design 冲突 → STOP、报告冲突，不得改 Frozen Design 去对齐实现。

sibling 的 `ub_limit` / scratch 洞只有在 **同一 API 被调用、同一 lifetime 消费该资源** 时才是证据。

---

## API Invocation Contract Gate

```text
A selected API is not implementation-ready until the exact invocation
has proven:
- overload/signature
- unit
- source extent
- destination extent
- padding/alignment
- stride
- completion semantics
- resource-specific limits
```

Repo-native Search 冻结 **哪套 API**。本门问 **这一次调用是否合法、物理效果是否符合声称**。

```text
correct API
  ≠
correct call

API selection
  ≠
parameter-level legality / physical effect
```

对性能关键或非自然对齐的数据搬运，冻结 API 后缺一项标 **未回答**：

```text
concrete overload:
units:                    bytes | elements
blockLen / burstLength:
src/dst stride:
padding / pad count:
destination footprint:
alignment:
event / completion / sync_id:
UB consumed by this call:
```

尤其必须一级证据（target-version header / 实现 / 成功调用，不是默认构造）：

```text
bytes vs elements
uint16 vs uint32
pad count
dst footprint
alignment
sync_id
UB limit
```

`DataCopyPadParams{}` **不是** 证据。4B source 声称 pad 到 32B slot 时，
必须证明 occupancy 公式（例如 9.1 dav_3510 `CopyGmToUbufAlignV2` 的
`AlignUp(dstStride*32 + burstLength + padLength, 32)`）与 `slot[k*stride]`
不碰撞。额外 `rightPadding` 可以把 occupancy 抬到 64B。

Gate B 从实际 `DataCopyParams` / `DataCopyPadParams` 实参重建 footprint。
声称与参数不符 → PERF-SMELL-12 unjustified。

---

## Frozen-Clause Extraction（写核前）

Implementation-fidelity 不得依赖实现 Agent **自选**「重要条款」。

Frozen Design / Contract / 已分级 fact 冻结之后、写第一行 kernel 之前：

1. 解析全部 authoritative frozen artifacts
2. 抽出每一条 normative clause：
   - MUST / MUST NOT
   - frozen formula
   - exact API selection
   - explicit architecture freeze
   - explicit support-domain condition
   - explicit resource choice
   - explicit ownership / event / ordering rule
3. 赋稳定 ID：`FC-001`、`FC-002`、…
4. 建表：

```text
Clause ID | Frozen clause | Intended implementation site | Verification method
```

```text
reviewer-selected checklist
  ≠
exhaustive Frozen-Clause Extraction

extracted normative clause count
  must equal
  later Gate B closure count
```

sketch / example / historical note **不是** clause（见主 Skill 句子分级）。
漏抽一条 resource / fallback / 禁止项 → 后续 Gate B 即使全 MATCH 也不是 exhaustive。

---

## Frozen-Clause Traceability（Gate B）

实现之后，对 Extraction 表逐条闭合：

```text
Clause ID | Actual source | Actual mechanism
        | MATCH | PROVEN_EQUIVALENT | DEVIATION | MISSING
```

```text
MATCH               = literal semantic fidelity
PROVEN_EQUIVALENT   = explicit proof of equivalence
DEVIATION           = cannot be silently accepted because it looks
                      safer, simpler, or faster
MISSING             = clause has no implementation site
```

提出的改进必须记成 **Design deviation proposal**，等待批准；不得在 Design-Execution 实验里偷偷落地。
任何未解释的 MISSING / DEVIATION → 不得 Gate B PASS。

```text
traceability table exists
  ≠
traceability is exhaustive

coverage audit:
  extracted count == closure count
```

---

## Integer Arithmetic Audit（Gate B）

不得只搜乘法 / `token*H` 一类 offset。必须审计：

```text
multiplication before widening
addition before widening
ceil-div / add-before-div formulas
signed negation
abs-style transforms
INT_MIN
sentinel encode / decode
subtraction underflow
signed/unsigned conversion
narrowing casts
shifts and shift width/domain
pointer offset + extent
element → byte conversion
```

support-domain 证明（例如合法 payload 达不到 `INT_MIN`）可以使风险表达式不可达，但证明必须显式写出。
零成本的 overflow-safe 写法优先（先 widen 再 negate / 先 `uint64` 再乘）。

漏检 negation / sentinel 却只报 multiply PASS → 本审计失败。

---

## Steady-state execution review

P3 提案和 Gate B 实现共用。审查的是 **时间线**，不是 API 名单。

### Per-phase coverage

不得只对 operator 的 dominant/main phase 画 pipeline。

每个包含以下任意两个 pipe 的阶段，都必须独立回答：

```text
MTE2 | Vector | MTE3 | communication
```

```text
phase name:              prologue | main | epilogue | metadata | ...
startup:
steady state:            至少两个 iteration（group g / g+1，或 token t / t+1）
drain:
next-iteration overlap:  哪两段可以叠、哪条 WAR 不能叠
buffer reuse:
resource depth:          concurrent stages / buffer count / in-flight / event credits
overlap envelope:        this phase E1 / E2 / E3 / N/A; selected vs best affordable
```

prologue / epilogue / metadata 只要本身有 meaningful pipeline，
就不能因为「比较小」或「不是主路径」跳过。
`single` out 可以选，但必须比较 ping/pong 并给出 overlap 理由，不能用「阶段很小」代替审查。
若 intended overlap 是 `MTE2(n+1) || V(n) || MTE3(n-1)`，还必须证明
output 有独立 buffer/credit；input ping/pong + single store 不够。见 **Pipeline resource depth**。

```text
main-phase timeline
  ≠
operator pipeline review

one phase ping-pong
  ≠
kernel pipeline PASS
```

---

## Side-path Integration Gate

Gate A / Gate B 必走。独立画完 prologue / main / epilogue 仍可能把
tiny high-frequency side work 整段串在 dominant 之后。

有 dominant payload path + small high-frequency side path 时必须交 **联合 timeline**。
缺一项标 **未回答**：

```text
dominant path:     e.g. hidden row + Vector reduction
side path:         none | weight gather / scale / metadata / flag
side frequency:    per-token / per-k / per-group
joint timeline:    drawn | not drawn
side placement:    interleaved into dominant idle slots | serialized after dominant
```

```text
independent phase pipeline review
  ≠
cross-subpath schedule

For a dominant payload path plus a small frequent side path,
draw a joint timeline.

Check whether side MTE2 / Scalar / MTE3 work can occupy
idle periods of the dominant pipeline.

Serial side epilogue requires cost or profiling justification.
```

审查：

```text
MTE2 side traffic during V-heavy periods
Scalar side work during V / MTE
MTE3 side output during next item's MTE2 / V
```

MTE2 不能同时发 hidden 和 weight。要求不是「两路 DMA 真并行」，
而是 **不要在 hidden 全做完以后再集中追加一串 tiny MTE2**。

只独立审查 weight 流水、或 hidden 完再 weight 而无 cost model
→ PERF-SMELL-04 unjustified。

本条不管「某个 phase 自己会不会叠」（那是上面 Steady-state per-phase）。
本条管 dominant ∥ side 是否共一张图。

---

### Statement ordering

声称 pipeline / double buffer / 通信掩盖 / Copy-Compute overlap 时，必须按 **实际 statement ordering** 交出：

```text
core occupancy          work_items vs available AIV
MTE2 / V / MTE3         至少两个 iteration
cross-rank comm         远程 CopyIn / SHMEM 相对 Vector 的位置
kernel boundary         每次 launch 和 barrier 切在哪、禁止了哪段 overlap
```

最低合格图：

```text
                 iteration n        iteration n+1

MTE2             CopyIn n+1         CopyIn n+2
                      │
Vector      Compute n ─────── Compute n+1
                 │
MTE3        Store n-1 ─────── Store n
```

画不出来，不准叫「形成流水」。把 buffering 标成 `none` / `single`，或记 PERF-SMELL-04 `present + unjustified`。

```text
第 n+1 个 DMA 是否在第 n 个 compute 完成前发出？
第 n 个 CopyOut 是否与第 n+1 个 compute overlap？
```

反例（有 `num=2` 仍串行）：

```text
CopyIn current → Compute current → CopyIn next → Compute next
Cast → EnQue → DeQue → CopyOut → Free → 下一 tile
```

正例（one-step prefetch）：

```text
CopyIn next  （异步挂出）
Compute current
```

Gate B **不得**用「我用了 TQue num=2」代替这张图。

---

## Gate B actual-code reconstruction

Gate B 审查 **写下的语句**，不审查 Design 口号。
**不得**只检查：有没有 ping-pong / Vector / event / bulk CopyIn。
**不得**只检查 helper 内部的 event 链。

必须从实际代码机械重建 **whole-call-graph**，并与 Gate A 冻结表对照。对不上 → 对应 smell unjustified / Gate 失败。

```text
writer
  → actual caller statement
  → helper
  → consumer
  → return
  → next writer
```

```text
Actual Code
   │
   ├─ Buffer graph
   │    writer
   │    reader
   │    next writer
   │    RAW/WAR event
   │    **across helper boundaries**
   │
   ├─ Operand graph
   │    src/dst/tmp
   │    dtype
   │    physical bytes
   │    lifetime
   │
   ├─ Timeline
   │    MTE2
   │    V
   │    MTE3
   │
   ├─ Traversal
   │    metadata each read how many times?
   │    O(K) or O(K²)?
   │    **outer × helper × nested × helper-of-helper must multiply**
   │    **not the caller-body algorithm label**
   │
   ├─ Overlay / footprint
   │    lifetime non-overlap?
   │    max(all phase footprints) <= allocated_extent?
   │    alignment?
   │
   ├─ API invocation
   │    overload
   │    bytes/elements
   │    alignment/padding
   │    completion
   │
   ├─ Support domain
   │    kernel assumptions
   │         ↕
   │    Host TORCH_CHECK
   │    **every physical inequality**
   │
   ├─ Publication graph
   │    producer mechanism → storage → visibility → consumer
   │    **including ABI tensors and same-AIV SIMT→SIMT**
   │
   └─ Call-graph lifecycle
        writer
             → actual caller statement
             → helper
             → consumer
             → return
             → next writer
```

| 从代码重建 | 对照具名 Gate | 失败形态 |
| --- | --- | --- |
| writer / reader / next writer / RAW/WAR | P4 Event type derivation | sibling 熟名 `MTE3_MTE2` 套在 MTE2→V→MTE2 |
| 每个 Cast/Add/Copy 的 src/dst/tmp | Physical Realizability operand graph | 逻辑有 tmp，UB 无 dst；口头 in-place |
| MTE2 / V / MTE3 语句顺序 | Steady-state + overlap envelope | 声称 E3 但 store 仍 WAR 串行 |
| **Wait / reuse 是否落在 actual caller statement，而不是 helper 入口** | Event protocol + whole-call-graph | helper 内部 event 闭合，caller Scalar 写后未 Wait 就 reuse |
| metadata 每条读几次；**outer × helper × nested × helper-of-helper** | **Hot-loop Traversal Gate** | count + rescan-from-0；helper O(B) 被 outer O(R·E) 再乘；只给 caller 贴 O(R·E) |
| overlay 各 phase footprint vs 分配 | **Memory Orchestration** + Launch Admission | lifetime 不重叠就 overlay；R=1 时 E+B > R·E；handshake leftover 被下一发认成 ready |
| Host 是否编码每一条物理不等式 | **Launch Admission Gate** | Design 写 unsupported，Host 用 sibling 弱 cap；缺 `E+B <= scratch` |
| **每个跨 mechanism / 跨 phase 边的 visibility** | **Publication graph** | 重建了 workspace MTE3_MTE2，漏掉 SIMT dst store→SIMT dst load |
| overload / 单位 / pad / dst extent | **API Invocation Contract Gate** | `DataCopyPad` 合法就结束；`{}` 当证据 |
| logical worker ID vs GetBlockIdx | **Logical Worker Topology Gate** | remainder 在错误 worker-space 里自洽；`worker=GetBlockIdx()` 因 Host 发了 N block |
| 每个 dominant phase 的 E1/E2/E3 | **Overlap envelope comparison** | 只因 scatter ping-pong 给整 kernel pipeline PASS；epilogue 可 E2 却 E1 |
| 连续同步原语的 distinct edge | **Synchronization minimality** | Drain + quiet + barrier 声称同一 publication；「更保险」保留 extra fence |
| Frozen-Clause 覆盖 | **Frozen-Clause Traceability** | 表全 MATCH 但漏抽 resource / fallback 条款 |
| 整数 negation / sentinel / narrowing | **Integer Arithmetic Audit** | 只搜了 `*`；`-x-1` 在 INT_MIN 未widen |

不要用「源码里出现过 `tmp_fp32` / `MTE2_V` / `dual out`」代替重建。
不要用「这个 helper 自己 Set/Wait 成对」代替 whole-call-graph 重建。

典型漏检：UB 上 `count_positive(K); for r: find_rth_from_k0()` —
无 GM 重读、无 Scalar hidden、API 也合法，普通 checklist 全绿。
`outer × helper × nested lookup` 重建后 `logical O(K) / actual O(K²)` → FAIL。

另一类漏检：helper 对单 buffer 做 `Flush → Wait` 看起来闭合，
但 caller 在进入 helper 之前已经 Scalar 写过同一 slot，Wait 发生在 callee 内部、写发生在 caller —
call-graph 上 WAR 未闭合 → FAIL。

第三类漏检：Design 标签 `O(R·E)`，caller 主循环看起来也是 `for d: for g<E`，
但 helper 内部还有 `for b < B` → 实际 `R·E·B`。只重建 caller 主体 → FAIL。

第四类漏检：overlay lifetime 不重叠，Host 只检查 UB 总和；某一 phase 的
`E+B` 大于物理 scratch → R=1 越界。checklist 写 support domain 闭合 → FAIL。

另一类 overlay 漏检：同一次 launch 内 handshake 与后级 payload lifetime 不重叠，
Host 也证了 max-footprint，但完成字叠在 Combine / 输出窗上、不 consume、不双 bank。
第一发 PASS；第二发 leftover 掉进 ready 窗 → 假就绪 / remaining 收不齐 → FAIL。

第五类漏检：workspace publication 已画出 MTE3_MTE2+SyncAll，
P3b SIMT 写 ABI `dst`、P4a 立刻 SIMT 读同一 slice，因「同一 AIV」未进 graph → FAIL。

重建表填完、自判 PASS，但上述负向搜索未做 → 仍 FAIL。见下一节。

---

## Gate B.5 Implementation Adversarial Challenge

对称于 Gate A 的 Performance Architecture Challenge。

```text
Gate A PAC
  Assume the design is correct.
  How would a performance engineer defeat it?

Gate B IAC
  Assume the implementation faithfully follows the design.
  How could actual statements still violate it?
```

原则：[implementation-adversarial-statics](../../../../../knowledge/cam/engineering/implementation-adversarial-statics.md)。

**不得**用「Design 要这样 → 代码看起来实现了 → PASS」。
Static PASS 必须来自 **负向搜索**，不是 reconstruction checklist 自证。

宣称 Static PASS 之前，每一项主动搜索（缺一项标 **未攻击**）：

```text
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
- physical launch index used as logical worker identity
- frozen formula replaced by a plausible simplification
- API resource restriction imported from a different path/tuple
- a dominant phase skipped in overlap-envelope comparison
- consecutive sync primitives claiming the same completion property
- signed negation / INT_MIN / sentinel / narrowing arithmetic
- Frozen-Clause Extraction count ≠ Gate B closure count
```

```text
Static PASS
  =
  negative search found no remaining defect
  ≠
  reconstruction checklist filled
```

未完成负向搜索 → 不得写 Static architecture reconstruction PASS，
即使 PERF-SMELL 表全绿、call graph / event / Host 都已重建。

---

## Static Performance Smell 表

Gate B **先**完成 Skill §7.1 Frozen-Clause 和 §7.2 worker topology，再走本表。
不得在未验证的 worker-space 里把 `task % N` 标 PASS，再拿本表收 baseline。

每条记：`absent` / `present + justified` / `present + unjustified`。

| ID | smell | 常见正当理由（仍须写） |
| --- | --- | --- |
| PERF-SMELL-01 | bulk elementwise 走 Scalar loop；**或不规则 metadata / control-heavy 工作未独立评估 Scalar/Vector/SIMT 就标 Scalar** | 长度极短且不可向量化；只处理真 serial control；**三轴已独立评估，且证明是 true serial cone** |
| PERF-SMELL-02 | 同一数据反复从 GM 加载；**含 H-split / cyclic 分核后每 tile 重读 dst 或 group metadata**；**或 metadata 已 bulk DMA 但 batch/window 是无容量账的魔法值（typical core-local range 本可 one-shot）**；**或已证明 compact/monotonic 仍整窗 min/max 扫描 / `g_win--` 重扫求 span** | 容量不够驻留；每次迭代值确实变；已说明为何不能 metadata outer；staging size 已从 range/UB/footprint/DMA 次数推出；**invariant 不足以头尾推导（须写明为何不 compact）** |
| PERF-SMELL-03 | 中间结果无必要落 GM，或无 footprint 理由的 UB 常驻；**或 over-materialize：通信/落 GM 只为以后重构 consumer state** | 跨核 / 通信协议要求该 GM；驻留会压 tile / 挡 buffering 且 reuse 不够；**PAC-2/5 已证明 producer-side 变换不划算，且 PAC-7 写下 L2 候选** |
| PERF-SMELL-04 | CopyIn→Compute→CopyOut 未分析就强制串行；或声称 overlap 但 statement order 仍串行；**或只对 main phase 画 timeline，prologue/epilogue 含 MTE2/V/MTE3 却跳过**；**或 event 已闭环但 buffer/credit 不够支撑声称的 concurrent stages（如 input ping/pong + single store 却画 `MTE3(n-1)`）**；**或 dominant 与 small high-frequency side path 无联合 timeline，side 默认串在 dominant 之后**；**或 production shape 能轻松放下更强档却选较弱档且无成本理由**；**或只因一个 phase ping-pong 就给整 kernel pipeline PASS，epilogue/local expand 未单独比 E1/E2/E3**；**或 helper 内部 event 闭合，但 writer → actual caller statement → helper → consumer 上的 Wait 不在 caller 语句里** | 无独立阶段；tile 使 overlap 无资格；**每个** performance-relevant phase 的 timeline **和 envelope 表**已画出；resource depth 表已证明 credits ≥ intended in-flight；**联合 timeline 已证明 side 无法进入 V/MTE 气泡，或有 profiling**；每 phase envelope 较弱档有成本理由；**whole-call-graph 已重建 writer → caller statement → helper → consumer → return → next writer** |
| PERF-SMELL-05 | PIPE_ALL / 过宽同步 / **无理由的全 rank phase barrier** 无 dependency 说明；**或 Host stream barrier 方便就把 fused operator 拆成多次 device launch**；**或未枚举 VEC-side SHMEM barrier 就把单 kernel 等同于 MIX+device Barrier**；**或 manual HardEvent 声明了边但 statement 不成对 / Wait 无 startup 规则**；**或 phase A→B 对已 signaled/free 且未经 Wait 的 Event ID 再 SetFlag**；**或 HardEvent 类型与 writer/reader/next-writer 拓扑不符（sibling 熟名，如 input 用 `MTE3_MTE2`）**；**或跨 mechanism / 跨 phase 的 producer→consumer 未进 publication graph（含 SIMT GM store→SIMT GM load、ABI tensor、同一 AIV）**；**或连续 WaitFlag/quiet/barrier/PIPE_ALL 声称同一 completion 且无 distinct-edge 表** | 判别实验（须标明拆掉）；已证 in-kernel 同步不可表达 / correctness 要求 launch 边界 / 测量表明 split 更好；机制搜索列出目标 API 与先例；协议要求的全局 publish；已说明它禁止哪段 overlap；Event Protocol Closure 表已填且 schedule 匹配；**phase 交接表已填：end state + inherit/Wait-then-reinit/disjoint**；**Event 类型从表推出，不是从 sibling 抄名**；**publication graph 已分类该边；same-AIV 只证明不需要跨核 SyncAll，不省略 visibility 证明**；**每个同步原语有 distinct unsatisfied edge；「更保险」不是 justification** |
| PERF-SMELL-06 | 生产 bulk 路径逐元素 GetValue/SetValue；**含本可 bulk DMA 的连续 descriptor 仍每 group 三次 GetValue** | 调试单点；非生产搬运；descriptor 不可成块且已比较过 bulk |
| PERF-SMELL-07 | 内层循环碎片 DMA。**source irregular 只 justify source gather，不自动 justify fragmented CopyOut** | 真随机 gather 且无法成块；目的地址也不连续 |
| PERF-SMELL-08 | 重算 loop-invariant metadata；或立刻被覆盖的 Duplicate / 清零；**或 UB 里已有 group header 仍扫描求可由头尾推导的 span**；**或逻辑单遍消费因 helper 退化成 repeated scan / O(N²)，即使数据已在 UB**；**或只报 helper 内 / caller 主循环复杂度，未把 outer × helper × nested × helper-of-helper 相乘** | 每次确实依赖不同输入；acc 可能全 skip 必须先零；**producer 非 monotonic（须引用 Contract）**；**额外遍数已证明必要，且不推迟下一发 MTE2**；**完整 call graph 相乘后仍是逻辑复杂度** |
| PERF-SMELL-09 | UB 分配后立刻 spill/reload | 生命周期被后续 tile 覆盖，必须让位 |
| PERF-SMELL-10 | occupancy 不足仍不审查第二轴；**或** 为填满 AIV 默认拆 natural unit（token/group）而无 cost model；**或** 未经比较的 flattened round-robin；**或** 把未经测量的启发式阈值（如 `H>=512`）写成 baseline 自动策略；**或 common-case 可 full inner axis 仍把 `h_tile`/`h_off` 写进 hot path（DMA burst 切块升成算法 tile）**；**或因 phase 内有一段 serial island 就把整个 phase 丢给 core0，岛前生产者 / 岛后消费者本可并行**；**或把 ordered identity generation 扩成整个 downstream 必须 serial** | 第二轴 write conflict / 协议串行；已枚举 2D 且 cost model 显示 metadata/DMA 代价更大；contiguous vs cyclic 已比较；阈值仅作为 optimization candidate；**任务合同明确超长 hidden，或 UB 在缩完 metadata 后仍装不下，且 fallback 是独立路径**；**serial-island DAG 已画出 true cone（身份/次序决定 vs 并行 lookup/materialize），岛外工作已映射 SIMT/Vector/并行核** |
| PERF-SMELL-11 | 大量 tiny Vector API call / repeat=1 小块循环 | 尾块；真不规则且无法拼成更大 contiguous 区 |
| PERF-SMELL-12 | 未先设计 physical UB map 就默认 TPipe/TQue/TBuf；把 AllocEventID + TBuf 切片叫 hybrid；无 physical map；**或 map 漏掉 Cast/DMA 中间物理 region（`Add(acc, Cast(in))`、`wgt=K*4` 当 landing）**；**或 width-change 口头 in-place 而无 API 证据**；**或冻结 API 后 Pad/blockLen/stride/pad 参数与声称 footprint 不符（默认 `{}` 当证据）**；**或 overlay 只证 lifetime 不重叠，未做 max-footprint closure 或 leftover identity**；**或 worker_id=GetBlockIdx() 仅因 Host 发射了 N 个 block，worker-space 未证**；**或 Frozen-Clause 表自选子集却声称 exhaustive** | correctness baseline / 动态 lifetime；目标仓高性能 sibling 普遍 TQue 且已对照；已交 physical map 并说明 TQue 只表达哪一段；Physical Realizability 已填 API + landing；**operand graph 每个 op 有 dst；API Invocation Contract 已用一级证据填 footprint**；**allocated_extent >= max(all phase footprints) 且 Host 编码了该不等式；handshake 平面跨 launch 身份已证**；**Logical Worker Topology 已重建；extracted FC count == closure count** |

`present + unjustified` → 还不是可接受的 development baseline。先改结构或补 justification，不要说「反正 correctness 先过」。

不要把本表写成 Knowledge fact，也不要根据 smell 报加速比。
