# UB TQue / TBuf and double buffer

status: **accepted**

普通 **Vector** kernel：先问 **这块 UB 由谁管理、`InitBuffer` 的 `num` 给这条队列加了几块 storage**。不要把模板参数 `depth` 当成 double buffer，也不要把 43 的 L1/L0 pingpong 槽抄进 `InitBuffer`。

上一张 [pipeline-events-and-ordering](../synchronization/pipeline-events-and-ordering.md) 回答：什么时候可以读、什么时候可以复用。  
本文回答：这块 storage 是 `TQue` 还是 `TBuf`，`num=2` 增加了什么资源和并发能力。  
本文 **不回答**「这个算子该不该用 TQue」。那是 [cam-operator-development Memory Orchestration Gate](../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md)。  
Cube `A1/A2/B1` 全表、完整 double-buffer 长模板、逐行 Softmax **不并进这里**。

证据种类：`official-document` | `source-code` | `recommendation` | `unknown`。  
本文件 **没有** `benchmark`。

---

## 先问什么

```text
1. 这块 buffer 要不要跨 MTE 与 Vector？（要 → TQue；纯 Vector temp → TBuf）
2. InitBuffer 的 num 是 1 还是 2？len 是单块字节还是总字节？
3. 模板 depth 是 queue protocol（producer 可领先 consumer 的层次），还是被误当成 double buffer？
4. num=2 之后 UB footprint 有没有按 2×len 回传到 tiling？
```

不要先问“depth 填 2 会不会更快”。

---

## Rule

```text
TQue
  = producer-consumer queue abstraction
  + 由 TPipe::InitBuffer 为它绑定的一组 LocalTensor backing blocks
  用 Alloc / EnQue / DeQue / Free
  普通 Vector：CopyIn 用 VECIN，CopyOut 用 VECOUT

TBuf
  = 计算用临时 storage
  用 Get<T>()
  官方：只能参与计算，不能入队/出队

InitBuffer(que, num, len)
  给这个 queue 配 backing storage
  num = backing blocks 数，每块 len 字节
  num=2 开启 double buffer（官方用语）
  num ≠ 模板 depth

depth
  = queue 的逻辑深度 / producer 可领先 consumer 的队列层次
  约束 EnQue / DeQue 的排队关系
  ≠ storage block count
  ≠ double buffer
  即使 depth=1，仍可 num=2
```

---

## 选 TQue 还是 TBuf

| 这块 UB 的角色 | 用 | 为什么 |
| --- | --- | --- |
| CopyIn / CopyOut，要和另一条 pipe 交接 | `TQue<VECIN>` / `TQue<VECOUT>` | 需要 EnQue/DeQue 表达 readiness |
| 纯 Vector 中间结果、workspace | `TBuf<VECCALC>` | 官方：TBuf 申请的空间只能计算，不能入队出队 |

TBuf 生命周期不重叠时可以复用同一块（tiling 文已有这条 `recommendation`）。不要给 TBuf 写 EnQue。

`A1/A2/B1/CO1` 是 Cube Case 的 TPosition。普通 Vector **不要**从 43 抄过来。

---

## `num` ≠ `depth`

官方把两件事拆开（`official-document`）：

| 参数 | 回答 | 典型 Vector |
| --- | --- | --- |
| `InitBuffer(que, num, len)` 的 **num** | 这条队列有几块 **storage** | 单缓冲 `1`；double buffer `2` |
| `InitBuffer` 的 **len** | **每一块** 的字节数（不足 32B 会向上补齐） | 按 aligned tile 算，不是 logical shape |
| 模板 **depth** | queue protocol：producer 可领先 consumer 的逻辑层次 | 非原地 **推荐 1**；原地 Tensor **必须 0** |

```text
TQue       → 管 queue protocol
InitBuffer → 给这个 queue 配 backing storage
num        → backing blocks 数
depth      → 排队层次，不是块数

depth=1
  普通 producer→consumer 一进一出范式

depth>1
  只有确实需要 producer 提前积累多个 queued tensor 时才使用

depth=1 + num=2
  = 合法且官方范式常用
```

`AllocTensor` 是从 InitBuffer 绑好的 backing blocks 里取当前可用块，不是临时新建一块 UB。

`depth>1` 官方只留给极少数 producer 需要提前排队多个 tensor 的 preload；**不推荐**当默认。不要把它读成“第 N+1 次 EnQue 前必须 DeQue”的机械计数器。  
`depth=1` 时编译器“通常更好”是官方 `recommendation`，不是本文件可引用的加速比。

`num=2` 的代价是实打实的 UB：这条队列占用约 `2 * AlignUp(len, 32)`。CopyIn 和 CopyOut 各 `num=2` 就是四块搬运槽，还要再加 TBuf。装不下就 **revise tile**，见 [tiling-from-shape](../engineering/tiling-from-shape.md) 和 [950 hierarchy](../hardware/ascend950/core-and-memory-hierarchy.md)。

同一 `TPosition` 上能挂的 buffer 块数有上限。官方 TQue 文档的例子：`num=1` 时可挂更多队列，`num=2` 时每个 TQue 占两块，能挂的 TQue 更少。这是 **资源上限**，不要把某代“8 / 4”抄成 950 硬件定律；超了会 Alloc/Free 失败或挂起。

---

## `num=2` 增加了什么

上一张已经固定：EnQue/DeQue 是 readiness，Alloc/Free 是 reuse。

`num=2` 多给的是 **第二块 storage**，让下一 tile 的 Alloc/CopyIn 不必等上一 tile 的 Free。这样 MTE2 搬 tile N+1 才有可能和 Vector 算 tile N 重叠。

```text
num=1
  同一队列通常只有一块
  下一 tile 的 Alloc 要等上一 tile Free
  阶段更容易排成串

num=2
  同一队列两块轮转
  合同还是 Alloc→Copy→EnQue / DeQue→Compute→Free
  并不是另写一套 Ping/Pong 函数
```

```text
num=2
  = double-buffer allocation（官方用语）
  ≠
double-buffered execution

Alloc 有第二块
  ≠
CopyIn(n+1) 已在 Compute(n) 完成前发出
```

是否重叠由 **software pipeline schedule** 决定，不是由 `num` 决定。
Development Gate 要为 **每个** performance-relevant phase 画 timeline
（不得只画 main），见 [performance-by-construction Steady-state](../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md)。

官方范式仍是 **一个 for-loop 里 CopyIn / Compute / CopyOut**，靠 `num=2` 轮转，不靠手拆两套 kernel。

`num=2` **不是**：

- 计算做两遍
- 模板 `depth` 改成 2
- 43 的 L1/L0 两个 slot
- “更快”的充分条件（无 `benchmark`；tile 太小或 UB 装不下时要 revise）

TBuf 没有 `InitBuffer(que, num=2)` 这种 queue double-buffer 开关。若算法确实需要多个计算临时区，应作为独立 buffer / lifetime 设计；不要把它称作 TQue `num=2` 意义上的 double buffer。同一句 ping-pong ≠ 同一套机制。

---

## What NOT To Generalize

| 不要当成 fact | 为什么 |
| --- | --- |
| `depth` 控制 double buffer | 官方：depth 与 double buffer 无关 |
| 43 的 2 slots = `InitBuffer(num=2)` | Cube L1/L0 pingpong，不是 UB TQue |
| 所有 buffer 都要 `num=2` | 只对需要和 MTE 重叠的 TQue 有意义 |
| Atlas 训练 4 / A2 8 张 event 表当 950 | cannbot 代际表；本文只用“同 TPosition 有块数上限” |
| 完整 double-buffer 时序长模板、批量逐行百科 | 超出本 Card |
| `num=2` 一定掩盖搬运延迟 | 无 `benchmark`；容量回传优先 |
| `num=2` = 已经形成流水 | allocation ≠ schedule；见  |
| AscendC 开发 = TPipe/TQue | 本文是合同；该不该用由 Skill 选 orchestration；见  |

---

## Sources

| Field | Value |
| --- | --- |
| 官方 InitBuffer | CANN 8.5.0 [InitBuffer](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850/API/ascendcopapi/atlasascendc_api_07_0110.html)（`num=2` 开 double buffer；`len` 按块、可 32B 上对齐） |
| 官方 TQue | CANN 8.5.0 [TQue简介](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850alpha002/API/ascendcopapi/atlasascendc_api_07_0137.html)（`depth` ≠ double buffer；`depth=1` 可开 `num=2`） |
| 官方范式 | CANN 8.5.0 [TPipe/TQue 编程范式](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850alpha001/opdevg/Ascendcopdevg/atlas_ascendc_10_00033.html)（TBuf 只能计算、不能入队出队；`InitBuffer(..., 2, ...)`） |
| 头文件 | `kernel_tpipe.h`（`TQue` / `TBuf` / `AllocTensor` / `Get`） |
| 发现来源（非真源） | cannbot `ops/ascendc-api-best-practices/references/api-buffer.md` @ `c4c425641d11127945d22e5a752fcad77646be97` |
| Related | [pipeline-events-and-ordering](../synchronization/pipeline-events-and-ordering.md)、[memory-copy-and-alignment](memory-copy-and-alignment.md)、[tiling-from-shape](../engineering/tiling-from-shape.md) |
| Last written | 2026-08-25 |
| status | accepted |
