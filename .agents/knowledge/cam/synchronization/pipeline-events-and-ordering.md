# Pipeline events and ordering

status: **accepted**

普通 **Vector** kernel：先问 **CopyIn 生产的 UB 数据是否已经 ready for Vector consumption**，以及 **Compute 结果是否已经 ready for MTE3 consumption**。不要先抄一份 double-buffer 模板，也不要把 `PipeBarrier<PIPE_MTE2>` 当成 CopyIn→Compute 的标准同步。

本文只管核内 **MTE2 / Vector / MTE3** 的 producer-consumer readiness 与 execution ordering。本文说的 local readiness **不是** MC2/MoE 的 remote visibility。Cube `MTE1`/`FIX`、Host 多 launch、MoE/MC2 的 flag **不并进这里**。TQue 的 `num`≠`depth`、double buffer 槽数见 [ub-tque-tbuf-and-double-buffer](../memory/ub-tque-tbuf-and-double-buffer.md)。怎么搬见 [memory-copy-and-alignment](../memory/memory-copy-and-alignment.md)。

证据种类：`official-document` | `source-code` | `recommendation` | `unknown`。  
本文件 **没有** `benchmark`。

---

## 先问什么

```text
1. 生产者在哪条 pipe？消费者在哪条 pipe？
   （典型：MTE2 写 UB → Vector 读 UB → MTE3 读 UB）
2. 这条依赖是同流水，还是跨流水？
3. 你用的是 TQue 范式（EnQue/DeQue），还是手写 SetFlag/WaitFlag？
4. AllocTensor 之后有没有把它误当成“数据已经在”？
```

不要先问“加一个 `PipeBarrier<PIPE_ALL>` 能不能好”。那是调试假说，不是设计。

---

## Rule

```text
发射 DataCopy / DataCopyPad
  ≠
搬运完成、consumer 可以读

CopyIn → Compute → CopyOut
  是三条 pipe 上的 data dependency，不是一条顺序 C++ 语句流

TQue EnQue / DeQue
  = 官方 Vector 范式用来表达跨流水 producer→consumer readiness 的合同
  （框架据此插入同步）

PipeBarrier<PIPE_MTE2>
  = MTE2 单流水同步原语
  ≠ 表达 MTE2→V 跨流水 RAW dependency 的标准方式
```

---

## 三条 pipe，不是三行同步 C++

官方流水类型（`official-document`）：

| pipe | 普通 Vector 路径上干什么 |
| --- | --- |
| `PIPE_MTE2` | GM → UB（CopyIn） |
| `PIPE_V` | Vector 计算 |
| `PIPE_MTE3` | UB → GM（CopyOut） |
| `PIPE_S` | Scalar；`GetValue`/`SetValue` 走这里 |

头文件里 GM→UB 的 `DataCopy`/`DataCopyPad` 标 `__inout_pipe__(MTE2)`，UB→GM 标 `MTE3`（`source-code`）。调用返回只表示 **Scalar 已发射**，不表示 DMA 写完。

官方抽象：Scalar 发射指令到各单元队列，各单元 **异步并行**。同一块 UB 上，必须保证先搬入再算、算完再搬出。

```text
CopyIn   : Alloc → DataCopy(Pad) → EnQue
Compute  : DeQue → Vector → EnQue → Free 输入
CopyOut  : DeQue → DataCopy(Pad) → Free
```

这是 CANN 8.5.0 Vector 编程范式（`official-document`），不是性能模板。`InitBuffer(..., num=2)` 打开的 double buffer **不在本文展开**。

---

## EnQue / DeQue ≠ Alloc / Free

官方编程模型（`official-document`）拆开两个 hazard：

```text
EnQue → DeQue
  producer → consumer
  RAW / readiness contract
  回答：什么时候可以读？

consumer → FreeTensor → later AllocTensor
  old consumer → next producer reuse
  buffer lifetime / reuse contract
  回答：什么时候这块 storage 可以重新拿去写？
```

| API | 解决的依赖 | 不是 |
| --- | --- | --- |
| `EnQue` / `DeQue` | 并行单元之间的 **写后读**（生产者写完，消费者才读） | buffer 可以复用 |
| `AllocTensor` / `FreeTensor` | **读后写**（没人再读，才能再分配去写） | 数据已 ready |

`AllocTensor` 只拿到一块 Local Memory。  
`EnQue` 之后，`DeQue` 的调用方才按范式等待上游写完成。

走这条范式时，**EnQue/DeQue 就是你要写的跨流水 readiness 合同**。官方说“按范式编程通常不必再手插同步”，意思不是“可以省略 EnQue”，而是框架替你插 `MTE2_V` / `V_MTE3` 这类事件。

缺 `EnQue`/`DeQue` 一对，缺的是 producer-consumer readiness。缺 `Alloc`/`Free` 一对，缺的是 storage reuse 合同。两件事不要并成一句“缺同步”。

手写跨流水用 `SetFlag`/`WaitFlag`（`HardEvent::MTE2_V`、`V_MTE3`、`S_MTE3` 等）。ISASI，**不保证跨硬件版本兼容**。普通 Vector **先走 TQue**，不要先抄 Cube Case 的 event ID。

`WaitFlag` 需要该 `(HardEvent, eventID)` 上有可证明的 preceding `SetFlag`。头文件不把未 Set 的 event 定义成 ready。手工 ping/pong 的 `*_FREE` 要么 first-use 跳过 Wait，要么 kernel 入口 `SetFlag` 建立 initial free token。声明的边必须在 statement schedule 里成对出现。

单 kernel 若 `phase A → barrier → phase B`，还要写清 phase A 结束时每个 Event ID 是 consumed / signaled / in-flight，以及 phase B 是 inherit、Wait 后再 Set、还是换一组 ID。禁止对已经 signaled 且未经 Wait 的 FREE token 再 `SetFlag`。细则：performance-by-construction **Phase-transition closure**。

`GetValue`/`SetValue` 在 `PIPE_S`。Scalar 写完再 `DataCopy` 出 GM，官方例子插的是 `S_MTE3`，不是 `PipeBarrier<PIPE_S>`（后者会硬件错误）。

循环里同一块 UB 既是 `SetValue` 源、又是 `DataCopyPad`（UB→GM）源时，**发射下一次 Scalar 写之前必须证明上一发 MTE3 已经读完这块 UB**（`MTE3_S` 或等价 completion）。`DataCopyPad` 返回只表示指令已进 MTE3 队列。

```text
SetValue(UB) → DataCopyPad(GM, UB) → SetValue(同一 UB)
  中间没有 MTE3 完成
  ≠
  上一发 payload 已离开 UB

issue DataCopyPad
  ≠
  remote flag / count 已被完整写出
```

缺这条边时，远端完成字会残缺或被踩。Consumer 按 `sum == expected` 自旋，看起来像协议 hang（“flag 收不齐”），根因是 **loop-carried UB reuse**，不要先改 publication 协议。循环结束后的 `PipeBarrier<PIPE_MTE3>` 盖不住迭代之间的 UB 写后写。

跨 launch 的 leftover / 假就绪（第一发过、第二发 hang；handshake overlay 在后级 payload）不在本页。走 [adversarial statics §8](../engineering/implementation-adversarial-statics.md)。

---

## `PipeBarrier` 不是 CopyIn→Compute 的标准原语

官方分类（`official-document`）：`PipeBarrier<pipe>` 是 **single-pipeline synchronization**，保证该 pipe 上前序读写完成后再发射后序。MTE2→V 的 RAW 是 **multi-pipeline** dependency，标准表达是 TQue 合同，或明确的 `HardEvent::MTE2_V` `SetFlag`/`WaitFlag`。

| 写法 | 它是什么 | 不要读成 |
| --- | --- | --- |
| `PipeBarrier<PIPE_V>()` | Vector 单流水屏障 | 等 MTE2 |
| `PipeBarrier<PIPE_MTE2>()` | MTE2 单流水同步原语 | CopyIn→Compute 的标准合同 |
| `PipeBarrier<PIPE_ALL>()` | 阻塞所有 pipe | 设计默认；可作调试假说（`recommendation`） |

`PipeBarrier<PIPE_MTE2>` **不是** MTE2→V 跨流水 dependency 的标准表达方式；不要用单流水 barrier 替代 TQue 或 `MTE2_V` event contract。  
cannbot 把 `PipeBarrier<PIPE_MTE2>` 写成 EnQue/DeQue 的平替：本文 **不 promote**。官方静态 Tensor 示例用的是 `MTE2_V` / `V_MTE3` event，不是 MTE2 barrier。

`PIPE_V` 上前后两条 Vector 有数据依赖时，开启 `--cce-auto-sync`（工程默认常开）时编译器会插 `PipeBarrier<PIPE_V>`，开发者通常不必手写。

编译器自动同步文档列出的是：MTE2↔Scalar、MTE3↔Scalar、Vector↔Scalar、Vector↔Vector。**没有把 MTE2↔Vector 写成编译器自动项**；那条边留给框架（TQue）或手写 `SetFlag`/`WaitFlag`。  
“没写 EnQue 却碰巧对了” **不能**证明可以省略范式。

MTE2 与 MTE3 **地址重叠** 时，官方要求开发者自己插同步。这是同/跨搬运冲突，不是“每次 CopyIn 后拦一道 MTE2 barrier”。

---

## 全 0 / 随机：先当 readiness 假说

输出全 0、随机、偶发错，**优先假说**（`recommendation`，不是唯一病因）：

```text
1. CopyIn → Compute 或 Compute → CopyOut 缺跨流水 readiness
   （没 EnQue/DeQue，或手写 event 不成对）
2. 再查 32B / effective vs aligned
   （见 copy Card）
3. 再查 GetValue/SetValue 当了生产搬运，或 S 与 MTE 之间缺边
```

`PipeBarrier<PIPE_ALL>` 加上之后变对，只说明 **可能是同步**，还要回到 TQue 合同，不要把 `PIPE_ALL` 留在生产路径上当设计。

507035 等错误码 **不要**在这里映射成“一定是没同步”。那是 debug Skill 的假说入口。

---

## What NOT To Generalize

| 不要当成 fact | 为什么 |
| --- | --- |
| `DataCopy` 是同步调用 | 发射在 MTE2/MTE3，调用返回 ≠ 完成 |
| `PipeBarrier<PIPE_MTE2>` = EnQue/DeQue 平替 | 它是 MTE2 单流水原语，不是 MTE2→V 的标准合同 |
| EnQue 比 PipeBarrier 更快 | 无 `benchmark`；而且两者解决的依赖类不同 |
| 开了 auto-sync 就可以不写 EnQue | auto-sync 列表不含 MTE2↔V；范式才是合同 |
| `PIPE_ALL` 当默认设计 | 调试假说 |
| `PipeBarrier<PIPE_S>` | 官方：会硬件错误 |
| 完整 double-buffer 长模板、Cube event 表 | 下一张 Card / GEMM Case |
| 全 0 一定是同步 | 优先假说，不是充分诊断 |

---

## Sources

| Field | Value |
| --- | --- |
| 官方范式 | CANN 8.5.0 [TPipe/TQue 编程范式](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850alpha001/opdevg/Ascendcopdevg/atlas_ascendc_10_00033.html) |
| 官方模型 | CANN 8.5.0 [编程模型设计原理](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850/opdevg/Ascendcopdevg/atlas_ascendc_10_00015.html)（EnQue/DeQue = 写后读；Alloc/Free = 读后写） |
| 官方同步 | CANN 8.5.0 [同步控制简介](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850alpha002/API/ascendcopapi/atlasascendc_api_07_0179.html) · [PipeBarrier](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850/API/ascendcopapi/atlasascendc_api_07_0271.html) |
| 自动同步 | CANN 8.5.0 [毕昇自动同步](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850/opdevg/BishengCompiler/atlas_bisheng_10_0008.html) |
| 头文件 | `kernel_operator_data_copy_intf.h`（`__inout_pipe__(MTE2/MTE3)`）；`kernel_tpipe.h`（`EnQue`/`AllocTensor`） |
| 发现来源（非真源） | cannbot `ops/ascendc-api-best-practices/references/api-pipeline.md` @ `c4c425641d11127945d22e5a752fcad77646be97` |
| Related | [memory-copy-and-alignment](../memory/memory-copy-and-alignment.md)、[ub-tque-tbuf-and-double-buffer](../memory/ub-tque-tbuf-and-double-buffer.md)、[tiling-from-shape](../engineering/tiling-from-shape.md) |
| Last written | 2026-08-25 |
| status | accepted |
