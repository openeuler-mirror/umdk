# Tiling from Shape

status: **accepted**

Agent 接到一个 **普通 AscendC Vector 算子**（Add / ReduceSum / 简单 Broadcast 一类）时，先问 **逻辑轴上有什么语义、proposal 过不过资源与 API 约束**，再写 `TilingData`。不要先抄一张 GEMM/MoE/FA Case 的 tile 常数。

本文是 **从 shape 做第一次 tiling 设计** 的索引，不是第二套 CATLASS pingpong 教程，也不是 CANNBot `ascendc-tiling-design` 三份长手册的搬家。

Cube 数据路径仍读 [43](../../../cases/cam/operators/compute/gemm/ascend950-basic-matmul/case.md)。核间切 K 读 [GEMM K-partition](gemm-k-partition-strategies.md)。FA KV-tile 读 [FA pipeline](fa-pipeline-online-softmax-and-paged.md)。MC2 chunk 读 [MC2 coupling](mc2-compute-collective-coupling.md)。那些文不并进这里。

证据种类：`source-code` | `design-doc` | `cannbot-secondary` | `recommendation` | `inference`。  
本文件 **没有** `benchmark`。cannbot 的“每核 4KB / 512 元素对齐 / 通常这样更快”一律是 `recommendation`。

---

## 先问什么

```text
1. 算子语义是什么？逐元素、沿轴归约、广播、还是 layout 敏感？
2. 哪些轴带着语义，不能当成普通长度 flatten 掉？
3. 核间切哪几根轴？切完 locality 还在不在？
4. 片上 tile 的有效长度、对齐长度、tail 各是多少？
5. proposal 过得了容量 / 对齐 / API 合法性 / 流水吗？
   过不了就改切分，不要硬填参数。
```

不要先问“tile 填多少能跑满 UB”。那是第 5 问的输入，不是第 1 问。

任务合同 / production shapes 若在容量与 API 下可以走 **full inner axis**，
baseline 就保持 full-axis。不要因为理论上可能超长 H，先引入 `h_tile` / `h_off`。
`DataCopyPad` 单次上限由 copy helper 切块，那不是算法维 tile。
超长 hidden 才允许独立 fallback；fallback 不得改 Contract 语义。
细则：[Hot-path vs Exceptional Shape Gate](../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md)。

---

## Graph

第一次设计可以按 1→9 往下走。真正的通例是循环，不是线性配方。

```text
1  operator semantics
        ↓
2  normalize logical iteration space
   (collapse only semantics-preserving axes)
        ↓
3–5  proposal
     core partition + on-chip tile + buffer lifetime
        ↓
6–7  constraint check
     capacity / alignment / API / pipeline
        │
        ├─ pass → 9 Host tiling 输出
        │
        └─ fail → 8 revise split / tile / buffer ──┐
                                                   │
                    <──────────────────────────────┘
```

名字：**proposal → constraint check → revise**。

---

## 1. 识别算子语义

在动任何轴之前先分类。分类错了，后面的 flatten / 切核都会错。

| 族 | 判定（够用就停） | 本文覆盖 |
| --- | --- | --- |
| **Elementwise** | 输入输出 shape 相同，逐元素无跨元素依赖 | 短 pattern |
| **Reduction** | 沿 `axes` 归约；输出丢掉这些轴（或变成 1） | 短 pattern |
| **Broadcast** | 输入 shape 不同，存在 dim=1 对 dim>1 | 短 pattern |
| Transpose / layout | 元素数同，维序或 stride 变 | 只提醒：先标物理连续轴。不展开 |
| GEMM / FA / MoE / MC2 | 已有 Case + Knowledge | **不要用本文当主设计** |

融合算子先拆成上述原子语义再切，不要把 SwiGLU+GMM 当成 elewise。

---

## 2. 规范化逻辑迭代空间

目标：去掉不必要的维度复杂度，**同时保住语义轴**。

cannbot 常把这一步叫“合轴 / 展平”。那只对 **等价轴** 成立。

```text
problem shape
    ↓
identify semantic axes
  elementwise → 各轴角色相同，可以 flatten 成一条迭代空间
  reduction   → 标 A（保留）/ R（归约）；只合并相邻同角色轴
  broadcast   → 先对齐 rank（左侧补 1），标 broadcast / 非 broadcast
  layout      → stride、物理连续轴先留下来
    ↓
collapse only semantics-preserving axes
```

**可以 collapse**

- size=1 且不改变访问连续性的轴（`recommendation` / `cannbot-secondary`）
- 相邻、角色相同的轴（elewise 任意相邻轴；reduce 仅相邻 A 或相邻 R）
- broadcast 上 **flag 相同** 的相邻轴（`cannbot-secondary`）

**不能为了 flatten 做的事**

- 把 R 轴并进 A 再当 1D elewise
- 把 broadcast 轴（stride=0）并进必须顺序读的非广播轴
- 把要 transpose 的短通道轴展平进长轴后再假装还能 cheap gather

规范化之后，才进入 core partition。

---

## 3. 选择 multi-core partition

proposal 的第一刀：哪些轴 **核间独立**。

要同时满足：

- 各核工作量接近（tail 核可以少，但不能空转一堆核）
- 每核拿到的数据尽量局部（相邻元素同核）
- 不要为了“用满核数”切碎唯一连续维，把 GM 打成碎片

`recommendation`（cannbot elewise，不是 950 事实）：每核工作量太小就不值得再开核。具体阈值跟 dtype、启动开销有关，不要把 4KB 写成硬件下限。

tail 在这一层就会出现：对齐之后，最后一核 / 最后一个虚拟 block 往往更短。Kernel 必须能得到每核真实 workload，不要隐含“每核 `ubLoop` 相同”。former/last 可以写成独立字段，也可以从 `totalLength` / 切分粒度确定性派生（见 §9）。

核间切轴之前，先把 **logical worker** 从 launch topology 推出来。`<<<block_dim>>>` 和 `GetBlockIdx()` 不是同一个空间。

```text
physical execution topology
    core_ratio / AIC vs AIV
    GetBlockIdx / GetBlockNum
    GetSubBlockNum / GetSubBlockId
        ↓
dense logical worker_id ∈ [0, worker_count)
        ↓
才允许按 worker_id 切 work item
```

禁止：

```text
<<<block_dim>>>  →  GetBlockIdx() == worker_id
core_ratio(0,1)  →  GetSubBlockNum() == 1   （无 first-party 证据时）
GetBlockIdx()/GetSubBlockNum()  →  GetBlockIdx()   （「看起来等价」）
```

`worker_count` 取 `GetBlockNum()`、`GetBlockNum()*GetSubBlockNum()` 还是 `GetBlockIdx()*GetSubBlockNum()+GetSubBlockId()` 这一族，必须由 **本条 launch** 的 AIC/AIV 角色决定，不要从 sibling 算子抄。没有对本 launch 的证据时，保留 Design 写明的公式，不要简化。

必须还能证明：每个参与的 logical worker 恰好一个 `worker_id`；每个 work item 恰好一个 owner。只证明「假定 worker_id 正确后 `task % N` 覆盖」不够。

---

## 4. 设计 on-chip tile

普通 Vector kernel：本文主要讨论的片上路径是 **GM ↔ UB**。  
L1 / L0 等 Cube-oriented hierarchy 不在本文通用 Vector tiling 范围内；需要时转到对应 Cube Case / [950 hierarchy](../hardware/ascend950/core-and-memory-hierarchy.md)。不要把 43 的 L1 `m1/n1/k1` 填进 Add。

对当前 tile，Kernel 必须能确定：

| 量 | 用途 |
| --- | --- |
| **effective length** | 真实元素 / 行 / 列，给 Compute 和 `DataCopyPad` 的 count |
| **aligned length** | 分配 UB、算 row stride 用（需要时） |
| **tile count** | 这核上完整 tile 的循环次数 |
| **tail tile** | 最后一次不完整块 |

这些量同样可以显式下发，或由更小的一组 Host 字段派生。Reduction 里 cannbot 把有效/对齐长度叫 `rLength` / `rLengthAlign`（`cannbot-secondary`）：搬运和 Reduce API 用有效长，UB 偏移和 buffer 尺寸用对齐长。通例是 **两套长度不要混**，不是必须用这两个字段名。

全载 vs 分载：整行或整块（加对齐）能否进 UB。能全载时可减少 tile 循环，以及某些跨 tile 状态维护；不能则继续切 tile。这是容量判定，不是“full-load 一定更快”（无 `benchmark`）。

```text
split
  ≠
partial

split a dependency-bearing axis  →  may require partial / merge
split independent tiles          →  只是多一轮 Copy/Compute，没有 merge
```

Elementwise 把 10000 切成 4×2500 没有 partial。Broadcast 多数也只是分 tile 搬运/计算。只有被切轴带着跨 tile 数据依赖（典型：Reduction 的 R）时，才准备 partial / merge。

---

## 5. Buffer lifetime 规划

列出 **input / output / temp**，标生命周期。

- 生命周期不重叠的 temp，复用同一块 UB（`cannbot-secondary`）
- 单 buffer vs double buffer 是容量决策：double 把同角色 buffer 乘起来，装不下就回到 revise
- UB 上的 double buffer ≠ 43 的 L1/L0 pingpong 槽。Cube Case 的“2 slots”不能当 `InitBuffer` 参数抄

半精度 Add/Sub 若走 FP32 中间结果，proposal 里要为中间 buffer 留份数。这是 `recommendation`（cannbot elewise Step 2），不是所有半精度算子的义务。

运行时容量用 `GetCoreMemSize` 读，不要把某张 Case 或 cannbot 表里的 248KB 写死。NpuArch=3510 在本机 CANN 8.5.0 上 22/22 ini 的 UB 典型值是 248 KiB，见 [950 hierarchy](../hardware/ascend950/core-and-memory-hierarchy.md)。

---

## 6. 加入 API / hardware constraints

proposal 做完必须过这一关。过不了就 revise，不要在 kernel 里“差不多对齐”。

典型回传（发现来源 `cannbot-secondary`；合法性以官方 API 为准）：

| 约束 | 回传到 tiling 的方式 |
| --- | --- |
| 对齐 / padding | aligned length 膨胀 → UB footprint 变大 → 减小 tile |
| Vector `repeatTime` 等窄整数上限 | 例如 `uint8_t` 时 repeat 不能按“行数随便写”；可能再切一层 loop 或减小 R。细则见 [mask-repeat-and-kernel-limits](../ascendc/vector/mask-repeat-and-kernel-limits.md) |
| 容量 | tile 或 double buffer 超 UB → 减 tile 或退回单 buffer |
| 支持的搬运路径 | 非对齐、带 pad 的 GM↔UB 用 Pad 类接口；不要把逐元素 GM 读写当生产数据路径（`recommendation`）。细则见 [memory-copy-and-alignment](../memory/memory-copy-and-alignment.md) |

“API 限制会回传到 tiling”是这篇最重要的工程规律之一。`repeatTimes≤255` 只是例子，不是唯一回传。

---

## 7. 检查 pipeline feasibility

```text
CopyIn
   ↘
   Compute
       ↘
       CopyOut
```

问的是：下一拍 CopyIn 能不能和当前 Compute 重叠，而不是“代码里是不是三个函数按顺序写了”。

过不了的常见原因：tile 太小、同步把三段串死、double buffer 实际没第二块、输出还在用的 temp 被下一次 CopyIn 盖掉。这些都回到第 8 步，不在这里发明加速比。

---

## 8. 不满足则 feedback

把失败原因映射回 **改哪一刀**，而不是再猜一组常数。

```text
UB 装不下              → 减小 on-chip tile，或拆掉 double buffer
tile 太小、核利用差    → 重新选 core 轴 / 每核工作量
alignment padding 膨胀 → 重算 footprint，必要时换切分轴
API repeat / stride 超限 → 再切一层 loop，或减小该轴 tile
流水叠不上             → 改 tile 与 buffer 对数，不要先改公式
```

这是 **revise**，不是第二套优化手册。没有实测不要声称某次 revise“更快”。

---

## 9. Host tiling 输出

Host tiling contract 必须让 Kernel **能确定** 每个 core / tile 的真实 workload 与 tail，而不是现场猜“全都一样长”。

必须可获得（或由更小字段确定性派生）的语义：

```text
effective core count
每核 workload
on-chip tile size
aligned storage size（如需要）
loop / tail
（如需要）workspace 或二阶段 merge 描述
```

这些量可以显式写入 `TilingData`，也可以只传例如 `totalLength` / `blockDim` / `tileLength`，由 Kernel 推：

```text
start = blockIdx * blockFormer
valid = min(blockFormer, totalLength - start)
```

former/last、loop/tail 同理，都可以派生。不要为了满足一张字段清单机械堆冗余 `TilingData`。

无法显式获得、也无法确定性推导 last/tail，才等于隐含假设所有 workload 同构。对齐一切过之后，这个假设常常是假的。

---

## Family patterns（短）

下面只留决策差。数字和模板以官方 API / 本机硬件为准。

### Elementwise

规范化：各轴等价 → **可以** flatten 成 1D 迭代空间。输入输出 shape 不同就不是本族，转 Broadcast。

proposal：沿这条 1D 空间切核，再按 UB 切 `ubFormer`。每核 / 每 tile 的 loop 与 tail 必须可确定（显式或派生）。tile 之间无跨 tile 依赖，**不要**为 elewise 准备 partial merge。

constraint：搬运对齐、中间 dtype 是否多占 buffer。不要从 43 抄 `m1/n1`。

### Reduction

规范化：标 A/R。消不贡献语义的 size=1 轴。 **只合并相邻同角色轴**。合完再看是单轴还是 A/R 交替。

proposal 差：

- 最内是连续 R、A0=1 → 按行归约（cannbot：AR）
- 连续块是 `[R, A0]` 且 A0>1 → 按块归约（cannbot：ARA）
- 整行/整块进 UB → 全载；否则沿 R 或沿行再切。切开的是 R（跨 tile 依赖）才准备 partial / merge

核不够且 R 很大、A 又很小：才考虑核间二阶段 merge。那是 Vector reduce 的 workspace+同步，**不是** 66/68。

constraint：Reduce 类 API 的 count 用有效长；buffer 用对齐长。repeat / pattern 限制回传 `R_max` 或 tileR。

### Broadcast

规范化：左侧补 1 对齐 rank。标哪些输入在哪些轴是 broadcast（stride=0）。 **只合并 flag 相同的相邻轴**。

proposal 差：从最内轴往外累乘，找到第一根放不进 UB 的轴当 tile 切分轴；该轴以外再展平分核。不要先把所有轴 flatten 成 elewise 再“顺便广播”。

constraint：广播发生在 GM→UB 还是 UB 内，路径不同。具体 NDDMA / UB Broadcast 选型等 Batch 2 API 文核对后再写死；本文只要求 **proposal 标明广播发生在哪一层**。

---

## What NOT To Generalize

Case 是实例，不是模板参数表。

| 已有 concrete | 能说明 | 不要推出 |
| --- | --- | --- |
| [43](../../../cases/cam/operators/compute/gemm/ascend950-basic-matmul/case.md) | 要先选核间轴 | Vector 也按 MN 切，或 Add 也有 `k1` |
| [60](../../../cases/cam/operators/compute/grouped-gemm/ascend950-grouped-matmul-slice-m/case.md) | 多组 M 时核映射跟着 group 走 | 普通 reduce 需要 `groupList` |
| [66](../../../cases/cam/operators/compute/gemm/ascend950-streamk-matmul/case.md) / [68](../../../cases/cam/operators/compute/gemm/ascend950-multi-core-splitk-matmul/case.md) | 核不够时可能要二阶段 | 普通 Reduce 上 StreamK/SplitK |
| [73](../../../cases/cam/operators/compute/gemm/ascend950-matmul-full-loadA/case.md) | 全载 vs 分载是容量权衡 | UB FullLoad = L1 full-K A |
| [CanImplement](canimplement-is-not-all-constraints.md) | 检查函数 ≠ 约束全集 | Host 有 CanImplement 就不用再做第 6 步 |
| MC2 Cases | 通信 chunk 有自己的 ownership | 普通 compute tiling 能解释 overlap |
| Sparse / FA Case | KV-domain policy | 本文的 tile = softmax 状态机 |

也不要：

- 把“先 flatten”当成所有 tiling 的固定第一步
- 把 1→9 当成填完就结束的清单
- 把 cannbot 的 4KB / 512 元素写成 950 硬件事实
- 把逐元素 GM `GetValue`/`SetValue` 写成“非法”；它是差的生产搬运（`recommendation`），合法性另证
- 把 split 当成一定要 partial；无跨 tile 依赖就只是多一轮 Copy/Compute
- 把 former/last/tail 必须写成独立 `TilingData` 字段；能确定性派生就够
- 把 `GetBlockIdx()` 写成 logical worker id；launch width 不定义 worker 空间

---

## Related

| 角色 | 文档 |
| --- | --- |
| 消费方（尚未改 Skill 结构） | `skills/cam/operator/cam-operator-development/` 的 Parallelism / Memory 节应先读本文 |
| Cube 选轴实例 | [43](../../../cases/cam/operators/compute/gemm/ascend950-basic-matmul/case.md) |
| 核间切 K（不要套到 Vector） | [GEMM K-partition](gemm-k-partition-strategies.md) |
| 命名检查 ≠ 约束全集 | [CanImplement](canimplement-is-not-all-constraints.md) |
| 950 片上容量 / 运行时接口 | [950 hierarchy](../hardware/ascend950/core-and-memory-hierarchy.md) |

---

## Sources

| Field | Value |
| --- | --- |
| repository | cann/cannbot-skills (discovery only) |
| remote | `https://gitcode.com/cann/cannbot-skills.git` |
| commit | `c4c425641d11127945d22e5a752fcad77646be97` |
| hardware | 面向 ascend950 写决策；容量数字与运行时接口见 [950 hierarchy](../hardware/ascend950/core-and-memory-hierarchy.md) |
| cannbot | `ops/ascendc-tiling-design/SKILL.md`；`references/{elewise,reduction,broadcast}/patterns.md` |
| Weaver Cases | 只作 What NOT To Generalize，不开新 Case |
| Last written | 2026-08-27 |
| status | accepted |
