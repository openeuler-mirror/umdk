# GEMM K-partition strategies

Agent 在 Ascend 950 上选 CATLASS 风格 GEMM 的 **核间轴**：只切 MN（43）、切每个 MN 的 K（68 SplitK）、还是只切余数 MN tile 的 K（66 StreamK）。

本文是选择索引，不是第二套 pingpong 教程。Cube 数据路径读 [43](../../../cases/cam/operators/compute/gemm/ascend950-basic-matmul/case.md)。live Kernel 读 [66](../../../cases/cam/operators/compute/gemm/ascend950-streamk-matmul/case.md) / [68](../../../cases/cam/operators/compute/gemm/ascend950-multi-core-splitk-matmul/case.md)。

证据种类：`source-code` | `design-doc` | `test` | `benchmark` | `inference`。  
本文件 **没有** `benchmark`。README / 实践文档里的“较优”一律是 `design-doc`。

不依赖 46 Fixpipe。不要把 GMM / MX / example 69 并进这棵树。

---

## Graph

```text
43 Basic Matmul
      │  standard MN tiling
      ├──────────────┐
      ↓              ↓
66 StreamK        68 SplitK
mnTiles % nAic    every MN tile
K partition       K partition
2 slots/AIC       full output-C planes
remainder         global
AIV reduce        AIV reduce
```

---

## Symbols

GEMM 矩阵名 **A、B、C** 只表示操作数与输出。核数和 tile 数不用 `B`/`C`。

对当前 live 三例的 L1 tile（fp32 example：`m1=n1=256`，`k1=128`）：

```text
nAic    = launched AIC count     // 66/68 Host: GetCoreNumAic()
mnTiles = CeilDiv(M,m1) * CeilDiv(N,n1)
kTiles  = CeilDiv(K,k1)
```

| 本文用词 | live 源码 | 不要理解成 |
| --- | --- | --- |
| **remainder MN tiles** | `streamkBlocks = mnTiles % nAic` | 默认前面已经有完整波 |
| **remainder AIV reduce** | AIV 只加这些 tile 的 partial | 大 GEMM 最后一轮的插图 |
| README「尾波」 | `design-doc`：`mnTiles > nAic` 且余数非 0 时对这些 tile 的叫法 | live 调度条件 |

CATLASS 66/68 README 写 `B`、`C`：那里的 `B` 是 `mnTiles`，`C` 是 `nAic`，**不是** 矩阵 B / 输出 C。下文引用 README 谓词时用括号标出。

`mnTiles < nAic` 时余数等于全部 MN tile，`normalBlocks = 0`。shipped 66/68 CLI `256×512` → `mnTiles = 2` 就是这种（`source-code` / `test`）。

---

## 先问什么问题

```text
1. 43 的一核一 MN、走完 K，核够不够满？
2. 不够满：是 mnTiles 太小（68），还是 mnTiles 已经 ≥ nAic
   但余数 mnTiles % nAic 在浪费一轮（66）？
3. 切 K 之后 partial 放哪、谁写输出 C、reduce 覆盖整张输出
   还是只覆盖 remainder tiles？
```

不要先问“K 大不大就 StreamK”。K 大只说明 **有东西可切**；切哪些 MN 的 K 才是 66 vs 68。

---

## Decision tree

步骤 1–2 是 `source-code` 占用；步骤 3–5 的“该用哪张模板”来自 README / 实践文档（`design-doc`）。**两个 example 都没有运行时选择器**（`source-code`）。选 43/66/68 是 Host 决策。

```text
1. 从 43 开始。
   一 MN tile = 一 AIC 走完 K。Workspace 0。本例 AIV 空。

2. 用 live L1 tile 数 mnTiles、kTiles。
   L1/L0/L0C 仍须按 43 公式放下。把 m1/n1 缩小来制造更多块
   是另一根旋钮；实践文档说 mnTiles 很小时先考虑它（design-doc）。

3. 若 mnTiles >= nAic 且 mnTiles % nAic == 0：
      留在 43。StreamK 多 mix/AIV 但没有 remainder 可切。
      SplitK 仍会给每个 tile 写 workspace 平面。

4. 若 mnTiles <= nAic/2 且 kTiles >= 2：
      文档匹配 68 SplitK（design-doc；README: B <= C/2）。
      代价：workspace M×N×acc×factor；AIV 归约整张输出 C；AIC 不写 C。

5. 若 mnTiles > nAic 且 mnTiles % nAic != 0
   （文档还加 mnTiles/nAic > 1 且余数 <= 0.8×nAic；
     README: B/C > 1 && B%C <= 0.8C）：
      文档匹配 66 StreamK（design-doc）。
      代价：每 AIC 两槽 L1 tile acc；AIV 只 reduce remainder tiles；
      normal tile 仍 43 式写输出 C。

6. 若 mnTiles < nAic 但想“K 很大所以 StreamK”：
      文档窗口是 68，不是 66 README。
      66 二进制仍会把全部 MN 标成 streamk（normalBlocks=0），
      workspace 仍是 2 槽/AIC，不是 68 的满输出-C 平面。
      不要把它叫做 SplitK。

7. 若 kTiles == 1：
      核间切 K 造不出额外 Cube 活。留 43 或改 tile。
```

---

## 43 vs 66 vs 68（live）

| | 43 MN tiling | 66 StreamK | 68 SplitK |
| --- | --- | --- | --- |
| 切哪些 K | 不跨核切 | **仅** remainder MN tiles | **每个** MN tile |
| Partial | 无（输出已在 GM） | 2 × `L1_M×L1_N` acc / AIC | `factor` 张满 `M×N` acc |
| 谁写输出 C | AIC Fixpipe | AIC（normal）+ AIV（remainder） | **仅 AIV** |
| Reduce 覆盖 | — | remainder tiles only | 全局 `M*N` |
| AIC→AIV | — | streamk 核可提前 flag | 全部 Cube 之后 |
| Host AIC | `min(nAic, taskNum)` | 全部 `nAic` | 全部 `nAic` |
| Binary | cube | mix | mix |

Cube Block 三例相同：`MmadPingpong` + UnitFlag + fp32 `256/256/128` · `256/256/32`（`source-code`）。

Workspace 公式（`source-code`）：

```text
66: max(2 MiB, L1_M × L1_N × sizeof(acc) × nAic × 2)
68: max(2 MiB, M × N × sizeof(acc) × splitkFactor)
    splitkFactor = 2
    if nAic / mnTiles > 0: splitkFactor = nAic / mnTiles   // 整数除，可为 1
    splitkFactor = min(splitkFactor, kTiles)
```

不要把公式写成加速比。

---

## 文档窗口 vs 二进制

| 局面 | 文档（design-doc） | 二进制（source-code） |
| --- | --- | --- |
| `mnTiles` 大且余数为 0 | 43；StreamK“通常不必” | 66 仍启动 StreamK，`streamkBlocks=0`，AIV 空转。68 若 `mnTiles>nAic` 仍至少 `min(2,kTiles)` |
| `mnTiles>nAic` 且有余数 | StreamK，若还满足 README `B/C>1` 且 `B%C<=0.8C` | 66 就是这个结构。68 会切 **所有** tile |
| `mnTiles<=nAic/2` | SplitK（README `B<=C/2`） | 68 `GetSplitkFactor`。66 把全部 MN 当 streamk |
| 短 K | 切 K 可能输给 reduce 成本 | 68 factor 被 `kTiles` 封顶 |

shipped 形状：66/68 都是 `256×512` → `mnTiles = 2`。这是 SplitK 文档窗口，不是 66 README 的 `B/C>1`。66 测的是 **zero-complete-wave 的 remainder tiles**，不是“大 GEMM 最后一轮”。

---

## What NOT To Copy

- 「StreamK = 换了个名的 SplitK。」调度器、workspace、reduce 覆盖面都不同（`source-code`）。
- 「StreamK 切所有 K。」只切 remainder MN tiles。
- 「SplitK 只切最后一轮。」每个 MN 都切。
- 「README 谓词编译进 kernel 了。」没有。
- 「66 CLI `256 512 1024` 是 StreamK 文档窗口。」`mnTiles=2` 不是 `mnTiles/nAic>1`。
- 把 README 的 `B`/`C` 当成矩阵 B / 输出 C。
- catalog 曾写的 fp16/cube；JIT `TileShapeScalerTLA` 把 fp32 L1-K 缩成 64；68 reduce 写死的 192 KiB；example 37 的 `StreamkReduceAdd`。

冲突只记录，不在本文调和：example vs JIT L1-K；66 CLI vs README 窗口；66 README 的 `37_ascend950_tail_...` 文件名 vs 树（37=A2 StreamK，69=950 余数 SplitK）。

---

## Related Cases

| 角色 | Case |
| --- | --- |
| MN baseline | [ascend950-basic-matmul](../../../cases/cam/operators/compute/gemm/ascend950-basic-matmul/case.md) |
| remainder-tile StreamK | [ascend950-streamk-matmul](../../../cases/cam/operators/compute/gemm/ascend950-streamk-matmul/case.md) |
| every-MN SplitK | [ascend950-multi-core-splitk-matmul](../../../cases/cam/operators/compute/gemm/ascend950-multi-core-splitk-matmul/case.md) |

非目标（本批不入库）：09/22/34/52 SplitK 变体、37 A2 StreamK、69、46 Fixpipe、60 GMM。

---

## Sources

| Field | Value |
| --- | --- |
| repository | cann/catlass |
| remote | `https://gitcode.com/cann/catlass.git` |
| commit | `a8b4fffbd9cabc021dfd47253e907a1cde59de25` |
| hardware | ascend950 (`CATLASS_ARCH=3510`) |
| 43 | `examples/43_ascend950_basic_matmul/` · `include/catlass/gemm/kernel/basic_matmul_tla.hpp` |
| 66 | `examples/66_ascend950_streamk_matmul/` · `include/catlass/gemm/kernel/streamk_matmul_tla.hpp` · `StreamkGemmIdentityBlockSwizzle` |
| 68 | `examples/68_ascend950_multi_core_splitk_matmul/` · `include/catlass/gemm/kernel/multi_core_splitk_matmul_tla.hpp` · `SplitkReduceAdd` |
| practice (design-doc) | `docs/zh/1_Practice/others/fused_kernel_optimization.md`（example 37 StreamK 谓词）；`docs/zh/1_Practice/others/matmul_kernels_optimization.md`（A2 SplitK 叙述） |
| Last verified | 2026-08-21（符号：矩阵 A/B/C vs `mnTiles`/`nAic`；remainder tiles，不用 tail-region） |
