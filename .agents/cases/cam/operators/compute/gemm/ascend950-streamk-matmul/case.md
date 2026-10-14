# Case Card: CATLASS 66 Ascend950 StreamK Matmul

本 Case 只描述 **当前 example 真正运行的路径**：fp32、mix、`StreamkMatmulTla` + `MmadPingpong`、UnitFlag。  
非 TLA `streamk_matmul.hpp`、`block_mmad_streamk.hpp`、example 37/69、Bias、Relu Fixpipe **存在但未运行**。

Agent 默认读本文件。Cube 数据路径与 [43 Basic Matmul](../ascend950-basic-matmul/case.md) 同一套 Block。本 Case 只教 **remainder MN tiles（`mnTiles % nAic`）切 K + workspace 双槽 + 这些 tile 的 AIV inline reduce**。  
sibling：[68 SplitK](../ascend950-multi-core-splitk-matmul/case.md)。不要把两者当成同一种切 K。

---

## What

在 Ascend 950 上计算 `C = A @ B`，但只把 **`mnTiles % nAic` 个 MN tile**（remainder tiles）的 K 拆到多个 AIC，再用 AIV 把这部分的 partial 加回输出 C。

- 本 Case 实例化：`A, B, C` 均为 **fp32**，**RowMajor**，无 Bias。
- 可执行文件是 **mix**：AIC 做 Cube，AIV 只归约 remainder tiles 的部分和。
- `normalBlocks = mnTiles - (mnTiles % nAic)` 那些 MN tile 仍由 AIC 直接 Fixpipe 到输出 C，与 43 相同。`mnTiles < nAic` 时 `normalBlocks = 0`，没有这条直写路径。

README 把 `mnTiles > nAic` 时的 remainder tiles 叫「尾波」（原文 `B>C`，那里的 B/C 是 tile 数/核数，不是矩阵）。那是 **design-doc** 画面。live 调度只认 `streamkBlocks = mnTiles % nAic`，不要求前面已经有完整波。

---

## Why This Case

价值不在又一套 pingpong tile，而在 43 分层上 **只多出来的 Kernel 行为**：

```text
Example / DeviceGemm          mix，全部 AIC，workspace ≠ 0
        ↓
Kernel (StreamkMatmulTla)
        ├── AIC  StreamkGemmIdentityBlockSwizzle
        │         normal  (mnTiles - remainder) → BlockMmad → 输出 C
        │         remainder tiles K 片 → BlockMmad → workspace 双槽
        └── AIV  等 flag，Add **仅 remainder tiles** 的 partial，写输出 C
        ↓
Block (BlockMmadTla / MmadPingpong)  ← 与 43 相同
```

读 68 之前先读本 Case，确认切的是不是 **只有 remainder MN tiles 的 K**。

---

## Data Flow

```text
mnTiles = CeilDiv(M,256)*CeilDiv(N,256)     nAic = GetBlockNum()
streamkBlocks = mnTiles % nAic               // remainder tiles
normalBlocks  = mnTiles - streamkBlocks      // 可为 0

normal MN tile:
  GM A,B → L1 → L0 → Mmad → L0C → Fixpipe → GM C     （同 43）

remainder tiles MN tile:
  每个 AIC 分到一段 L1-K
        │  BlockMmad，目的是 workspace
        ▼
  workspace[2*aic]     当前 MN tile 的 K 段
  workspace[2*aic+1]   跨 MN tile 边界时的下一块头（isCrossBlock）
        │  CrossCoreSetFlag PIPE_FIX
        ▼
  AIV  WaitFlag + Barrier
        │  DataCopyPad → Add → DataCopyPad
        ▼
  GM C 上该 MN tile
```

Cube 核内仍是 43 的 L1/L0 pingpong。K 在 **核间** 被切开的，只有 remainder tiles 里那些 MN tile。

---

## K partition（live）

`source-code` `StreamkGemmIdentityBlockSwizzle`：

```text
kTiles          = CeilDiv(K, 128)
kTileNumPerCore = (streamkBlocks * kTiles) / nAic
kTileRemain     = (streamkBlocks * kTiles) % nAic
```

| 问题 | 本 Case |
| --- | --- |
| 哪些 K 被拆 | 仅 remainder MN tiles 的全 K |
| 拆给谁 | 全部 AIC 均分这些 L1-K；余数核多 1 个 L1-K |
| Partial 在哪 | 每 AIC 两槽 `L1_M×L1_N` acc，下限 2 MiB |
| 谁 reduce | AIV，inline `Add`，**只归约 remainder tiles**（不是 37 的 `StreamkReduceAdd`，不是 68 的 `SplitkReduceAdd`） |
| 如何同步 | `CrossCoreSetFlag<0x2, PIPE_FIX>` / AIV `WaitFlag<0x2, PIPE_MTE2>` + Barrier |

`isCrossBlock`：一个 AIC 的 K 段跨过 MN tile 边界时，溢出写进槽 1。AIV 用 `IsCross` / `GetCoreIdx` 把槽 1 当下一 tile 的头。

当 `normalBlocks > 0`，Kernel 会交换 streamk 核的一次 loop 下标：先做 remainder tiles，再做本来那次 normal MN。源码在；README 没写。example 37 的实践文档称之为“尾轮提前计算”（`design-doc`）。说“就是为了和 AIV overlap”是 **inference**。

`streamkBlocks == 0` 时不切 K，AIV 循环次数为 0。

---

## Parallel Strategy

| 层级 | 本例 |
| --- | --- |
| 启动核数 | 全部 `GetCoreNumAic()`（不像 43 的 `min(C, taskNum)`） |
| normal | 与 43 相同：一核走完该 MN tile 的 K；`normalBlocks` 可为 0 |
| remainder tiles | `GetCoreLoops = completeWaves*nAic + min(streamkBlocks*kTiles, nAic)` |
| Swizzle | **固定** `StreamkGemmIdentityBlockSwizzle<3, 0>`，没有 43 的 `M>N` 切换 |
| L2 bypass | 单 L1-M tile 关 B；单 L1-N tile 关 A（与 43 同类，CATLASS-specific） |

README（**design-doc only**；原文 B=`mnTiles`，C=`nAic`）：`mnTiles/nAic > 1` 且余数 `<= 0.8*nAic` 时“可能较优”。**没有** `benchmark`。二进制 **没有** 这个 if；选 66 是 Host 决策。

CLI / optest MN = `256×512` → `mnTiles = 2`。对 `nAic > 2`，`mnTiles/nAic > 1` 不成立。这组 shape 落在 68 的文档窗口，本调度仍把 2 个 MN tile 全标成 streamk（`normalBlocks=0`）。正确性测的是 **zero-complete-wave 的 remainder tiles**，**不是**“大 GEMM 最后一轮”的插图。

---

## Memory Strategy

Cube 占用与 43 相同（fp32、2/2/1 stages）：L1A/B 各 256 KiB，L0A/B 各 64 KiB，L0C 256 KiB。

Workspace：`max(2 MiB, 256×256×4×nAic×2)`。不是 `M×N×slices` 立方。

AIV 用 `Arch::Ascend950::UB_SIZE` 算每核行数。live 路径 `ElementC == acc`，不走 Cast。

---

## Pipeline

`pipeline_pattern`: **double-buffer**（Cube pingpong）+ **multi-stage**（AIC 写 workspace / GM，然后 AIV reduce）。

不要把 loop-index swap 写成已测过的 overlap 优化。

---

## Key APIs / 组件

| 层 | 本例类型 | 为何出现 |
| --- | --- | --- |
| Device | `DeviceGemm<StreamkMatmulTla<...>>` | mix 启动；workspace |
| Kernel | `StreamkMatmulTla` | remainder tiles 切 K + inline AIV |
| Policy / Block | 与 43 相同 | 不要在本 Case 重讲 pingpong |
| Sched | `StreamkGemmIdentityBlockSwizzle<3,0>` | `streamkBlocks`、`GetStreamkBlockDec` |
| Reduce | Kernel 内 `Add` | 不是独立 Reduce 类型；只覆盖 remainder tiles |

---

## Source conflicts

| 冲突 | 记录 |
| --- | --- |
| Catalog 曾写 fp16 / cube | 已按 live 改为 fp32 / vector+cube |
| Example L1-K=128 vs JIT scaler L1-K=64（fp32） | 不调和 |
| README StreamK 窗口 vs CLI `B=2` | 不调和 |
| README 对比名 `37_ascend950_tail_multi_core_splitk_matmul` vs 树里 37=A2 StreamK、69=950 tail SplitK | 不调和 |

This Case does not attempt to resolve the conflicts.

---

## What Agent Should Learn

1. 先画 43 分层，确认 Block 没变，再读 Kernel。
2. StreamK ≠ 把所有 K 都切给多核。只切 remainder MN tiles。`normalBlocks > 0` 时那些 tile 仍是 43。
3. Workspace 是 **每 AIC 两槽 L1 tile**，不是整张 C 的多平面。AIV 也只 reduce 该 region。
4. README 启发式不是门禁，也不是 benchmark。「尾波」是文档对 `mnTiles>nAic` 画面的叫法（原文 B/C = tile/核）。
5. sibling 68 才是“每个 MN 都切 K”。

---

## What NOT To Copy

### 不要把 catalog 旧的 fp16/cube 当 live

本 Case 是 fp32 mix。optest 另有 fp16 JIT，不是 shipped example。

### 不要抄 37 的 `StreamkReduceAdd` 或 A2 tile

reduce 写在 `StreamkMatmulTla` 的 AIV 里。

### 不要把 `SwizzleOffset=3` / dir 0 当 950 最优

观察值。

### 不要把 README `B/C>1 && B%C<=0.8C`（B=`mnTiles`，C=`nAic`）当测过的结论或编译进去的 if

### 不要把 remainder tiles 默认画成“大 GEMM 的最后一轮”

`B < C` 时整个问题都在这个 region。shipped `256×512` 就是这种。

### 不要在 `B<=C/2` 时用本 Case 当 SplitK

那是 [68](../ascend950-multi-core-splitk-matmul/case.md)。

### 不要依赖这个 `CanImplement`

恒 `true`。

---

## Applicable Scenarios

参考本 Case，当：

- 已经有 43 风格的 MN tiling，问题是 **remainder tiles 上核空闲**
- 需要看 CATLASS 如何只切这些 tile 的 K，并用 AIV **只归约该 region**

不要参考本 Case，当：

- 需要 Cube pingpong 本身 → [43](../ascend950-basic-matmul/case.md)
- `B` 填不满核、每个 MN 都要切 K → [68](../ascend950-multi-core-splitk-matmul/case.md)
- 需要量化 / padding / 单核切 K / tail-SplitK（69）

选 43 / 66 / 68 → [K 轴切分策略](../../../../../../knowledge/cam/engineering/gemm-k-partition-strategies.md)

---

## Vs 43 / 68

| | 43 | 66 | 68 |
| --- | --- | --- | --- |
| 变化层 | 黄金 Cube | **Kernel：remainder tiles 切 K** | **Kernel：每个 MN 切 K** |
| 谁写输出 C | AIC | AIC（normal）+ AIV（remainder tiles） | 仅 AIV |
| Workspace | 0 | 2 槽 / AIC | `M×N×factor` 平面 |
| 二进制 | cube | mix | mix |

---

## Related Cases

- **base:** [43 Basic Matmul](../ascend950-basic-matmul/case.md)
- **sibling:** [68 SplitK](../ascend950-multi-core-splitk-matmul/case.md)
- **index:** [gemm-k-partition-strategies](../../../../../../knowledge/cam/engineering/gemm-k-partition-strategies.md)

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/catlass |
| remote | `https://gitcode.com/cann/catlass.git` |
| commit | `a8b4fffbd9cabc021dfd47253e907a1cde59de25` |
| hardware | ascend950 (`CATLASS_ARCH=3510`) |
| example | `examples/66_ascend950_streamk_matmul/streamk_matmul.cpp` |
| kernel | `include/catlass/gemm/kernel/streamk_matmul_tla.hpp` |
| scheduler | `include/catlass/gemm/block/block_swizzle.hpp` (`StreamkGemmIdentityBlockSwizzle`) |
| block | `include/catlass/gemm/block/block_mmad_pingpong_tla.hpp` |
| test | `tests/optest/tests/test_66_ascend950_streamk_matmul.py` |
| license | CANN Open Software License Agreement Version 2.0 |
