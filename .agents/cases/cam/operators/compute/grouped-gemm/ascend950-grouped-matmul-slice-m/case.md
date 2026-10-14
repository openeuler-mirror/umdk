# Case Card: CATLASS 60 Ascend950 Grouped Matmul Slice-M

本 Case 只描述 **当前 example 真正运行的路径**：fp16 A/B/C、fp32 累加、`GroupedMatmulSliceMTla` + `MmadPingpong`、UnitFlag、prefix-sum `groupList`。  
Slice-K GMM / dequant GMM / `CATLASS_EXPERIMENTAL_GROUPLIST_SEGMENTED` **存在但未运行**，本 Case 不教授其行为。

Agent 默认读本文件，不要去复制完整上游源码。Cube 数据路径与 [43 Basic Matmul](../../gemm/ascend950-basic-matmul/case.md) 同一套 Block；本 Case 的新内容在 **Kernel 调度 + `groupList` 契约**。

---

## What

在 Ascend 950 上计算一组共享 `N,K`、在 M 上拼接的 GEMM：

```text
for g in groups:
    C[rows_g] = A[rows_g] @ B[g]
```

- 本 Case 实例化：`A, B, C` 均为 **fp16**，**RowMajor**，累加 **fp32**，无 Bias。
- `groupList` 元素类型 `int64_t`，编码是 **prefix-sum 边界**，不是每组行数。
- 有效计算全部在 **AIC / Cube** 上完成。AIV 入口存在但为空。**不是** MIX 算子。

---

## Why This Case

价值不在“又一个 pingpong GEMM”，而在于它是 43 黄金分层之上、**唯一多出来的那一层**：

```text
Example / DeviceGemm
        ↓
Kernel (GroupedMatmulSliceMTla)  — 读 groupList、按组切 MN、旋转 startCoreIdx
        ↓
Block (BlockMmadTla / MmadPingpong)  — 与 43 相同
        ↓
Tile / AscendC primitive             — 与 43 相同（dtype/tile 数字不同）
```

读 MoE / 生产 GMM 时，先判断变化发生在 Kernel 调度还是 Cube 流水，而不是把“Grouped Matmul”当成一种新的硬件路径。

---

## Data Flow

```text
GM  A  fp16 RowMajor, 形状 m × k（各组在 M 上拼接）
GM  B  fp16 RowMajor, 形状 k × n × problemCount（每组一份 B）
GM  C  fp16 RowMajor, 形状 m × n（各组在 M 上拼接）
        │
        ▼  Kernel：currentM ← prefix-sum groupList
GM  A[totalM : totalM+currentM, :]
GM  B[group]
        │  MTE2  GM → L1  (pingpong，同 43 BlockMmad)
        ▼
L1
        │  MTE1  L1 → L0A / L0B
        ▼
L0A, L0B
        │  Cube Mmad → L0C（fp32 acc，UnitFlag，1 stage）
        ▼
L0C
        │  CopyL0CToDst (3510) → GM
        ▼
GM  C[totalM : totalM+currentM, :]
```

K 在该组的 MN tile **内部**由 BlockMmad 走完。没有跨组切 K。

---

## `groupList` 契约（live path）

```text
groupIdx = 0 .. problemCount-1
currentM = (groupIdx == 0) ? groupList[0]
                           : groupList[groupIdx] - groupList[groupIdx - 1]
inGroupProblemShape = (currentM, N, K)
```

optest 把 `(128,128,128,128)` `cumsum` 之后放到 device，与 kernel 减法一致。

Host `golden::GenerateGroupList`：在 `[0, m]` 抽随机数再排序。那是 prefix-sum 形态。最后一个值是这些随机数的 **max**，**不**强制等于 CLI `m`。Host 仍按 CLI `m` 分配 A；compare 用 `groupList[problemCount-1] * n`。

若定义 `CATLASS_EXPERIMENTAL_GROUPLIST_SEGMENTED`，生成器会改成 **每组 size**。本 example 的 CMake **没有**定义该宏。Kernel 始终做相邻相减。Segmented 形式不是 live path。

不要写成：“groupList 是 expert token count 列表。” live 编码是 prefix-sum 边界。

---

## Parallel Strategy

对每个 group，Kernel：

1. 从 GM 读 `currentM`。
2. `blockScheduler.Update(inGroupProblemShape, (L1_M, L1_N))`。
3. `coreLoops = scheduler.GetCoreLoops()` = **这一组**的 MN L1 tile 数。
4. 用旋转起点把本组 loops 分给各核：

```text
startLoopIdx = (coreIdx - startCoreIdx)  mod coreNum
for loopIdx = startLoopIdx; loopIdx < coreLoops; loopIdx += coreNum
    BlockMmad on that MN tile
startCoreIdx = (startCoreIdx + coreLoops) % coreNum
```

不规则的 `currentM` 变成常规 256×256 Cube tile，外加 `GetActualBlockShape` 的尾块。

Host 启动 **全部** `GetCoreNumAic()`，不像 43 那样 `min(aicCoreNum, taskNum)`。小 group 剩下的核靠下一组的旋转起点接着干活。

Swizzle（shipped example，source-code）：

- `m / problemCount >= n` → `GemmIdentityBlockSwizzle<3,0>`
- 否则 → `<3,1>`

用的是 **CLI `m` / group 数**，不是每个 group 的 `currentM`，也不是 43 的 `M > N`。

**Conflict / divergence — do not resolve:**

| Source | Swizzle 方向启发式 |
| --- | --- |
| shipped example / Python op docstring | `m / problemCount >= n` |
| optest JIT wrapper | `params.k > params.n` → dir 0 else dir 1 |

`SwizzleOffset = 3` 是观察值，不是测过的 950 GMM 最优（若有人写成“为了局部性”，那是 **inference**）。

L2（source-code kernel）：若 `CeilDiv(currentM, L1_M) == 1`，对本组 **B** 关 L2。没有 43 那种“单个 N-tile ⇒ 关 A 的 L2”。CATLASS-specific，不是通用知识。

---

## Memory Strategy

硬件容量来自 `Arch::Ascend950`（source-code）：L1 512 KiB，L0A/L0B 64 KiB，L0C 256 KiB。

公式来自 `block_mmad_pingpong_tla.hpp`，**fp16** A/B、**fp32** acc、2/2/1 stages：

| Buffer | 公式 | 本例 |
| --- | --- | --- |
| L1A | `L1_M × L1_K × 2 × 2` | `256×256×2×2 = 256 KiB` |
| L1B | `L1_N × L1_K × 2 × 2` | `256×256×2×2 = 256 KiB` |
| L0A | `L0_M × L0_K × 2 × 2` | `256×64×2×2 = 64 KiB` |
| L0B | `L0_K × L0_N × 2 × 2` | `64×256×2×2 = 64 KiB` |
| L0C | `L1_M × L1_N × 4 × 1` | `256×256×4×1 = 256 KiB` |

With fp16 and these stage counts, these tiles fully consume listed L1 / L0A / L0B / L0C.

这 **不是** 43 的 fp32 256/128/32 pack。同一 pingpong policy，换 dtype → K tile 变成 `L1_K=256`、`L0_K=64`（每步 L1-K 仍切 4 次 L0-K）。

（**inference**：fp16 下把 K 加倍以贴满同一套容量。不要写成“作者就是为了填满才选这些数”。）

UB 在 live cube 路径上未使用。Workspace：`GetWorkspaceSize` 返回 0。

---

## Pipeline

Live pipeline **就是 43 的 BlockMmad pingpong**：L1 预取下一 K、L0 pingpong、Fixpipe 到 GM。

`pipeline_pattern`: **double-buffer**。

没有额外的 GMM pipeline stage。README 也说本例用 `MmadPingpong` + `BlockMmadTla`。

`CanImplement`：`GroupedMatmulSliceMTla` 返回 `true`。Device 转发。Host 调用了但不检查返回值。与 43 同类的非守卫，**仅限本 kernel**。

---

## Key APIs / 组件

| 层 | 本例类型 | 为何出现 |
| --- | --- | --- |
| Device | `DeviceGemm<GroupedMatmulSliceMTla<...>>` | Host 启动；核数 = 全部 AIC |
| Kernel | `GroupedMatmulSliceMTla<BlockMmad, void, Swizzle, int64_t>` | `groupList` → 每组 MN tiles |
| Policy | `MmadPingpong<Ascend950, UnitFlag=true>` | 与 43 相同的 L1/L0 stage / UnitFlag |
| Block | `BlockMmadTla<...>` | 与 43 相同 |
| Copy | `PackedTileCopyTla` | 与 43 相同角色；fp16 tile 数字不同 |
| Sched | `GemmIdentityBlockSwizzle<3, dir>` | dir 启发式见上，与 43 不同 |

---

## Key Optimization Ideas

值得作为 **本 Case 内** 的设计观察（复制前要重新验证）：

1. 把不规则 `currentM` 收成常规 Cube tile，而不是给 Cube 写变长 M kernel。
2. 跨 group 旋转 `startCoreIdx`，让 Host 可以启动全部 AIC。
3. 复用 43 的 pingpong Block，GMM 变化停在 Kernel。

不要把“旋转 startCoreIdx”写成已证明的 load-balance 策略（**inference** 若那样写）。

---

## Interesting Implementation Details

### Host 核数

43：`min(aicCoreNum, taskNum)`。  
60：始终 `aicCoreNum`。占用依赖跨组旋转，不依赖单组 tile 数。

### L2 bypass（CATLASS-specific）

仅当 **本组** `CeilDiv(currentM, L1_M) == 1` 时对本组 B 关 L2。不要写成 43 的 A/B 对称规则，也不要写成通用 GMM 规则。

---

## Non-active variants

- Slice-K GMM（example 05 / `grouped_matmul_slice_k`）
- 47/48 dequant GMM、80 GMM+GELU
- `CATLASS_EXPERIMENTAL_GROUPLIST_SEGMENTED`
- Mutex / Preload / ShuffleK / Bias / L1 resident
- AIV compute（空函数体）

存在 ≠ 运行 ≠ 本 Case 教学内容。

---

## Source conflicts

| Source | Swizzle 启发式 |
| --- | --- |
| C++ example | `m / problemCount >= n` |
| optest JIT | `k > n` |

This Case does not attempt to resolve the conflict.

生成器最后一个 prefix 不必等于 CLI `m`。同样只记录，不圆回来。

---

## What Agent Should Learn

1. 先画与 43 相同的分层，再看 Kernel 多了什么。
2. `groupList` 先确认编码（prefix-sum vs per-group size），再谈 MoE token。
3. fp16 的 256/256/64 不能抄到 fp32，也不能把 43 的 256/128/32 抄到这里。
4. 启动全部 AIC + 旋转起点，是这个 kernel 的调度选择，不是 950 硬件要求。
5. 这个 `CanImplement` 仍然不是合法性守卫。

---

## What NOT To Copy

### 不要把 CLI `m` 当成“每组都有 `m/G` 行”

live `currentM` 来自 prefix-sum `groupList`。

### 不要把 43 的 fp32 tile 或本例的 fp16 tile 互相套用

容量公式随 `sizeof` 变。

### 不要把 `SwizzleOffset=3` 或 `m/problemCount >= n` 当成通用 GMM 规则

optest 已经用了另一套判断。

### 不要依赖这个 `CanImplement` 做合法性检查

本 kernel 返回 `true`。不要写成“所有 CATLASS GMM 都恒 true”。

### 不要把空 AIV 写成“架构上没有 AIV”

有效路径在 AIC；入口存在但为空。

### 不要把 Slice-K、dequant、MoE routing 写进本 Case

那些是别的 example。

---

## Applicable Scenarios

参考本 Case，当：

- 需要 **多组 GEMM、共享 N/K、A/C 在 M 上拼接**
- 需要看 CATLASS 如何把 `groupList` 映射到现成 Cube Block
- 已经读过 43，要找 Kernel 层的下一课

不要参考本 Case，当：

- 需要 MIX / L0C→UB Fixpipe（那是 46，尚未建 Case）
- 需要 Slice-K、量化 GMM
- 需要 MoE EP / window → [ops-transformer EP](../../../compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md)
- 需要生产 GMM+SwiGLU+MX 融合 → [ops-transformer GMM SwiGLU](../ascend950-gmm-swiglu-mx-quant/case.md)
- 需要可执行的 shape/dtype/`groupList` 编码守卫

---

## Vs 43 Basic Matmul

| | 43 | 60 |
| --- | --- | --- |
| 变化层 | 黄金 Cube pingpong | **Kernel 调度**，Block 相同 |
| Dtype | fp32 | fp16 in/out，fp32 acc |
| L1/L0 K | 128 / 32 | 256 / 64 |
| 问题 | 一个 GEMM | 多 GEMM，共享 N,K；A/C 在 M 拼接 |
| 启动核数 | `min(aic, taskNum)` | 全部 AIC；跨组旋转 `startCoreIdx` |
| Epilogue | void / L0C→GM | 相同 |
| Engine | cube，AIV 空 | 相同 |

---

## Related Cases

- **production extension:** [ops-transformer GMM+SwiGLU+MX](../ascend950-gmm-swiglu-mx-quant/case.md) — 60 的 groupList + 53 的 MX，加上 AIV SwiGLU。不要在那张卡里重学本 Case。
- **MoE groupList 谁生产：** [token/expert/rank 契约](../../../../../../knowledge/cam/engineering/moe-token-expert-rank-data-contracts.md) Rule 5。减法怎么算仍读本 Case。

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/catlass |
| remote | `https://gitcode.com/cann/catlass.git` |
| commit | `a8b4fffbd9cabc021dfd47253e907a1cde59de25` |
| hardware | ascend950 (`CATLASS_ARCH=3510`) |
| example | `examples/60_ascend950_grouped_matmul_slice_m/grouped_matmul_slice_m.cpp` |
| kernel | `include/catlass/gemm/kernel/grouped_matmul_slice_m_tla.hpp` |
| block | `include/catlass/gemm/block/block_mmad_pingpong_tla.hpp` |
| arch | `include/catlass/arch/arch.hpp` |
| test | `tests/optest/tests/test_60_ascend950_grouped_matmul_slice_m.py` |
| license | CANN Open Software License Agreement Version 2.0 |
