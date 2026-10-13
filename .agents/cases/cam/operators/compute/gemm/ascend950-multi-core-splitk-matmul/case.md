# Case Card: CATLASS 68 Ascend950 Multi-Core SplitK Matmul

本 Case 只描述 **当前 example 真正运行的路径**：fp32、mix、`MultiCoreSplitkMatmulTla` + `MmadPingpong`、UnitFlag。  
Padding / 单核 / 量化 / tail SplitK（09/22/34/52/69）**存在但未运行**。

Agent 默认读本文件。Cube 数据路径与 [43 Basic Matmul](../ascend950-basic-matmul/case.md) 同一套 Block。本 Case 只教 **每个 MN tile 切 K + 整张 C 的 workspace 平面 + `SplitkReduceAdd`**。  
sibling：[66 StreamK](../ascend950-streamk-matmul/case.md)。不要把两者当成同一种切 K。

---

## What

在 Ascend 950 上计算 `C = A @ B`，用切 K 把任务数做成 `B * splitkFactor`，让更多 AIC 有活干。

- 本 Case 实例化：`A, B, C` 均为 **fp32**，**RowMajor**，无 Bias。
- 可执行文件是 **mix**：AIC **不写** GM C；AIV `SplitkReduceAdd` 写 C。
- `splitkFactor` 在 Host `GetSplitkFactor` 算一次，不是 README 里的 if。

---

## Why This Case

价值是 43 分层上另一种 Kernel：**MN 并行度不够时，把 K 也变成核间轴**。

```text
Example / DeviceGemm          mix，全部 AIC，workspace ≠ 0
        ↓
Kernel (MultiCoreSplitkMatmulTla)
        ├── AIC  SplitkGemmIdentityBlockSwizzle
        │         每个 (MN tile, K slice) → BlockMmad → workspace 平面[slice]
        └── AIV  等全部 Cube 结束，ReduceAdd 平面 → GM C
        ↓
Block (BlockMmadTla / MmadPingpong)  ← 与 43 相同
```

若问题其实是 **remainder MN tiles 上核空闲**，那是 66，不是把本 Case 的 `splitkFactor` 套到那些 tile 上。

---

## Data Flow

```text
blockNum   = CeilDiv(M,256)*CeilDiv(N,256)          // B
kTileNum   = CeilDiv(K,128)
splitkFactor = min( (aicCoreNum/blockNum 或默认 2), kTileNum )

AIC:
  coreLoops = blockNum * splitkFactor
  每个任务：(MN 坐标, kIdx) → BlockMmad
  写出 gmW[M*N * splitkSliceIdx] 上对应 MN tile     // acc dtype，RowMajor 整张 C

        │  全部 loop 结束后 CrossCoreSetFlag PIPE_FIX
        ▼
AIV:
  WaitFlag + Barrier
  SplitkReduceAdd：按元素把 splitkFactor 张平面加起来 → GM C
```

Cube 核内仍是 43 pingpong。**每个** MN tile 的 K 都被切开，没有“完整波不切 K”。

---

## K partition（live）

`source-code` `GetSplitkFactor` / `SplitkGemmIdentityBlockSwizzle`：

```text
splitkFactor = 2
if aicCoreNum / blockNum > 0:
    splitkFactor = aicCoreNum / blockNum     // 整数除
splitkFactor = min(splitkFactor, kTileNum)

slice 的 L1-K 个数尽量均分；前 (kTileNum % factor) 个 slice 多 1 个 L1-K
```

`blockNum > aicCoreNum` 时 if 不进，factor **仍为 2**（再被 `kTileNum` 卡住）。README 启发式不是关闭开关。

| 问题 | 本 Case |
| --- | --- |
| 哪些 K 被拆 | **每个** MN tile 的 K |
| 拆给谁 | 抽到该 `(MN, slice)` 任务的 AIC；`coreLoops = B * factor` |
| Partial 在哪 | `factor` 张满 `M×N` acc 平面 |
| 谁 reduce | AIV `SplitkReduceAdd<..., STAGES=1, computeLength=192KiB/sizeof(acc)>` |
| 如何同步 | AIC **全部** Cube 结束后才 `SetFlag`；没有 66 那种提前 flag |

`splitkFactor` 被 `kTileNum` 封顶，所以 **不保证** 打满全部 AIC。

`computeLength` 写死 **192 KiB**，不是 `Arch::Ascend950::UB_SIZE`（248 KiB）。`static_assert` 只要求不超过 UB。不要把 192 KiB 写成 950 的 UB 容量。

---

## Parallel Strategy

| 层级 | 本例 |
| --- | --- |
| 启动核数 | 全部 `GetCoreNumAic()` |
| 任务 | `loopIdx = blockIdx; loopIdx < B*factor; loopIdx += C` |
| Swizzle | **固定** `SplitkGemmIdentityBlockSwizzle<3, 0>` |
| L2 bypass | 与 43/66 同类，CATLASS-specific |

README（**design-doc only**）：`B <= C/2` 时“能获取较优性能”。**没有** `benchmark`。二进制总是 SplitK。

CLI / optest：`256×512×1024` → `B = 2`，对典型 `C>=4` 落在该文档窗口。是否快于 43 **未测**。

---

## Memory Strategy

Cube 占用与 43 / 66 相同。

Workspace：`max(2 MiB, M×N×4×splitkFactor)`。  
对 CLI 形状 `kTileNum=8`：若 `aicCoreNum/2 >= 8`，`factor=8` → `256×512×4×8 = 4 MiB`。不要把某颗芯片的 `C` 写死进本 Case。

AIV 把整张 `M*N` 摊到所有 Vector 核上归约，不是按 MN tile 归约（那是 66）。

---

## Pipeline

`pipeline_pattern`: **double-buffer**（Cube）+ **multi-stage**（全部 AIC 结束 → 全局 AIV reduce）。

本源码 **没有** “reduce 与剩余 Cube 重叠”。

---

## Key APIs / 组件

| 层 | 本例类型 | 为何出现 |
| --- | --- | --- |
| Device | `DeviceGemm<MultiCoreSplitkMatmulTla<...>>` | mix；workspace |
| Kernel | `MultiCoreSplitkMatmulTla` | `GetSplitkFactor` + 平面 workspace |
| Policy / Block | 与 43 相同 | |
| Sched | `SplitkGemmIdentityBlockSwizzle<3,0>` | `GetSplitkSliceIdx` / `GetKIdxBySplitkSliceIdx` |
| Reduce | `SplitkReduceAdd` in `splitk_matmul.hpp` | **只**复用这个 struct；A2 `SplitkMatmul` kernel 不是 live 类型 |

---

## Source conflicts

| 冲突 | 记录 |
| --- | --- |
| Catalog 曾写 fp16 / cube | 已按 live 改为 fp32 / vector+cube |
| Example L1-K=128 vs JIT scaler L1-K=64 | 不调和 |
| 192 KiB reduce vs 950 UB 248 KiB | 不调和 |
| README `B<=C/2` vs 二进制总是切 K | 不调和 |

This Case does not attempt to resolve the conflicts.

---

## What Agent Should Learn

1. SplitK 的默认画面是：**每个 MN 都切 K，AIC 只写 workspace，AIV 拥有 C**。
2. `splitkFactor` 先被核数/块数抬高，再被 `kTileNum` 压住。
3. 代价是整张 C × factor 的 acc workspace，外加一次全局 Vector reduce。
4. remainder tiles 空核是 66，不是把 factor 理解成“只切最后一轮”。
5. README 启发式不是门禁，也不是 benchmark。

---

## What NOT To Copy

### 不要把 catalog 旧的 fp16/cube 当 live

### 不要假设 SplitK 一定打满 AIC

### 不要把 192 KiB 写成 950 UB_SIZE

### 不要把 `SwizzleOffset=3` / dir 0 当最优

### 不要把 README `B<=C/2` 当测过的结论或编译进去的 if

### 不要在只需切 remainder tiles 时用本 Case 当 StreamK

那是 [66](../ascend950-streamk-matmul/case.md)。

### 不要依赖这个 `CanImplement`

恒 `true`。`static_assert` 禁止 Relu Fixpipe，那是模板约束，不是 shape 守卫。

---

## Applicable Scenarios

参考本 Case，当：

- MN tile 数填不满 AIC，K 还够切成多段 L1-K
- 需要看满 `M×N` 平面 workspace + `SplitkReduceAdd`

不要参考本 Case，当：

- 需要 Cube pingpong 本身 → [43](../ascend950-basic-matmul/case.md)
- 需要只切 remainder tiles → [66](../ascend950-streamk-matmul/case.md)
- 需要 padding / 单核切 K / 量化切 K / 69 tail SplitK

选 43 / 66 / 68 → [K 轴切分策略](../../../../../../knowledge/cam/engineering/gemm-k-partition-strategies.md)

---

## Vs 43 / 66

| | 43 | 66 | 68 |
| --- | --- | --- | --- |
| 切哪些 K | 不跨核切 | 仅 remainder tiles | **每个** MN |
| Workspace | 0 | 2 槽 / AIC | 满 C × factor |
| 谁写 GM C | AIC | AIC + AIV | 仅 AIV |
| 同步 | — | 可提前 flag | 全部 Cube 之后 |

---

## Related Cases

- **base:** [43 Basic Matmul](../ascend950-basic-matmul/case.md)
- **sibling:** [66 StreamK](../ascend950-streamk-matmul/case.md)
- **index:** [gemm-k-partition-strategies](../../../../../../knowledge/cam/engineering/gemm-k-partition-strategies.md)

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/catlass |
| remote | `https://gitcode.com/cann/catlass.git` |
| commit | `a8b4fffbd9cabc021dfd47253e907a1cde59de25` |
| hardware | ascend950 (`CATLASS_ARCH=3510`) |
| example | `examples/68_ascend950_multi_core_splitk_matmul/multi_core_splitk_matmul.cpp` |
| kernel | `include/catlass/gemm/kernel/multi_core_splitk_matmul_tla.hpp` |
| scheduler | `include/catlass/gemm/block/block_swizzle.hpp` (`SplitkGemmIdentityBlockSwizzle`) |
| reduce | `include/catlass/gemm/kernel/splitk_matmul.hpp` (`SplitkReduceAdd`) |
| block | `include/catlass/gemm/block/block_mmad_pingpong_tla.hpp` |
| test | `tests/optest/tests/test_68_ascend950_multi_core_splitk_matmul.py` |
| license | CANN Open Software License Agreement Version 2.0 |
