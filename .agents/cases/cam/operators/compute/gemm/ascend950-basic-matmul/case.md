# Case Card: CATLASS 43 Ascend950 Basic Matmul

本 Case 只描述 **当前 example 真正运行的路径**：FP32、`MmadPingpong`、UnitFlag、L1/L0 double buffer。  
Mutex / Preload / ShuffleK **存在但未运行**，本 Case 不教授其行为。

Agent 默认读本文件，不要去复制完整上游源码。

---

## What

在 Ascend 950 上计算 `C = A @ B`。

- 本 Case 实例化：`A, B, C` 均为 **fp32**，**RowMajor**，无 Bias。
- 有效计算全部在 **AIC / Cube** 上完成。
- 框架保留 AIV 入口，对应实现为空，不执行实际计算。**不是** AIC+AIV MIX 算子。

---

## Why This Case

价值不在“又一个 GEMM”，而在于它是 CATLASS 的 **黄金分层样本**：

```text
Example / DeviceGemm
        ↓
Kernel (BasicMatmulTla)     — MN 分核、GM 视图、调度
        ↓
Block (BlockMmadTla)        — L1-K pingpong、L0 循环、Mmad、写回
        ↓
Tile (TileCopy / TileMmad)  — GM→L1、L1→L0、L0C→GM
        ↓
AscendC primitive
```

读后续 GMM / StreamK / MX / FA 时，先判断变化发生在哪一层，而不是把整个仓当成一份 kernel。

---

## Data Flow

```text
GM  A, B  (fp32, RowMajor)
        │  MTE2  GM → L1   (L1A / L1B 各 2 stage pingpong)
        ▼
L1
        │  MTE1  L1 → L0A / L0B  (各 2 stage pingpong)
        ▼
L0A, L0B
        │  Cube Mmad，累加到 L0C（本例 1 stage + UnitFlag）
        ▼
L0C
        │  Fixpipe / CopyL0CToDst（3510）
        ▼
GM  C  (fp32, RowMajor)
```

没有独立的 fused epilogue stage。`BlockEpilogue = void` 的意思是：**没有 EVG/激活融合**；L0C→GM 写回仍在 BlockMmad 内部完成。不要理解成“没有写回”。

K 方向：

```text
先加载第一个 L1-K
        ↓
处理当前 L1-K
        ║
        ╚══ 预取下一个 L1-K 到另一组 L1 buffer
        ↓
L1 → L0A/L0B（L0-K 再切 4 次：128/32）
        ↓
Mmad → L0C
        ↓
循环 L1-K
        ↓
L0C → GM
```

这是 **MmadPingpong 的 L1 预取**，不是 `MmadPreloadAsyncWithCallback`。

---

## Parallel Strategy

| 层级 | 本例做法 |
| --- | --- |
| 多核 | 按 L1 tile 切 MN；`taskNum = CeilDiv(M,256) * CeilDiv(N,256)` |
| 启动核数 | `aicCoreUsed = min(aicCoreNum, taskNum)` |
| 核内任务 | `loopIdx = blockIdx; loopIdx < coreLoops; loopIdx += blockNum` |
| K | 不跨核切 K；每个 MN block 在单核内走完 K |
| Tail | `GetActualBlockShape` 处理末块不足 256 的 M/N；K 用 `min(remain, L1_K)` |
| Swizzle | `M > N` → `GemmIdentityBlockSwizzle<3,0>`，否则 `<3,1>` |

Observed：`SwizzleOffset = 3`，方向随 M/N 相对大小切换。

Interpretation（**inference**）：可能意在改善遍历局部性。  
**没有** benchmark 证明 3 是 950 Matmul 最佳配置。不要照搬。

---

## Memory Strategy

硬件容量来自 `Arch::Ascend950`（source-code）：

| Buffer | Arch 容量 |
| --- | --- |
| L1 | 512 KiB |
| L0A | 64 KiB |
| L0B | 64 KiB |
| L0C | 256 KiB |

本例占用按 BlockMmad **静态公式**（元素个数 × sizeof × stages），不是按 nZ 可视化“看起来对称”去猜：

| Buffer | 公式 | 本例 fp32 |
| --- | --- | --- |
| L1A | `L1_M × L1_K × 4 × L1A_STAGES` | `256×128×4×2 = 256 KiB` |
| L1B | `L1_N × L1_K × 4 × L1B_STAGES` | `256×128×4×2 = 256 KiB` |
| L0A | `L0_M × L0_K × 4 × L0A_STAGES` | `256×32×4×2 = 64 KiB` |
| L0B | `L0_K × L0_N × 4 × L0B_STAGES` | `32×256×4×2 = 64 KiB` |
| L0C | `L1_M × L1_N × 4 × L0C_STAGES` | `256×256×4×1 = 256 KiB` |

With fp32 and the selected stage counts, these tile sizes fully consume the listed L1 / L0A / L0B / L0C capacities.

（**inference**，非正式结论：tile 可能是贴着容量边界选的。不要写成“作者就是为了填满才选这些数”。）

L0A 公式是 `M × K`，L0B 公式是 `K × N`。本例两者都是 64 KiB，是因为 `L0_M == L0_N == 256`，不是因为公式对称。L0B 的 **layout tag 是 nZ**；64 KiB 是 `L0B_TILE_SIZE` 分配量，不是 fractal padding 后的额外占用。

Workspace：本 kernel `GetWorkspaceSize` 返回 0。

---

## Pipeline

`pipeline_pattern`: **double-buffer**（L1 与 L0 的 pingpong）。不标 `multi-stage`：几乎所有 Cube kernel 都是多级流水，没有检索辨识度。

组织原因：GM→L1 与 L1→L0/Mmad 用两套 buffer 重叠，避免每步等搬运。UnitFlag 打开时 **禁止** L0C 多 stage（源码 `static_assert`）。

---

## Key APIs / 组件

本 Case 选用它们是因为这是 CATLASS 把 Cube GEMM 拆开后的默认组装，不是因为 API 名字好听。

| 层 | 本例类型 | 为何出现 |
| --- | --- | --- |
| Device | `DeviceGemm<MatmulKernel>` | Host 启动、workspace、转发 `CanImplement` |
| Kernel | `BasicMatmulTla<BlockMmad, void, Swizzle>` | MN 调度 + GM tiling |
| Policy | `MmadPingpong<Ascend950, UnitFlag=true, ...>` | 声明 L1/L0 stage 与 UnitFlag |
| Block | `BlockMmadTla<...>` | 真正的 pingpong 与 Mmad |
| Copy | `PackedTileCopyTla` | GM/L1/L0/L0C 搬运；L0B layout `nZ` |
| Sched | `GemmIdentityBlockSwizzle<3, dir>` | MN 遍历顺序 |

---

## Key Optimization Ideas

值得作为 **本 Case 内** 的设计观察（复制前要重新验证）：

1. L1 双缓冲：计算当前 L1-K 时预取下一 L1-K。
2. L0 双缓冲：L1→L0 与 Mmad 重叠。
3. UnitFlag + 单 L0C stage：与 L0C double buffer 互斥（源码约束）。
4. 启动核数截断到 `taskNum`，避免多余核。

L2 cache hint 见下一节，**不**升为通用优化模式。

---

## Interesting Implementation Details

### L2 bypass（CATLASS-specific）

Kernel 中：当 `M` 只覆盖 1 个 L1-M tile 时，对 **B** 设 `CACHE_MODE_DISABLE`；当 `N` 只覆盖 1 个 L1-N tile 时，对 **A** 同样处理。

Treat this as a CATLASS-specific optimization until its hardware rationale and applicability are independently verified.

不要写成：“Ascend 算子遇到单 tile 都应该 bypass L2。”

### UnitFlag + `SetMMLayoutTransform`

UnitFlag 且 C 为 RowMajor 时，Block 构造里会 `SetMMLayoutTransform(true)`。本 Case **不解释**该硬件开关的语义（未独立核实）。

---

## Non-active variants

源码/README 中还出现：

- `MmadPingpongMutex`
- `MmadPreloadAsyncWithCallback`（含 `enableShuffleK`）
- Bias / L1 resident

当前 example **未启用**。本 Case 不讨论其行为。

存在 ≠ 运行 ≠ 本 Case 教学内容。

---

## Source conflicts

README 写 Mutex 为 “A5 新增”；`MmadPingpongMutex` 的 `static_assert` 只允许 `Arch::Ascend950`。

This Case does not attempt to resolve the conflict.

规则：上游资料冲突时 **保存冲突**，不要凭常识圆回来。

---

## What Agent Should Learn

1. 先画 CATLASS 分层，再读具体 kernel。
2. 先确认 **实例化 dtype / policy / 是否启用的变体**，再谈“模板还能干什么”。
3. Pingpong 预取下一 L1-K ≠ PreloadAsync policy。
4. Tile 数字必须用 `sizeof × stages` 对容量做验算；换 dtype 后同一 256/128 不再合法。
5. `CanImplement` 这个名字不保证做了检查；做了检查也不保证编码了全部约束。恒 true 见本 Case；真实但部分见 [73](../ascend950-matmul-full-loadA/case.md) / [索引](../../../../../../knowledge/cam/engineering/canimplement-is-not-all-constraints.md)。

---

## What NOT To Copy

### 不要把本 Case 当成 fp16 GEMM

实例化与 optest 都是 fp32。`dtypes` 只含 fp32。模板是否还支持其他 dtype，不进入本 Case 主 metadata。

### 不要复用这组 tile 到其他 dtype / 其他算子

这组 256/128/32 在 fp32、2-stage 下贴满 950 列出的 L1/L0 容量。fp16 下同一数字含义完全不同。

### 不要把 SwizzleOffset=3 当成 950 最佳配置

只是本 example 的观察值。

### 不要依赖这个 `CanImplement` 做合法性检查

本 example 的检查链：

1. Host 调用 `DeviceGemm::CanImplement(arguments)`
2. Device 只转发 `GemmKernel::CanImplement(args)`
3. **本例 Kernel 类型** `BasicMatmulTla` 的实现是 `return true`
4. Host 调用了 `matmulOp.CanImplement(arguments)`，但没有检查返回值

它不验证任意 shape、layout、资源是否被当前 policy 支持。

这是 **这个 TLA BasicMatmul 实例的 Device→Kernel 链** 的行为，不要写成“所有 CATLASS BasicMatmul / 所有 CATLASS kernel 的 CanImplement 都恒 true”。仓内其他 kernel 可以有非平凡实现；那也不等于编码了全部约束。样本：[73 FullLoadA](../ascend950-matmul-full-loadA/case.md)（A+B vs `L1_SIZE`；Host 文案还写成 “cannot be full loaded”）。索引：[CanImplement 不是全部约束](../../../../../../knowledge/cam/engineering/canimplement-is-not-all-constraints.md)。

### 不要把空 AIV 写成“没有 AIV 入口的纯 AIC 架构”

有效路径在 AIC；AIV 入口存在但为空。

### 不要启用或解释 Mutex / Preload / ShuffleK

本 Case 边界之外。ShuffleK 的 “950 建议 false” 只是样例注释，不是实测平台规律。

---

## Applicable Scenarios

参考本 Case，当：

- 目标是 **Cube GEMM 骨架**（GM→L1→L0→Mmad→GM）
- 需要理解 CATLASS Example/Kernel/Block/Tile 怎么组装
- 需要一份 **double-buffer pingpong** 的具体实现

不要参考本 Case，当：

- 需要 fp16/bf16/MX/量化实例（本 Case 没有）
- 需要 MIX Vector epilogue、EVG、GMM、FA
- 需要 **remainder tiles 切 K / StreamK** → [66 StreamK](../ascend950-streamk-matmul/case.md)
- 需要 **mnTiles 不够填核 / SplitK** → [68 SplitK](../ascend950-multi-core-splitk-matmul/case.md)
- 需要 MX 块缩放 → [53 MXFP8](../ascend950-fp8-mx-matmul/case.md)
- 需要 **full-K A load + cross-N A reuse** → [73 FullLoadA](../ascend950-matmul-full-loadA/case.md)
- 需要可执行的 shape/dtype guard

---

## Related Cases

| | 关系 | 何时读 |
| --- | --- | --- |
| 本 Case | 基线 MN tiling | Cube pingpong、tile 验算 |
| [68 SplitK](../ascend950-multi-core-splitk-matmul/case.md) | complement | `mnTiles` 填不满核，每个 MN 切 K |
| [66 StreamK](../ascend950-streamk-matmul/case.md) | complement | remainder tiles（`mnTiles % nAic`）切 K |
| [53 MXFP8](../ascend950-fp8-mx-matmul/case.md) | complement | 同一分层，Block 换成 `MmadMx` |
| [73 FullLoadA](../ascend950-matmul-full-loadA/case.md) | complement | full-K A load + cross-N A reuse；不是 L1 resident A |
| [MoE local permute](../../moe/ascend950-moe-local-permutation/case.md) | unrelated algorithm | 单卡 routing，不是 GEMM |

选 43 / 66 / 68 → [K 轴切分策略](../../../../../../knowledge/cam/engineering/gemm-k-partition-strategies.md)

`CanImplement` 名字 vs 实现 → [CanImplement 不是全部约束](../../../../../../knowledge/cam/engineering/canimplement-is-not-all-constraints.md)

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/catlass |
| remote | `https://gitcode.com/cann/catlass.git` |
| commit | `a8b4fffbd9cabc021dfd47253e907a1cde59de25` |
| hardware | ascend950 (`CATLASS_ARCH=3510`) |
| example | `examples/43_ascend950_basic_matmul/basic_matmul_tla.cpp` |
| kernel | `include/catlass/gemm/kernel/basic_matmul_tla.hpp` |
| block | `include/catlass/gemm/block/block_mmad_pingpong_tla.hpp` |
| arch | `include/catlass/arch/arch.hpp` |
| device | `include/catlass/gemm/device/device_gemm.hpp` |
| test | `tests/optest/tests/test_43_ascend950_basic_matmul.py` |
| license | CANN Open Software License Agreement Version 2.0 |
