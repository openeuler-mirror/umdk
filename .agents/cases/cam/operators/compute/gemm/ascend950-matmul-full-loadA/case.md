# Case Card: CATLASS 73 Ascend950 Matmul Full Load A

本 Case 只描述 **当前 example 真正运行的路径**：fp16、`MatmulFullLoadATla` + `MmadAscend950FullLoadA`、UnitFlag、`L1A_STAGES=1`。  
A2 example 25、`ENABLE_L1_RESIDENT=true`、Bias、44 quant full-loadA **存在但未运行**。

Agent 默认读本文件。Cube 仍是 GM→L1→L0→Mmad→GM，但 A 不再按 L1-K pingpong。本 Case 还钉死：`CanImplement` **不等于** 全部 L1 约束。

冻结术语（不要换成别的口号）：

```text
full-K A load + cross-N A reuse
```

不要叫 **L1 resident A**。`ENABLE_L1_RESIDENT` 在本例是 **false**；那是 Block 里 B 侧跳过重载的另一旋钮。两套机制必须继续隔离。

Host 两条 swizzle 都是 shipped 合法路径，**不要选一个当唯一 live scheduler**：

```text
M <= L1_M (256)  →  GemmIdentityBlockSwizzle<3, 0>     CLI 256×512×256
M >  L1_M        →  GemmIdentityBlockSwizzleL1FullLoad<1, 0>
                   example Host 上 optest 512×512×256
```

JIT 默认 Identity 且 L1-K 与 example 不同：那是 example vs JIT 冲突，不是 Host 还要再挑一条。

---

## What

在 Ascend 950 上计算 `C = A @ B`：每个 MN tile 做 **full-K A load**（整段 problem K 一次进 L1），B 仍按 L1-K pingpong；同一核上后续 N 向 tile 若 A 的 GM 偏移没变，则 `needLoadL1=false`，做 **cross-N A reuse**。

- 本 Case 实例化：`A, B, C` 均为 **fp16**，**RowMajor**，累加 **fp32**，无 Bias。
- 可执行文件是 **cube**。AIV 入口为空。**不是** MIX。
- `ENABLE_L1_RESIDENT` 为 **false**。不是这条路径的开关。

---

## Why This Case

43 的 A 按 L1-K 双缓冲。这里 `static_assert(L1A_STAGES == 1)`，抄 pingpong 的 A stages 会编不过。

第二件事：Host 调用 `CanImplement`，`kInvalid` 时打印 “MatA tile cannot be full loaded to L1.”

**报错文案不是谓词。** 谓词只是 `A_bytes + B_pingpong <= L1_SIZE`。文案说的是 full-K A load 的意图；它没有检查 README 一半 L1，也没有检查名为 `L1A_TILE_SIZE = L1/2` 的常量。

```text
Example / DeviceGemm          cube，min(nAic, mnTiles)
        ↓  CanImplement：A_bytes + B_pingpong <= L1_SIZE
           Host 失败文案仍写 “cannot be full loaded”（文案 ≠ 公式）
Kernel (MatmulFullLoadATla)   needLoadL1
                              M<=256 Identity / M>256 FullLoad swizzle
        ↓
Block (MmadAscend950FullLoadA)  L1A 命名为 L1/2；拷贝 (L1_M, full K)
```

---

## Data Flow

```text
GM  A, B  fp16 RowMajor
        │
        ▼  若 needLoadL1          // full-K A load
L1A  ←  形状 (L1_M, K)            // K = problem K，不是 L1_K
L1B  ←  pingpong (L1_K, L1_N)，2 stage
        │  MTE1  当前 L1-K 条带的 A 切片 + B → L0
        ▼
L0A, L0B  pingpong
        │  Mmad → L0C（fp32，UnitFlag）
        ▼
GM  C  fp16
```

同一核下一 MN tile 的 A GM 偏移不变 → 跳过上面的 A 拷贝（**cross-N A reuse**）。

Kernel 不切 K。`GetActualBlockShape.k() = problemShape.k()`。

---

## L1A vs CanImplement（live，必须分开）

950 `L1_SIZE = 512 KiB`。本例 fp16 tile `256/256/128`、`L1B_STAGES=2`：

| 约束 | 公式 | 本例推出的 K 上限 |
| --- | --- | --- |
| README 一半 L1（`design-doc`） | `256×K×2 <= 256 KiB` | `K <= 512` |
| 命名 `L1A_TILE_SIZE` | `L1_SIZE/2` | 256 KiB，**不是拷贝上限** |
| `CanImplement` | `256×K×2 + 128 KiB <= 512 KiB` | `K <= 768` |
| 物理布局 | B 在 offset 0（128 KiB）；A 从其后开始，长度为 `256×K×2` | 字节**总和**对上 CanImplement；仍不是 half-L1 / `L1A_TILE_SIZE` |

`GetBufferByByte(l1AOffset)` 不传入 `L1A_TILE_SIZE`。无 Bias 路径 **没有** L1 `static_assert`。Bias 路径才用 `L1A_TILE_SIZE + L1B*stages` 做编译期检查。

CLI / optest `K=256` → A 拷贝 128 KiB，README 一半 L1 与 CanImplement 都过。**测例没有打到缺口。** 缺口在公式里，也在 Host 文案里。

因此：函数叫 `CanImplement`、Host 也看了返回值，**不能**认定它编码了全部你以为存在的约束。Host 那句 “cannot be full loaded” 尤其不能当成检查语义。

---

## Parallel Strategy

两条都是 example Host 的 live 分支：

| 谓词 | Scheduler | 本树里的形状 |
| --- | --- | --- |
| 启动核数 | `min(nAic, mnTiles)` | 两条相同 |
| `M <= 256` | `GemmIdentityBlockSwizzle<3, 0>` | CLI `256×512×256` |
| `M > 256` | `GemmIdentityBlockSwizzleL1FullLoad<1, 0>` | optest `512×512×256`（example Host） |
| `needLoadL1` | 本核下一 MN tile 的 A GM 偏移相同则 false | 两条都有 |

不要把 CLI 画成“这个 example 只用 Identity”，也不要把 optest 画成“这个 example 只用 FullLoad swizzle”。

JIT 默认 `CATLASS_JIT_BLOCK_SCHEDULER==30` → Identity `<3,0>`，且 `TileShapeScalerTLA` 基座 L1-K **256** / L0-K **64**，与 example 128/32 不同。这是 **example vs JIT**，记录，不调和。

README：N 大则 cross-N A reuse 收益大、N 小可能比 basic 慢。**design-doc only**，无 `benchmark`。二进制没有 “N 够大才 full-K A load” 的 if。

---

## Memory Strategy

不要用 43 的 `L1_M×L1_K×L1A_STAGES` 算 A。

```text
命名 L1A 窗口  256 KiB  （L1/2）
实际 A 拷贝    L1_M × K × 2          // full-K A load
L1B            256×128×2×2 = 128 KiB
L0A/B          与 43 数字同类的 256×32 pingpong，dtype 是 fp16
L0C            256×256×4×1 = 256 KiB
```

Workspace 0。

---

## Pipeline

`pipeline_pattern`: B 与 L0 **double-buffer**。A 单缓冲（`L1A_STAGES=1`）。不是 mix。

---

## Key APIs / 组件

| 层 | 本例类型 | 为何出现 |
| --- | --- | --- |
| Device | `DeviceGemm<MatmulFullLoadATla<...>>` | Host 消费 `CanImplement` |
| Kernel | `MatmulFullLoadATla` | `needLoadL1`；总和式 CanImplement |
| Policy | `MmadAscend950FullLoadA` | 强制 `L1A_STAGES==1` |
| Block | 950 full-loadA TLA header | full-K A load；B pingpong |
| Sched | Identity **和** FullLoad，按 `M ? 256` | Host 编译期两分支，都是 live |

---

## Source conflicts

| 冲突 | 记录 |
| --- | --- |
| README `34_ascend950_basic_matmul` vs 树（34=A2 SplitK，950 basic=43） | 不调和 |
| Example L1-K 128 vs JIT 256 | 不调和 |
| JIT 默认 Identity vs Host 在 `M>256` 时的 FullLoad swizzle | 不调和（Host 两分支本身不是冲突） |
| README 一半 L1 vs `CanImplement` 总和 vs 命名 `L1/2` | 见 mini-read；不调和成“其实是一回事” |
| README N 收益 | design-doc only |
| 把本路径叫做 L1 resident A | 与 live `ENABLE_L1_RESIDENT=false` 冲突；本 Case 不用这个叫法 |

This Case does not attempt to resolve the conflicts.

---

## What Agent Should Learn

1. 本路径的名字是 **full-K A load + cross-N A reuse**。不是 43 再开 `ENABLE_L1_RESIDENT`。
2. `L1A_STAGES` 只能是 1。
3. **函数叫 `CanImplement` ≠ 编码了全部约束。** 本例不等式只保证 A+B 字节和不超过 `L1_SIZE`。Host 失败文案 “MatA tile cannot be full loaded to L1.” **不是** 这条不等式。它也不证明 `L1A_TILE_SIZE`、README 一半 L1、或无 Bias 的 L1 `static_assert` 已被检查。
4. Host 有两条 live swizzle：`M<=256` Identity，`M>256` FullLoad。CLI `256×512×256` 只覆盖第一条。

---

## What NOT To Copy

### 不要把这条路径叫做 L1 resident A

`ENABLE_L1_RESIDENT` 是 B 侧旋钮，本例为 false。

### 不要只保留一条 Host swizzle 当“唯一 live”

### 不要把 Host 文案 “cannot be full loaded” 当成 `CanImplement` 的语义

打印的是意图；检查的是 A+B 总和。

### 不要把 `CanImplement==true` 当成“L1 规划已闭合”

### 不要把 `L1A_TILE_SIZE` 当成拷贝长度

### 不要开 `L1A_STAGES=2`

### 不要把 README 一半 L1 写进 `CanImplement` 的语义

### 不要把 JIT L1-K=256 当 example live tile

---

## Applicable Scenarios

参考本 Case，当：

- 需要 **full-K A load + cross-N A reuse**
- 需要区分 **命名 buffer、实际拷贝、CanImplement 不等式**
- 需要看 Host 如何按 `M ? L1_M` 在 Identity 与 FullLoad swizzle 之间分支

不要参考本 Case，当：

- 需要普通 A/B pingpong → [43](../ascend950-basic-matmul/case.md)
- 需要打开 `ENABLE_L1_RESIDENT`（本例没开，也不是 A 的机制）
- K 大到 Host `CanImplement` 返回 `kInvalid`（本模板会拒绝，不是切 K）。通过也不等于 A 落在 named half-L1 里。
- 需要 66/68 核间切 K

---

## Vs 43

| | 43 | 73 |
| --- | --- | --- |
| A 在 L1 | pingpong L1-K，2 stage | **full-K A load**，1 stage |
| N 向 | A 每 tile 再搬 | **cross-N A reuse**（`needLoadL1`） |
| B 在 L1 | pingpong | pingpong（同结构） |
| `CanImplement` | 恒 true | **A+B vs L1_SIZE**（仍非全部约束） |
| Host swizzle | `M>N` 切方向 | `M ? 256` 切 Identity / FullLoad |
| dtype | fp32 | fp16 |

---

## Related Cases

- **base:** [43 Basic Matmul](../ascend950-basic-matmul/case.md)
- **index:** [CanImplement 不是全部约束](../../../../../../knowledge/cam/engineering/canimplement-is-not-all-constraints.md)

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/catlass |
| remote | `https://gitcode.com/cann/catlass.git` |
| commit | `a8b4fffbd9cabc021dfd47253e907a1cde59de25` |
| hardware | ascend950 (`CATLASS_ARCH=3510`) |
| example | `examples/73_ascend950_matmul_full_loadA/matmul_full_loadA_tla.cpp` |
| kernel | `include/catlass/gemm/kernel/matmul_full_loadA_tla.hpp` |
| block | `include/catlass/gemm/block/block_mmad_pingpong_full_loadA_ascend950_tla.hpp` |
| test | `tests/optest/tests/test_73_ascend950_matmul_full_loadA.py` |
| license | CANN Open Software License Agreement Version 2.0 |
