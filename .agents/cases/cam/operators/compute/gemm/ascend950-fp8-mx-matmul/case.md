# Case Card: CATLASS 53 Ascend950 MXFP8 Matmul

本 Case 只描述 **当前默认 example 真正运行的路径**：`float8_e4m3`、e8m0 scale、fp32 C、`MxMatmulTla` + `MmadMx`、UnitFlag、`GemmIdentityBlockSwizzle<3,0>`。  
同目录 ASWT 可执行文件、optest ASWT、e5m2、Bias、`MmadMxPreload`、`enableL1Resident`、54/58/59 **存在但未运行**。

Agent 默认读本文件。MN 分核仍是 43 风格的 Identity swizzle；新内容在 **MX 契约 + `MmadMx` Block**，不是 43 的 pingpong Block。

---

## What

在 Ascend 950 上计算块缩放 MX GEMM：

```text
C = (MxScaleA ⊙ A) @ (MxScaleB ⊙ B)
```

- 本 Case 实例化：A/B **fp8_e4m3**，scale **fp8_e8m0**，C **fp32**，无 Bias。
- 布局：A **RowMajor**，B **ColumnMajor**，C **RowMajor**（`trans_a=0, trans_b=1`）。
- 有效计算全部在 **AIC / Cube**。AIV 入口为空。**不是** MIX。
- 运行前需要 `gen_data.py` 写出 `input/` 与 `golden/`（example 不随机填数）。

---

## Why This Case

43 教的是 fp32 pingpong。本 Case 教 **同一套分层上换掉的 Block**：操作数是 MXFP8，scale 跟 A/B 一起进 L1，L0 元素是 `mx_fp8_e4m3_t`。

```text
Example / DeviceGemm          cube，min(nAic, mnTiles)，workspace 0
        ↓
Kernel (MxMatmulTla + Identity<3,0>)
        ↓
Block (BlockMmadTla / MmadMx)  — 不是 43 pingpong
        ↓
Tile (PackedMxTileCopyTla)
```

不要写成“43 外面加一层 scale epilogue”。`BlockEpilogue = void`；scale 在 Cube Block 内。

---

## Data Flow

```text
GM  A     fp8_e4m3  RowMajor     M × K
GM  B     fp8_e4m3  ColumnMajor  K × N
GM  MxScaleA  e8m0   MakeMxScaleLayout(M, CeilDiv(K,32))
GM  MxScaleB  e8m0   MakeMxScaleLayout(CeilDiv(K,32), N)
        │  MTE2  A/B pingpong per L1-K
        │        scale 每 L1_SCALE_FACTOR_K(=16) 条 L1-K 搬一次
        ▼
L1  A, B, MxScaleA, MxScaleB
        │  MTE1  L1 → L0   L0 元素 mx_fp8_e4m3_t
        ▼
L0A, L0B
        │  Cube Mmad → L0C（fp32 acc，UnitFlag，1 stage）
        ▼
L0C
        │  CopyL0CToDst → GM
        ▼
GM  C   fp32 RowMajor  M × N
```

K 在 MN tile **内部**由 `MmadMx` 走完。没有 66/68 那种核间切 K。

---

## MX 契约（live）

`source-code` `catlass.hpp` / example / `gen_data.py`：

```text
MX_SCALE_GROUP_NUM      = 32    // 每 32 个 K 元素一个 e8m0
MX_SCALE_COPY_GROUP_NUM = 2     // scale 轴 C0 打包
MX_BASEK_FACTOR         = 64    // A/B 的 K；L1_K、L0_K 必须是 64 的倍数
```

Host：

```text
mxScaleK     = CeilDiv<32>(K)
layoutScaleA = MakeMxScaleLayout<e8m0, RowMajor, false>(M, mxScaleK)
layoutScaleB = MakeMxScaleLayout<e8m0, ColumnMajor, true>(mxScaleK, N)
lenScaleA    = M * RoundUp<2>(mxScaleK)
lenScaleB    = RoundUp<2>(mxScaleK) * N
```

`gen_data.py` 的 block size 是 **32**。README 写 RowMajor A 的 scale 形状 `(m, ceil(k/64), 2)`：那是 `ELE_NUM_PER_C0=2` 把 `mxScaleK` 收成嵌套维，**不是** 第二种分组大小。

模板还出现 `float8_e5m2`。本 Case `dtypes` **只有 e4m3**。

---

## Parallel Strategy

| 层级 | 本例 |
| --- | --- |
| 启动核数 | `min(nAic, mnTiles)`（同 43） |
| Swizzle | **固定** `GemmIdentityBlockSwizzle<3, 0>`，没有 43 的 `M>N` 切换 |
| L2 bypass | 单 L1-M tile 关 B；单 L1-N tile 关 A（与 43 同类） |

ASWT（`BlockSchedulerAswt`、`UpdateTailTile`）只在第二可执行文件 / optest 里。本 Case 不教授它。

---

## Memory Strategy

L1（e4m3，2/2 stages，`L1_SCALE_FACTOR_K=16`），`source-code` 公式：

```text
L1A / L1B     256×256×1×2 = 128 KiB each
L1 scale A/B  256×256/32 × 1 × 16 × 2 = 64 KiB each
sum 384 KiB   （static_assert vs 950 L1 512 KiB）
```

不要把 43 的 fp32 L0 字节公式抄到这条路径。L0 元素是 `GetL0Element<e4m3, true> = mx_fp8_e4m3_t`。Workspace 0。

---

## Pipeline

`pipeline_pattern`: **double-buffer**（A/B L1/L0 pingpong）。Scale 按 16 条 L1-K 一批从 GM 进 L1。不是 mix。

README 的 `enableL1Resident` 窗口是 **design-doc**。本例该 flag 为 false。

---

## Key APIs / 组件

| 层 | 本例类型 | 为何出现 |
| --- | --- | --- |
| Device | `DeviceGemm<MxMatmulTla<...>>` | cube |
| Kernel | `MxMatmulTla` + Identity `<3,0>` | MN 分核；AIV 空 |
| Policy | `MmadMx<950, UnitFlag, 16>` | MX Block，不是 pingpong |
| Block | `BlockMmadTla<MmadMx, ...>` | scale 与 A/B 同住 L1 |
| Tile | `PackedMxTileCopyTla` | GM↔L1 scale copy |

---

## Source conflicts

| 冲突 | 记录 |
| --- | --- |
| Catalog 曾列 e5m2 | 本 Case 只有 e4m3 |
| README `(m, ceil(k/64), 2)` vs `MX_SCALE_GROUP_NUM=32` | 打包 vs 分组；不发明第二种 group |
| 默认二进制 Identity vs optest 只测 ASWT + 四种转置 | 不调和 |
| README L1-resident vs live `false` | 不调和 |
| `CanImplement` 恒 `true` | 不是 dtype/shape 守卫 |

This Case does not attempt to resolve the conflicts.

---

## What Agent Should Learn

1. MX GEMM 的变化在 **Block + TileCopy**，不是 Kernel 再套一个 Vector epilogue。
2. 分组大小 live 是 **32**；README 的 64 是 scale 布局 C0。
3. 默认 example 的转置写在 **layout tag** 里，CLI 没有 `trans_a/trans_b`。
4. optest 覆盖的是 ASWT 兄弟二进制，不是本 Case 的 Identity 路径。
5. 不要把 54/59 再收成第二份 MX Case（同一 `MmadMx` 契约、不同打包 dtype）。

---

## What NOT To Copy

### 不要把 e5m2 写进本 Case 的 dtypes

模板能力 ≠ 本 example 实例化。

### 不要抄 43 的 `MmadPingpong` / fp32 L1 公式

L1 还要算 scale；L0 dtype 也不是 fp32 A。

### 不要把 ASWT / `UpdateTailTile` 当默认路径

### 不要把 README `enableL1Resident` 窗口当本例在跑的东西

### 不要依赖这个 `CanImplement`

恒 `true`。

### 不要把 66/68 的切 K 套进来

本例 Kernel 不切 K。

---

## Applicable Scenarios

参考本 Case，当：

- 需要 CATLASS 风格的 **MX 块缩放 GEMM**（e8m0 × 32 分组）
- 需要看 `MmadMx` 如何把 scale 和 A/B pingpong 放在同一 Block

不要参考本 Case，当：

- 需要 Cube pingpong 本身 → [43](../ascend950-basic-matmul/case.md)
- 需要 ASWT 尾块均衡（本目录第二二进制，未收 Case）
- 需要 FP4 / A8W4 / batched MX
- 需要生产 **MX GMM + SwiGLU + requant** → [ops-transformer GMM SwiGLU](../../grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md)

---

## Vs 43

| | 43 | 53 |
| --- | --- | --- |
| 变化层 | 黄金 Cube | **Block `MmadMx` + MX TileCopy** |
| 操作数 | fp32 | e4m3 + e8m0 → fp32 C |
| B 布局 | RowMajor | **ColumnMajor** |
| L1-K / L0-K | 128 / 32 | **256 / 128**（且须 64 对齐） |
| AIV | 空 | 空 |

---

## Related Cases

- **base:** [43 Basic Matmul](../ascend950-basic-matmul/case.md)
- **production extension:** [ops-transformer GMM+SwiGLU+MX](../../grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md)

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/catlass |
| remote | `https://gitcode.com/cann/catlass.git` |
| commit | `a8b4fffbd9cabc021dfd47253e907a1cde59de25` |
| hardware | ascend950 (`CATLASS_ARCH=3510`) |
| example | `examples/53_ascend950_fp8_mx_matmul/fp8_mx_matmul.cpp` |
| kernel | `include/catlass/gemm/kernel/mx_matmul_tla.hpp` |
| block | `include/catlass/gemm/block/block_mmad_mx_tla.hpp` |
| gen_data | `examples/53_ascend950_fp8_mx_matmul/gen_data.py` |
| test | `tests/optest/tests/test_53_ascend950_fp8_mx_matmul_aswt.py` (ASWT, not this binary) |
| license | CANN Open Software License Agreement Version 2.0 |
