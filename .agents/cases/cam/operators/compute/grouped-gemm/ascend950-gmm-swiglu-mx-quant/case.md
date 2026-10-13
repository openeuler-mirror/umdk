# Case Card: ops-transformer Ascend950 GMM + SwiGLU + MX Quant

本 Case 只描述 **生产融合**：`GroupedMatmulSwigluQuantV2` 950 路径 = **[60](../ascend950-grouped-matmul-slice-m/case.md) 的 M 分组** + **[53](../../gemm/ascend950-fp8-mx-matmul/case.md) 的 MX/`MmadMx`** + **AIV SwiGLU + 输出 requant**。

**不要**在本文件里重学：什么是 GMM、什么是 `MmadMx`、什么是 MX group=32。那些分别由 60 和 53 负责。

本 Case 实例化重点：950 MIX（`KERNEL_TYPE_MIX_AIC_1_2`）。A2 A8W8/MSD 路径 **存在但不是本 Case 教学内容**。

---

## What

对 **已经按 local expert 拼在 M 上的** 行做一次 grouped up-proj，再 SwiGLU，再量化：

```text
X[M,K] · W[E,K,N]   →  split N → SwiGLU → Q[M, N/2], Q_scale
分组边界 = groupList[E]   type 0 cumsum（默认）/ 1 count
```

- 这是 fused **GMM1 + 激活 + requant**，**不是**完整 expert FFN（没有 down-proj）。
- Down-proj 是另一个算子：`gmm/grouped_matmul/`；本 Case 不再展开该接口，也不为它另开 Case。
- `M` **不重排**。行序 = 上游 `expand_x` 行序（EP 上即 Dispatch recv 序）。

---

## Why This Case

跨源价值：Agent 写生产 MoE FFN 时，应把变化标成 **60/53 的 extension**，而不是新发明一种 Cube。

真正新增的是：

```text
AIC grouped MMA (cgmct MmadMx on MX)
        ↓  AIC→AIV
AIV SwiGLU（N 对半）
        ↓
output requant / MX scale 生成
```

以及 **生产 `groupList` 从哪来**：EP 上是 Dispatch `expert_token_nums`，不是 InitRouting 的 histogram。

---

## Data Flow

```text
GM  x          quant  [M, K]     // Dispatch expand_x，若 quant_mode 匹配
GM  x_scale    fp32 或 e8m0
GM  group_list INT64 [E]
GM  weight     NZ/ND，MX 时 e8m0 weight_scale group-32
        │
        ▼  AIC  按 groupList 切 M，MmadMx / grouped MMA
L0C / epilogue 握手
        │
        ▼  AIV  SwiGLU + quant
GM  y          INT8 / FP8 / FP4   [M, N/2]
GM  y_scale
```

L1/L0 容量公式 **抄 53/60，不要在本 Case 另写一套 tile 表**（生产 tiling 有自己的 key zoo；未冻结为“唯一 live 数字”）。

---

## `groupList` 生产契约

| 问题 | 本 Case 的答案 |
| --- | --- |
| 谁生产？ | **不是本 op。** EP：`dispatch.expert_token_nums`。单卡无 EP：Init counts 只是 **候选**，本 Case 不把它写成直连。 |
| 编码 | 0 = prefix-sum / cumsum；1 = per-group count。Kernel type 0 会减前一项（同 60 的减法）。 |
| 长度 | `E` = **本 rank 的 local experts**（及 weight 组数），不是全局 E。shared expert rank 上可能是 1。 |
| Host | **不**做 count↔cumsum 转换。 |
| 默认陷阱 | Dispatch 默认 type **1**；本 op 与 plain `GroupedMatmul` 默认 type **0**。shape 对 ≠ attr 对。 |

`dtype/shape 能接 ≠ 默认配置能接`。写进 Agent 检查单。

GMM2 必须 **同一份** `group_list` + 同一 type + `groupType=0`（M）。K-group（`groupType=2`）是错轴。

---

## Parallel Strategy

- AIC：按 group 的 M 切片分 MN tile（60 的课）。MX Block 是 53 的课。
- AIV：SwiGLU 把 N 切成 act/gate 两半，再量化。
- MIX 1:2。不要写成 60/53 那样的 “AIV 空、纯 Cube”。

---

## Memory Strategy

相对 60/53 多出来的：

- AIV UB：SwiGLU + quant 中间（`gmmsq_quant_mx_vf` 一类）
- `y` / `y_scale` 新 GM
- workspace：融合 tiling 用，不是 68 的 C 平面

不要把 43 的 fp32 L1 公式抄到 MX 融合路径。

---

## Pipeline

Cube MMA 与 Vector SwiGLU/quant 在 **同一 MIX kernel** 里握手（cgmct AIC→AIV builder）。这是生产融合，不是 53 的 `BlockEpilogue=void`。

不要把 mega_moe 的“通信和 GMM 同一 kernel”写进本 Case。那张卡是 [MegaMoe](../../../compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/case.md)。

---

## Key APIs / 组件

| 层 | 950 | 相对 60/53 |
| --- | --- | --- |
| Host tiling | `op_tiling/arch35/` | 生产 key zoo；`tuning_config` |
| AIC | cgmct `BlockMmadMx` / grouped MMA | **53 extension** |
| AIV | SwiGLU VF + MX/pertoken quant | **新增融合** |
| `group_list` | INT64 + `group_list_type` | **60 编码**，producer 换了 |

---

## What Agent Should Learn

1. 先画 60 分层，再画 53 Block，再问：“融合 epilogue 多了什么？”
2. EP 上 `groupList` 的 producer 是 **Dispatch nums**，且 type 必须手对。
3. 本 op 的 `y` **不是** Combine `expand_x`（宽 `N/2`、量化、还缺 down-proj）。
4. GMM2（plain GroupedMatmul）保持 M 序，输出 fp16/bf16 `[M,H]` 才是 Combine 的 **conditional-direct** 候选。
5. 不要给 plain `grouped_matmul` 再开一张与 60 重复的 GEMM Case；它在本链上是 **接口**。

---

## What NOT To Copy

### 不要重教 60 的 prefix-sum 减法或 53 的 group-32

链到那两张卡。

### 不要把本 op `y` 接到 Combine

E17：**logical-edge**。

### 不要把 Init counts 当本 Case 的 groupList 生产者

EP 链上 **不是边**。见 [Case B](../../../compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md)。

### 不要假设默认 `group_list_type=0` 能接 Dispatch 默认 `=1`

### 不要把 A2 A8W8/MSD 数字当 950 MX live

### 不要把 FullLoadA / StreamK / SplitK 写进本融合

73/66/68 不是这条二进制的课。生产 GMM 里若出现 FullLoadA 名字，那是 **另一张卡已经钉过的 Agent trap**，不要在这里克隆。

---

## Applicable Scenarios

参考本 Case，当：

- 生产 MoE expert **up-proj + SwiGLU + requant**
- 需要 60+53 之上的 **MIX 融合** 该怎么标
- 需要 EP 后 `groupList` 从哪接

不要参考本 Case，当：

- 只要 CATLASS GMM 调度 → [60](../ascend950-grouped-matmul-slice-m/case.md)
- 只要 MX Block → [53](../../gemm/ascend950-fp8-mx-matmul/case.md)
- EP 坐标 / window → [Case B](../../../compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md)
- 单卡 permute → [Case A](../../moe/ascend950-moe-local-permutation/case.md)
- 通算融合把本 Case 与 EP 压进一发 → [MegaMoe](../../../compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/case.md)

---

## Related Cases

| | 关系 |
| --- | --- |
| [60](../ascend950-grouped-matmul-slice-m/case.md) | **base** M-group / groupList 编码 |
| [53](../../gemm/ascend950-fp8-mx-matmul/case.md) | **base** MX / MmadMx |
| [Case B](../../../compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md) | `expand_x` + `expert_token_nums` 的 producer |
| [MegaMoe](../../../compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/case.md) | 本 Case + B + GMM2 的融合压缩 |
| GMM2 接口 | 已内化为本 Case 的数据合同；不另开 Case |

工程索引：[MoE token/expert/rank 数据契约](../../../../../../knowledge/cam/engineering/moe-token-expert-rank-data-contracts.md)。

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/ops-transformer |
| remote | `https://gitcode.com/cann/ops-transformer.git` |
| commit | `9311b63bcd065b9779eb08a7d634e9463ee41ef1` |
| hardware | ascend950 |
| op | `gmm/grouped_matmul_swiglu_quant_v2/` live `grouped_matmul_swiglu_quant_v2_apt.cpp` |
| license | CANN Open Software License Agreement Version 2.0 |
