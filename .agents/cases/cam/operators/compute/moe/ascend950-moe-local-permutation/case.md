# Case Card: ops-transformer Ascend950 MoE Local Permutation

本 Case 只描述 **单卡 routing loop**：Gating 契约 → `MoeInitRoutingV3` → expert compute（本 Case 不教）→ `MoeFinalizeRoutingV2`。  
**不是** `InitRouting → Dispatch → GMM → Combine → Finalize` 一条生产直连链。那条链不存在；EP 是 [Case B](../../../compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md) 的另一套 loop。

Agent 默认读本文件。Gating **没有**单独 Case；`MoeGatingTopK`（或文档指定的 `MoeGatingTopKSoftmaxV2`）只作为本 Case 的 **upstream tensor 契约**。

冻结规则：

```text
tensor name ≠ tensor lifetime
```

典型：两个 `expanded_x`。Init 的是 expert **input**；Finalize 的是 expert **output**。同名不能当边。

---

## What

在 **同一张卡** 上把 token-major hidden 变成 expert-major，再加权还原：

```text
logits [T,E]  --gating-->  expert_idx [T,K],  y [T,K]
hidden [T,H]  --init---->  expanded_x (expert-major) + expanded_row_idx + counts
              --FFN/GMM->  (outside this Case)
expanded_x'   --finalize-> y_token [T,H]
```

- 本 Case 实例化：950 Vector 路径。Init 910 二进制可以是 `MIX_AIV_1_0`，但 AIC 直接 return。**MIX ≠ Cube。**
- `expert_idx`：INT32 `[T,K]`。
- Finalize 只吃 fp16/fp32/bf16 的 expert **output**。Init 量化后的 INT8/FP8 不能直连 Finalize。

---

## Why This Case

价值不在 TopK 公式，而在 **permutation 坐标系 + 索引 layout**：

1. 边按 dtype / rank / shape rule / **index layout** 判断，不按 tensor 名字。
2. Init 有 GATHER / SCATTER 两种 `expanded_row_idx`；Finalize 有 COLUMN / ROW 两种 stride。同名 INT32 1-D **不等于**可接。
3. Init `counts` 是 GMM `groupList` 的 **候选形态**（type 0 prefix-sum 像 [60](../../grouped-gemm/ascend950-grouped-matmul-slice-m/case.md)），**不是** EP 生产链上的直连边。EP 后真正喂 GMM 的是 [Case B](../../../compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md) 的 `expert_token_nums`。

---

## Data Flow

```text
GM  x_hidden [T,H]     token-major          (不是 gating 的 logits)
GM  expert_idx [T,K]   INT32                (gating 或 SoftmaxV2)
        │
        ▼  InitRoutingV3  Vector
    sort by expert → histogram → gather/scatter
        │
GM  expanded_x          expert-major rows   // expert INPUT
GM  expanded_row_idx    一种 map，见下
GM  expert_tokens_count_or_cumsum
        │
        ▼  expert FFN / GMM（本 Case 不教）
GM  expanded_x'         同 layout，新值     // expert OUTPUT
        │
        ▼  FinalizeRoutingV2  Vector
    row_idx[offset] → 读 expert 行 → * scales → 加到 token
        │
GM  y [T,H]             token-major
```

没有 L1/L0。有效路径在 **AIV / UB**。

---

## 坐标系与 `expanded_row_idx`

Init `row_idx_type`：

| type | 写入 | 含义 |
| --- | --- | --- |
| 0 GATHER | `expanded_row_idx[original_flat] = slot` | original → expert slot |
| 1 SCATTER | `expanded_row_idx[slot] = original_flat` | expert slot → original |

Finalize 读 `expanded_row_idx[offset]`，把 **值** 当 `expanded_x` 的行号。Offset 自己还有两种 stride（`drop_pad_mode`）：

| modes | 名 | offset |
| --- | --- | --- |
| 0 / 1 | COLUMN | `token + k * T` |
| 2 / 3 | ROW | `token * K + k` |

直连只在 **map 方向 + (token,k) 展平 stride** 同时配对时成立。Init 示例用 `rowIdxType=1`；Finalize 示例用 `dropPadMode=0`。两份示例 **不是** 联合证明。

**不要**把这条 map 拿去 EP。Dispatch/Combine 用 `assist_info` triples，见 Case B。

---

## Gating 契约（upstream，不是本 Case 的 kernel）

| tensor | 给谁 | 边 |
| --- | --- | --- |
| `expert_idx` INT32 `[T,K]` | Init 必选；Finalize 在 bias/extras 时可选 | **direct-data-edge** |
| `y` gate weights | Finalize `scales`（dtype 重叠的 float） | **direct-data-edge**（optional） |
| `y` | Init | **no edge**（Init 的 scale 是量化参数） |
| logits `x [T,E]` | Init `x [T,H]` | **not an edge** |

文档/950 op-list 把 Init 的 canonical producer 写成 **`aclnnMoeGatingTopKSoftmaxV2`**。GatingTopK 是 sibling，`expert_idx` 同契约。不要写“图一定用 GatingTopK”。

---

## Parallel Strategy

Init：AIV 上 sort / histogram / gather。多核切 token 或 expert 段（Host tiling）；**不要**从本 Case 抄具体核数。  
Finalize：按 token（或 token×k）分核，对 K 个 expert 行做加权加。  
Cube 核若被 MIX 拉起：Init 950 AIC **空**。

---

## Memory Strategy

| 区 | 用途 |
| --- | --- |
| GM | hidden、idx、expanded payload、row map、counts |
| UB | Vector sort / histogram / gather 工作区 |
| L1/L0 | **未使用** |
| workspace | tiling 分配的 Vector 临时区，不是 68 那种 C 平面 |

---

## Pipeline

`copy-compute-copy`（Vector）。没有 Cube pingpong，没有 MTE window。

---

## Key APIs / 组件

| 角色 | 950 | 为何出现 |
| --- | --- | --- |
| Gating / SoftmaxV2 | `moe_gating_top_k_apt` 或 SoftmaxV2 | 只提供 `expert_idx` + `y` |
| Init | `moe_init_routing_v3_apt` | 建 expert-major 与 row map |
| Finalize | `moe_finalize_routing_v2_apt` | 按 row map 加权还原 token-major |

通信 API：**无**。

---

## Key Optimization Ideas

本 Case 要学的不是性能数字，而是 **契约**：

1. 先画坐标系，再连边。
2. 量化 Init 与 float Finalize 之间必须有 expert compute（或反量化），不能因同名 `expanded_x` 直连。
3. counts type 0/1 **shape 相同**，下游必须读 attr，不能猜。

---

## What Agent Should Learn

1. **两套 MoE loop**：单卡 = 本 Case；EP = Case B。Init 不是 Dispatch 的前处理。
2. 边分类：direct / conditional-direct / logical。名字不够。
3. `expanded_row_idx` 要同时核对 Init 的 map 方向和 Finalize 的 stride。
4. MIX binary 仍可能 `engines: [vector]`。
5. Init counts 像 60 的 prefix-sum，但 EP 生产链上 **不要**写成 `init.counts → GMM.groupList`。

---

## What NOT To Copy

### 不要把 Init `expanded_x` 接到 Finalize `expanded_x`

生产 MoE 中间有 FFN。那是 **logical-edge**。量化 dtype 更是 **not an edge**。

### 不要把 `expanded_row_idx` 当无条件 INT32 缓冲

GATHER vs SCATTER；COLUMN vs ROW。

### 不要把 gating logits 当 Init 的 hidden

`[T,E]` vs `[T,H]`。

### 不要把 gating `y` 当 Init 的 quant scale

### 不要给 Gating 再开一张 Case

### 不要把本 Case 的 row map 用到 Dispatch/Combine

### 不要把 Init 910 MIX 写成“用了 Cube”

---

## Applicable Scenarios

参考本 Case，当：

- 单卡 MoE：token-major ↔ expert-major
- 需要判断 routing tensor 能不能接
- 需要 `expanded_row_idx` / count-vs-cumsum 的 layout 课

不要参考本 Case，当：

- 多卡 EP / window AllToAll → [Case B](../../../compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md)
- 专家 FFN / MX GMM + SwiGLU → [Case C](../../grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md) 与 [60](../../grouped-gemm/ascend950-grouped-matmul-slice-m/case.md)
- Cube pingpong → [43](../../gemm/ascend950-basic-matmul/case.md)

---

## Related Cases

| | 关系 |
| --- | --- |
| [Case B EP](../../../compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md) | **sibling loop**，不是下游 |
| [MegaMoe](../../../compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/case.md) | B+C 融合；仍不是本 Case 的下游 |
| [Case C GMM+SwiGLU](../../grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md) | 单卡路径上可插在 Init 与 Finalize 之间的 expert compute |
| [60 groupList](../../grouped-gemm/ascend950-grouped-matmul-slice-m/case.md) | counts type 0 **像** 60；EP 直连边不在本 Case |


工程索引：[MoE token/expert/rank 数据契约](../../../../../../knowledge/cam/engineering/moe-token-expert-rank-data-contracts.md)。

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/ops-transformer |
| remote | `https://gitcode.com/cann/ops-transformer.git` |
| commit | `9311b63bcd065b9779eb08a7d634e9463ee41ef1` |
| hardware | ascend950 |
| gating | `moe/moe_gating_top_k/`（upstream；canonical 文档名 SoftmaxV2） |
| init | `moe/moe_init_routing_v3/` |
| finalize | `moe/moe_finalize_routing_v2/` |
| license | CANN Open Software License Agreement Version 2.0 |
