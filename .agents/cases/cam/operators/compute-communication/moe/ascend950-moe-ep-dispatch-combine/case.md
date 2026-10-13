# Case Card: ops-transformer Ascend950 MoE EP Dispatch / Combine

本 Case 只描述 **EP routing loop**：`MoeDistributeDispatchV2` + `MoeDistributeCombineV2` 成对。  
950 有效通信是 **MTE window**（`GetHcclContext` + window `DataCopy`），不是 `Hccl::AllToAllV` 黑盒。README 公式写 AllToAllV，那是 **job 名**。

Agent 默认读本文件；Dispatch/Combine pair 合同已内化在本 Case。
第一课是 **坐标系**，不是 RDMA 实现。

InitRouting **不是** 本 Case 的前处理。Dispatch 从 token-major `x [BS,H]` + `expert_ids [BS,K]` 自己 pack。sibling：[Case A](../../../compute/moe/ascend950-moe-local-permutation/case.md)。

Combine **已经**做 rank 逆变换 + TopK 加权。EP 路径 **不再接 Finalize**。

---

## What

把本卡 token 按 expert 发到持有该 expert 的 rank，收回后还原 token-major 并加权：

```text
token-major x[BS,H] + expert_ids[BS,K]
        ↓ Dispatch  permute + window send
recv expand_x  local-expert-major[A,H]
        ↓ expert FFN（Case C + GMM2，本 Case 不教 MMA）
combine expand_x  同行新值
        ↓ Combine  reverse window + weighted sum
token-major x[BS,H]
```

- 有效引擎：**AIV + 通信 window**。`Process()` 是 `if ASCEND_IS_AIV`。无 MMA。
- 必须成对；A3/950 也允许 CombineAddRmsNorm 替代 CombineV2（本 Case 不教融合 RMSNorm）。

---

## Why This Case

1. 生产 MoE 在 EP 上换了一套 **map**：`assist_info` triples，不是 `expanded_row_idx`。
2. GMM 的 group 元数据在 **通信之后** 才出现：`expert_token_nums [localExpertNum]`。
3. `dtype/shape 能接 ≠ 默认配置能接`：Dispatch 默认 count(1)，GMM 默认 cumsum(0)。

---

## 坐标系（必须会）

```text
(token, k) + x[token, :]                    # Dispatch 输入。不是 init.expanded_x
     │  dst_rank  = expert_id / localE + sharedExpertRankNum
     │  local_e   = expert_id % localE
     │  send slot = 该 (dst_rank, local_e) 的 running count
     ▼
window (dst_rank, src_rank, local_e, slot)  # FillTriple: (src_rank, tokenIndex, k)
     ▼  WaitDispatch + LocalWindowCopy
expand_x (local expert, src-rank 子序, slot)
     + expert_token_nums[local_e]
     + assist_info [A×128]
     + ep_recv_count
     ▼  GMM 不重排 M
     ▼  Combine 读 assist triples，不是 expert_ids
origin window slot = tokenId*(K+shared) + topkId
     ▼
token-major 加权和
```

live send 用整数 `/`，不是 A2 design-doc 的 `ceil`。

`expert_ids` **复用**为 expert 身份 / mask。`(tokenId, topkId)` 来自 **assist_info**，不能从 `expert_ids` 自己长出来。

---

## Data Flow

```text
GM  x [BS,H]  token-major
GM  expert_ids [BS,K]
        │  AIV：按 (dst_rank, local_e) pack，可选量化
        ▼
window data（对端 WindowsIn）+ status（先数据后 flag）
        │  对端 Wait + LocalWindowCopy
        ▼
GM  expand_x [A,H]          local-expert-major
GM  dynamic_scales
GM  assist_info             FillTriple 展开
GM  expert_token_nums       INT64 [localE]  type 0 prefix-sum / 1 count（默认 1）
GM  ep_recv_count           Combine 名 ep_send_counts
        │
        ▼  expert compute（layout 不变）
        │
GM  expand_x' [A,H]         通常 GMM2 后的 fp16/bf16
GM  assist_info / ep_send_counts / expert_ids / expert_scales
        │  AIV：按 triple 写回 origin window
        ▼
GM  x_out [BS,H]            token-major，已加权
```

Window **前后半区**：comment 与 design-doc — Combine 用前半、Dispatch 用后半，避免快 rank 踩未完成的 dispatch。

---

## Metadata 生命周期

| 对象 | 谁写 | 谁读 | 备注 |
| --- | --- | --- | --- |
| `assist_info [A×128]` | Dispatch | Combine | reverse `(src_rank, token, k)`。不是 “token 个数” |
| `ep_recv_count` | Dispatch | Combine `ep_send_counts` | **改名同缓冲** |
| `expert_token_nums` | Dispatch 收完后 | **GMM `group_list`** | Combine 的 `group_list` **预留不用** |
| `expert_ids` | gating | **两端都读** | 不改写 |
| `expert_scales` | gating `y` 若 fp32 | Combine 必选 fp32 | **conditional-direct** |
| `dynamic_scales` | Dispatch | GMM `x_scale` | 不是 gate |
| init `expanded_row_idx` / counts | Init | **两端都不读** | |

---

## Parallel Strategy

Dispatch `Process`：`AlltoAllDispatch` → `SetStatus` → `WaitDispatch` → `LocalWindowCopy` → `SetExpertTokenNums`。  
分核：发送按 token/expert 切；等待按 status 槽切；回搬按 recv 段切。核数由 Host 总 AIV 给出，kernel 自己切阶段。

Combine：`ExpertAlltoAllDispatchCopyAdd`（读 triples 发回）→ wait packed flags → `LocalWindowCopy` 加权。

不要把 HCCL 高阶集合通信原语当数据搬运。

---

## Memory Strategy

| 区 | 用途 |
| --- | --- |
| HCCL window | 跨 rank payload + 状态。compat 层取址（`GetBaseWindAddrByRankId`），不要硬编码 A3/A5 结构体偏移 |
| GM expand_x | 本 rank 专家行，给 GMM |
| status 槽 | 每核只写自己的；先数据后 ready；消费后清自己的段 |
| UB | Vector pack / wait / copy |
| L1/L0 | **未使用** |

共享 GM / 状态走 `DataCopyPad`。`SetValue`/`GetValue` 直打共享区不稳定（`SyncAll` ≠ cache 一致）。

---

## Pipeline

状态协议：写 count/payload → 发布 ready → 对端轮询自己的槽 → 回搬。  
Dispatch 与 Combine 方向相反，共用 window 资源、错开半区。  
本 Case **不**声称通信与 GMM 在同一 kernel 重叠（那是 [MegaMoe](../ascend950-mega-moe-fused-ep-ffn/case.md)）。

---

## Key APIs / 组件

| 角色 | 为何出现 |
| --- | --- |
| `GetHcclContext` + window DataCopy | 950 MTE 路径 |
| `FillTriple` | reverse 坐标进 payload / assist |
| `expert_token_nums_type` | 0 prefix-sum / 1 count |
| Combine `expert_scales` fp32 | 门控加权在 Combine 内完成 |

---

## Key Optimization Ideas

1. 按目标 rank 连续 pack，减少通信下发次数（design-doc “MoePermute”）。那是 **Dispatch 内核 permute**，不是调用 InitRouting。
2. Device 侧算路由，避免 Host AllGather 路由表。
3. 双半区 window 防 dispatch/combine 踩踏。

性能数字本 Case **不**给。HCCL_BUFFSIZE 是 design-doc。

---

## What Agent Should Learn

1. Dispatch 输入是 **token-major**。`init.expanded_x → dispatch.x` **不是边**。
2. Combine 恢复的是 **token 序**，不是 Init 的 expanded-slot。Finalize 不是下一跳。
3. `(tokenId, topkId)` ∈ **assist_info**；`expert_ids` 是身份。
4. `dispatch.expert_token_nums → GMM.group_list` 是 **conditional-direct**：`E == localExpertNum`、type 对齐、shared expert 时 localE 可能为 1。默认 type **对不上**。
5. `gating.y → combine.expert_scales` 仅当 y 为 **fp32**。

---

## What NOT To Copy

### 不要把 InitRouting 接到 Dispatch 前面

### 不要写 `Hccl::AllToAllV` 当本 Case 的搬运

### 不要把 README “assist = token 个数” 当 SoT

shape 是 `A×128`；kernel 是 triples。

### 不要把 gating fp16/bf16 `y` 直接当 Combine `expert_scales`

### 不要把 Dispatch 量化 `expand_x` 直接当 Combine 输入

中间有 GMM；Combine README 主路径是 fp16/bf16 expert **output**。

### 不要把 `ep_recv_count` 当 GMM groupList

那是 Combine 占用。GMM 吃 `expert_token_nums`。

### 不要把 DeepEP 写进本 Case

融合压缩 → [MegaMoe](../ascend950-mega-moe-fused-ep-ffn/case.md)。

---

## Applicable Scenarios

参考本 Case，当：

- 多卡 EP：token / expert / rank 坐标
- 要接生产 GMM 的 **post-EP** group 元数据
- 要写或读 MTE window Dispatch/Combine

不要参考本 Case，当：

- 单卡 permute → [Case A](../../../compute/moe/ascend950-moe-local-permutation/case.md)
- Cube / MX / SwiGLU → [Case C](../../../compute/grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md)、[60](../../../compute/grouped-gemm/ascend950-grouped-matmul-slice-m/case.md)、[53](../../../compute/gemm/ascend950-fp8-mx-matmul/case.md)
- 通算融合把 GMM 塞进同一 kernel → [MegaMoe fused EP+FFN](../ascend950-mega-moe-fused-ep-ffn/case.md)

---

## Related Cases

| | 关系 |
| --- | --- |
| [Case A](../../../compute/moe/ascend950-moe-local-permutation/case.md) | sibling loop |
| [Case C](../../../compute/grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md) | 消费 `expand_x` + `expert_token_nums` |
| [60](../../../compute/grouped-gemm/ascend950-grouped-matmul-slice-m/case.md) | groupList **编码课**；producer 是本 Case 的 nums，不是 60 的 example |
| [MegaMoe](../ascend950-mega-moe-fused-ep-ffn/case.md) | 把本 Case + C + GMM2 **压进一发**；本卡仍是 split EP loop |

工程索引：[MoE token/expert/rank 数据契约](../../../../../../knowledge/cam/engineering/moe-token-expert-rank-data-contracts.md)。

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/ops-transformer |
| remote | `https://gitcode.com/cann/ops-transformer.git` |
| commit | `9311b63bcd065b9779eb08a7d634e9463ee41ef1` |
| hardware | ascend950 |
| dispatch | `mc2/moe_distribute_dispatch_v2/` live `moe_distribute_dispatch_v2.h` |
| combine | `mc2/moe_distribute_combine_v2/` live `moe_distribute_combine_v2_a5_mte.h` |
| license | CANN Open Software License Agreement Version 2.0 |
