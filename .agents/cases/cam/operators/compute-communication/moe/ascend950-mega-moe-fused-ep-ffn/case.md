# Case Card: ops-transformer Ascend950 MegaMoe fused EP+FFN

本 Case 是 **B + C + GMM2 的融合压缩**，不是第四张 GEMM Case，也不是 MegaMoe 算子说明书。

Baseline：[MoE token/expert/rank 数据契约](../../../../../../knowledge/cam/engineering/moe-token-expert-rank-data-contracts.md)。  

不在这里重教：Case B 的 EP 坐标、Case C 的 MIX GMM1+SwiGLU+MX、60 的 groupList 减法、53 的 MmadMx。那些仍然读原卡。本卡只教 **融合以后边、metadata、同步边界变成了什么**。

仍是 **Case B 的 EP loop**。不是 Case A；无 InitRouting / Finalize / `expanded_row_idx`。

live 950 SoT：`arch35/mega_moe.h` 的 **MTE** `MegaMoe`。Host `CalTilingKey` 写死 MTE。不要把 URMA `MegaMoeLayered` 或 `arch22` 当本卡路径。

---

## What

一张 MIX kernel 吃 token-major `x` + `topk_ids`，吐 token-major `y`。中间的 API-visible / inter-op GM handoff 被内化。核心寿命（不要画模块树）：

```text
token-major source window
        ↓ remote pull
workspace local-expert-major
        ↓
GMM1 + SwiGLU + quant          // preserve M
        ↓
GMM2                           // preserve M
        ↓ triple scatter
combine window (token, k)
        ↓ world sync
weighted unpermute
        ↓
token-major output
```

与 Case B 的差别（通信形态，不是新 loop）：payload 留在 **源窗口** token-major，dest **pull**；B 是 **push** 进 dest `(rank, local_e, slot)`。rank 公式无 `sharedExpertRankNum`。

---

## Why This Case

1. split 图上哪些 **API-visible GM handoff** 被内化（workspace 仍可以是 GM）。
2. metadata 如何从 API tensor 变成 **workspace / window state**。
3. Host 四发（Dispatch → GMM1 → GMM2 → Combine）如何变成 **wave / per-expert flags**。
4. 哪些 **跨 rank visibility barrier** 仍然不能删。

---

## 1. 哪些 API-visible handoff 被内化

仍暴露：`x`、`topk_ids`、`topk_weights`、`weight1/2` + scales、`y`、以及 **输出** `expert_token_nums`。

从 split 图上消失（不是从设备上消失）。表里是 **handoff 角色被什么替代**，不是「同一个 tensor 换了地址」：

| split API handoff | fused replacement / internal state |
| --- | --- |
| dispatch `expand_x` | workspace `dispatchRevDataPtr`（同行缓冲，换地址） |
| `assist_info` | workspace triples；Unpermute **不再读**（角色还在，消费点变了） |
| `ep_recv_count` | dest window `[mask\|count]` **协议状态**（不是把 count 向量原样搬进 window） |
| GMM `group_list` | workspace recv counts → GMM `M`（没有 list tensor） |
| GMM1 `y` / `y_scale` | workspace `swigluQuant*`（同行缓冲，换地址） |
| GMM2 `y` / combine `expand_x` | **不**作为 expert-major API tensor；generic 路径 GMM2 result → CombineTokens，不必落一份与 split GMM2 `y` 等价的完整 buffer |

不要写「没有 expand_x」。没有的是 **API-visible** `expand_x`。

---

## 2. Metadata：API tensor → workspace / window

Rule 4 / 5 没有作废。问的还是 **何时统计、scope 是什么、encoding 是什么**；只是地址变了。

| 对象 | split | 本 Case |
| --- | --- | --- |
| routing map | API `assist_info` triples | workspace triples；CombineTokens 散射时用；restore 读 `(token*K+k)` 窗口 |
| occupancy | API `expert_token_nums` 喂 GMM | window `[mask\|count]` → workspace count → GMM `M` |
| API `expert_token_nums` | GMM 候选（INT64，type 0/1） | **晚复制输出**：INT32 **count**，GMM 已跑完 |
| `topk_ids` | expert 身份 | 仍是身份，不是 reverse map |
| `topk_weights` | Combine 要求 fp32 | fp32 **或** bf16，kernel Cast 成 fp32 |

Dispatch 默认 count vs GMM 默认 cumsum：**不再是用户图上的 compose**。输出 nums 若再接独立 GMM，INT32 vs INT64 是 **新**陷阱。

Init counts / `active_expert_range` **不是** 本 op 的 producer。

---

## 3. Host launch → 核内 flags

```text
split:   Dispatch  →  GMM1  →  GMM2  →  Combine     // 四次 launch
fused:   一次 launch
         Dispatch expert e+1  ∥  GMM1 expert e      // wave flag
         GMM1 → GMM2                                 // per-expert flag
         GMM2 result → CombineTokens                 // 同 expert loop
```

Case C 的 AIC→AIV 仍在 GMM1 **内部**。本卡不重教那条 MIX。

---

## 4. 不能删的跨 rank barrier

两次 `CrossRankSyncInWorldSize`：

1. quant + mask 写进源/dest 窗口之后，pull / GMM1 之前。
2. CombineTokens 填完 origin `(token,k)` 窗口之后，Unpermute 之前。

融合压缩的是 **同 rank 上的 op 间 happens-before**，不是 EP 可见性。不要写成「通信和 GMM 无屏障重叠」。prefetch 是 **下一个 expert 的 dispatch ∥ 当前 GMM1**，且发生在第一次 world sync 之后。

---

## Data Flow

```text
API  x [BS,H]  token-major          (live 950 kernel：BF16)
API  topk_ids [BS,K]
        │  AIV：本卡 MX quant → 源窗口
        │  AIV：SendMaskCal → dest [mask|count]
        │  world sync
        ▼
dest pull 源窗口 by tokenIndex
        │
workspace  local-expert-major + triples
        │  AIC GMM1 / AIV SwiGLU+quant   preserve M
workspace  swigluQuant
        │  AIC GMM2                      preserve M
        │  AIV CombineTokens by triple
        ▼
window  (token, k)  combineSendPtr
        │  world sync
        ▼
API  y [BS,H]  token-major 加权
API  expert_token_nums [localE] INT32 count   // 输出；不是 GMM 输入
```

有效引擎：**Cube + Vector + window 通信**。`KERNEL_TYPE_MIX_AIC_1_2`。

---

## Parallel Strategy

- 发送 mask：AIV 按全局 expert 切。
- pull / triple：AIV 按 src rank 分组。
- GMM：按 local expert 循环；`M` = 该 expert 的 recv count。
- Unpermute：AIV 按 token 切。

核数来自 Host AIC/AIV；阶段切分在 kernel 内。不要把 HCCL 高阶集合通信当搬运。

---

## Memory Strategy

| 区 | 用途 |
| --- | --- |
| HCCL window | 源 quant（token-major）、dest mask、combine `(token,k)`、world sync 字 |
| workspace GM | local-expert-major 行、triples、swigluQuant、wave/per-expert flags |
| UB | quant / mask / pull 软流水 / Unpermute 加权 |
| L1/L0 | GMM（读 C / 53，不在本卡展开） |

共享状态走 window / workspace + flag，不把 API tensor 当核间邮箱。

---

## Pipeline

1. 本卡 quant + 推 mask → world sync。
2. 下一 expert dispatch prefetch ∥ 当前 GMM1（`dispatchToGmm1Flag`）。
3. GMM1 epilogue → `flagSwiGluToGmm2Ptr` → GMM2 + CombineTokens。
4. world sync → Unpermute。

A8W4 会把 cumsum 备份到 workspace（UB 被 epilogue 覆盖）。那是融合税，不是又一条 API 边。

---

## Key APIs / 组件

| 角色 | 为何出现 |
| --- | --- |
| `GetRankWinAddrWithOffset` | 950 MTE 窗口，与 B 同族 |
| `SendMaskCal` / `CopyGMToGMPerToken` | 源窗口 pull，不是 B 的 dest pack |
| workspace triples + `CombineTokens` | 内化的 `assist_info` |
| `CrossRankSyncInWorldSize` | 不能删的 EP 可见性 |
| `ExpertTokenNumCopyOut` | API 输出 count；GMM 已用过 workspace 计数 |

---

## What Agent Should Learn

1. 融合删的是 **API-visible / inter-op GM handoff**，不是寿命，也不是「非 GM」。
2. map 仍属 EP loop：triples 在散射时用，Unpermute 读 `(token,k)` 窗口。
3. group metadata 仍要带 time / scope / encoding 读；本卡内部是 post-EP、localE、count。
4. 两次 world sync 留着。同 rank 的 Dispatch/GMM/Combine launch 边界可以压进 flag。
5. expert compute **preserve M**（Knowledge 冻结句）。本卡没有新 permute。

---

## What NOT To Copy

### 不要当第四张 GEMM Case

60/53/C 仍读原卡。本卡只回答 handoff / metadata 地址 / sync。

### 不要写「设备上没有 expand_x / assist / groupList」

### 不要抄 Case B 的 dest-push 与 shared-expert 公式

### 不要把 README `π` 当成 InitRouting map

### 不要把输出 `expert_token_nums` 当 60 `groupList`

### 不要把 URMA Layered / arch22 当 950 SoT

### 不要宣称通信与 GMM 零屏障重叠

### 不要把 Case A 接到本卡前面或后面

---

## Applicable Scenarios

参考本 Case，当：

- 已经会 B/C，要写或读 **融合后** 还剩哪些 API tensor、哪些必须留 world barrier
- 要把 split MoE 图压成单 kernel，判断 **哪些 GM materialization 可以内化**

不要参考本 Case，当：

- 要学 EP 坐标 / assist / post-EP nums 默认 type → [Case B](../ascend950-moe-ep-dispatch-combine/case.md)
- 要学 GMM1+SwiGLU+MX → [Case C](../../../compute/grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md)
- 要学 groupList 减法 → [60](../../../compute/grouped-gemm/ascend950-grouped-matmul-slice-m/case.md)
- 单卡 permute → [Case A](../../../compute/moe/ascend950-moe-local-permutation/case.md)

---

## Related Cases

| | 关系 |
| --- | --- |
| [Case B](../ascend950-moe-ep-dispatch-combine/case.md) | **被压缩的 EP loop**；split 上的 map / nums / window |
| [Case C](../../../compute/grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md) | **被压缩的 GMM1**；本卡不重教 MIX |
| GMM2 接口 | 已内化为本 Case 的数据合同；不另开 Case |
| [60](../../../compute/grouped-gemm/ascend950-grouped-matmul-slice-m/case.md) | 减法语义；本卡没有 list tensor |
| [Case A](../../../compute/moe/ascend950-moe-local-permutation/case.md) | sibling loop，不是前驱 |

工程索引（split 五条）：[MoE token/expert/rank 数据契约](../../../../../../knowledge/cam/engineering/moe-token-expert-rank-data-contracts.md)。  
融合层：[materialization and sync](../../../../../../knowledge/cam/engineering/moe-fusion-materialization-and-sync.md)。

---

## Source

| Field | Value |
| --- | --- |
| repository | cann/ops-transformer |
| remote | `https://gitcode.com/cann/ops-transformer.git` |
| commit | `9311b63bcd065b9779eb08a7d634e9463ee41ef1` |
| hardware | ascend950 |
| op | `mc2/mega_moe/` live `op_kernel/arch35/mega_moe.h` |
| status | accepted |
| license | CANN Open Software License Agreement Version 2.0 |
