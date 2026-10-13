# MoE fusion：materialization 与 sync

融合一条 **已经能接线的多算子 pipeline** 时，先问三个问题，再动手删 tensor / 并 kernel。不要先问“能不能 AllToAll+Matmul 叠在一起”。

本文是 **融合层** 索引，不是 MegaMoe 说明书，也不是第二份 split 契约。split 五条仍读 [token/expert/rank 数据契约](moe-token-expert-rank-data-contracts.md)。live 压缩读 [MegaMoe Case](../../../cases/cam/operators/compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/case.md)。

证据种类：`source-code`（Case / close-read）。本文 **没有** `benchmark`。

目标：这三条能迁到别的 **MC2 / 通算融合**，不绑死 MegaMoe 字段名。

---

## 先问什么

```text
1. 哪些 materialization 真被删除？
2. 哪些 metadata 只是从 API tensor 变成内部 state？
3. 哪些 Host happens-before 可以内化为核内同步？
   哪些跨设备 visibility / ordering requirement 必须保留？
```

不要先问“融合以后还剩几个 GM”。workspace 也可以是 GM。问的是 **API-visible / inter-op handoff** 还在不在，以及 **角色** 是被搬走、被替代，还是连缓冲一起没了。

冻结：融合可以替换或细化同步原语，但不能删除数据依赖所要求的可见性与顺序语义。

---

## 三种 handoff 结局

| 结局 | 含义 | 不要读成 |
| --- | --- | --- |
| **deleted** | 那种寿命/形状的缓冲不再作为可接线对象存在；后级直接吃前级结果 | “设备上再也没有这块数据” |
| **relocated** | **同一角色** 换地址（API tensor → workspace / window 同行缓冲） | “融合删掉了这个寿命” |
| **replaced** | 旧 handoff **角色** 还在，但由 **另一套内部 state / 协议** 承担 | “同一个 tensor 搬进了 window” |

表头用 `split API handoff → fused replacement / internal state`，不用“落点”。

---

## Graph

```text
split pipeline（已能按契约接线）
        │
        ├─ API-visible inter-op GM
        │     deleted     /  relocated  /  replaced
        │
        └─ Host launch happens-before
              ↓ fusion
        same-device dependency
              → 可内化为合适的 intra-kernel
                synchronization / ordering protocol
              → 不能机械写成“一个 flag 就够”
        cross-device dependency
              → communication visibility requirement 必须保留
              → barrier primitive 可被细化或替换，
                visibility / ordering semantics 不能删
```

不能删的是 **producer→consumer 的 ordering / visibility requirement**，不是某一种 barrier 原语。

---

## Q1 — 哪些 materialization 真被删除？

删的是 **可被下一 op 当输入的 API tensor**，不是「凡 GM 都删」。

判据：融合后是否还存在 **与 split 同角色、可被外部 op 消费** 的缓冲。没有，才是 deleted。内部仍有一块 workspace GM，那是 relocated，不是 deleted。

MegaMoe 证据（[Case](../../../cases/cam/operators/compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/case.md)）：

| split API handoff | 结局 |
| --- | --- |
| `x` / `topk_ids` / `y` | **keep**（图的两端） |
| dispatch `expand_x` | **relocated** → workspace local-expert-major |
| GMM1 `y` / `y_scale` | **relocated** → workspace swigluQuant |
| GMM2 `y` / combine `expand_x` | **deleted**（generic 路径不必落一份 expert-major 完整 buffer；GMM2 result → CombineTokens） |

「没有 expand_x」只在 **API-visible** 意义上成立。workspace 行缓冲还在。

融合还可能 **加** materialization（融合税）：MegaMoe A8W4 把 cumsum 备份到 workspace，因为 epilogue 覆盖 UB。那不是又一条 API 边。

迁到别的融合：先列出 split 图上每一条 inter-op GM，标 keep / relocated / deleted。不要按算子模块名删。

---

## Q2 — 哪些 metadata 只是变成内部 state？

契约没死。Layer 1 的 Rule 4 / 5 仍要问 **loop、time、scope、encoding**。变的是：**还是不是 API tensor**。

两类：

**relocated（同角色换地址）** — 仍是那张 map / 那份 counts，只是 Host 看不见。

**replaced（角色由新协议承担）** — 不是把旧向量 memcpy 进 window。

MegaMoe：

| split API handoff | fused replacement / internal state | 哪一类 |
| --- | --- | --- |
| `assist_info` triples | workspace triples；散射时用，Unpermute 改读 `(token,k)` 窗口 | relocated（消费点变了） |
| `ep_recv_count` | dest window `[mask\|count]` 协议状态 | **replaced**（E19 角色被新协议替代，不是 count 向量原样搬家） |
| GMM `group_list` | workspace recv counts → GMM `M` | **replaced**（没有 list tensor） |
| API `expert_token_nums` | 晚复制 **输出** INT32 count | 角色变了：不再喂 GMM |

Layer 1 Rule 3（Dispatch 默认 count vs GMM 默认 cumsum）在 **融合后的用户图上消失**，因为它是 API compose。内部仍用 count。若有人把融合 op 的输出 nums 再接到独立 GMM，那是 **新** 的 compose（INT32 vs INT64）。

迁到别的融合：对每份 metadata 问「是搬走了，还是换了一套协议来演同一个角色」。换协议就不要沿用旧 tensor 的 dtype/type/layout 假设。

---

## Q3 — 哪些 Host happens-before 可以内化，哪些 visibility / ordering 必须保留？

```text
Host launch happens-before
        ↓ fusion

same-device dependency
    → 可内化为合适的 intra-kernel synchronization /
      ordering protocol
    → 不能机械写成“一个 flag 就够”
      （可能是 pipeline event、workspace atomic、
        cross-core barrier、memory fence / visibility protocol；
        取决于是否同核、跨核，以及数据在哪一级 memory）

cross-device dependency
    → communication visibility requirement 必须保留
    → barrier primitive 可以被细化或替换
      （world barrier、peer-ready、per-chunk ready、
        per-expert flag、credit / sequence）
    → 但不能删掉语义：
          remote payload visible
                  before
          consumer reads remote payload
```

冻结：融合可以替换或细化同步原语，但不能删除数据依赖所要求的可见性与顺序语义。

handshake / 完成字还要跨 **launch** 保持身份：

```text
handshake / completion word
  ≠
payload a later fused phase will smash

one-launch lifetime non-overlap
  ≠
next launch cannot observe leftover as ready
```

若 overlay 它们，下一发 waiter 采样前必须 consume-and-clear、双 bank / dataState，或显式清平面。第一发 PASS 不是 leftover-safe。见 [adversarial statics §8](implementation-adversarial-statics.md)。

MegaMoe live（证据，不是通例原语）：

- same-device launch edges → wave / per-expert **workspace flags**
- cross-rank visibility → 仍保留两次 `CrossRankSyncInWorldSize`
  （quant/mask 对端可见之后才能 pull；combine 窗口填完之后才能 Unpermute）

不要写成「通信和计算无屏障重叠」。能叠的是 **已经满足 visibility 的那一段 same-device 依赖**。

迁到 AllGather+Matmul / ReduceScatter+Matmul / A2A+GMM：先写清 producer→consumer 的可见性与顺序，再选原语。读对端窗口的依赖，不能换成「本核 SetFlag 就当对端数据好了」。本核 AIC→AIV 可以换成合适的核内协议。

---

## 和 layer 1 的边界

| 层 | 管什么 |
| --- | --- |
| [数据契约](moe-token-expert-rank-data-contracts.md) | split 图怎么接线：loop、map、time/scope/type |
| 本文 | 接线之后怎么压：handoff 结局、内部 state、可见性/顺序语义 |

不要把融合结局写回 layer 1 的五条。MegaMoe 仍是 Case B 的 EP loop；freeze（expert compute 不擅自 permute M）在融合后仍成立。

---

## What NOT To Copy

- 「融合 = 把中间 GM 从设备上删掉。」问 API-visible handoff，再分 deleted / relocated / replaced。
- 「`ep_recv_count` 被搬进了 window。」角色被 `[mask\|count]` **替代**。
- 「`group_list` 还在，只是改名叫 recv counts。」没有 list tensor；GMM 吃的是 `M`。
- 「一次 launch 就可以删掉所有 barrier。」不能删的是 visibility / ordering **语义**；原语可以换。
- 「同一次 launch 内 handshake 与后级 payload 不重叠，就可以 overlay。」下一发仍可能把 leftover 认成 ready。
- 「same-device 依赖 = 换一个 flag。」可能要 event / atomic / cross-core barrier / fence，看核与 memory 层级。
- 「cross-device 必须永远是 world barrier。」可以细化成 peer-ready / per-chunk；`remote payload visible before consumer reads` 必须成立。
- 「这是第四张 GEMM Case / MegaMoe 原理课。」证据在 MegaMoe 卡；60/53/B/C 仍读原卡。
- 把 URMA / 未选中的 tiling key 当融合通例。

---

## Related Cases

| 角色 | Case |
| --- | --- |
| 本层证据 | [MegaMoe fused EP+FFN](../../../cases/cam/operators/compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/case.md) |
| 被压的 EP loop | [B](../../../cases/cam/operators/compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md) |
| 被压的 GMM1 | [C](../../../cases/cam/operators/compute/grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md) |
| split 契约 | [layer 1](moe-token-expert-rank-data-contracts.md) |

非目标：DeepEP、arch22、把每条 MC2 都先写成 MegaMoe 说明书再抽象。下一份融合 Case 应直接填这三问。

---

## Sources

| Field | Value |
| --- | --- |
| repository | cann/ops-transformer |
| remote | `https://gitcode.com/cann/ops-transformer.git` |
| commit | `9311b63bcd065b9779eb08a7d634e9463ee41ef1` |
| hardware | ascend950 |
| Case | `cases/cam/operators/compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/` |
| status | accepted |
| Last verified | 2026-08-21 |
