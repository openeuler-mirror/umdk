# FA pipeline：跨 KV-tile online-softmax 与 optional paged

Agent 接到 950 Flash Attention / PFA / IFA / CATLASS FA infer 时，先问 **KV-domain 扫什么、softmax 状态跨不跨 tile、`block_table` 的 logicalId 谁给**，再问算子名。不要先问“这是不是 Sparse Attention”。

本文是 **FA-pipeline family** 索引，不是 Sparse Case 说明书，也不是 CATLASS 49 / FIA 第二张卡。

三者是 **common FA-pipeline family 的 peer implementations**，**KV-domain policy 不同**。不要写成 “49 / FIA 是 Sparse 的 alternative”。

CATLASS 49 与 FIA 950 的对照已通过（`review: passed`）；二者是 FA-pipeline peer，不另开 Case。

`select_idx` **不**写进本文通例。那条只在 [Sparse Case](../../../cases/cam/operators/compute/attention/ascend950-block-sparse-paged-attention/case.md)。

证据种类：`source-code`（Case / contrast / live path）。本文 **没有** `benchmark`。

---

## 先问什么

```text
1. KV-domain policy 是什么？
     连续 kvSeq / S2 tiles
     还是 mask-truncated window（FIA sparse_mode）
     还是（仅 Sparse Case）MMA 前 selected pages
2. 第一块 KV 与后续块：online softmax 是 init 还是 update？
     已累积的 O 是否按新的 max/sum 做 normalization-aware merge？
3. 若有 block_table：logicalId 的 producer 是哪套 KV-domain policy？
```

不要先问 Cube–Vector 重叠了几拍，也不要先问 FIA 有没有名叫 rescale-O 的独立 Vector stage。

---

## Graph

```text
FA-pipeline family（peers）
        Cube QK
            → Vector online softmax
                 first KV-domain tile : init max / sum
                 later tiles          : update max / sum
            → Cube PV
            → normalization-aware O update / merge
                 已累积 O 必须与新的 max / sum 一致
                 Sparse / 49 : 可落成独立 Vector EpilogueRescaleO
                 FIA 950     : 未证明独立 rescale-O stage；
                               停在这条 invariant

        可选 PA
            logical page id     ← producer 由 KV-domain policy 决定
                → block_table   # logical → physical indirection
                → physical KV page

KV-domain policy（不共用，所以是 peers）
  Sparse Case : selected pages（select_idx 产 logicalId）
  CATLASS 49  : 连续 kvSeq tiles（+ optional mask）
  FIA 950     : 连续 / mask-truncated S2（sparse_mode）
```

共享的是 **跨 tile 的 softmax 状态机**，以及 **normalization-aware O merge**。  
可选共享的是 `block_table` 这层 **logical → physical indirection**。  
不共享的是 **扫哪些 KV**，以及 **logicalId 谁产**。

---

## Rule 1 — family 不是一张融合 MMA；O 侧是 merge invariant

```text
Cube QK
  → Vector online softmax
  → Cube PV
  → normalization-aware O update / merge
```

不要把 FA 读成 “又一个 Cube GEMM”。QK 与 PV 是两段 Cube；softmax 在 Vector。

第四段 **不是** “三源都有独立 Vector rescale-O”。Sparse / 49 的 `EpilogueRescaleO` 是这条 invariant 的一种实现。FIA 950 已证明 SoftMaxFlashV2 `no_update` / `update` 带着跨 tile 状态；**不要**把 FIA 写成已证明存在独立 rescale-O stage，也不要为了对齐 stage 名再下钻。

---

## Rule 2 — 第一块 init，其后 update；tile 身份跟 policy 走

跨 KV-domain tiles 必须带着 **running max / sum**。第一块初始化，后面更新。已累积的 O 必须按新统计量做 **normalization-aware merge**（实现可以叫 rescale，也可以折进 softmax update）。

| peer | “第一块”是什么 | init / update 记号 |
| --- | --- | --- |
| Sparse Case | 第一个 **selected page** | `kvBlockIdx==0` / 其后 |
| CATLASS 49 | 第一个 **连续 kvSeq tile** | `isFirstLoop` / `!isFirstLoop` |
| FIA 950 | 第一个 **S2 / sInner tile** | SoftMaxFlashV2 VF `no_update` / `update` |

不要把 “selected page” 写进 49/FIA，也不要把 “连续 S2 tile” 写进 Sparse Case。

---

## Rule 3 — `block_table` 是 logical → physical indirection，不是 sparsity

PA 时：

```text
logicalId  —producer = KV-domain policy→  block_table  →  physical KV page
```

`block_table` 本身 **不**规定 logicalId 连续。谁产 logicalId 由 KV-domain policy 决定：

| policy | typical logicalId producer |
| --- | --- |
| Sparse Case | `select_idx`（非连续 pages；`-1` skip） |
| CATLASS 49 | 连续 `kvSeq` 位置 `/ blockSize` |
| FIA 950 PA | 连续 / mask-truncated S2 位置 `/ blockSize` |

`select_idx` 如何产 logicalId 只在 Sparse Case，不是本文通例。

`block_table` 存在 ≠ 这块 attention 是 block-sparse。

---

## Rule 4 — 名字碰撞：`sparse_mode` ≠ page 选择

FIA `sparse_mode` 编的是 **mask 几何**（no-mask / causal / band）→ Host `ComputeSparseType`。它裁的是 S2 window，不是 MMA 前的 page 列表。

生产 FIA 950 **没有** `select_idx`。看到 `sparse` 不要默认 Sparse Case。

---

## Rule 5 — Cube–Vector 重叠拍数不是 family invariant

Sparse live path 有 `PRE_LAUNCH=2`。  
49 live path 有 `taskId` 上 QK → softmax(+1) → PV(+2) → rescale(+3)。那是 **49 自己的** 错拍，含它自己的 rescale stage。  
FIA 950 走 PFA/IFA arch35；**未**把 “PV 落后 QK 两拍” 钉成 950 规则。A2 SplitFuse 的 `PRE_LAUNCH=2` **不是** 950 FIA SoT。

重叠调度可以写进各自 live path / Sparse Case，不要写进本文当通例。

---

## 不要做

- 把 `select_idx` 写进这篇 Knowledge。
- 把 FIA 950 写成已证明存在独立 **Vector rescale-O** stage。
- 把 `block_table` 写成永远 **sequential** logical → physical。
- 把 “PV 相对 QK 延迟” 写成 Sparse + 49 + FIA 共同规则。
- 把 49 / FIA 写成 Sparse alternative，或为它们再开 Case。
- 把 FIA `sparse_mode` 写成 page 选择。
- 把 A2 SplitFuse / `experimental/.../fused_infer_attention_score/` demo README 当 950 生产 SoT。
- 为了把三个实现的内部 stage 名称对齐，再开一轮 FIA close-read。
- 现在开 MLA / indexer / CATLASS 70 / `sparse_flash_attention`。

---

## Sources

| Field | Value |
| --- | --- |
| supporting Case | [Sparse block-sparse paged](../../../cases/cam/operators/compute/attention/ascend950-block-sparse-paged-attention/case.md)（selection SoT；pipeline 只作 peer 证据） |
| CATLASS 49 | `examples/49_ascend950_flash_attention_infer/fai_kernel.h` @ `a8b4fffbd9cabc021dfd47253e907a1cde59de25` |
| FIA 950 | `attention/fused_infer_attention_score/` @ `9311b63bcd065b9779eb08a7d634e9463ee41ef1`；Host `TilingFusedInferAttentionScoreV4`；kernel `fused_infer_attention_score_apt.cpp` |
| hardware | ascend950 |
| status | accepted |
| Last verified | 2026-08-21 |
