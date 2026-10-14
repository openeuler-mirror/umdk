# MoE token / expert / rank 数据契约

Agent 接到 ops-transformer 风格 MoE 时，先问 **token 在哪个坐标系、哪张 map、哪份 group 元数据**，再接线。不要先问“Dispatch 怎么做 AllToAll”。

本文是 **split pipeline** 的工程索引，不是 MoE 算子介绍，也不是第二套 Case Card。live 细节读：

- [A 单卡 permute](../../../cases/cam/operators/compute/moe/ascend950-moe-local-permutation/case.md)
- [B EP dispatch/combine](../../../cases/cam/operators/compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md)
- [C GMM+SwiGLU+MX](../../../cases/cam/operators/compute/grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md)

`groupList` 的 **prefix-sum 减法** 仍读 [60](../../../cases/cam/operators/compute/grouped-gemm/ascend950-grouped-matmul-slice-m/case.md)。MX Block 读 [53](../../../cases/cam/operators/compute/gemm/ascend950-fp8-mx-matmul/case.md)。C 只教它们之上的生产融合与 **谁生产 groupList**。

证据种类：`source-code`（close-read / Case）。本文 **没有** `benchmark`。  
**不覆盖融合规则。** API-visible handoff / 内部 state / 哪些 barrier 不能删，读 [materialization and sync](moe-fusion-materialization-and-sync.md)。那些结论不并进本文五条。

本知识统一使用以下边分类：

| 标签 | 含义 |
| --- | --- |
| **direct-data-edge** | dtype、rank、shape rule、**index layout** 都能接 |
| **conditional-direct** | 还要 attr / dtype / 范围条件 |
| **logical-edge** | 同一 MoE 寿命，但中间改过、换名、或缺 producer |

名字从来不够。

---

## Graph（两套 loop，不是一条链）

```text
token-major hidden [T,H] + expert_idx [T,K]
        │
        ├─ Case A 单卡
        │     InitRouting → expert-major expanded_x
        │                   map = expanded_row_idx
        │     expert compute（可插 C + GMM2）
        │     Finalize → token-major
        │
        └─ Case B EP
              Dispatch → rank/expert window
                      → local-expert-major expand_x
                        map = assist_info triples
                        nums = expert_token_nums [localE]
              Case C 不重排 M
              GMM2 不重排 M（接口，不是第四张 Case）
              Combine → token-major（已加权）
```

**没有** `InitRouting → Dispatch → … → Finalize` 生产直连链（`source-code`）。Init 与 Dispatch 是 **sibling permute**。

冻结：Routing loop 决定 map；expert compute 不应擅自改变 routing row order，除非 Case 明确证明存在新的 permutation。C / GMM2 当前证据是 **preserve M**，不是新 permute。

坐标脊梁（字段以源码为准，不要把草稿维当事实）：

```text
token-major
    → expert-major                  // A: Init
    → rank/expert window            // B: Dispatch pack
    → local-expert-major            // B: recv expand_x
    → GMM row order = 上一行        // C: 不 permute M
    → token-major restore           // A: Finalize / B: Combine
```

---

## Rule 1 — tensor name ≠ tensor lifetime

同名 tensor 可以处于 **expert 寿命的不同阶段**。

| 名字 | 寿命 A | 寿命 B |
| --- | --- | --- |
| `expanded_x` / `expand_x` | Init / Dispatch **out** = expert **input** | Finalize / Combine **in** = expert **output** |
| `scales` | gating `y` = gate weight | Init `scale` = quant；GMM `x_scale`/`y_scale` = 量化系数 |

典型错误：把 Init `expanded_x` 接到 Finalize；把 GMM1（C）的量化 `y` 接到 Combine。前者中间有 FFN（**logical-edge**）；后者还缺 down-proj 且宽是 `N/2`（C）。

证据：A（两个 `expanded_x`）；C（`y` ≠ Combine `expand_x`）。

---

## Rule 2 — shape/dtype match ≠ layout match

INT32 1-D、`[T,K]`、甚至都叫 `expanded_row_idx`，仍可能是两种 map。

A：Init `row_idx_type` 0 GATHER vs 1 SCATTER；Finalize `drop_pad_mode` COLUMN `token+k*T` vs ROW `token*K+k`。直连要 **方向 + 展平 stride** 同时配对。示例程序各用一套 attr，**不是**联合证明。

B：Combine 的 origin `(tokenId, topkId)` 在 **assist_info** 的 FillTriple 里，不在 `expert_ids [BS,K]` 里。`expert_ids` 是身份。

先问 layout，再问“shape 对得上吗”。

证据：A row map；B assist vs `expert_ids`。

---

## Rule 3 — API compatible ≠ defaults compose

两头都声明 count/cumsum，默认值仍可能反着。

| attr | Dispatch `expert_token_nums_type` | GMM / GMM1 `group_list_type` |
| --- | --- | --- |
| 0 | prefix-sum | cumsum（**默认**） |
| 1 | count（**默认**） | count |

dtype INT64、长度都能接，**不等于** 默认图能跑。Host **不**做 count↔cumsum 转换（`source-code`）。

同类：gating `y` 随 logits 可以是 fp16/bf16/fp32；Combine `expert_scales` OpDef 是 **fp32**。shape `[T,K]` 对，dtype 仍是 **conditional-direct**。

证据：B + C；B 的 gating→`expert_scales`。

---

## Rule 4 — routing map 属于一条 routing loop

```text
expanded_row_idx     ∈  Case A 单卡 loop
assist_info triples  ∈  Case B EP loop
```

不要把 A 的 row map 带过 EP，也不要用 B 的 assist 去喂 Finalize。

Combine **已经**做 rank 逆变换 + TopK 加权。EP 路径 **不接** Finalize。Finalize 的 `y` 和 Combine 的 `x` 是同一寿命类（token-major hidden），是 **替代终点**，不是先后级。

证据：A vs B sibling；chain E20。

---

## Rule 5 — group metadata 要带三件套读

同样叫 expert count，必须先问 **routing 寿命的哪个时刻** 统计的，以及 **统计 scope 是什么**。不要默认 Init = 全局、Dispatch = 局部。

接到 `groupList` / counts / `expert_token_nums` 时问：

```text
1. producer time     通信前还是通信后？（pre-EP / post-EP）
2. expert scope      这次统计覆盖哪些 expert？（不是“全局还是局部”二选一）
3. encoding type     0 prefix-sum / cumsum 还是 1 count？
```

本批钉死的两份：

```text
Init counts
  pre-EP expert-range metadata
  shape = [expertEnd - expertStart]
  scope = active_expert_range（空则 0, expertNum)）
  → 不是 post-EP local-recv counts
  → 不是 EP 生产链上的 GMM 直连边

Dispatch nums
  post-EP local-expert metadata
  scope = 本 rank 收到的 local experts（shared expert rank 上可能是 1）
  → GMM groupList 的 conditional-direct 候选
```

GMM1 / GMM2 吃同一份 list、同一 type；**M 序不变**（上节冻结规则）。type 0 的 **减法语义** 与 60 相同；EP 上 **producer** 换成了 Dispatch。不要写 `init.counts ──────→ GMM.groupList`。


---

## 先问什么

```text
1. 这条图是单卡 loop 还是 EP loop？
2. 当前 payload 在坐标脊梁的哪一格？
3. 手上的 map 属于哪条 loop？
4. group 元数据的 time / scope / type 是什么？默认 type 对齐了吗？
5. 这个名字的 tensor 处于 expert input 还是 output 寿命？
```

不要先问“AllToAll 怎么写”。B 的 README AllToAllV 是 job 名；950 live 是 MTE window。

---

## What NOT To Copy

- 「InitRouting 是 Dispatch 的前处理。」sibling permute（B）。
- 「两个 `expanded_x` 同名就能接。」Rule 1。
- 「`expanded_row_idx` 和 `assist_info` 都是 row map。」属于不同 loop（Rule 4）。
- 「Combine 之后还要 Finalize。」EP 上 Combine 已是 token-major 加权终点。
- 「Dispatch counts 默认就能喂 GMM。」默认 type 反着（Rule 3）。
- 「Init counts = 全局，Dispatch nums = 局部。」先问 time + scope，不要二选一（Rule 5）。
- 「C 的 `y` 就是 Combine `expand_x`。」缺 GMM2，宽 `N/2`，常为量化。
- 把融合边界写进本文。去 [materialization and sync](moe-fusion-materialization-and-sync.md)。
- 把 60/53 的 Cube 课重抄一遍。C 是 extension，不是替换。

---

## Related Cases

| 角色 | Case |
| --- | --- |
| 单卡 loop + row map | [A](../../../cases/cam/operators/compute/moe/ascend950-moe-local-permutation/case.md) |
| EP loop + window + post-EP nums | [B](../../../cases/cam/operators/compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md) |
| GMM1 融合 + groupList 消费者 | [C](../../../cases/cam/operators/compute/grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md) |
| B+C+GMM2 融合压缩 | [MegaMoe](../../../cases/cam/operators/compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/case.md) |
| prefix-sum 减法怎么算 | [60](../../../cases/cam/operators/compute/grouped-gemm/ascend950-grouped-matmul-slice-m/case.md) |
| MX Block | [53](../../../cases/cam/operators/compute/gemm/ascend950-fp8-mx-matmul/case.md) |


非目标：DeepEP、Gating 单独成卡、plain `grouped_matmul` 第二张 GEMM Case。

融合层：[moe-fusion-materialization-and-sync.md](moe-fusion-materialization-and-sync.md)。不要把消失的 API-visible handoff 写回上面五条。

---

## Sources

| Field | Value |
| --- | --- |
| repository | cann/ops-transformer |
| remote | `https://gitcode.com/cann/ops-transformer.git` |
| commit | `9311b63bcd065b9779eb08a7d634e9463ee41ef1` |
| hardware | ascend950 |
| Cases | A / B / C / MegaMoe as above |
| status | accepted |
| Last verified | 2026-08-21 |
