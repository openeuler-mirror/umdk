# Case Card: ops-transformer Ascend950 Matmul + Native ReduceScatter

本 Case 教的是 **chunked MM–collective coupling**（Cube 产 C tile → native ReduceScatter 消费），不是 `matmul_reduce_scatter_v2` 算子说明书，也不是 43。

Canonical live instance：**fp16/bf16 / `MatmulReduceScatterFP16BF16` / `TPL_COMMALG = TPL_CCU_REDUCESUM`**。  

`status: accepted`。content_review passed 2026-08-21。  
**upstream identity verify 不是本卡 accepted gate**（与 MoE A–D 相同：SoT 是 scanned fork `9311b63bcd065b9779eb08a7d634e9463ee41ef1`；`cann/ops-transformer` 未 fetch）。

MC2 coupling 读 [Knowledge](../../../../../../knowledge/cam/engineering/mc2-compute-collective-coupling.md)（`accepted`）。AG 是 sibling contrast，不开第二张卡。AR 是 M1 member，不开 AR Case。

本卡 **技术内容冻结**：不要回改 canonical / timeline / ownership / AG contrast。

job 名 ReduceScatter **不是**机制。950 4P/8P + CCU **默认**走 `TPL_CCU_ALL2ALL_VEC_REDUCE`（A2A + Vector reduce）。那条 sibling **不是本卡**。

---

## What

每个 rank 用本卡 A shard 做 Matmul，按 **M-tile** 把 C 交给 native `Hccl::ReduceScatter`，得到 rank-local C shard。per-tile Wait deferred 到 `PostProcess`；**RSᵢ overlaps MMᵢ₊₁**。

```text
local A shard + B
        ↓ Cube ASW  MM（一个 M-tile，覆盖各 rank 在该切片上的 C）
workspace send buf
        ↓ same-device  FIXPIPE 就绪（flag 3）
ReduceScatter<true>     handle 留下，不在这里 Wait
        ↓ 下一块 Cube
…
        ↓ AIC 0  Wait(handles_) + Finalize
API  C shard
```

有效引擎：**Cube + HCCL**。`KERNEL_TYPE_MIX_AIC_1_2`。本路径 AIV **不参与**（`Compute()` 直接 return）。不是 EP window，不是 43 的 MN pingpong 课。

---

## Why This Case

相对已冻结的 GEMM / MoE / Attention：

1. **collective 与 Matmul 的耦合**，不是 “MM 完再调一次 HCCL”。
2. chunk 何时成为 comm 的合法输入：Cube 写完 → same-device FIXPIPE → `ReduceScatter<true>`。
3. per-tile Wait deferred 到 `PostProcess`；**RSᵢ overlaps MMᵢ₊₁**。
4. job 名 ≠ 实现：同 op 还有 A2A+vec sibling。
5. **compute baseline = 43**；本卡不重教 MN pingpong。教学增量在 coupling / ownership。

---

## Canonical instance

| Field | Value |
| --- | --- |
| hardware | ascend950（`DAV_3510`） |
| dtype | **fp16 或 bf16**（同一 kernel class） |
| kernel | **`MatmulReduceScatterFP16BF16`** |
| `TPL_COMMALG` | **`TPL_CCU_REDUCESUM`（0）** |
| `TPL_COMM_MODE` | CCU 或 AICPU |
| 何时 live | **非** 4P/8P CCU 默认；或 `commMode=ai_cpu`（Host 强制 native） |
| task_type | mix |
| engines | cube, communication（本路径无 AIV 工作） |
| Cube | `mc2_mat_mul_asw_kernel.h` → `3rd/mat_mul_v3/.../mat_mul_asw_kernel.h` |
| comm | `hccl_.template ReduceScatter<true>` + `SetCcTilingV2` |
| Host 配置串 | `ReduceScatter=level0:fullmesh`（native） |

Sibling（同卡，不要另开）：fp16 与 bf16。  
**不是 sibling：** `TPL_CCU_ALL2ALL_VEC_REDUCE`、quant RS、v1 `matmul_reduce_scatter`。

---

## 1. Live variant 必须 pin

Kernel 分派（`matmul_reduce_scatter_v2_apt.cpp`）：

```text
TPL_INPUT == INPUT_TYPE_IS_FP16_BF16
TPL_COMMALG == TPL_CCU_REDUCESUM          → 本卡
TPL_COMMALG == TPL_CCU_ALL2ALL_VEC_REDUCE → 不要
```

Host `isA2APath_ = IsUseA2APath(rankDim, npuArch)`：**DAV_3510 且 rankDim ∈ {4, 8}**。AICPU 强制 `isA2APath_=false`。

Agent trap：Host `GetTilingKey` 对这条 fp16/bf16 仍填 `OUTPUT_TYPE_IS_FP8`（枚举值 1）。那是模板槽，**不是**输出 FP8。看 `TPL_INPUT` + `TPL_COMMALG`。

---

## 2. Chunk coordinate

Host 按 **M** 切 `tileCnt` 主块 + 可选 `tailCnt`（formulaic，再受 HCCL 256MB / 最多 16 次通信约束）。`rankM` = 用户原始 M。

一个 comm tile：Cube 覆盖 **所有 rank 在该 M 切片上的 C**（`isGather=false`，`calRankNum = rankDim`），然后 RS 散射。

```text
recvCount = (tCubeTiling.M / rankDim) * tCubeTiling.N
handles_[i]           主块
handles_[tileCnt + j] 尾块
```

这不是 66/68 的 K 切分。不要在本卡验算 L1/L0 容量。

---

## 3. Timeline：producer Cube，consumer ReduceScatter

```text
Init:  InitV2 + SetCcTilingV2；gmToFloat_ = workspace（send）

每个 tile（AIC used cores）
  UpdateSlice(i) → Cube Process → flag 3（PIPE_FIX）
  ReduceScatter<true>(send, recv, recvCount, SUM, stride, 1)
  指针 += cOffset          // 不 Wait

PostProcess（仅 AIC block 0）
  Wait(handles_[0 .. tileCnt+tailCnt-1])
  Finalize
```

`<true>` = launch 并交出 handle。没有单独 `Commit`。per-tile Wait deferred；**RSᵢ overlaps MMᵢ₊₁**。

**没有** AG 那种本卡 shortcut。每一块都是 MM → RS。

---

## 4. Buffer ownership

| 角色 | 正常路径 |
| --- | --- |
| A / B | 本 rank shard |
| MM 写出 / RS send | workspace `gmToFloat_` |
| RS recv / API 输出 | `cGM` = **C shard** |

`MC2_DEBUG_ONLY_CUBE` 对调缓冲，不是合同。  
A2A sibling 会多一份 workspace recv，本卡 native 只要 send。

中间 full-C 切片在 workspace，是 comm send，不是下一张 API tensor。

---

## 5. Same-device vs cross-rank

| | 本卡 |
| --- | --- |
| same-device | Cube 后 `CrossCoreSetFlag/WaitFlag` flag **3**（PIPE_FIX）。AIV 不 Wait。读成 **GM 写完再发 comm** |
| cross-rank | `hccl_.Wait(handle)`。只有 AIC 0 在 PostProcess 做 |
| 编译条件 | `--cce-auto-sync=off` **不是** sync 原语 |

Flag 3 ≠ 远端可见。Layer 2 的 visibility 句子可以引用，不要把本卡并进 MoE Knowledge。

源码里 **used AIC 核都会调** `ReduceScatter`；Wait 只有 block 0。HCCL 是否在非 0 核内部过滤：**未证明**，不要编故事。

---

## Reverse sibling：AG v2（不开 Case）

`all_gather_matmul_v2` / `AllGatherMatmulFP16BF16`：同一套 ASW + 每 chunk 一个 handle，方向相反。

```text
StartNotify: 全部 AllGather<true>
InnerProcessLocalMM: 本卡 A，不 Wait     // 与远端 AG overlap
InnerProcessGatherMM: Wait 再 MM 远端 tile
```

producer = collective，consumer = Cube。本卡 A 可绕过 Wait；RS **没有**对偶 shortcut。  
不要为 AG reverse sibling 再开 Case。

---

## Parallel Strategy

| 层级 | 本例 |
| --- | --- |
| 多卡 | ReduceScatter；输出按 rank 切 M |
| 核间 | ASW 在一个 comm tile 内切 MN（**compute baseline = 43**，不重教） |
| 核内 overlap | per-tile Wait deferred；**RSᵢ overlaps MMᵢ₊₁** |
| AIV | 本路径空转 |

---

## Memory Strategy

角色，不是容量规划。

| 区 | 用途 |
| --- | --- |
| GM API | A shard、B、C shard |
| GM workspace | RS send（full tile C） |
| HCCL | `mc2CcTiling` / CCU 或 AICPU engine |
| L1/L0 | ASW Cube；**compute baseline = 43**，不要在本卡重算 |

---

## Variants

同一张卡：fp16 与 bf16。

不要开第二张卡：

| 东西 | 原因 |
| --- | --- |
| A2A+vec RS | 同 job、不同机制 |
| quant RS | 另一套 tiling |
| v1 `matmul_reduce_scatter` | 950 非 live |
| AG v2 | reverse sibling，本卡已对照 |
| AR | M1 pending，粒度未钉 |

---

## What Agent Should Learn

1. 教学是 **chunked MM→RS coupling**，不是 GEMM Case，也不是 EP。
2. 必须 pin `TPL_CCU_REDUCESUM`；4P/8P CCU 默认不是本卡。
3. Cube 写完 + flag 3 之后，C tile 才是 ReduceScatter 的合法输入。
4. handle 一个 tile 一个；per-tile Wait deferred；**RSᵢ overlaps MMᵢ₊₁**。
5. 最终 ownership 是 **C shard**；workspace 是 send。
6. flag 3 是 same-device；跨 rank 是 `Wait(handle)`。
7. AG 是反向 sibling，不是第二张 Case。

---

## What NOT To Copy

### 不要把 job 名 ReduceScatter 当成 native RS

### 不要把 4P/8P CCU 默认路径写成这张卡

### 不要把 `OUTPUT_TYPE_IS_FP8` 读成输出 dtype

### 不要把内部 ASW 开成 43 / 66 / 68

M-tile 是 comm 切片，不是 remainder-K / every-MN-K。

### 不要把 flag 3 / `--cce-auto-sync=off` 写成跨 rank

### 不要开 AG Case / 不要为补齐 collective 名去读 AR

### 不要写成 Case B 的 MTE window

`Hccl::ReduceScatter` + handle Wait。M4 quant-only window 也不是本卡。

### MC2 Knowledge

[mc2-compute-collective-coupling](../../../../../../knowledge/cam/engineering/mc2-compute-collective-coupling.md)（`accepted`）。本卡仍是 M1 canonical 证据，不是那篇的扩写。

---

## Applicable Scenarios

参考本 Case，当：

- 要在 950 上读 **Matmul 与 collective 按 chunk overlap**
- 要分清 ReduceScatter **job** 和 native / A2A+vec **机制**
- 要分清 same-device 就绪和 cross-rank Wait

不要参考本 Case，当：

- 要学 Cube pingpong / MN tiling → [43](../../../compute/gemm/ascend950-basic-matmul/case.md)
- 要学 StreamK / SplitK → [66](../../../compute/gemm/ascend950-streamk-matmul/case.md) / [68](../../../compute/gemm/ascend950-multi-core-splitk-matmul/case.md)
- 要学 EP routing / window → [B](../../moe/ascend950-moe-ep-dispatch-combine/case.md)
- 要学融合 visibility 分类 → [Layer 2](../../../../../../knowledge/cam/engineering/moe-fusion-materialization-and-sync.md)（引用，不要把 MC2 并进去）
- 要判断下一种 MC2 的 ownership / progress / visibility → [MC2 Knowledge](../../../../../../knowledge/cam/engineering/mc2-compute-collective-coupling.md)

---

## Related Cases

| | 关系 |
| --- | --- |
| [43 Basic Matmul](../../../compute/gemm/ascend950-basic-matmul/case.md) | **compute baseline = 43**；不是本卡要教的 MN GEMM |
| [B EP dispatch/combine](../../moe/ascend950-moe-ep-dispatch-combine/case.md) | 都有通信；**family 不同**（window token routing vs HCCL RS） |
| [D MegaMoe](../../moe/ascend950-mega-moe-fused-ep-ffn/case.md) | Layer 2 visibility 可引用；不是 EP+FFN 压缩 |
| AG v2 | reverse sibling；**不开 Case** |
| [MC2 Knowledge](../../../../../../knowledge/cam/engineering/mc2-compute-collective-coupling.md) | coupling 四问；`accepted` |


---

## Source

| Field | Value |
| --- | --- |
| repository | cann/ops-transformer |
| remote | `https://gitcode.com/cann/ops-transformer.git` |
| scanned fork commit | `9311b63bcd065b9779eb08a7d634e9463ee41ef1` |
| official remote | `https://gitcode.com/cann/ops-transformer.git` |
| hardware | ascend950 |
| op | `matmul_reduce_scatter_v2` |
| live kernel | `mc2/matmul_reduce_scatter_v2/op_kernel/arch35/matmul_reduce_scatter_fp16_bf16.h` |
| live entry | `mc2/matmul_reduce_scatter_v2/op_kernel/arch35/matmul_reduce_scatter_v2_apt.cpp` |
| host tiling | `mc2/matmul_reduce_scatter_v2/op_host/op_tiling/matmul_reduce_scatter_tiling_base.cpp` |
| status | accepted |
| accepted gate: content review | **passed**（2026-08-21） |
| accepted gate: upstream verify | **不是 gate**。SoT = scanned fork；与 MoE A–D 相同。`cann/ops-transformer` 未 fetch |
| license | CANN-OSLA-2.0 |
