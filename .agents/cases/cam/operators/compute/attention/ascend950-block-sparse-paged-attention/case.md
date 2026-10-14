# Case Card: SGLang Ascend950 Block-Sparse Paged Attention

本 Case 教的是 **block-sparse paged attention 机制**，不是 `npu_sparse_attention_score` 算子说明书。

Canonical live instance：**bf16 / tilingKey `10002` / `SasaRegularKernelArch35`**。  

Indexer **不在**本 kernel。`select_idx` 是外部契约。Lightning indexer 在 950 CMake 关闭。

`status: accepted`。content_review passed. Upstream SoT：`sgl-project/sgl-kernel-npu` `main` @ `ee334193e5278d7b3a64afcc2e3ee5243133c4a0`。扫描 fork commit 仍是 `8d76a8da75315ae9add5cfd2458b8028289f1ada`；三条 live 证据路径与 upstream 该 commit 字节一致。

---

## What

对每个 query token、每个 KV head，只对 **被选中的 paged KV blocks** 做 QK / online softmax / PV。稀疏发生在 MMA **之前**。跨 block 的注意力归约靠 Vector 上的 **running softmax 状态** 和 `EpilogueRescaleO`。

```text
select_idx [kvHead, maxQSeqlen, topK]     # logical block id；-1 skip
        ↓
block_table[batch, logicalId]             # logical → physical page
        ↓
paged K/V [physicalId, blockSize, kvHead, D]
        ↓ Cube QK
S (UB) → Vector online softmax → P (L1)
        ↓ Cube PV   PRE_LAUNCH=2
O_tmp → Vector rescale-O
attentionOut [T, N, D]
```

有效引擎：**Cube + Vector**。`KERNEL_TYPE_MIX_AIC_1_2`。不是 43 那种 MN GEMM。

---

## Why This Case

相对已冻结的 GEMM / MoE Cases，这是 sgl-kernel-npu 上 **第一个没被吸收的 family**。要会五件事：

1. logical sparse selection：`select_idx` → `block_table` → physical KV page
2. sparsity happens **before** MMA：只对选中的 pages 做 QK/PV
3. task 坐标：`(qToken, kvHead)` + `groupSize` 个 Q heads
4. QK → online softmax → PV 流水：`PRE_LAUNCH=2`，PV 落后 QK 两个 sparse blocks
5. **online-softmax state 跨 sparse blocks 保留**：新 block 进来时 rescale 旧 O

第 5 条是本卡核心。不要把本卡写成 paged 地址计算器。

---

## Canonical instance

| Field | Value |
| --- | --- |
| hardware | ascend950（Host `SOC_VER_950_CODE = 4`） |
| dtype | **bf16** |
| tiling_key | **10002** |
| variant | Regular → `SasaInferIntfRegular` → `SasaRegularKernelArch35` |
| task_type | mix |
| engines | cube, vector |
| QK Block | `block_mmad_qk_arch35_ABf16_C_to_UB.hpp`（`BlockMmadTla<MmadAtlasA5BsaQK, Shape<128,128,128>>`） |
| tiles | QK/PV Mmad base shape `128×128×128`；Host `qBaseTile=128`；product `blockSize=128`；`pL1BufNum = PRE_LAUNCH+1 = 3` |

fp16 `10001` 与 fp8 `10003` 是 **同一 Case 的 sibling**，见 Variants。

---

## 1. Logical sparse selection

| tensor | 含义 |
| --- | --- |
| `select_idx` | **logical** KV-block id，按 `(kvHead, query token, topk slot)`。0-based。`-1` = unused。**不是** token range，**也还不是** physical page |
| `block_table` | 该 batch 的 paged map：logical block → physical block |
| `key` / `value` | `[blockNum, blockSize, kvHead, D]`，用 **physical** id 寻址 |

物理页在 **`SasaRegularKernelArch35` 外层**解析进 `validPhysicalIds[]`，再形成 `gmOffsetK/V`。Cube Block 吃的已经是 physical page。

可选 `select_num_idx` 给出该 `(kvHead, qToken)` 的有效 topK；全 `-1` / `validTopK==0` 则该 task 跳过。序列尾页可以是 partial tile（`lastBlockTileSize`）。

Indexer 怎么生成 `select_idx` **不是本卡**。

---

## 2. Sparsity happens before MMA

外层 KV-block loop，不是 MMA 里的 mask。

对每个 task：读 logical ids → skip `< 0` → 查 `block_table` → 只对 `actualLoopNum` 个 surviving pages 跑 QK / softmax / PV。

不是 dense FA + MMA mask。不是 43 的 MN GEMM。不要把 A2 `block_mmad_qk.hpp` 里 **Block 内** `gSelectIdx` gather 写进本卡：那个文件只在 `__CCE_AICORE__==220`。

---

## 3. Task coordinate

```text
totalTaskNum = totalQTokens * kvHeads
blockDim     = min(totalTaskNum, aicNum)
task         = (qToken, kvHead)

groupSize = numHeads / kvHeads
一个 task → groupSize 个 Q heads → 共享这个 kvHead
qHeadStart = kvHeadIdx * groupSize
```

Regular 把这一组 Q heads 当作 **一个 M tile**（`rowNum = groupSize`）。FullQuant 按 `headInGroup` 更细地循环，**不改变** sparse-selection 机制。

---

## 4. QK → online softmax → PV

MIX。Cube 做 QK 和 PV。Vector 做 online softmax（写出 L1 `P`）和 rescale-O。

```text
kvBlock  0:  QK₀  softmax₀
kvBlock  1:  QK₁  softmax₁
kvBlock  2:  QK₂  softmax₂   PV₀  rescale-O₀     ← PV 从这里开始（PRE_LAUNCH=2）
kvBlock  3:  QK₃  softmax₃   PV₁  rescale-O₁
...
drain:                   PV_{n-2} … PV_{n-1}
```

循环上界是 `kvSLoopNum + PRE_LAUNCH`。PV 用的 physical id 是 `kvBlockIdx - PRE_LAUNCH`。

跨核握手：`CrossCoreFlag` `mm1ToSm` / `smToMm2` / `mm2ToRe`。UB S / O_tmp ping-pong（`UB_S_OTMP_BUF_STAGES = 2`）。L1 `P` 缓冲 `pL1BufNum = 3`。这些是实现事实，不是本卡的容量课。

---

## 5. Online-softmax state across sparse blocks（核心）

43 的 Cube 路径是一次 MN GEMM，没有跨 tile 的注意力归约状态。本 Case 的新机制是：

**Vector 上的 online-softmax 状态活过整个 sparse-block loop。**

- 第一个 selected page（`kvBlockIdx == 0`）：`EpilogueOnlineSoftmax` **初始化** running max / sum。
- 之后每个 page：同一套 softmax 把新 S 折进 running 状态，写出该 page 的 `P`。
- `EpilogueRescaleO`：新 page 的 PV 结果进来时，**rescale 已经累加的 O**，再写入更新后的 O。
- 最后一个 page（`kvBlockIdxDe == kvSLoopNum - 1`）收尾写 `attentionOut`。

所以稀疏不是“少算几次无关 GEMM”。每个新 block 都会改写 **已经对先前 selected pages 累加好的注意力输出**。漏 rescale 或把每个 page 当独立 softmax，数值是错的。

Host 另分配内部 `softmaxLse [T,N,1]` fp32；`op_host` 写明 **不返回**。不要把它当成 API 输出。

`inner_precise`：Host 写入 tiling blob，README 要求 sglang 传 `4`。当前 950 kernel tree **没有读取**该字段。这是 **wrapper / golden contract**，不是第二条 live kernel 分支。不要按 `inner_precise` 虚构不同 950 路径。

---

## Data Flow

```text
API  query [T, N, D]  bf16
API  select_idx, block_table, paged K/V
        │  每 task 解析 validPhysicalIds[]
        ▼
for each selected physical page:
        Cube QK → UB S
        Vector online softmax → L1 P
        （PV 落后 PRE_LAUNCH 个 page）
        Cube PV → UB O_tmp
        Vector rescale-O → running O
        ▼
API  attentionOut [T, N, D]  bf16
```

---

## Parallel Strategy

| 层级 | 本例做法 |
| --- | --- |
| 多核 | 按 `(qToken, kvHead)` 切 task |
| 启动核数 | `min(totalTaskNum, aicNum)` |
| 核内 | `taskIdx = blockIdx; taskIdx < totalTaskNum; += coreNum` |
| GQA | 一个 task 覆盖 `groupSize` 个 Q heads |
| 稀疏维 | **单 task 内**串行扫 selected pages；不按 page 分核 |

---

## Memory Strategy

角色，不是容量规划：

| 区 | 用途 |
| --- | --- |
| GM | Q / O、paged K/V、`select_idx`、`block_table` |
| L1 | QK/PV tiles；softmax 写出的 `P`（`pL1BufNum=3`） |
| UB | S、O_tmp ping-pong；Vector running softmax / rescale 状态 |
| L0 | QK/PV Cube MMA（base M/N/K shape `128×128×128`；不在本卡展开 43 那套容量验算） |

不要用本卡去算满不满 L1/UB。

---

## Variants

同一张卡，不要开第二张。

| tilingKey | dtype | kernel | 相对 canonical |
| --- | --- | --- | --- |
| **10002** | bf16 | Regular `SasaRegularKernelArch35` | **canonical** |
| 10001 | fp16 | 同一个 Regular | 同一机制，换元素类型 |
| 10003 | fp8 e4m3 | `SasaFullQuantKernelArch35` | **同一** sparse outer loop；多 `q/k/v_dequant_scale`；输出元素 `SMDtype`（fp16）；GQA 按 `headInGroup` 循环 |

`10004` / `10005`（D=64）在 header 里存在。Host **从不返回**。死 key，不是本卡合同。

---

## Host fallback ≠ supported contract

`GenerateTilingKey` 在 950 上：匹配到的 fp8/bf16/fp16（D=128，blockSize=128）分别给 10003/10002/10001。  
**其他 dtype  fall through 到 `tilingKey = 10001`（Regular fp16 template）。**

只记录为：源码缺少严格 legality guard。

**不要写：** SparseAttentionScore 支持其他 dtype，并自动转成 fp16。

和 `CanImplement()==true` 同类：Host fallback ≠ supported contract。

本卡 **supported dtype** 只有有明确 API / Host 分支 / kernel 证据的 **fp16、bf16、fp8 e4m3**。

---

## What Agent Should Learn

1. `select_idx` 是 logical block id；physical page 要再走 `block_table`。
2. 稀疏是 MMA 前的 page 选择，不是 MMA mask，也不是 43。
3. 调度坐标是 `(qToken, kvHead)`，GQA 用 `groupSize` 进同一个 task 的 M。
4. QK 与 PV 不是同步成对出现：`PRE_LAUNCH=2`。
5. **跨 selected pages 的正确性依赖 Vector running softmax + rescale-O**，不是每页独立 attention。
6. Host fall-through 到 10001 ≠ 支持任意 dtype。

---

## What NOT To Copy

### 不要再开一张 fp16 / fp8 Attention Case

同一 Regular 机制，或同一 outer loop 的 FullQuant sibling。

### 不要写成 43 / 53 / CATLASS 49

Cube tiles 存在，教学是 sparse paged FA。fp8 注意力 ≠ 53 GEMM。不要克隆 Basic Matmul。

### 不要把 A2 `block_mmad_qk.hpp` 的 in-block `gSelectIdx` 当 950 SoT

950 QK live Block 是 `block_mmad_qk_arch35_ABf16_C_to_UB.hpp`。physical id 在 kernel 外层已经解析完。

### 不要把本卡并进 FIA / MLA / lightning indexer

它们是 **alternative attention stacks**。本卡的 `select_idx` 是外部输入。950 上 indexer 没编进来。

### 不要按 `inner_precise` 分裂 live kernel

### 不要把 Host 对其它 dtype 的 10001 fallback 写成支持合同

### 不要把内部 `softmaxLse` 当成用户可见输出

### 不要把 arch22 / `SasaInferIntfRegularArch22` 当本卡路径

---

## Applicable Scenarios

参考本 Case，当：

- 要在 950 上实现或阅读 **block-sparse + paged KV** 的主注意力
- 需要理解 **selected pages 上的 online softmax / rescale-O**，而不是又一个 Cube GEMM
- 需要把 GQA 映射成 `(qToken, kvHead)` task

不要参考本 Case，当：

- 要学 Cube pingpong / MN tiling → [43](../../gemm/ascend950-basic-matmul/case.md)
- 要学 MX GEMM → [53](../../gemm/ascend950-fp8-mx-matmul/case.md)
- 要学 EP / fused MoE → 读冻结的 A–D，不要从本卡倒回去
- 要学 indexer / MLA 怎么产 `select_idx`（还不是本仓的 950 Case）
- 要学 FA pipeline 共性（跨 tile online-softmax、normalization-aware O merge、logical→physical `block_table`）→ [FA Knowledge](../../../../../../knowledge/cam/engineering/fa-pipeline-online-softmax-and-paged.md)；49/FIA **不是** Sparse alternative

---

## Related Cases

| | 关系 |
| --- | --- |
| [43 Basic Matmul](../../gemm/ascend950-basic-matmul/case.md) | Cube tiles 在注意力里出现；**不是**本卡要教的 MN GEMM |
| CATLASS 49 / ops-transformer FIA | FA-pipeline **peers**（KV-domain 不同）；**不开** 49/FIA Case |
| [FA pipeline Knowledge](../../../../../../knowledge/cam/engineering/fa-pipeline-online-softmax-and-paged.md) | 跨 tile online-softmax + O-merge invariant + logical→physical `block_table`；**不含** `select_idx`；**不含** FIA 独立 rescale-O |
| A–D MoE | unrelated family |


---

## Source

| Field | Value |
| --- | --- |
| repository | sgl-project/sgl-kernel-npu |
| remote | `https://github.com/sgl-project/sgl-kernel-npu.git` |
| scanned fork commit | `8d76a8da75315ae9add5cfd2458b8028289f1ada` |
| verified upstream | `sgl-project/sgl-kernel-npu` `main` @ `ee334193e5278d7b3a64afcc2e3ee5243133c4a0` |
| official remote | `https://github.com/sgl-project/sgl-kernel-npu.git` |
| hardware | ascend950 |
| op | `torch.ops.npu.npu_sparse_attention_score` |
| live kernel | `csrc/sparse_attention_score/op_kernel/arch35/sparse_attention_score_kernel_arch35.h` |
| live QK Block | `csrc/sparse_attention_score/op_kernel/attn_infra/gemm/block/block_mmad_qk_arch35_ABf16_C_to_UB.hpp` |
| host tiling | `csrc/sparse_attention_score/op_host/tiling/sparse_attention_score_tiling.cpp` |
| status | accepted |
| license | MIT |
