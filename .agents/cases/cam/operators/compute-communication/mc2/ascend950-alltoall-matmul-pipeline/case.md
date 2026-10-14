# Case Card: ops-transformer Ascend950 AllToAll ↔ Matmul Pipeline

本 Case 教的是 **三阶段 pipeline**（AllToAll / AIV rank-block permute / ASW Cube），不是 `allto_all_matmul` 算子说明书，也不是 43，也不是 [RS Case](../ascend950-matmul-native-reduce-scatter/case.md) 换了个 collective 名。

Canonical live instance：**fp16/bf16 / `AlltoAllMatmulPipeLine` / WAIT_ONE**（`AICSync=false`, `SendCnt=0`, `RecvCnt=1`）。  

`status: accepted`。content_review passed 2026-08-21。  
**upstream identity verify 不是本卡 accepted gate**（与 MoE A–D / RS Case 相同：SoT 是 scanned fork `9311b63bcd065b9779eb08a7d634e9463ee41ef1`；`cann/ops-transformer` 未 fetch）。

MC2 coupling 读 [Knowledge](../../../../../../knowledge/cam/engineering/mc2-compute-collective-coupling.md)（`accepted`）。MM→A2A 是同栈 reverse sibling，不开第二张卡。AR 是 M1 member，不开 AR Case。M3 不读。

本卡 **技术内容冻结**：不要回改 canonical / Commit-Wait / permute / MM→A2A contrast。

本卡 pinned 的 fp16/bf16 950 path 中，AllToAll job 对应 live `Hccl::AlltoAll` primitive；未观察到 RS 那种 job 与底层 collective mechanism 分叉。`job ≠ mechanism` 仍是普适纪律，这次二者碰巧对齐。`X2TRANSPOSE` **不是** AIV permute。

---

## What

每个 rank 把本卡 `x1` shard 做 AllToAll，AIV 把 recv 排成 Cube 要的 A，再和 `x2` 做 Matmul，得到 `y`。

```text
API x1 shard
        ↓ AlltoAll<false> Prepare；PrepareAll 里 Commit 全部   // progress，不是 Wait
workspace comm recv
        ↓ AIV0 Wait(i)                                      // consumer gate
        ↓ AIV rank-block permute
        ↓ flag 8 drain MTE3 → flag 9
        ↓ AIC WaitFlag 9
Cube ASW  MM → API y
```

有效引擎：**AIV + Cube + HCCL**。`KERNEL_TYPE_MIX_AIC_1_2`。通信控制核是 **AIV 0**，不是 AIC。不是 EP window，不是 43 的 MN pingpong 课，不是 M1 的 AIC 直接 `Hccl::*`。

---

## Why This Case

相对已 accepted 的 RS Case / 冻结 GEMM：

1. **三阶段**：comm、AIV layout permute、Cube。M1 没有 permute 阶段。
2. 通信控制在 **AIV 0**（`HcclCommunicator`，`AICSync=false`）。
3. **Commit = communication progress；Wait = completion / consumer gate。Commit ≠ cross-rank visibility。**
4. **compute baseline = 43**；本卡不重教 MN pingpong。
5. 两 op 同一套栈、顺序相反；不要各开一张卡。

---

## Canonical instance

| Field | Value |
| --- | --- |
| hardware | ascend950（`DAV_3510`） |
| dtype | **fp16 或 bf16** |
| op | **`allto_all_matmul`** |
| pipeline | **`AlltoAllMatmulPipeLine`** |
| communicator | `HcclCommunicator` `AICSync=false` `SendCnt=0` `RecvCnt=1` → **WAIT_ONE** |
| primitive | `AlltoAll<false>` + `Commit` / `Wait` |
| `QUANTMODE` | `NON_QUANT_MODE` |
| `COMMTYPE` | CCU 或 AICPU（Host 默认 `comm_mode=ai_cpu`） |
| task_type | mix |
| engines | vector, cube, communication |
| Cube | `mc2_fp_matmul.h` → `Mc2MatmulAswKernel` |
| permute | `MC2VecTranspose`（AIV） |
| Host 配置串 | `AlltoAll=level0:fullmesh;level1:pairwise` |

Sibling（同卡，不要另开）：fp16/bf16；**`matmul_allto_all` SEND_ONE**（反序）。  
**不是 sibling：** KC / MX / `ProcessKC` / arch22。

---

## 1. Live variant 必须 pin

```text
ORIG_DTYPE_X1 == ORIG_DTYPE_X2 == fp16|bf16
QUANTMODE == NON_QUANT_MODE
→ AlltoAllMatmulPipeLine
```

Agent trap：

- `X2TRANSPOSE` = Cube **B** 是否转置，**不是** AIV permute。
- `withReduceType(SUM)` 是 builder API，**不是** AllReduce。
- 默认 `ai_cpu` **仍是** 950 live（AICPU engine）。

`--cce-auto-sync=off` 是编译条件，不是 sync 原语。

---

## 2. Chunk / task coordinate

Host formulaic 切 **M**：`tileCnt` + 可选 `tailCnt`。A2A→MM 通信内轴是 **K**。  
Kernel 一个 `taskIndex` = 这一 M-chunk 上的 **一整轮** AllToAll / permute / MM。

这不是 66/68 的 K 切分，也不是 M1 “AIC 上一次 ReduceScatter、没有 AIV permute”。  
`MAX_HCCL_HANDLE_ = 63`。`tileCnt > 63` 是否被挡住：**未证明**。

---

## 3. Commit vs Wait（必须会）

| API | 语义 |
| --- | --- |
| `Prepare` `AlltoAll<false>` | 交出 handle，**还没** launch |
| `Commit` | **communication progress**：启动该 handle 的搬运 |
| `Wait` | **completion / consumer gate**：下一段可以读这块 |

**Commit ≠ cross-rank visibility。** 远端结果对消费者合法的点是 Wait。

WAIT_ONE（本卡）：`PrepareAll` 里 **Commit 全部**，循环里 **Wait(i)** 再 permute。  
Pipeline **permits** 后续 task 的搬运与当前 permute/MM 重叠；**不要**写成已测到的 overlap。

---

## 4. Timeline：producer AllToAll，consumer permute → Cube

```text
Init:  AIC/AIV 都 InitV2 + SetCcTilingV2
       notifyFlag 只在 AIV 0（Prepare/Process/End）

PrepareAll(taskCnt)                 // AIV0：Commit 全部 = progress

for i:
  AIV:  Wait(i) → SyncAll → permute → flag 8（MTE3 drain）→ flag 9
  AIC:  WaitFlag 9 → ASW MM(i)

End: Finalize
```

matmul **内核**不消费 flag 8/9。8/9 是 pipeline 外壳的 AIC↔AIV。

---

## 5. Buffer ownership

| 角色 | 缓冲 |
| --- | --- |
| AlltoAll send | API `x1` |
| AlltoAll recv | workspace `commOut`（`commLen`） |
| permute dst / Cube A | `all2all_out`；空则 workspace `commOut + commLen` |
| Cube B / C | API `x2` / `y` |

中间 permute 缓冲不是下一张 API tensor（除非用户给了 `all2all_out`）。

---

## 6. Same-device vs consumer gate

| | 本卡 |
| --- | --- |
| same-device AIC↔AIV | flag **9**（8 = 本侧 pipe drain） |
| same-device AIV↔AIV | `SyncAll<true>` |
| communication progress | `Commit`（AIV 0） |
| consumer gate | `Wait`（AIV 0） |
| 编译条件 | `--cce-auto-sync=off` **不是** sync |

Flag 8/9 ≠ 远端可见。Commit ≠ 远端可见。

AIV permute 是 **rank-block layout permute**（`nextSrc/DstBlockOffset` + `innerOffsetIn/Out`），不是 `transpose_x2`。

---

## Reverse sibling：MM → permute → A2A（不开 Case）

`matmul_allto_all` / `MatmulAlltoAllPipeLine::ProcessDefault`：`SendCnt=1` `RecvCnt=0` → **SEND_ONE**。

```text
PrepareAll：只填 handle
AIC: MM → flag 8 FIX drain → flag 9
AIV: WaitFlag 9 → permute → SyncAll → Commit(i)   // progress
End: Wait leftover                                 // consumer gate
```

Cube C 在 workspace；permute 后当 AlltoAll send；API `y` 是 recv。  
Pipeline **makes overlap eligible**（当前 send vs 下一块 MM）。不要写成已测 overlap。  
**不要**读 `ProcessKC`。

---

## Parallel Strategy

| 层级 | 本例 |
| --- | --- |
| 多卡 | AllToAll；按 `taskIndex` 切 M |
| 核间 Cube | ASW 切 MN（**compute baseline = 43**，不重教） |
| 核间 AIV | permute 切块；Commit/Wait 只有 AIV 0 |
| pipeline | WAIT_ONE：Wait(i) 之后才 permute/MM；Commit 已在循环前做完 |

---

## Memory Strategy

角色，不是容量规划。

| 区 | 用途 |
| --- | --- |
| GM API | `x1` send、`x2`、`y`；可选 `all2all_out` |
| GM workspace | AlltoAll recv；无 `all2all_out` 时还有 permute dst |
| UB | AIV permute |
| L1/L0 | ASW Cube；**compute baseline = 43**，不要在本卡重算 |

---

## Variants

同一张卡：fp16 / bf16；MM→A2A reverse。

不要开第二张卡：

| 东西 | 原因 |
| --- | --- |
| `matmul_allto_all` | 同栈反序 |
| KC / MX / `ProcessKC` | 另一套量化 pipeline |
| arch22 | 非本卡 950 SoT |
| RS / AG | **M1**；读 [RS Case](../ascend950-matmul-native-reduce-scatter/case.md) |
| AR / M3 | 不读 |

---

## What Agent Should Learn

1. 教学是 **A2A + AIV permute + Cube 三阶段**，不是 GEMM，不是 EP，不是 M1 换名。
2. 通信控制核是 **AIV 0**。
3. **Commit = progress；Wait = consumer gate；Commit ≠ visibility。**
4. AIV permute ≠ `X2TRANSPOSE`。
5. flag 8/9 是 AIC↔AIV；跨 rank 的消费者门是 `Wait`。
6. pipeline **permits** overlap；不要写成 benchmark。
7. MM→A2A 是 reverse sibling，不是第二张 Case。

---

## What NOT To Copy

### 不要把本卡写成 M1 / RS 换了 AllToAll

### 不要把 Commit 当成 cross-rank visibility

### 不要把 `X2TRANSPOSE` 当成 AIV permute

### 不要把内部 ASW 开成 43 / 66 / 68

### 不要把 flag 8/9 / `--cce-auto-sync=off` 写成跨 rank

### 不要为 MM→A2A 再开一张卡

### 不要写成 Case B 的 MTE window

### 不要抽 MC2 Knowledge / 不要读 AR / M3

### 不要把 “permits overlap” 写成已测 overlap

---

## Applicable Scenarios

参考本 Case，当：

- 要在 950 上读 **AllToAll 与 Matmul 中间还有 AIV layout permute**
- 要分清 `HcclCommunicator` 的 **Commit vs Wait**
- 要分清 AIC↔AIV flag 和 consumer-gate Wait

不要参考本 Case，当：

- 要学 Cube pingpong / MN tiling → [43](../../../compute/gemm/ascend950-basic-matmul/case.md)
- 要学 M1 chunked MM→native RS → [RS](../ascend950-matmul-native-reduce-scatter/case.md)
- 要学 EP routing / window → [B](../../moe/ascend950-moe-ep-dispatch-combine/case.md)
- 要学融合 visibility 分类 → [Layer 2](../../../../../../knowledge/cam/engineering/moe-fusion-materialization-and-sync.md)（引用，不要把 MC2 并进去）
- 要判断下一种 MC2 的 ownership / progress / visibility → [MC2 Knowledge](../../../../../../knowledge/cam/engineering/mc2-compute-collective-coupling.md)

---

## Related Cases

| | 关系 |
| --- | --- |
| [RS native](../ascend950-matmul-native-reduce-scatter/case.md) | **M1 mechanism contrast**；AIC 直接 `Hccl::*`，无 AIV permute |
| [43 Basic Matmul](../../../compute/gemm/ascend950-basic-matmul/case.md) | **compute baseline = 43** |
| [B EP dispatch/combine](../../moe/ascend950-moe-ep-dispatch-combine/case.md) | 都有通信；**family 不同** |
| MM→A2A | reverse sibling；**不开 Case** |
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
| op | `allto_all_matmul` |
| live entry | `mc2/allto_all_matmul/op_kernel/arch35/allto_all_matmul_apt.cpp` |
| live pipeline | `mc2/allto_all_matmul/op_kernel/allto_all_matmul_pipeline.h` |
| communicator | `mc2/common/op_kernel/mc2_templates/communication/communicator/hccl_communicator.h` |
| host tiling | `mc2/allto_all_matmul/op_host/op_tiling/arch35/allto_all_fp_matmul_tiling_base.cpp` |
| status | accepted |
| accepted gate: content review | **passed**（2026-08-21） |
| accepted gate: upstream verify | **不是 gate**。SoT = scanned fork；与 MoE A–D / RS Case 相同 |
| license | CANN-OSLA-2.0 |
