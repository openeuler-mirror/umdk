# Cases

`cases/` 是 **机制样例**，不是模板复制源。`metadata.yaml` 里的 `accepted` / `reviewed` **都是 live teaching**；只有 `under-review` 不是。

下面只回答：什么时候读、什么时候不要读。

## Task views

Case 仍按计算/通信机制存放，不按生命周期复制。所有当前 Case 的
`metadata.yaml` 都标注 `lifecycle: [development, optimization]`：

- Development：用 Case 比较数据流、切分、流水和集成模式；不得整份复制。
- Optimization：用 Case 提出候选机制，再用本算子的测量验证。
- Debugging：当前没有独立调试 Case；结果错、hang 或通信失败应先走
  `cam-operator-debug`，只在假说需要机制对照时读取相关 Case。

## GEMM

| Case | 什么时候读 | 不要读成 |
| --- | --- | --- |
| [Basic Matmul](operators/compute/gemm/ascend950-basic-matmul/case.md) | 950 Cube pingpong 数据路径 | 普通 Vector 的 tile 常数 |
| [StreamK](operators/compute/gemm/ascend950-streamk-matmul/case.md) | 核不够时 remainder MN tiles 的二阶段 | 所有大 K 都 StreamK |
| [SplitK](operators/compute/gemm/ascend950-multi-core-splitk-matmul/case.md) | 核间切 K | Vector reduce 也切 K |
| [FullLoadA](operators/compute/gemm/ascend950-matmul-full-loadA/case.md) | full-K A load + 跨 N 复用 | “L1 resident A” 口号 |
| [MXFP8](operators/compute/gemm/ascend950-fp8-mx-matmul/case.md) | MX 量化 MatMul 路径 | 所有 FP8 都走 MX |

索引：[GEMM K-partition](../../knowledge/cam/engineering/gemm-k-partition-strategies.md)

## Grouped GEMM / MoE compute

| Case | 什么时候读 | 不要读成 |
| --- | --- | --- |
| [GMM Slice-M](operators/compute/grouped-gemm/ascend950-grouped-matmul-slice-m/case.md) | group 维跟着 M 走；prefix-sum 减法 | 普通 Add 需要 `groupList` |
| [GMM+SwiGLU+MX](operators/compute/grouped-gemm/ascend950-gmm-swiglu-mx-quant/case.md) | 专家 GMM1 融合 + 谁生产 groupList | 又一张基础 GEMM |

## MoE

| Case | 什么时候读 | 不要读成 |
| --- | --- | --- |
| [Local permutation](operators/compute/moe/ascend950-moe-local-permutation/case.md) | 单卡 token↔expert 行重排 | EP 通信协议 |
| [EP Dispatch/Combine](operators/compute-communication/moe/ascend950-moe-ep-dispatch-combine/case.md) | EP loop、window、post-EP nums | 融合后仍有同样的 API-visible handoff |
| [MegaMoe fused EP+FFN](operators/compute-communication/moe/ascend950-mega-moe-fused-ep-ffn/case.md) | 哪些 GM handoff 被 deleted/relocated | 把 split 契约写回融合核 |

契约：[token-expert-rank](../../knowledge/cam/engineering/moe-token-expert-rank-data-contracts.md)、[materialization](../../knowledge/cam/engineering/moe-fusion-materialization-and-sync.md)、[sufficient-state](../../knowledge/cam/engineering/communicate-sufficient-state.md)

## Attention

| Case | 什么时候读 | 不要读成 |
| --- | --- | --- |
| [Block-sparse paged FA](operators/compute/attention/ascend950-block-sparse-paged-attention/case.md) | `select_idx` 驱动的 page selection | 所有 FA 都有这套 selection |

流水：[FA pipeline](../../knowledge/cam/engineering/fa-pipeline-online-softmax-and-paged.md)

## MC2

| Case | 什么时候读 | 不要读成 |
| --- | --- | --- |
| [Matmul → ReduceScatter](operators/compute-communication/mc2/ascend950-matmul-native-reduce-scatter/case.md) | 通算耦合、compute 与 collective 的 visibility | 普通 Vector 也先走卡间 |
| [AllToAll → Matmul](operators/compute-communication/mc2/ascend950-alltoall-matmul-pipeline/case.md) | A2A 与 MM 的 overlap 形态 | 和 MoE window 是同一套协议 |

索引：[MC2 coupling](../../knowledge/cam/engineering/mc2-compute-collective-coupling.md)
