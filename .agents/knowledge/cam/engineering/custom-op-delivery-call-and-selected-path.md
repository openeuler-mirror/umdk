# Delivery ≠ Call ≠ Selected Path

Agent 看到 wheel 里有 custom OPP、看到 `_C_ascend`、看到 `enable_custom_op()`，容易把三件事压成一步。不要。

本文是 **framework–算子集成边界** 索引，不是某个 op 的说明书，也不是 Indexer / MoE / MC2 Case。**不开** `cases/cam/operators/compute/`。P3 **FREEZE**。P1 indexer canonical 仍暂停，不要用本文去填那张卡。

证据种类：`source-code`（vLLM-ascend close-read）。本文件 **没有** `benchmark`。

可以 **引用** P2 的 API-contract 纪律。**不要**把本文并进 FA / MoE / MC2 Knowledge：教的是 implementation selection，不是 kernel mechanism。

---

## Rule

```text
Build / delivery artifacts
    ≠
Python call surface
    ≠
selected runtime path

artifact presence
    ≠  call selection
Python call
    ≠  kernel identity
load gate
    ≠  build availability
independent delivery artifacts
    ≠  mutually exclusive runtime branches
composition-capable
    ≠  runtime composition observed
```

先分开问三层，再问它们 **能不能** compose。不要把源码上的 composition-capable 写成 runtime 已经 observed。不要先画一条链，也不要先画互斥两叉。

证据状态不能互换：`built` / `called` / `bound` / `dispatched` / `resolved` / `observed`。一句 “这个 op 支持 A5” 不要把五层压扁。

```text
built       artifact 在 wheel / OPP 中存在
called      Python path 调用了某 namespace
bound       TORCH_LIBRARY / binding 映射到 C++ wrapper
dispatched  wrapper 发起 ACLNN / other runtime dispatch
resolved    runtime 已确认落到具体 kernel artifact
observed    目标设备实际运行证据
```

---

## 先问什么

```text
1. 这个 binary / OPP 是从哪条 Build / delivery artifact 来的？
2. Python 实际 call 的是哪个 namespace / 哪个 adaptor 分支？
3. runtime 选中的 path 是哪一条？
   binding → ACLNN dispatch → delivered kernel
   还是 vendor torch_npu
   还是 unresolved
   不要用 1 或 2 自动填 3。
4. 源码上 composition-capable 吗？runtime composition / OPP resolution 是否 observed？
```

不要先问“这是不是 custom op”。

---

## Graph

```text
                   Build / delivery artifacts
             ┌──────────────┴──────────────┐
             │                             │
      vendor ACLNN OPP              torch extension .so
       (_cann_ops_custom)             (vllm_ascend_C)
             │                             │
             └────── may compose ──────────┘
                           ↓

                   Python call surface
             torch_npu.* / _C_ascend.* / ...


                           ↓

                selected runtime path
       binding → ACLNN dispatch → delivered kernel
       or vendor torch_npu implementation
       or unresolved
```

different artifacts ≠ mutually exclusive branches。  
源码结构可以让一次 path 只用其中一个，也可以让两者共同参与。**composition-capable ≠ runtime composition observed。**

`_C_ascend` 完全可能只是 wrapper：继续 `EXEC_NPU_CMD(aclnn...)`，再靠 runtime OPP resolution 解析另一个 artifact。看到 `_C_ascend` **不要**自动当成 in-tree AscendC kernel body。

---

## 1 — 三层分别问

```text
delivery
    ≠ call
call
    ≠ selected implementation
```

`DeviceOperator` / `A5DeviceAdaptor` 选的是 **Python call**（层 2），不是 kernel identity（层 3）。

反例：同一语义 indexer job，SFA A5 走 `torch_npu.npu_lightning_indexer*`，DSA 走 `_C_ascend.npu_vllm_quant_lightning_indexer`。不要写成一个全局 “A5 indexer”。

---

## 2 — artifact presence ≠ call selection

A5 ACLNN list 有 `vllm_quant_lightning_indexer`，**推不出** SFA 用它。SFA 的实际 Python call 是 `torch_npu.npu_lightning_indexer*`。

A5 list **没有** `sparse_attention_score`，MiniMax 仍然 **call** `_C_ascend.npu_sparse_attention_score`。那是层 2，不是 “A5 ACLNN built it”。

GMM SwiGLU：`csrc/gmm/...` 作为 delivery 存在，A5 默认 call 仍是 `torch_npu.npu_grouped_matmul_swiglu_quant_v2`。

---

## 3 — Python call ≠ kernel identity

```text
API / Python contract aligned
    ≠  kernel mechanism identity proved
```

P2 已经用过这条（`MoECommType.MC2` dispatch/combine = contract alternative，不是 MTE dest-push 再证一遍）。本文把它收成 framework 通例。

`_C_ascend.npu_vllm_quant_lightning_indexer` 钉住的是 **binding → ACLNN dispatch**。最终 kernel identity 还取决于 ACLNN/OPP resolution。不要把 binding 和 kernel 压成 “in-tree ACLNN”。

---

## 4 — load gate ≠ build availability

`enable_custom_op()==False` on A5 只跳过 generic `import vllm_ascend.vllm_ascend_C`。

它 **不等于**：

- artifact 没构建（`build_aclnn.sh` / CMake 仍可产出 OPP 和 `.so`）
- 所有其他 import path 都不存在（serving `camem.py` 仍可能 try-import `.so`）
- “950 没有这些 kernel”

vendor OPP **不**注册 `torch.ops._C_ascend`。

---

## 5 — delivery artifacts may compose

源码结构证明两个 delivery artifact **可以** compose，而不是 XOR。当前 DSA A5 runtime 是否实际完成这次 composition **仍未验证**。

```text
composition-capable
    ≠  runtime composition observed
```

已钉死的 binding / dispatch chain（`source-code`）：

```text
vllm_ascend_C
    ↓ TORCH_LIBRARY
_C_ascend.npu_vllm_quant_lightning_indexer
    ↓ torch_binding.cpp
EXEC_NPU_CMD(aclnnVllmQuantLightningIndexer)
    ↓
ACLNN dispatch
```

delivery composition **candidate**（OPP resolve **unresolved** without runtime evidence）：

```text
ACLNN dispatch
    ↓ runtime OPP resolution
ASCEND_CUSTOM_OPP_PATH may expose
_cann_ops_custom / vendor OPP
    ↓
selected kernel
```

`.so` 是否在目标 A5 加载、ACLNN 最终 resolve 到哪份 implementation：P1 canonical gate 仍 pending。不要把上半段 dispatched 写成下半段 resolved / observed。

---

## Worked examples（不要升级成 Case）

| 现象 | 读成 | 不要读成 |
| --- | --- | --- |
| A5 ACLNN list 有 `vllm_quant_lightning_indexer` | delivery artifact 在 | SFA 调用了它 |
| SFA `torch_npu.npu_lightning_indexer*` | Python call | 与 in-tree ACLNN indexer 同一 kernel |
| DSA `_C_ascend.npu_vllm_quant_lightning_indexer` | bound + dispatched（源码） | A5 已 resolve 到这份 `_cann_ops_custom` / kernel body 在 `.so` 里 |
| MiniMax `_C_ascend.npu_sparse_attention_score` | 层 2 call | A5 ACLNN 构建了该 op |
| `enable_custom_op()` A5=False | 跳过 generic import | artifact 不存在 / 无任何 `.so` 加载 |
| GMM `csrc/` 与 A5 `torch_npu` v2 并存 | 两层分开 | A5 跑了 in-tree GMM |

---

## Related

| 角色 | 文件 |
| --- | --- |

不要并进 Sparse Case / Indexer Case / MoE Cases。不要重开 P1 canonical `.so` probe。

---

## Sources

| Field | Value |
| --- | --- |
| repository | vllm-project/vllm-ascend |
| remote | `https://github.com/vllm-project/vllm-ascend.git` |
| commit | `d8268faea90dd9b999a0a82f6d133751d57b5770` |
| delivery | `csrc/build_aclnn.sh` · `setup.py` / CMake · `vllm_ascend/_cann_ops_custom` |
| binding hop | `csrc/torch_binding.cpp` `EXEC_NPU_CMD(aclnnVllmQuantLightningIndexer)` |
| load gate | `enable_custom_op()` A5 False；`camem.py` try-import |
| Last verified | 2026-08-21 |
