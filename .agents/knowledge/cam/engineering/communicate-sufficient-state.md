# Communicate sufficient state

status: **accepted**（**核心 distributed-design principle**。不是某个算子的通信配方。）

一次独立 fused-operator 实现已经回归验证：Agent 的第一版跨 rank 架构走的是
sufficient-state exchange + producer-side compact，而不是把可重构全表
（如 `dst` / `topk` 一类）再 all-gather。规则改变了第一次写出来的通信结构，
不只是「写进 Skill 后看起来有道理」。

跨 rank / 跨核 materialization 时，先问 **consumer 真正需要的语义状态**，再问传输哪块 tensor。不要先问“生成这个结果时手头有什么，就原样发出去”。

本文是 **充分统计 / 可重构状态** 的索引。不绑定某个 routing / KV / all-to-all 实现。live 压缩与融合 handoff 仍读 [fusion materialization](moe-fusion-materialization-and-sync.md)。

证据种类：`recommendation`。本文 **没有** `benchmark`。

对应 PAC-1 / PAC-2 / PAC-5。

---

## 先问什么

```text
1. Over-materialization
   Is any tensor communicated/materialized only because it can later
   reconstruct the actual consumer state?

2. Sufficient-state communication
   Can producer-side transformation reduce cross-rank bytes, replicated
   workspace, remote scans, or synchronization?

3. Communication envelope
   Compare bytes/rank, total bytes, remote operations, barriers,
   replicated state, and asymptotic scaling — on this operator's
   critical path.
```

不要先问“这块数据后面还用不用”。问的是 **下游能不能从更小的 payload 重构它需要的东西**。

---

## Graph

```text
producer-local raw state
        │
        ├─ reconstructible by consumer from a smaller payload
        │     → over-materialization unless envelope proves otherwise
        │
        └─ minimum sufficient state for the consumer
              → 这才是通信 / GM handoff 的候选
```

```text
needed by a later reconstruction
  ≠
must be transferred as-is

cheapest to generate locally
  ≠
cheapest to communicate

correct and affordable
  ≠
best justified production baseline
```

---

## 和已有门的边界

| 问题 | 走 |
| --- | --- |
| 单 kernel / 单 tile 内中间结果住 UB 还是 GM | PBC P2 |
| 融合后 API-visible tensor 删/搬/换角色 | [fusion materialization](moe-fusion-materialization-and-sync.md) |
| 跨 rank 传的是原始状态还是充分统计 | **本页**；Gate A 后 [PAC-1/2/5](../../../skills/cam/operator/cam-operator-development/SKILL.md) |
| 实现是否忠实于该通信选择 | [adversarial statics](implementation-adversarial-statics.md)；Gate B.5 |

不得用「相对另一个更大算子的 payload 很小」证明本算子的通信选择。比较必须落在 **本算子 critical path** 的 bytes/rank、rescans、workspace、barriers。

```text
dest-side reconstruct / Quant that sits on the waiter gating Cube
  ≠
free (bytes saved on the wire)
```

把 producer 侧可重叠的 materialization 挪到 **挡住 Cube 开工的 recv waiter** 上，链路字节减少通常盖不住关键路径变长。这是 envelope 比较，不是禁止 dest reconstruct。

---

## 禁止写成配方

```text
必须 all-gather 原始表
必须 source-side compact inbox
必须某种 done-flag 协议
```

这些都是 **candidate**，不是本页合同。PAC 要求把它们放进 communication envelope 再 freeze。L1 可以接受较简单、物理闭合的方案，但必须写明被挑战过的渐近项，以及 L2 候选是什么（PAC-7）。

| Related | [fusion materialization](moe-fusion-materialization-and-sync.md)、[cam-operator-development PAC](../../../skills/cam/operator/cam-operator-development/SKILL.md)、[PBC Sufficient-State](../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md)、[adversarial statics](implementation-adversarial-statics.md) |
