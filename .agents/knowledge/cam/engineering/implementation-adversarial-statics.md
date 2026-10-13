# Implementation adversarial statics

status: **accepted**（Gate B 静态攻击原则。不是某个算子的实现配方。）

Gate A / PAC 问的是「正确设计还会怎么被性能工程师推翻」。
本页问下一层：**假定实现忠实于 Design，实际语句仍可能怎样违例。**

对应 [cam-operator-development Gate B.5](../../../skills/cam/operator/cam-operator-development/SKILL.md) 与 PBC **Implementation Adversarial Challenge**。

证据种类：`recommendation`。本文 **没有** `benchmark`。

---

## 1. Buffer overlay legality

```text
Lifetime compatibility is necessary but not sufficient for overlay legality.

Buffer overlay legality
  =
  lifetime non-overlap
  + max-footprint closure
  + alignment legality
  + leftover identity（下一发不得把 handshake leftover 认成 ready）
```

同一物理 region 跨 phase 复用时，支持域由 **所有 phase 的最大 footprint** 决定，不是由「先用的那个 phase」的尺寸决定。

```text
allocated_extent
  >=
  max(all phase-specific footprints)
```

必须覆盖整个 Host-admitted domain。lifetime 完全不重叠，仍可能因某一 phase 的 footprint 大于分配而越界。

同一次 launch 内 lifetime 不重叠，仍可能在 **下一发** 假就绪。handshake / 完成字若叠在后级会写的 payload 上、或不 consume / 不双 bank / 不在 waiter 采样前清平面，下一发会把 leftover 比特（上一发 flag，或 Combine 一类后级激活）认成 ready。见 §8。

Host support domain 不能只从顶层条件推（整除、`K>=1`、UB 总和不超过预算）。
必须从每一个实际物理不等式反推，再求交集：

```text
Host admissible domain
  =
  semantic domain
  ∩ API domain
  ∩ physical-layout domain
  ∩ temporary-footprint domain
```

---

## 2. Complexity through callsites

```text
Traversal intent ≠ traversal complexity.

Complexity must be reconstructed through callsites,
not assigned to logical phases.
```

对每条 hot-path callsite，沿完整可达 helper 链相乘：

```text
outer loop
  × called helper
  × helper nested loop
  × helper-of-helper
  = actual path complexity
```

O(B) helper 被放进 O(R·E) caller 循环，实际路径是 O(R·E·B)，
与 caller 的名义算法标签无关。不得只给 `ProcessP*` 主体贴一个复杂度标签。

---

## 3. Visibility still requires a proof

```text
Same-core / same-AIV ownership removes some synchronization needs,
but never removes the requirement to prove producer-consumer visibility.
```

每一条跨执行机制或跨 phase 的 producer→consumer 边都要有
visibility / completion 证明，不论存储是 ABI 输出、workspace 还是 symmetric memory。

```text
producer mechanism
    ↓
physical storage
    ↓
completion / cache visibility
    ↓
consumer mechanism
```

同一 AIV 消费自己的 slice、两端都是 SIMT、对象是 ABI tensor，
都不能从「ownership 已划分」推出「无需证明」。
可以证明这条边不需要跨核 SyncAll；不能省略「必须分类 / 必须证明」。

---

## 和已有门的边界

| 问题 | 走 |
| --- | --- |
| Design 会不会被更强通信 / 并行方案推翻 | Gate A PAC |
| 实现语句会不会在 helper / reuse / phase 交接上违例 | **本页**；Gate B.5 |
| 跨 rank 传充分统计还是可重构全表 | [sufficient-state](communicate-sufficient-state.md) |
| HardEvent 类型 / Set-Wait 成对 | PBC Event protocol |
| 同一次 launch 完成字没发出去 | [pipeline](../synchronization/pipeline-events-and-ordering.md)  |
| 下一发把 leftover 认成 ready | **§8**； |

禁止把本页写成「必须某种 barrier / 禁止 overlay」。
要求的是 **负向搜索**：在宣称 Static PASS 之前，主动找上述违例。

---

## 4. Worker-space before partition math

```text
physical launch index
  ≠
logical worker identity
```

remainder / cover 证明若建立在错误的 worker-space 上，数学自洽仍是 FAIL。
Gate B 必须从 actual `GetBlockIdx` / subblock / engine role 重建 logical ID。
见 PBC **Logical Worker Topology Gate**。

---

## 5. Integer expressions beyond multiply

只搜 `token * H` 不够。必须覆盖 negation、INT_MIN、sentinel decode、
ceil-div、narrowing、shift domain。support-domain 不可达必须显式证明。
见 PBC **Integer Arithmetic Audit**。

---

## 6. Incomplete traceability is a fail mode

有 Frozen-Clause 表但漏抽 normative clause，然后全 MATCH + PASS，
等于没有 traceability。coverage 本身要审计：extracted == closed。

---

## 7. Extra synchronization is not free correctness

后续更强 primitive 已关闭同一 completion 时，「再加一道更保险」不是 justification。
标 review；不要自动删除。见 PBC **Synchronization minimality**。

## 8. Handshake leftover across launches

```text
one-launch lifetime non-overlap
  ≠
cross-launch leftover-safe overlay

handshake / completion word
  ≠
payload a later phase of the same kernel will smash

published one-shot flag
  ≠
consumed, bank-flipped, or zeroed before the next launch samples it

value in this launch's ready window
  ≠
identity of this launch's publish
```

新 remote one-shot flag 在宣称 Static PASS 之前必须能回答：

- 发布之后，字有没有 **consume-and-clear**、**dataState / 双 bank**，或在下一发 waiter **采样前**显式清平面？
- 同 kernel **后级**会不会写同一物理字节（典型：完成字 overlay 在 Combine / 输出窗）？
- leftover 编码会不会掉进下一发的 ready 窗（例如 FP32 `1.0`/`2.0` ± 0.5）？
- waiter 若在 ready 时推进 ordinal：假就绪会不会 **跳过真 primary**，使 `remaining` / expected 永远到不了？
- dest 仍按 **plan count** 等待时，publisher 会不会 cap 超了就静默 `return`？

```text
第一发 PASS
  ≠
flag 协议 leftover-safe

假就绪 + 跳过真 ordinal
  →
waiter remaining 收不齐（看起来像“flag 协议 hang”）
```

不要先改 Classify、加更多 remote flag。先证 **下一发看到的字只能是这一发的 publish**。

不规定必须 per-token flag、必须双 bank、或禁止 scratch overlay。缺的是 **handshake 身份在跨 launch 上唯一**。

。同一次 launch 的源 UB 被踩走 。

---

| Related | [cam-operator-development Gate B](../../../skills/cam/operator/cam-operator-development/SKILL.md)、[PBC Implementation Adversarial Challenge](../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md)、[sufficient-state](communicate-sufficient-state.md)、[golden-delta-review](golden-delta-review.md)、[fusion materialization](moe-fusion-materialization-and-sync.md) |
