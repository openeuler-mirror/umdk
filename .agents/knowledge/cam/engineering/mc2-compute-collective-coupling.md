# MC2 Compute–Collective Coupling：Chunk Ownership、Progress 与 Visibility

Agent 接到 950 上 **Matmul × collective** 时，先问 **chunk 归谁、哪条是 progress、哪条是 visibility、中间有没有独立 transform**，再问算子名。不要先问“这是 AG、RS、AR 还是 A2A”。

本文是 **MC2 coupling** 索引，不是 [RS Case](../../../cases/cam/operators/compute-communication/mc2/ascend950-matmul-native-reduce-scatter/case.md) 扩写，也不是 [M2 Case](../../../cases/cam/operators/compute-communication/mc2/ascend950-alltoall-matmul-pipeline/case.md) 说明书。**不开** AG Case，**不开** AR Case。M3 不在本文。

证据种类：`source-code`（Case / close-read / verdict）。本文 **没有** `benchmark`。

可以 **引用** [Layer 2](moe-fusion-materialization-and-sync.md) 的 visibility 纪律（换原语，不删语义）。**不要**把 MC2 并进 MoE Knowledge：dataflow family 不同。

compute baseline = **43**。MC2 里的 ASW Cube 不是新 GEMM Case。

---

## 先问什么

```text
1. 这一 chunk 现在归谁？
     producer-owned → communication-owned
     → [optional transform-owned] → consumer-owned
2. 哪条原语只是 communication progress？
   哪条才是 completion / consumer gate？
3. 哪条是 producer readiness / same-device ordering？
   哪条是 collective completion？
   （有没有 local flag、flag 在哪一侧，由 coupling direction 决定）
4. compute 与 collective 之间有没有独立的 layout-transform stage？
     没有 → 先按 M1 读
     有（AIV rank-block permute + AIC↔AIV handoff + communicator on AIV0）→ M2
```

不要先问重叠了几拍，也不要先问 handle 数组有多长。

---

## Graph

```text
MC2 compute–collective coupling

  chunk ownership 沿 pipeline stage 转移
      producer-owned
          ↓ readiness
      communication-owned
          ↓ completion
      [ optional transform-owned ]
          ↓ local handoff
      consumer-owned

  M1  compute ↔ collective          # 无独立 layout-transform stage
      AG : comm → compute
      RS : compute → comm            # canonical Case
      AR : compute → comm            # member；request morphology 不同

  M2  collective
        ↔ AIV rank-block permute    # 这一级定义机制
        ↔ compute
      AIC↔AIV handoff
      communicator orchestration on AIV0
```

共享的是 **ownership 转移、progress ≠ completion、producer readiness ≠ collective completion**。  
不共享的是 **request morphology**、**有没有 transform-owned stage**、以及 **哪些核发起 / Wait**。

---

## Rule 1 — chunk ownership 沿 stage 转移

```text
producer-owned
    ↓ readiness gate
communication-owned
    ↓ completion / consumer gate
[ optional transform-owned ]
    ↓ local handoff
consumer-owned
```

ownership 沿 pipeline stage 转移；communication 前后可以存在独立 **transformation owner**。  
consumer 只有在 **对应 gate 之后** 才能合法读。最终 API ownership / shape 由 **collective–compute 顺序** 决定，不是“MM partial 一定在 workspace”。

证据（形状不是通例，通例是转移规则）：

| | producer → comm input → consumer / API |
| --- | --- |
| AG | local/remote A shard → gathered input → full C |
| RS | MM C chunk → RS input → rank-local C shard |
| AR | MM partial chunk → AR input → full Y |
| M2 A2A→MM | x1 shard → A2A recv → **permute** → Cube A → y |

AG 的 collective **前面不是** MM partial。不要拿 RS/AR 的 send buf 去套 AG。

迁到下一种 MC2：先画这一 chunk 在每个 stage 归谁，再选原语。

---

## Rule 2 — progress ≠ completion

```text
<true> launch  /  Commit
    → communication progress

Wait
    → completion / consumer gate
```

`Commit` **不是** cross-rank visibility。Wait 完之前，不要把 recv / output 当已经对消费者合法。

request morphology **可以不同**，仍是同一条 progress/completion 纪律：

| | progress | completion |
| --- | --- | --- |
| AG / RS | 每 chunk `Collective<true>`（launch，留下 handle） | `Wait(handle_i)` 各一次 |
| AR | Init `AllReduce<false>(…, tileCnt)` + 每 turn `Commit`（同一 handle） | `Wait(同一 handle)` × N |
| M2 | `AlltoAll<false>` Prepare + `Commit` | `Wait`（consumer 侧；WAIT_ONE vs SEND_ONE） |

AR 与 M2 都出现 `<false>` + Commit/Wait，**不够**把它们合成一个 family（见 Rule 4）。

---

## Rule 3 — same-device ordering ≠ collective completion

producer readiness 与 collective completion 是 **不同 gate**。  
具体有没有 local flag、flag 在 producer 还是 consumer 一侧，由 **coupling direction** 决定。共用的是这套语义分类，不是 flag 3 这个 primitive。

```text
M1 RS / AR     compute → comm
  local MM result ready:
      PIPE_FIX / Mc2SyncAll 等 same-device ordering
  collective completion:
      HCCL Wait

M1 AG          comm → compute
  collective 是 producer
  remote gathered chunk:
      HCCL Wait 后 Cube 才能消费
  不要求存在与 RS/AR 对偶的 flag 3
  （Cube FIXPIPE 后再让 comm 读，不是 AG 的核心依赖）

M2
  AIC↔AIV:
      flag 8/9 + SyncAll
  collective completion:
      communicator Wait
```

flag / `SyncAll` 不是跨 rank。`--cce-auto-sync=off` 是编译条件，不是 sync 原语。

Layer 2 仍适用：**可以换原语，不能删** `remote payload visible before consumer reads`。MC2 的 dataflow 不是 EP window。

---

## Rule 4 — 中间 transform 可以定义新机制

```text
M1:
  compute ↔ collective
  无独立 AIV layout-transform stage
  reviewed paths 的 communication orchestration 位于 AIC side
  具体由哪些 AIC 发起 / Wait，属于 member-specific morphology

M2:
  collective ↔ AIV rank-block permute ↔ compute
  AIC↔AIV handoff
  HcclCommunicator control 明确在 AIV0
```

定义 M2 的是 **independent transform stage + AIC↔AIV handoff + communicator orchestration on AIV0**，不是 AllToAll 这个 job 名，也不是 Commit/Wait API。

**不要**写成 `M1 = AIC0`、`M2 = AIV0`。  
M2 的 AIV0 是钉死的。M1 只冻结 **AIC-side、没有独立 AIV transform**。RS 上 used AIC 都会调 `ReduceScatter`，Wait 在 AIC 0，非 0 核是否被 HCCL 过滤 **未证明**——不能在本文压成“通信控制在 AIC0”。新的 M1-like op 若多个 AIC 调 HCCL，仍可能是 M1。

Cube 仍是 ASW。不要开第二张 43。

---

## 非不变量

面对下一种 MC2，**不要要求**：

- one handle per chunk（那是 AG/RS 形态；AR 是 repeat 同一 handle）
- communication 一定在 AIC，或一定在 **AIC 0**（M2 在 AIV0；M1 哪些 AIC 发起/Wait 是 member-specific）
- 所有 M1 都有 flag 3（AG 的核心 gate 是 Wait，不要求与 RS/AR 对偶的 FIXPIPE flag）
- 一定有独立 `Commit`（AG/RS 的 `<true>` 就是 launch）
- 一定有 AIV permute（那是 M2）
- collective 一定是 AG / RS / AR / A2A（job ≠ mechanism；4P/8P sibling 会换内层）
- pipeline **允许** overlap ≠ **已测得**性能 overlap

job 名 AllReduce / ReduceScatter 仍可能走 A2A+vec / A2A+AG sibling。先看 tiling key，再套本文。

---

## 不要做

- 按 AG / RS / AR / A2A 四个算子各写一课，或为 AR / AG 再开 Case。
- 把 handle-per-chunk 写成 M1 通例。
- 把 flag 3 写成所有 M1 都有，或把 “Cube FIXPIPE 后再让 comm 读” 套到 AG。
- 把 M1 写成 communication control on AIC0（Wait 在 AIC0 ≠ 只有 AIC0 发起 collective）。
- 因为 AR 与 M2 都有 `<false>` + Commit/Wait，就合成一个 family。
- 把 `Commit` 写成 visibility。
- 把 flag / `SyncAll` 写成跨 rank。
- 把 “permits overlap” 写成已经测到重叠。
- 把 Cube ASW 写成新的 43 / 66 / 68（MC2 的 M-tile 是 **comm 切片**，不是 StreamK/SplitK）。
- 把 HCCL Wait 写成 Case B 的 MTE dest-push。
- 把本文并进 [Layer 2](moe-fusion-materialization-and-sync.md) / [FA pipeline](fa-pipeline-online-softmax-and-paged.md)。
- 现在展开 M3 / window-only M4。

---

## Related Cases / close-reads

| 角色 | 读什么 |
| --- | --- |
| M1 canonical | [RS native Case](../../../cases/cam/operators/compute-communication/mc2/ascend950-matmul-native-reduce-scatter/case.md) |
| M2 canonical | [A2A pipeline Case](../../../cases/cam/operators/compute-communication/mc2/ascend950-alltoall-matmul-pipeline/case.md) |
| compute baseline | [43](../../../cases/cam/operators/compute/gemm/ascend950-basic-matmul/case.md) |
| visibility 分类（引用） | [Layer 2](moe-fusion-materialization-and-sync.md) |

下一份 MC2 实现应直接填四问。不要先补第四种 collective 名。

---

## Sources

| Field | Value |
| --- | --- |
| repository | cann/ops-transformer |
| remote | `https://gitcode.com/cann/ops-transformer.git` |
| commit | `9311b63bcd065b9779eb08a7d634e9463ee41ef1` |
| hardware | ascend950 |
| supporting Cases | RS native；M2 A2A pipeline |
| AR / AG | close-read / verdict；**no Case** |
| status | accepted |
| Last verified | 2026-08-21 |
