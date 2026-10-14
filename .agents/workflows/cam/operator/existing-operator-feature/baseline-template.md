# Baseline reconstruction templates

落盘到目标仓 `.ascendweaver/`。本轮禁止写 Feature 方案。

```text
baseline-contract.md
baseline-design.md
baseline-event-protocol.md
baseline-open-questions.md
baseline-gate.md
```

局部 Feature 可合并为 targeted 文件，但 blast neighborhood 必须盖全。

---

## baseline-contract.md

```text
# <Operator> — Baseline Contract

repo / branch / commit / SOC / CANN:

## External Contract
    inputs / outputs / dtype / shape / optional / attrs / public ABI / Host checks

## Fast / Fallback Paths
    hot path · fallback · multi-round · optional feature · unsupported domain
```

---

## baseline-design.md

从源码重建，不要写“应该怎样”。

```text
# <Operator> — Baseline Design

## Call Graph
    Python/framework → Host → tiling → __global__ → kernel classes → target helper

## Execution Topology
    launch · blockDim · AIC/AIV · GetBlockIdx · GetSubBlock*

## Logical Worker Ownership
    每个阶段：谁负责什么数据。禁止只写“多核并行”。

## Phase Graph
    P0 / P1 / …  live path
    每 phase：producer · consumer · engine · input · output · workers · completion

## Dataflow
    payload / metadata / workspace / status / communication window
    producer · writer · reader · lifetime · reset

## Buffer / Memory Map
    GM / workspace / HCCL window / IPC status / UB / L1 / L0
    byte-accurate：offset · size · alignment

## Count / Metadata Domains
    分类，禁止混语义：
    PLAN_COUNT · SLOT_ALLOCATION · PAYLOAD_READINESS ·
    WORKER_COMPLETION · GMM_GROUP_SIZE · GENERATION

## Performance Architecture（只描述当前代码）
    pipeline · buffer depth · serial island · comm · barriers · repeated traversal
    本轮禁止优化建议
```

---

## baseline-event-protocol.md

```text
# <Operator> — Baseline Event Protocol

MTE2 / V / MTE3 / Cube
SetFlag / WaitFlag / PipeBarrier / SyncAll / CrossCore / Atomic

每条边区分：
    issued · local complete · remote visible · consumer observed
```

---

## baseline-open-questions.md

```text
# Open Questions
PROVEN / INFERRED / NEEDS_EVIDENCE
```

---

## baseline-gate.md

| ID | 检查 |
| --- | --- |
| BG01 | call graph closed |
| BG02 | external contract closed |
| BG03 | execution topology closed |
| BG04 | worker ownership closed |
| BG05 | phase graph closed |
| BG06 | dataflow closed |
| BG07 | memory map closed |
| BG08 | API usage reconstructed |
| BG09 | event graph closed |
| BG10 | state/count domains closed |
| BG11 | zero-work/tail closed |
| BG12 | fast/fallback paths closed |
| BG13 | visibility assumptions honestly labeled |
| BG14 | performance architecture reconstructed（无优化提案） |

```text
OVERALL:
NEXT: 等人 Baseline Freeze
```
