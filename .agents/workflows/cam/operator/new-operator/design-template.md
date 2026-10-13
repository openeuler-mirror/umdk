# operator-design.md template

落盘到目标仓 `.ascendweaver/operator-design.md`。每节结论标 `PROVEN` / `INFERRED` / `NEEDS_EVIDENCE`。

```text
# <Operator> — Operator Design

SOC / CANN / repo / date:

## 1. Requirement Contract
## 2. Support Domain
## 3. Host / Kernel Admission
    Host admissible domain  <=  kernel proven support domain
## 4. Execution Topology
    physical launch · AIC/AIV · GetBlockIdx / GetSubBlock*
## 5. Logical Worker Mapping
    physical worker → logical worker，再分工
## 6. Work Partition
    无重叠写 / 无遗漏 / tail closed / zero-work closed
## 7. Dataflow Graph
    每条边：dtype · width · layout · address space · lifetime · producer · consumer
## 8. Buffer / Memory Map
    GM / workspace / UB / L1 / L0：offset · size · alignment · lifetime · overlay
    overlay 还要 leftover identity（下一发不得把 handshake leftover 认成 ready）
    禁止 magic offset
## 9. API Contract
    exact overload · src/dst space · count unit · alignment · extent · footprint · completion · event
## 10. Event Protocol
    每条 PipeBarrier / Set/Wait / SyncAll / CrossCore / Atomic 保护哪条 edge
    禁止保险 barrier
## 11. Pipeline Timeline
    MTE2 / V / MTE3 / Cube；buffer depth；event credits
    buffer_num=2  ≠  pipeline = double buffer
## 12. Boundary / Tail Handling
## 13. Arithmetic Audit
    widening · int32 · signed · ceil-div · packed / sub-byte · alignment · tail
## 14. Performance Design
    与至少一个合理 alternative 比较（serial island / overlap / GM / UB / 重复遍历）
## 15. Alternatives Considered
## 16. Open Questions
## 17. NEEDS_EVIDENCE
## 18. Frozen Clauses
    FC-001 …
```
