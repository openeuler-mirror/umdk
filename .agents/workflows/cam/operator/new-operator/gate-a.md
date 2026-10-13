# Gate A — New Operator

落盘到目标仓 `.ascendweaver/gate-a.md`。

P-gate 物理项仍打开 [performance-by-construction](../../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md)。本页是关卡清单，不替代 P1–P5 / PAC。

每条状态只能是：`PASS` / `REPAIR` / `NEEDS_EVIDENCE` / `FAIL`。

correctness-level `FAIL` → 不允许 Implementation。

| ID | 检查 |
| --- | --- |
| GA01 | semantic contract closed |
| GA02 | Host admission ≤ kernel support |
| GA03 | physical → logical worker mapping proven |
| GA04 | partition no overlap / no omission |
| GA05 | tail / zero-work closed |
| GA06 | complete operand graph |
| GA07 | dtype / layout / storage closed |
| GA08 | byte-accurate memory footprint |
| GA09 | lifetime / overlay closed（含跨 launch leftover identity） |
| GA10 | API parameter-level contract closed |
| GA11 | event protocol closed |
| GA12 | pipeline resources sufficient（闭环 ≠ 够飞） |
| GA13 | synchronization minimal and justified |
| GA14 | arithmetic audit closed |
| GA15 | fallback / unsupported domain explicit |
| GA16 | performance design has evidence（比较过 alternative） |
| GA17 | open assumptions labeled NEEDS_EVIDENCE |
| GA18 | no speculative generality on hot path |

```text
# Gate A — <Operator>

| ID | Status | Evidence / blocker |
| --- | --- | --- |

OVERALL:
NEXT:
```
