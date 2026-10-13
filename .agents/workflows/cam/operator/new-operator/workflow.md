# New Operator Development

status: **accepted**

从 0 写算子。没有可继承的 mature production kernel。

**第一份核心文档是 Design。** Design 冻结后才是实现的 source of truth。

主 Skill：[cam-operator-development](../../../../skills/cam/operator/cam-operator-development/SKILL.md)  
P-gate：[performance-by-construction](../../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md)  
落盘模板：[design-template.md](design-template.md) · [gate-a.md](gate-a.md)

```text
Requirement
    ≠
Implementation

API 存在
    ≠
当前路径合法

Case 用过
    ≠
当前 SOC / CANN 一定合法

canImplement = true
    ≠
kernel 可运行
```

---

## 状态机

```text
Requirement
    ↓
Requirement Freeze
    ↓
Source / Case Retrieval
    ↓
Operator Design          →  <target>/.ascendweaver/operator-design.md
    ↓
Static Gate A            →  <target>/.ascendweaver/gate-a.md
    ↓
STOP（等人审）
    ↓  用户批准
PAC + Frozen Clauses
    ↓
Implementation
    ↓
Frozen-Clause Traceability + Gate B
    ↓
Runtime Handoff          →  cam-operator-run
```

没有明确批准，不得从 Gate A 自动进入 Implementation。

---

## 第一轮（默认）

只做：

```text
REQUIREMENT ANALYSIS + OPERATOR DESIGN + GATE A
```

禁止改 production source。完成后 STOP。

每条关键结论标：`PROVEN` / `INFERRED` / `NEEDS_EVIDENCE`。

证据优先级：

1. 当前仓 build / Host / ABI / framework contract  
2. 当前 SOC+CANN 的仓内 native idiom  
3. Weaver Knowledge  
4. Weaver Case（shape/dtype/SOC 对不上不得整份复制）  
5. close_reads  
6. 外部参考  

---

## Design 必须闭合

按 [design-template.md](design-template.md) 写满 A–K。缺轴标 **未重建**，不得假装闭合。

关键决策给稳定 ID：`FC-001`…

Gate A 按 [gate-a.md](gate-a.md) 逐条。correctness-level `FAIL` → 禁止 Implementation。

物理 Gate A 之后、freeze 之前仍要走 PAC（七条）。本 workflow 不复述 PAC。

---

## 本轮输出卡

```text
PHASE:            NEW OPERATOR / DESIGN
STATUS:           PASS | REPAIR | NEEDS_EVIDENCE | FAIL
DESIGN:           <一句话>
FROZEN CLAUSES:   <count + IDs>
PROVEN:           <关键已闭合>
NEEDS_EVIDENCE:   <只有上板/目标 CANN 能证的>
DESIGN_BLOCKER:   <如有>
NEXT:             是否允许 Implementation（默认：等人审）
```
