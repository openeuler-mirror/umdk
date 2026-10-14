# Existing Operator Feature Development

status: **accepted**

已有成熟 production kernel 上加 Feature。最大风险是带着 Feature 目标读老代码，把“当前实现”和“觉得应该怎样”混在一起。

**第一份核心文档是 Baseline，不是 Delta Design。**

主 Skill：[cam-operator-development](../../../../skills/cam/operator/cam-operator-development/SKILL.md)  
实现后的 P-gate / Gate B 仍走该 Skill + [PBC](../../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md)。  
上板走 [cam-operator-run](../../../../skills/cam/operator/cam-operator-run/SKILL.md)。

```text
Feature Requirement
    ≠
可以直接改代码

当前实现
    ≠
Agent 认为应该怎样实现

整个算子重设计
    ≠
Feature Delta

export FEATURE=1
    ≠
Host 已 admitted（上板后仍走 iteration）
```

这不是 [cam-operator-spec-reconstruction](../../../../skills/cam/operator/cam-operator-spec-reconstruction/SKILL.md)。那边是没有可靠设计文档时重建 Contract。这里读的是 **当前 production source**。

---

## 状态机

```text
Existing Source
    ↓
Baseline Reconstruction     ← 第一轮：隐藏未来方案
    ↓
Baseline Freeze             ← STOP，等人审
    ↓
Feature Requirement
    ↓
Change Contract
    ↓
Blast Radius
    ↓
Delta Design
    ↓
Gate A-Delta
    ↓
STOP，等人批准
    ↓
Implementation（只实现 frozen delta）
    ↓
Frozen-Clause Traceability + Gate B
    ↓
Runtime Handoff             →  cam-operator-run
```

没有明确批准，不得自动跨 Gate。

---

## 第一轮 — Baseline Reconstruction

只允许知道：“将对某模块增加一个 Feature，因此要重建相关 Baseline。”

禁止预设 Feature 该用 counter / flag / atomic / 新 buffer / 某条 pipeline / 某个 API。  
禁止提 Feature 方案、改 production source、顺手优化、把可疑代码直接修掉。

从真实源码重建，按 [baseline-template.md](baseline-template.md)。Feature 只碰局部协议时，文件可以 targeted，但必须盖住 **全部 blast neighborhood**。

结论标：`PROVEN` / `INFERRED` / `NEEDS_EVIDENCE`。本轮禁止提出优化方案。

Baseline Gate：`BG01`–`BG14`，见模板末节。任一条 correctness 未闭合 → 不得 Baseline Freeze。

完成后 STOP。输出卡：

```text
PHASE:            EXISTING FEATURE / BASELINE
STATUS:           PASS | REPAIR | NEEDS_EVIDENCE | FAIL
PROVEN:
NEEDS_EVIDENCE:
CHANGED:          none
DESIGN_BLOCKER:
NEXT:             等人 Baseline Freeze；禁止进 Feature Design
```

---

## 第二轮 — Feature Design

只有用户宣布 Baseline Freeze 之后才能进入。

生成（目标仓 `.ascendweaver/`）：

| 文件 | 模板 |
| --- | --- |
| `change-contract-<feature>.md` | [change-contract-template.md](change-contract-template.md) |
| `blast-radius-<feature>.md` | [blast-radius-template.md](blast-radius-template.md) |
| `delta-design-<feature>.md` | [delta-design-template.md](delta-design-template.md) |
| `gate-a-delta-<feature>.md` | [gate-a-delta.md](gate-a-delta.md) |

只设计 Feature 引入的 delta。不要重设计整个算子。多个候选必须比较后冻结一个，不得留给 Implementation 临时选。

实现 write set 必须是 Blast Radius 三表的物理投影。发现要改 `MUST NOT CHANGE` → `STOP` / `DESIGN_BLOCKER`。禁止偷偷扩大 blast radius。

Gate A-Delta `FAIL` → 禁止 Implementation。PASS 后冻结 Feature Clauses：`FC-001`…

---

## Implementation

用户明确批准 Gate A-Delta 之后。进入时先打印：

```text
PHASE:
FROZEN BASELINE:
FROZEN FEATURE:
WRITE SET:
MUST NOT CHANGE:
OPEN NEEDS_EVIDENCE:
NEXT:
```

1. 只实现 frozen delta  
2. 不重构 baseline  
3. 小步改、每个结构阶段 compile  
4. compile 失败找 first bad layer  
5. 不因 compile 静默 redesign  

建议顺序：Host guards → 最小结构 → producer → consumer → sync/cleanup，每步 compile。

然后 `frozen-clause-traceability.md`：每个 FC → file / function / region / `MATCH|DEVIATION|NOT_IMPLEMENTED|NEEDS_EVIDENCE`。未经批准的 `DEVIATION` → Gate B FAIL。

Gate B 审实际代码，不准复述 Design。Compile PASS ≠ Gate B PASS。未上板不得写 Runtime PASS。

---

## 本轮输出卡（每阶段）

```text
PHASE:
STATUS:
PROVEN:
NEEDS_EVIDENCE:
CHANGED:
DESIGN_BLOCKER:
NEXT:
```
