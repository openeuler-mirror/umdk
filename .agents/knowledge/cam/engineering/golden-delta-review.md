# Golden / reference delta review

status: **accepted**（实验后对照方法。不是把参考实现升成合同。）

Golden / 参考代码是 **证据**，不是绝对真理。

对应 [cam-operator-development Gate B](../../../skills/cam/operator/cam-operator-development/SKILL.md)
对照参考实现时的分类义务。

证据种类：`recommendation`。本文 **没有** `benchmark`。

---

## 禁止的推理

```text
different from Golden
  →
change to Golden
```

Design-Execution 实验的忠实对象是 **Frozen Design**，不是参考树。

```text
correct technical reasoning
  ≠
experimental fidelity
```

一条改动可以在工程上更合理，同时在 Design-Execution 里仍是未批准 deviation。

---

## 每条实质 delta 必须分类

| 类 | 含义 |
| --- | --- |
| A | Generated implementation defect |
| B | Golden / reference defect |
| C | Shared defect |
| D | Generated improvement |
| E | Unauthorized Design deviation（Frozen 选择被改了，即使更好） |
| F | Performance maturity difference（envelope / sync / 资源深度） |
| G | Neutral implementation-style difference |
| H | Needs runtime evidence |

D 与 E 可以同时成立：生成代码更完整，但仍改了 frozen choice → 记 E，提出 Design deviation proposal，**等待批准**，不得 silently land。

不得因为 Golden 更熟、或 generated 看起来更安全，就自动选边。

---

## 和已有门的边界

| 问题 | 走 |
| --- | --- |
| 实现是否忠实 Frozen Design | Frozen-Clause Traceability |
| 参考实现是否物理上更好 | 本页分类；批准后才改 Frozen |
| 是否该抄 sibling 整算子 |  idiom ≠ architecture |

| Related | [cam-operator-development](../../../skills/cam/operator/cam-operator-development/SKILL.md)、[PBC Frozen-Clause Traceability](../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md) |
