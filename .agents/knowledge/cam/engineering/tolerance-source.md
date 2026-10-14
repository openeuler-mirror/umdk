# Tolerance source

status: **accepted**

判定算子输出“过不过”时，先问 **这次验收用哪把尺子、能不能声称符合官方标准**。不要抄 FP16 `1e-3` / CANNBot `2^-9` 表，也不要把 rtol 失败写成公式错了。

本文只定 **真源和比法**。查根因走 [cam-operator-debug](../../../skills/cam/operator/cam-operator-debug/SKILL.md)。

证据种类：`official-document` | `recommendation` | `unknown`。  
本文件 **没有** 官方阈值表，也 **没有** `benchmark`。

---

## 先问什么

```text
1. Plan / 用户有没有写下本次验收阈值？
2. 这是搬运、整数、量化、浮点计算，还是随机输出？
3. 有没有 applicability 匹配的官方标准？
4. 这次是任务验收，还是要声明官方符合性？
```

不要先问“FP16 默认是不是 1e-3”。

---

## Rule

```text
task acceptance
  Plan / 用户合同优先
  没有 → applicable 官方标准
  再没有 → unknown（记下临时尺子）

official-conformance claim
  必须实际满足并引用对应官方标准
  Plan 不能覆盖官方标准

Plan overrides test acceptance
  ≠
Plan overrides official standard

comparison method
  ≠
threshold numbers

|actual − golden| ≤ atol + rtol × |golden|
  浮点常用比法，不是某 dtype 的官方阈值

integer
  bitwise 或 abs error = 0

copy / 非计算
  通常 bitwise
  float Cast 的舍入不是搬运 bitwise

logical equivalence
  ≠
finite-precision execution equivalence

(a+b)+(c+d) = a+b+c+d
  只是实数代数，不是 bitwise 合同
  fusion / unfusion、partial reduction、split-K、
  cross-rank reduction、intermediate cast
  都可以插入 rounding boundary
  不得把“实现了同一逻辑和”写成 bit-exact / 严格数值等价
  浮点验收仍走上面的 task acceptance 尺子

random / stochastic
  不用普通 elementwise 容差
  本轮不定义 KS / p-value
```

官方表在，不等于适用于当前调用。有则核对：CANN 版本、算子类、输入输出 dtype、mode / 量化属性、SOC（若标准有区分）。

Case 里的 rtol 是 **那条测试的合同**，不是平台通例。

rtol 挂了 → [wrong-result](../../../skills/cam/operator/cam-operator-debug/SKILL.md)，不是“公式一定错”。

不上板不得报精度已过。临时尺子不得写成“已按官方标准通过”。

---

## What NOT To Generalize

| 不要当成 fact | 为什么 |
| --- | --- |
| FP16=1e-3 / FP32=1e-5 | precision-debug 兜底 |
| CANNBot `2^-9` / `0.99` 表 | `cannbot-secondary`；未见官方文 |
| Plan 更松 ⇒ 符合官方 | 只覆盖任务验收 |
| 所有 Cast bitwise | 舍入过严 |
| `(a+b)+(c+d)=a+b+c+d` ⇒ bit-exact | 中间 dtype / rounding；逻辑等价 ≠ 有限精度执行等价 |

---

## Sources

| Field | Value |
| --- | --- |
| 发现来源（非真源） | cannbot `ops/ops-precision-standard` @ `c4c425641d11127945d22e5a752fcad77646be97` |
| Related | [cam-operator-debug](../../../skills/cam/operator/cam-operator-debug/SKILL.md)、[correctness-debug](../../../workflows/cam/operator/correctness-debug/README.md) |
| Last written | 2026-08-25 |
| status | accepted |
