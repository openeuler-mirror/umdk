# delta-design-<feature>.md

只设计 Feature 引入的 delta。多个候选比较后冻结一个。

```text
# Delta Design — <feature>

## Selected design（已冻结，Implementation 不得另选）
## Alternatives considered

## Invariant check
    Baseline invariants still hold?
    worker ownership 变了吗？
    state / count domain 变了吗？
    buffer / workspace 变了吗？
    event protocol：新增 / 删除哪些 edge？
    pipeline resource 变了吗？
    zero-work / tail
    fallback 是否仍可达
    arithmetic / offsets
    Host admission

## Frozen Feature Clauses
    FC-001 …
```
