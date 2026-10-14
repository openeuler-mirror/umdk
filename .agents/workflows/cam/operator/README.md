# Workflows

status: **accepted**

开发入口先分任务类型。复杂度在本目录和 Skill 里，不在用户每次手写的长 Prompt。

```text
NEW OPERATOR
    →  workflows/cam/operator/new-operator/workflow.md

EXISTING OPERATOR FEATURE
    →  workflows/cam/operator/existing-operator-feature/workflow.md

上板验证
    →  skills/cam/operator/cam-operator-run

失败归因
    →  skills/cam/operator/cam-operator-debug
```

主路由仍是 [cam-operator-development](../../../skills/cam/operator/cam-operator-development/SKILL.md)。本目录规定 **第一轮停在哪、落哪些文件、何时允许跨 Gate**。P-gate 细则不在这里展开。

---

## 用户最小 Prompt

填类型和需求即可。不要把 Gate 清单再贴一遍。

### 新算子

```text
使用 Weaver 开发一个新算子。任务类型：NEW OPERATOR。
Operator / Repo / SOC / CANN / Requirement / representative shape / success criteria：
<填>
本轮只要 Design + Gate A，不要改 production source。
```

### 已有算子 Feature

```text
使用 Weaver 给 <算子> 增加一个 Feature。任务类型：EXISTING OPERATOR FEATURE。
Repo / branch / commit / SOC / CANN / Feature Requirement：
<填>
先从源码重建 Baseline，本轮不要改代码，不要提实现方案。
```

未写任务类型时，Agent 必须先问，不得默认当成新算子。
