---
name: cam-operator-docs-search
description: 检索并分级 CANN、AscendC API、头文件、overload、参数单位和平台适用性证据。API 合同未知、需要官方或目标版本依据时使用；不负责重建算子语义，也不替代调试和优化判断。
---

# Docs Search Skill

status: **accepted**

本 Skill 是 **检索器**。事实还没冻结、合同不确定、或准备改 Card 时，定位资料并标证据等级。  
不是 API 百科，也不是改代码前的门禁。

```text
retrieval
  ≠
Knowledge fact

canonical retrieval
  ≠
source-of-truth verification
```

已覆盖且 scope 匹配：直接读 accepted Knowledge / Case。  
[cam-operator-debug](../cam-operator-debug/SKILL.md) / [cam-operator-optimization](../cam-operator-optimization/SKILL.md) 只在合同未知或要取证时进来。

算子「做什么、参数是什么」不是本 Skill。无设计文档时走 [cam-operator-spec-reconstruction](../cam-operator-spec-reconstruction/SKILL.md)。

---

## 1. 先定模式和 target version

```text
reuse
  Card / Case 已回答且 scope 匹配 → 复用，停

verification / promotion
  新事实、冲突、准备改 accepted Card
  → 回到 target-version first-party
  不得用 Card 证明同一张 Card
```

始终先确定 **target CANN version**（用户 / 任务 / 运行环境声明）。

```text
本机头文件是该目标的一手证据
  only when 本机 CANN == target version

不一致
  → 本机头文件只作其他版本参考
  不得覆盖 target 官方资料
```

不要把仓内某次扫描的 8.5.0 / `cam_wangyibo_dev_85` 当成永远的默认合同。

---

## 2. 怎么查

**reuse：** accepted Knowledge / Case → 停。

**verification / promotion：**

```text
1. target-version 官方文档
2. 仅当版本匹配：本机头文件
3. 可选：同版本 asc-devkit docs（examples 仍是 recommendation）
4. 在线兜底，钉 target version
```

没有 `$ASC_DEVKIT_DIR` 也能查。同名 API 先列出全部变体（`Add.md` / `Add-25.md`），后缀数字无语义。  
先看 overload，再填数。

---

## 3. 查到了怎么标

| 落到哪 | 标 |
| --- | --- |
| 官方文档与头文件一致，且都对上 target | `official-document` + `source-code` |
| 两者冲突 | **分别记录**，保留 version / overload / platform；不要合并成一个 fact |
| 仅示例 / 模板 | `recommendation` 或 unknown |
| 仅 cannbot / 博客 | 不得升 fact |

```text
查到示例
  ≠
查到合同

two first-party sources disagree
  ≠
pick whichever fits the hypothesis

debug / perf heuristic
  cannot override
accepted API / hardware contract
```

### 选 API ≠ 本 Skill 的结论

本 Skill 回答：这个 overload 在 target CANN 上是否合法、参数合同是什么。

**不回答**：这个仓库这条数据路径默认该用哪套。那是
[cam-operator-development Repo-native API Search Gate](../cam-operator-development/references/performance-by-construction.md)。

选对 API 之后，**这一次调用**的 blockLen / pad / dst footprint 是否合法，
是 [API Invocation Contract Gate](../cam-operator-development/references/performance-by-construction.md)，不是本 Skill 的结论。

```text
cam-operator-docs-search: API is legal
  ≠
this operator should use it as baseline
  ≠
this call's parameters have the claimed physical effect

same-repo + same-SOC + same pipeline role idiom
  outranks a generic legal API
```

---

## 4. 不要做

- 改代码前必须先跑本 Skill  
- 把 1022 篇 API md / api-index 搬进 `knowledge/`  
- 用别的 CANN 版本头文件覆盖 target  
- 示例里的 double buffer 当 TQue 合同  
- 用本 Skill 重建 MoonEP / DeepEP 等算子语义（那是 spec reconstruction）
- 把「API 合法」写成「本仓这条路径的 baseline idiom」
