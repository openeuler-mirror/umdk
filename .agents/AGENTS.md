# Agent 资产维护规则

本文件仅在编辑 `.agents/` 时生效。仓库运行时路由位于根目录
`AGENTS.md`，CAM 源码规则位于 `src/cam/AGENTS.md`。

## 目录职责

- `skills/cam/`：可执行的 CAM 决策流程和工具使用方法。
- `knowledge/cam/`：已确认的 CAM 事实和可复用工程知识。
- `cases/cam/`：经过评审、带有来源信息的 CAM 机制案例。
- `workflows/cam/`：CAM 生命周期门禁和可复用任务流程。
- `tools/cam/`：CAM 资产校验工具。

不要在 Skill 中复制大段知识文章或完整源码。应链接到满足任务所需的最小支持资产。

## CAM Skills

CAM Skills 的根目录是 `skills/cam/`，算子 Skills 位于下一层
`skills/cam/operator/`。每个 Skill 必须：

1. 包含带 YAML frontmatter 的 `SKILL.md`；
2. 使用全仓唯一、由小写字母和连字符组成的 `name`；
3. 保持 `name` 与直接父目录同名；
4. 同时说明“做什么”和“何时使用”；
5. 需要其他能力时进行路由，不复制其他 Skill 的流程正文。

CAM 算子生命周期 Skill 使用 `cam-operator-*` 前缀。`cam-build` 和
`cam-ci` 单独保留，因为它们描述仓库交付机制，而不是算子设计。

## 内容变更

修改 Agent 资产时：

1. 将内容分类为 Skill、Knowledge、Case 或 Workflow；
2. 说明来源和适用范围；
3. 删除无法泛化的来源特有结论；
4. 从相关运行时入口添加链接；
5. 运行 `.agents/tools/cam/check_links.py`。
