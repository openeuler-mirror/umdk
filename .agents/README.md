# UMDK Agent 资产

`.agents/` 是仓库级 Agent Skills 及其支持材料的唯一事实源。请从 UMDK
Git 仓根打开项目，以便 Cursor 递归发现嵌套的 Skills。

## 目录结构

```text
.agents/
├── skills/cam/
│   ├── operator/       # cam-operator-* 可调用流程
│   ├── cam-build/      # build/cam/build.sh 构建合同
│   └── cam-ci/         # GitCode 和 Jenkins 门禁
├── knowledge/cam/      # 已确认的 CAM/AscendC 事实和工程知识
├── cases/cam/          # 按机制组织的算子案例
├── workflows/cam/      # 多阶段算子工作流
└── tools/cam/          # CAM 链接维护工具
```

只有包含 `SKILL.md` 的目录才是可调用 Skill。Knowledge、Cases、Workflows
属于支持资产，不应放在 `skills/` 下。

## 任务路由

首先查看 [CAM Skill 导航](skills/cam/README.md)。简要路由如下：

- 重建未知算子合同：`cam-operator-spec-reconstruction`
- 设计或实现算子：`cam-operator-development`
- 在 NPU 上构建、安装、加载和分层验证：`cam-operator-run`
- 诊断已定位的失败层：`cam-operator-debug`
- 正确性通过后进行性能优化：`cam-operator-optimization`
- 收集阶段计时证据：`cam-operator-instrumentation`
- 核对 CANN API 合同：`cam-operator-docs-search`
- 调用 CAM 构建入口：`cam-build`
- 判断 GitCode/Jenkins 门禁：`cam-ci`

仓库总路由位于 [UMDK AGENTS.md](../AGENTS.md)，CAM 源码专用规则位于
[src/cam/AGENTS.md](../src/cam/AGENTS.md)。

## 资产边界

- `skills/` 描述 Agent 如何完成任务。
- `knowledge/` 记录已确认的可复用事实和工程规则。
- `cases/` 解释已评审实现中的机制，不是源码复制库。
- `workflows/` 定义多个 Skills 共享的生命周期门禁。

## 维护要求

Skill 名称必须全仓唯一，并与直接父目录同名。面向用户的命令使用仓根相对路径，
内部导航使用相对 Markdown 链接。移动资产后运行：

```bash
python3 .agents/tools/cam/check_links.py
```

不要创建第二棵 `src/cam/.agents/` 目录，也不要在 `.claude/` 下复制
Skill 正文。
