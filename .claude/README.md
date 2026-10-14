# Claude Code 适配层

本目录只提供 Claude Code 的仓库级适配，默认不保存 Agent 能力正文。

- `../CLAUDE.md` 导入仓根 `AGENTS.md`。
- Agent Skills 的唯一事实源位于 `.agents/skills/`。

如需让 Claude Code 发现这些 Skills，请将 `.agents/skills/` 复制到本目录，
或在本目录创建指向它的 `skills` 软链接。软链接方式可以避免维护重复内容：

```bash
ln -s ../.agents/skills .claude/skills
```

复制后不要在两处分别修改；应以 `.agents/skills/` 为准并重新同步。
