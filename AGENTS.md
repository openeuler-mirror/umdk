# UMDK Agent Guide

This file is the repository-wide entry point. Open UMDK at the Git root.
Project Agent Skills have a single canonical home under `.agents/`; do not
create component-local copies of that directory.

## Repository routing

| Task path or topic | Read first | Build or test entry |
| --- | --- | --- |
| `src/cam/**`, `build/cam/**`, `test/cam/**` | `src/cam/AGENTS.md` | `./build/cam/build.sh` |
| `src/urma/**`, `test/urma/**` | component README, CMake files, and `doc/{en,ch}/urma/` | `umdk.spec` / CMake from `src/` |
| `src/urpc/**`, `test/urpc/**` | component README, CMake files, and `doc/{en,ch}/urpc/` | `umdk.spec` / CMake from `src/` |
| `src/ulock/**`, `test/ulock/**` | component README, CMake files, and `doc/{en,ch}/ulock/` | `umdk.spec` with dlock enabled |
| `src/usock/**`, `test/usock/**` | component README, CMake files, and `doc/{en,ch}/usock/` | `umdk.spec` with ums enabled |
| `umdk.spec`, `src/CMakeLists.txt`, packaging | root README and `umdk.spec` | `rpmbuild -ba umdk.spec` |
| `test/intergration_test/**` | `test/pytest.ini` and the affected component contract | component build, then pytest |

CAM currently has the repository's mature Agent Skills. Other components do
not have placeholder skills: use their source, documentation, build files,
and tests as the contract until a repeated workflow justifies a skill.

## Agent assets

```text
.agents/
├── skills/cam/       # callable CAM skills
├── knowledge/cam/    # reusable facts and engineering guidance
├── cases/cam/        # mechanism-oriented operator cases
├── workflows/cam/    # multi-stage task workflows
└── tools/cam/        # CAM asset maintenance scripts
```

For CAM operator work, select a `cam-operator-*` skill under
`.agents/skills/cam/operator/`. Use `.agents/skills/cam/cam-build/` for the
repository build entry and `.agents/skills/cam/cam-ci/` for GitCode/Jenkins
gate decisions.

## Repository-wide rules

- Preserve component boundaries. CAM has a separate CANN build path; do not
  add it to the URMA/URPC/ULOCK/USOCK CMake or RPM flow without an explicit
  integration task.
- Prefer existing build, registration, binding, and test entry points.
- Keep component-specific rules in that component's `AGENTS.md`; do not copy
  skill bodies into `AGENTS.md`, `.claude/`, or another `.agents/` tree.
