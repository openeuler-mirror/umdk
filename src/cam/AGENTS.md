# CAM Agent Guide

This file applies to CAM source under `src/cam/`. Repository Agent Skills are
owned centrally by `umdk/.agents/`; do not create a second `src/cam/.agents/`.

## Task routing

- New or changed AscendC operator:
  `.agents/skills/cam/operator/cam-operator-development/SKILL.md`
- Unknown operator contract:
  `.agents/skills/cam/operator/cam-operator-spec-reconstruction/SKILL.md`
- Build, install, load, and staged NPU validation:
  `.agents/skills/cam/operator/cam-operator-run/SKILL.md`
- Compile/runtime/correctness failure:
  `.agents/skills/cam/operator/cam-operator-debug/SKILL.md`
- Correct operator requiring measured performance work:
  `.agents/skills/cam/operator/cam-operator-optimization/SKILL.md`
- TRACE_POINT, MoeTracing, or Chrome trace instrumentation:
  `.agents/skills/cam/operator/cam-operator-instrumentation/SKILL.md`
- CANN API lookup:
  `.agents/skills/cam/operator/cam-operator-docs-search/SKILL.md`
- CAM build options and outputs:
  `.agents/skills/cam/cam-build/SKILL.md`
- GitCode or Jenkins compile gates:
  `.agents/skills/cam/cam-ci/SKILL.md`

Paths above are relative to the UMDK repository root.

## Build and integration

Use the single repository build entry from the UMDK root:

```bash
./build/cam/build.sh [options]
```

Operator names and SOC mappings come from
`src/cam/comm_operator/ascend_kernels/operator_registry.json`. Reuse existing
OpDef, tiling, kernel ABI, pybind, registration, and test conventions. Do not
create a parallel build system for an operator that already has an integration
path.

## CAM conventions

- Prefer concrete types and named constants. Do not add mutable globals.
- Keep CAM-specific changes to copied upstream code minimal and documented.
- Do not add GitHub Actions or Buildkite configuration: UMDK uses GitCode
  community gates and an external Jenkins compile path.
- Do not duplicate centralized skills under `.claude/` or this directory.
