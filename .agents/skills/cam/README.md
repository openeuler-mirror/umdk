# CAM Skill Map

Select one primary skill from the current task state.

## Operator lifecycle

```text
unknown contract
  → cam-operator-spec-reconstruction
  → cam-operator-development
  → cam-operator-run
       └─ failed layer → cam-operator-debug
  → correctness passed → cam-operator-optimization
       └─ timing evidence → cam-operator-instrumentation
```

- [Spec reconstruction](operator/cam-operator-spec-reconstruction/SKILL.md):
  reconstruct semantics from call sites, tests, tiling, and kernels when the
  operator contract has blocking unknowns.
- [Development](operator/cam-operator-development/SKILL.md): route new operator
  and existing-feature work through design and implementation gates.
- [Run](operator/cam-operator-run/SKILL.md): build, install, load, and validate
  in staged NPU layers; record the first failing layer.
- [Debug](operator/cam-operator-debug/SKILL.md): diagnose a known compile,
  runtime, correctness, hang, or communication failure.
- [Optimization](operator/cam-operator-optimization/SKILL.md): explain measured
  bottlenecks after correctness and stability pass.
- [Instrumentation](operator/cam-operator-instrumentation/SKILL.md): add and
  process TRACE_POINT/MoeTracing evidence when debug or optimization requests
  stage timing.
- [Docs search](operator/cam-operator-docs-search/SKILL.md): verify CANN API,
  overload, header, unit, and platform contracts.

## Repository delivery

- [CAM build](cam-build/SKILL.md): use the single
  `./build/cam/build.sh` entry and its supported options.
- [CAM CI](cam-ci/SKILL.md): determine GitCode/Jenkins compile scope and gate
  status.

Build and CI skills do not replace the operator lifecycle. A kernel change
normally uses an operator skill first, then `cam-build` through
`cam-operator-run`.
