---
name: cam-ci
description: CAM GitCode/Jenkins compile gate. Use when explaining BUILD_KIND, 910 vs 950 jobs, community ci_successful wait, or reading Generic_PR / cie logs. Do not copy GitHub Actions or Buildkite into umdk.
---

# CAM CI

status: **accepted**

CAM 没有 GitHub Actions / Buildkite。门禁是：

```text
GitCode MR
  → 社区门禁（MaJun check_code / check_sca）→ 标签 ci_successful
  → CAM Jenkins 编译（analyze → 按需 910/950 Docker）
  → 标签 cam_build_successful
```

## When CAM compile runs

Paths under `src/cam/**`, `build/cam/**`, or `test/cam/**` enter analyze;
other UMDK paths skip CAM compile. `jenkins_analyze.py` +
`operator_registry.json` set `BUILD_KIND`.

| KIND | Compile? |
|---|---|
| `skip` (docs / test / utilities only) | No |
| `partial_run` / `partial_run_whl` | Yes, changed ops |
| `full_run` / `full_run_whl` / `full_all` | Yes, all gens |
| `pybind` / `framework_only` | Yes, corresponding bucket |

`GEN_LIST` contains `ascend910_93` → 910 image `cam-dev:a3_9.0_open`.  
`GEN_LIST` contains `ascend950` → 950 image `cam-dev:a5_9.1_open`.  
Commands inside the container stay `./build/cam/build.sh …` (see `cam-build`).

## Before compile: community labels

Do not re-run MaJun on the CAM host. If compile is needed:

- `ci_successful` → compile
- `ci_failed` → fail, no Docker
- `ci_processing` / missing → wait (cie: `wait_community_ci.sh`)
- timeout → fail closed unless `CIE_CI_TIMEOUT_POLICY=pass`

Skip / non-CAM changes must not wait.

## Where scripts live

| Tree | Role |
|---|---|
| `/home/maerlei` | Production Jenkins; cie must not edit this tree |
| `/home/yw/cie` | Implemented trial: `entry_generic_pr.sh`, `wait_community_ci.sh`, `compile_in_docker.sh`, `run_build.sh` |
| Jenkins templates | `UMDK_CAM_Generic_PR_cie` + `UMDK_CAM_Compile_Ascend910_93_PR_cie` / `_950_PR_cie` under `/home/yw/cie/jenkins/jobs/` (not yet imported over production jobs) |
| This repo | Skills and operator source; `tools/ci/` later |

Never guess “latest open PR” when webhook has no `pr_iid`. Wait for `ci_successful` **before** writing `need_910` / `need_950`.

## Agent checklist

1. Classify paths → expected `BUILD_KIND` / `GEN_LIST`.
2. Point authors at community `ci_successful` before asking for a CAM rebuild.
3. Incremental op change: expect `partial_run` and only the registered SOC.
4. Read Docker logs for `BUILD_ARGS:` and `compile success` / `compile failed`.
