---
name: cam-build
description: Build CAM operators with umdk/build/cam/build.sh. Use when compiling run/whl, selecting SOC (-c) or operators (-a), pybind (-p), run-only (-r), or cam_comm (-m). Do not invent a second build entry.
---

# CAM Build

status: **accepted**

唯一编译入口（UMDK 仓根）：

```bash
./build/cam/build.sh [options]
```

不要在 `src/cam` 下另写一套 CMake 调用。CI 容器内也是这条命令。

## Options

| Flag | Meaning |
|---|---|
| `-c <soc>` | Registry key: `ascend910_93` or `ascend950` |
| `-a <ops>` | Semicolon-separated operators; requires `-c` |
| `-r` | Run package only |
| `-p` | Pybind whl only |
| `-m` | cam_comm library only (`cam_feature`) |
| `-q` | `fused_deep_moe_w4a8` instead of `fused_deep_moe` |
| `-d` | Debug |
| `-t` | Unit tests only |

Mutex: `fused_deep_moe` and `fused_deep_moe_w4a8` cannot share one `-a`.
Registry: `src/cam/comm_operator/ascend_kernels/operator_registry.json`.

## Examples

```bash
./build/cam/build.sh -c ascend910_93 -a "cam_moe_distribute_combine_recv" -r
./build/cam/build.sh -c ascend910_93 -p
./build/cam/build.sh -c ascend910_93 -m
./build/cam/build.sh -c ascend950 -a "fused_deep_moe_arch35" -r
```

Outputs:

```text
output/cam/comm_operator/run/CAM_<soc>_<os>_<arch>.run
output/cam/comm_operator/dist/umdk_cam_op_lib_*.whl
```

Writing a new kernel: route through `cam-operator-development`, then compile with this skill. Debugging a failed kernel: `cam-operator-debug`. CI decision of *whether* to compile: `cam-ci`.
