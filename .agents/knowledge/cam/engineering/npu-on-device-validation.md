# On-device NPU operator validation

status: **accepted**

人在 **NPU / 内网上板** 时，主循环是 [cam-operator-run](../../../skills/cam/operator/cam-operator-run/SKILL.md)。本文只提供那台状态机要用的合同：测试对象分层、异步错误语义、runtime facts、证据门槛、run manifest。

不是 npu-smi 百科，不是 DataCopy / HardEvent / HCCL 说明书，也不是某个 op 的协议。

蓝区无 NPU：仍可设计下一层检查。**不要**为了读本文要求 `npu-smi`。

证据种类：`recommendation`（FusedDeepMoe 上板对话）。本文件 **没有** `benchmark`。不开 Case。

---

## 先问什么

```text
1. ITERATION 卡填了吗？现在最高已 PASS 的是哪一层？
2. 运行时加载的是不是这次刚编的 OPP？
3. synchronize / 507xxx 收回来的错误，FIRST BAD 在哪一层？
4. 准备当证据的数字，是 dump 出来的，还是推出来的？
```

不要先问“新 kernel 的 flag 协议是不是错了”。

---

## Rule

```text
完整 e2e
    ≠
第一定位工具

Python stack / synchronize 行号
    ≠
kernel fault location

export FEATURE=1
    ≠
Host tiling admitted

推测的 aicNum / 洞大小
    ≠
runtime fact

旧成功日志的 env / harness
    ≠
本次机器合同

timeout 父进程退出
    ≠
子进程已死、卡已释放

op_summary.csv 在
    ≠
采到了目标 kernel

静态“看起来有竞态”
    ≠
可以 patch

profiler
    ≠
correctness debugger

2 卡通过
    ≠
4 卡失败就是某代卡不兼容

刚编过 / import 过
    ≠
LOADED OPP 就是这份 BUILD

上一份 binary 的 L2+ PASS
    ≠
换包后仍有效

一次改两个主变量的 run
    ≠
有资格的根因证据（必须标 NON-DIAGNOSTIC）
```

---

## 测试对象分层（L0–L9）

一层没过，禁止用更后层的假说。L6 挂了但 L3–L5 没跑：没有定位信息。

| L | 对象 | 最小证明 | 失败时先别怪 |
| --- | --- | --- | --- |
| L0 | Python / runtime alive | 指定 python `import torch` / `torch_npu` | kernel |
| L1 | NPU basic op | 同卡 `npu_swiglu` / matmul / `.npu()` | 自定义 op |
| L2 | 注册 / tiling alive | op 能进 Host；打印 tiling key / admitted | 多卡协议 |
| L3 | 单卡 custom kernel smoke | 1 rank、最小 shape、隔离无关路径 | HCCL、芯片代 |
| L4 | HCCL / IPC / window smoke | 写成文件的 `mp.spawn` hello；同可见设备集 | visible-devices 玄学 |
| L5 | 2-rank operator | 2 张空闲同类卡 | 目标 4 卡配置 |
| L6 | target-rank operator | 目标 world size；先 bypass 无关参照 | 精度公式 |
| L7 | golden | 参照路径已冻结；数学顺序与 fused 一致 | hang / 协议 |
| L8 | repeated stability | 合同次数；**无 profiler**；**新 one-shot flag 至少 2 launch**（含 dataState 翻转或后级 smash） | 第一发 PASS 当 leftover-safe |
| L9 | performance / profile | 与 L8 同一 manifest；profiler 显式打开 | 回头改 publication |

`bypass_small_check`（或等价）以脚本源码为准：有的只跳过对比，有的连 SmallOps 都不构造。读完再宣布“已经隔离 FusionOp”。

隔离 FusionOp 是 **L6 的合法最小测试**。它不能代替 L3–L5，也不能代替 L7。

---

## 异步错误定位

```text
fused_ops(...)
torch_npu.npu.synchronize()   # 或测试脚本里等价 sync
```

`synchronize` 报 `507014` / `507015` / device error 的语义是：

```text
前面某个已下发的 kernel / DMA / HCCL
已经 trap 或超时；
现在 Host 把错误收回来。
```

不是 “synchronize 有问题”，也不是 “synchronize 的前一行一定有问题”。

```text
Python stack
    ≠
AIC / AIV / DMA / HCCL fault location
```

先问 FIRST BAD 层，再考虑：前序 kernel trap、对齐、非法访问、spin 超时、HCCL kernel。  
`ASCEND_LAUNCH_BLOCKING=1` 只为收回 AI Core 细节，**不是第一轮实验**，会改时序，不能用来宣布某代卡跑不了。

| 观察 | 先当成 | 不要先当成 |
| --- | --- | --- |
| 507015，且还没有本算子 warmup | L0–L4 或装错包 | 新 kernel hang |
| 507014，Host 已 FALLBACK | baseline 或 watchdog | 新协议死锁 |
| 507014，L8 无 profiler 过、L9 才坏 | profiler / 默认 aicore 超时 | 必须改 publication |
| 高 util + 长时间 | 还在算 | 已证实死锁（死锁常见 util 掉空） |
| `timeout` 后卡仍高 util | 子进程没死 | kernel hang 已证实 |

---

## Runtime facts（不许靠推测）

凡是能打印的，先 dump，再推导洞大小 / FALLBACK / 核数。

至少这些，用到哪条 dump 哪条：

```text
aicNum  aivNum  blockDim  tiling key
roundNum  oneRound  admitted feature
actual BS / H / expert per rank / token counts
window size  buffer offset  bank stride
dataState
device type + visible ids + world size
```

推出来的 `aicNum=64` 可以把整条根因推翻。数字进证据卡之前必须来自这次 run。

---

## 证据门槛（patch 之前）

```text
Hypothesis:
Evidence for:
Evidence against:
Observable:     一次 dump / 一次 A/B 能看见
Minimal test:
Expected A:
Expected B:
```

例：怀疑 `donePub` 复用竞态 → Observable 是远端 DONE 槽值是否偶发 ≠ destCount；Probe 是 dump GM DONE 表；Expected 写清楚。没看见 Observable，只许设计检查，不许改语句。

实验装置必须先自证。`python -c` 里的 local function 不能被 `mp.spawn` pickle：这是装置坏了，不是 “HCCL 不认 visible devices”。

一张假说、一处改动。改完 BINARY 变了则 L2+ 作废，从 Install → Load 再走。  
证据卡之后默认只改一个主变量（`device / world_size / shape / feature flag / binary / profiler`）。多变量 run 标 **NON-DIAGNOSTIC**，只许探索。

---

## Freeze / Run manifest

同时改 operator + test harness + worktree，实验失去可比性。一棵树、一份脚本 sha、一份 OPP。

卡上的 **BINARY** 必须能对上 `BUILD ID / OP COMMIT / TEST COMMIT / LOADED OPP`。`LOADED OPP` 是运行时路径 + `.o` mtime，不是“刚才编过”。任一项变化：L2+ LAST PASS 全部失效。

每次 launch 前打印（有仓内格式则沿用）：

```text
========== RUN MANIFEST ==========
repo commit:
test script sha256:
custom opp path:
opp build id / .o mtime:
CANN / torch_npu / python:
device type + ids:
world size:
env vars (only those actually set):
shape / feature flags / admitted:
harness frozen: yes
==================================
```

结果目录：

```text
runs/<id>/
  manifest.txt
  stdout.log
  npu_smi.txt
  result.json          （有则写）
```

旧 `run*.log` 只证明“曾经走过”，不是本次 env 合同。不要整表复制 `HCCL_BUFFSIZE`（单位是 MiB；多进程组再乘一份，常见 `EL0019`）。

---

## Functional / Stability / Performance

| 阶段 | 允许 | 禁止 |
| --- | --- | --- |
| Functional | warm 0–2，iter 1–3；可选 blocking；允许 probe | 报加速比；msprof |
| Stability | warm 20 + iter 100/1000（或合同）；无 debug print | profiler |
| Performance | known-good binary；与 Stability 同一 manifest | 用第一趟大 bs+长 iter+msprof 当 correctness |

**profiler 永远不是 correctness debugger 的第一步。**  
大配置 + 长 iter + msprof 一起跑，超时先做「同配置、无 profiler」决定性实验。一轮脚本用 `warm_iter` / `test_iter`（或仓内等价），禁止为 N 轮 launch N 次进程。只有 weight-init 的 `op_summary` 不是 fused 性能。

---

## 有设备时的仪式（01–04）

蓝区禁止把下面写成思考门槛。上板 01 Freeze 时做完：

1. `npu-smi`：芯片代、util、HBM、PID。占用中的卡不要抢。跨容器 PID 杀不掉就换空闲同类卡。
2. 只认用户点名的 worktree。不要混 sibling 树“顺便修 golden”。
3. 用户能 `import torch_npu` 的那个 python。不要发明不存在的 conda。
4. CANN 实际目录对上 `CMakePresets` / `ASCEND_HOME_PATH`。`torchair` 常可选。
5. `libtorch_npu.so` 在 `LD_LIBRARY_PATH`（或 rpath）。
6. 杀上一轮 `mp.spawn` 残留；`df /tmp`（msprof / opp_extract 会写满根分区）。
7. 共享机端口（常见 `16666`）被占：换 `HCCL_NPU_SOCKET_PORT_RANGE`，不要先改 kernel。
8. 重编后重装 `.run`，核对 `.o` mtime，确认 `ASCEND_CUSTOM_OPP_PATH` 进了 spawn 子进程。选路仍读 [delivery](custom-op-delivery-call-and-selected-path.md)。

对照必须同 world size、同芯片代、同占用状态。

---

## Related

| 角色 | 文件 |
| --- | --- |
| 状态机 | [cam-operator-run](../../../skills/cam/operator/cam-operator-run/SKILL.md) |
| 本层失败后归因 | [cam-operator-debug](../../../skills/cam/operator/cam-operator-debug/SKILL.md) |
| 装上 ≠ 选中 | [delivery](custom-op-delivery-call-and-selected-path.md) |
| hang 协议边 | [pipeline](../synchronization/pipeline-events-and-ordering.md) |
| 跨域搬运 | [correctness-debug](../../../workflows/cam/operator/correctness-debug/README.md) |

不要并进 MoE Case。不要把 D2 / DONE 方案升成本文。

---

## Sources

| Field | Value |
| --- | --- |
| Origin | FusedDeepMoe 上板对话复盘：缺的是实验科学 / Operator Dev Loop，不是 API 百科 |
| Last verified | 2026-09-08 |
