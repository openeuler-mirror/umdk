---
name: cam-operator-run
description: NPU 算子上板迭代状态机。改了 kernel 要测、编译安装跑、507xxx 还不能先怪核、何时才允许上 profiler 时使用。禁止写完就跑完整 e2e。
---

# Operator Iteration Skill

status: **accepted**

本 Skill 是 **上板强制状态机**。决定按什么顺序冻结、编译、安装、确认加载、跑哪一级测试、何时才允许怀疑 kernel、何时才允许上 profiler。

不是 API 百科，不是排障假说树，不是性能手册。

```text
写核          → cam-operator-development
上板验证      → 本 Skill（未走完分层不得跳走）
本层已失败、要归因 → cam-operator-debug（必须带着 FIRST BAD L）
L8 已过、只要快慢 → cam-operator-optimization
打点 / TRACE   → instrumentation（本 Skill 未到 L8 不得当主路径）
```

细则只读 [on-device](../../../../knowledge/cam/engineering/npu-on-device-validation.md)。

---

## 1. Entry

进这里：人在 NPU / 内网，要验证刚写或刚改的算子；或用户说“编译安装跑一下 / 帮我测一下”。

立刻转走：

| 情况 | 走 |
| --- | --- |
| 还在写核、没要求上板 | [cam-operator-development](../cam-operator-development/SKILL.md) |
| 已有 ITERATION 卡，本层失败要排假说 | [cam-operator-debug](../cam-operator-debug/SKILL.md) |
| Functional + Stability（无 profiler）已过，只要加速比 | [cam-operator-optimization](../cam-operator-optimization/SKILL.md) |

蓝区无 NPU：只冻结 manifest、设计下一层检查。Runtime 标 **未测**。不要要求 `npu-smi`。

```text
用户说测一下
  ≠
允许直接跑目标 4 卡 + golden + msprof
```

---

## 2. 状态机（禁止跳级）

一轮只许处在其中一个阶段。未 PASS 的阶段，禁止用更后阶段的假说改代码或上 profiler。
进入 02 Build 时，构建命令、参数与产物路径见
[cam-build](../../cam-build/SKILL.md)；本 Skill 只规定验证顺序和通过门槛。

```text
01 Freeze     commit / 一棵树 / python / CANN / 卡 / harness / feature
02 Build      这次改动对应的 tiling/kernel 是否真的重编
03 Install    精确 OPP 路径；set_env；子进程看得到
04 Load       运行时加载的是这份 artifact（mtime / path / op 名）
05 L0–L2      Python / NPU basic / registration+tiling alive
06 L3–L5      单卡 kernel smoke → HCCL/IPC smoke → 2-rank
07 L6         目标 rank（如 4 卡）；先隔离无关路径
08 L7         golden / SmallOps；此时才比精度
09 L8         20+100（或合同次数）；无 profiler、无 debug print；新 flag 协议至少 2 launch
10 L9         profiler / 性能；known-good binary
11 Triage     仅当某 L 失败：填 FIRST BAD，再进 debug
12 Patch      一张证据卡、一处改动，从 03/04 再走
```

```text
end-to-end test
  ≠
第一定位工具

synchronize 报错的那一行
  ≠
fault location

export FEATURE=1
  ≠
Host 已 admitted

静态“看起来有竞态”
  ≠
可以 patch

profiler
  ≠
correctness debugger
```

仓内若已有 `env_check` / 上板脚本：一次性跑完 01–05。没有就按 Knowledge 仪式做完。禁止边猜边装。

---

## 3. ITERATION 卡（每轮必须能看见）

没这张卡，不许宣布“环境坏了 / kernel hang / 该上 profiler”。

```text
[ITERATION nn]

BINARY
  BUILD ID / OP COMMIT / TEST COMMIT / LOADED OPP

PHASE         Freeze|Build|Install|Load|L0..L9|Triage|Patch
LAST PASS     L?     （绑定上面这份 BINARY；换 binary 则作废）
FIRST BAD     L?  op?  （未知就不许猜 kernel）
ADMITTED      tiling 打印的字段，不是 env
PROFILER      OFF|ON   （L8 前必须 OFF）
NEXT          下一层最小命令
CHANGED       本轮只许一个主变量，见 §3.1
DIAGNOSTIC    YES | NON-DIAGNOSTIC
```

六个工作字段够用：**PHASE / LAST PASS / FIRST BAD L / ADMITTED / PROFILER / NEXT**。  
**FIRST BAD L** 防错归因。**ADMITTED** 防“以为测了 feature，Host 其实 FALLBACK”。  
**BINARY** 和 **DIAGNOSTIC** 是资格：谁的 PASS、这份结果能不能当根因。

结果落到一次 run 目录（有则用之，无则 `/tmp/runs/<id>/`）：

```text
manifest.txt
stdout.log
npu_smi.txt
```

### 3.1 两条硬 invariant

**Binary identity。** 源码改的是 A、加载的是 B，是 NPU 上最脏的一类失败。卡上必须能对上：

```text
BUILD ID / OP COMMIT / TEST COMMIT / LOADED OPP
```

`LOADED OPP` 是运行时路径 + `.o` mtime（或等价），不是“刚才编过”。任一项相对上一张卡变化：

```text
L2+ LAST PASS 全部失效
必须回到 Install → Load
禁止继承旧 PASS 当下层证据
```

**One-variable。** 证据卡之后的实验，默认只改下面其中一个主变量：

```text
device / world_size / shape / feature flag / binary / profiler
```

一次改两个及以上：卡必须标 **NON-DIAGNOSTIC**。结果只许探索，**不许**写成根因、不许当 A/B 证明、不许用来怀疑 kernel。要下结论，拆成只改一个变量的下一轮。

---

## 4. 测试对象分层

完整定义见 Knowledge。这里只定 **归因权**：

| 最高已 PASS | 允许怀疑 | 仍禁止 |
| --- | --- | --- |
| < L2 | 环境 / 安装 / 加载 | kernel 协议、IPC 布局 |
| L2 | tiling / 注册 | 多卡协议 |
| L3 | 单卡 kernel | HCCL、PR 不兼容 |
| L4–L5 | 通信 / 2-rank | 目标 4 卡配置当第一证据 |
| L6 且 Host admitted 且 A/B 特性开才坏 | **本算子 / 本特性** | 顺便改 harness、上 profiler |
| L7 | 精度 / golden 数学 | hang 协议 |
| L8 无 profiler 过、L9 才坏 | profiler / 超时 / 性能合同 | 回头改 publication |

L6 挂了但 L3–L5 没跑：你 **没有** 定位信息。回去补层，不要改核。

`bypass_small_check`（或仓内等价）以源码为准：先读它跳过对比还是连参照都不跑。隔离 FusionOp 是 L6 的合法最小测试，不是跳过 L3–L5。

---

## 5. 何时允许怀疑 kernel

必须同时成立：

```text
1. Load 已证明是这份 OPP
2. FIRST BAD ≥ L3，且失败发生在本算子启动之后（fused warmup 或等价）
3. Host admitted 已打印（不是 env）
4. 同卡同 manifest A/B：关特性不坏、开特性才坏
     或 该层本来就没有特性开关
```

否则 FIRST BAD 停在更早层。`507014` / `507015` / `npuSynchronizeDevice` **不是** 允许怀疑 kernel 的充分条件。

Python 栈只回答错误 **收回来的位置**。见 Knowledge「异步定位」。

---

## 6. 何时允许上 profiler

必须同时成立：

```text
L7 functional 已过（或用户明确只要性能、且 L6 已短跑通）
L8 stability 已在无 profiler 下过
binary / shape / rank / feature 与 L8 同一份 manifest
PROFILER 从 OFF 显式改为 ON
```

大 bs + 长 iter + msprof **禁止** 作为第一趟。profiler 改变运行行为；超时先做「同配置无 profiler」决定性实验。

---

## 7. Patch 门槛

怀疑 kernel 之后、改语句之前，必须写出：

```text
Hypothesis:
Evidence for:
Evidence against:
Observable:          运行时能打印的事实，禁止用推测值
Minimal test:
Expected A / B:
```

`aicNum` / `aivNum` / `roundNum` / tiling key / window / offset / token counts / `dataState`：**先 dump，再算洞、再谈 FALLBACK**。

一张假说、一处改动。改完 BINARY 变了：L2+ 作废，从 **Install → Load** 再走。禁止把上一份 binary 的 PASS 带到新包。

实验装置本身必须先活：`python -c` + `mp.spawn` 不能 pickle 时，那是装置坏了，不是 HCCL 结论。

---

## 8. Decision Rules

```text
MUST     上板第一动作是发出 ITERATION 卡（或读出已有卡）
MUST     一层 PASS 才进入下一层
MUST     改核 / 换 OPP 后重做 Install → Load；L2+ PASS 不得跨 BINARY 继承
MUST     能打印的 runtime fact 先 dump，再推导
MUST     证据卡之后一次只改一个主变量；否则标 NON-DIAGNOSTIC
MUST NOT 写完核就跑目标 shape 完整测试
MUST NOT 用 NON-DIAGNOSTIC run 下根因结论
MUST NOT 同时改 operator + harness + worktree
MUST NOT 用完整 e2e 当第一 locators
MUST NOT 把 synchronize / 507014 / 507015 当成 fault 行号
MUST NOT L3–L5 未跑就宣布 PR 不兼容 / HCCL 不认 visible devices / 新协议 hang
MUST NOT 静态“看起来有竞态”就 patch
MUST NOT L8 未过（无 profiler）就上 msprof / 打点当主路径
MUST NOT 把新 flag 协议的第一发 PASS 当成 L8 leftover-safe
MUST NOT 无 NPU 时要求 npu-smi 才能设计下一层检查

IF 用户说「改了 dispatch，帮我测一下」
THEN 从 01 Freeze 进本 Skill；MUST NOT 直接 build + 完整测试

IF 某 L 失败且卡已填 FIRST BAD
THEN 进 cam-operator-debug；诊断不得丢掉层号

IF Host 未 admitted
THEN 你在调 baseline；MUST NOT 按新特性改 publication

IF 实验装置（探活脚本 / pickle / 可见设备）未自证
THEN MUST NOT 推出硬件或通信结论

IF BUILD ID / OP COMMIT / TEST COMMIT / LOADED OPP 任一变化
THEN L2+ LAST PASS 失效；PHASE = Install

IF 本轮改了两个及以上主变量
THEN DIAGNOSTIC = NON-DIAGNOSTIC；MUST NOT 当根因
```

---

## 9. Output

回复必须能让人 10 秒内看见 ITERATION 卡：PHASE、LAST PASS、FIRST BAD、ADMITTED、PROFILER、NEXT，以及 BINARY 与 DIAGNOSTIC。

不要在本页展开 DataCopy / HardEvent / HCCL 百科。需要层定义、异步语义、manifest 字段、证据卡样例：读 Knowledge。
