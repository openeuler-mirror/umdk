---
name: cam-operator-debug
description: 诊断 CAM AscendC 算子的编译、加载、运行时、结果错误、Hang 和多卡通信故障。已通过 cam-operator-run 定位 FIRST BAD 层后使用；正确性未过时由本 Skill 主导，性能问题转 cam-operator-optimization。
---

# Operator Debug Skill

status: **accepted**

本 Skill 是 **路由器**。遇到算子失败时，按诊断循环走完一轮，再决定改哪一处。不要把它当成排障百科，也不要并行打开四套流程。

上板还没有 ITERATION 卡 / 不知道 FIRST BAD 在哪一层：先回 [cam-operator-run](../cam-operator-run/SKILL.md) 补层，不要在这里发明完整 e2e。

API / 资源事实只读已 `accepted` 的 Knowledge。调试排序是 `recommendation`，不能覆盖 Card。

```text
debug heuristic
  cannot override
accepted API contract
```

---

## 1. 诊断循环

```text
symptom
  → classify（本轮一个 primary route）
  → collect evidence
  → form ranked hypotheses
  → smallest discriminating check
  → fix
  → retest
```

还不能分桶：先问跑完了没有、返回码是什么、输出长什么样。  
还没有可重复的 failure contract：先固定下来，再改代码。优先缩成最小复现；缩不小也至少固定 code identity / command / shape·dtype·inputs / environment / failing observation。  
检查区分不了两条假说：换更小的检查，不要同时改两处。

新证据改变“是否跑完 / 返回码 / 是否还在跑”时，**重新 classify**。  
每轮仍然只走一个 primary route。

```text
one primary route at a time
  ≠
classification is immutable
```

---

## 2. 五条边界

```text
symptom        ≠ root cause
error code     ≠ root cause
hypothesis     ≠ Knowledge fact
fix            ≠ validation
blind retry    ≠ debugging
```

- 全 0 / 随机 / 507035 / “精度不对” 都只是症状或入口，不是根因。
- 编译通过 ≠ 修好了。最小 case 变对 ≠ 原失败场景都解决了。
- 没有新观察：停止同质修改，切二分 / dump / instrumentation。不要数“试了几次”。
- 改完必须 retest：同一条 failure contract + 至少一条原先失败用例（若有）。
- 蓝区无 NPU：可以 classify / 排假说 / 做代码检查；Runtime 标 **未测**。不要要求先过 `npu-smi`。
- **已经在 NPU 机器上要跑**：走 [cam-operator-run](../cam-operator-run/SKILL.md) 状态机；层定义读 [on-device](../../../../knowledge/cam/engineering/npu-on-device-validation.md)。占卡 / HCCL / Host 未放行，不要进新 kernel 假说。
- `synchronize` / 507014 / 507015 只是把前面异步 trap 收回来。Python 栈 ≠ fault location。

---

## 3. Classify

用户说“精度不对”但没跑完或返回码非 0，**不要进 wrong-result**。  
表面 timeout、设备一直不结束 → 改走 **hang**。

| 桶 | 判定（够用就停） | primary route |
| --- | --- | --- |
| compile / load / runtime error | 编译失败；找不到 kernel / `.so`；aclnn / aclrt 非 0；507035 经 stream sync 回来 | `runtime-error` |
| wrong result | kernel **跑完**，输出错（全 0、随机、NaN、rtol 挂、tail 少、看起来算错） | `wrong-result` |
| hang | 不结束、超时、507046、核无响应 | `hang` |
| crash | Segfault / Abort / 进程被杀 | `crash` |

```text
wrong result
  ≠
precision problem
```

性能差交给 `cam-operator-optimization`。多卡通信 hang 先读 [MC2 coupling](../../../../knowledge/cam/engineering/mc2-compute-collective-coupling.md)。SIMT 不进默认树。

`runtime-error` 前两支是 compile / load，本 Skill 不另开 env 手册。上板怎么选卡、装包、分层：只读 [on-device](../../../../knowledge/cam/engineering/npu-on-device-validation.md)。

错误码只是 **routing hint**。未核到该 CANN 版本官方文档前，不要把 161/361/507014/507015/507035/507046/561002/561003 写成永久 taxonomy。

上板且出现 `507015` / `507014` / `npuSynchronizeDevice` device error 时，**先填 ITERATION 卡的 FIRST BAD L**（L0–L9），再选本表的桶。还没有本算子 warmup 就不要把新 kernel 当 primary。Python 行号不是核内位置。

---

## 4. 四条路径

### `runtime-error`

先取 `aclGetRecentErrMsg` / 已有 plog，再排假说。不要从码号跳到补丁。

| 入口 | 假说往哪排 | 禁止写成 |
| --- | --- | --- |
| 161xxx | 参数 / dtype / shape / nullptr | “改某一个字段就好” |
| 361xxx | runtime / 设备 / 环境 | “环境坏了” |
| 507035 | 访存 / buffer / 对齐 / copy shape | “一定是 Pad 没 32B 或 UB overflow” |
| 561002 | TilingKey / TilingFunc / 不支持组合 | “tiling 公式错了” |
| 561003 | 安装 / vendor / SEL / SOC | vLLM 选了另一条 kernel（读 [delivery](../../../../knowledge/cam/engineering/custom-op-delivery-call-and-selected-path.md)） |
| 507046 | 先按 hang 重新 classify | 和 507035 同一个病 |

507035 必须回读 [copy Card](../../../../knowledge/cam/memory/memory-copy-and-alignment.md)：先分清 DataCopy vs Pad、`blockLen` 单位、UB 起址 / 行偏移、effective vs aligned。  
**不要**把 DataCopy 的 32B 长度合同套到 `DataCopyPad.blockLen`。

### `wrong-result`

kernel 已跑完。按下面族排序，**不要一上来改 dtype / Cast / tolerance**。

```text
wrong-result
  ├─ data movement / ordering
  ├─ indexing / layout / tail
  ├─ tiling / bounds
  ├─ formula / logic
  └─ numerical / dtype / precision
```

全 0 / 随机：优先假说是跨流水 readiness，然后 32B / effective vs aligned，然后 Get/SetValue 当了生产搬运。这是排序，不是诊断。见 [pipeline](../../../../knowledge/cam/synchronization/pipeline-events-and-ordering.md)。

`CopyIn → CopyOut`（不做 Compute）若对：

```text
可降权：GM/UB 地址、Copy 参数、effective/aligned、基本搬运
可升权：Vector Compute / 公式 / dtype
不降权：MTE2→V / V→MTE3 readiness
```

该实验把 `MTE2 → V → MTE3` 收成了 `MTE2 → MTE3`，覆盖不了原 kernel 的跨流水合同。

跨 pipe dependency 必须被显式表达。普通 Vector 优先 TQue `EnQue`/`DeQue`；手写 `SetFlag`/`WaitFlag` 是另一条合法机制。`PIPE_ALL` 只当判别实验，用完拆掉。

容差：读 [tolerance-source](../../../../knowledge/cam/engineering/tolerance-source.md)。Plan 只覆盖任务验收，不能用来声称符合官方标准。API 合同未知时才走 [cam-operator-docs-search](../cam-operator-docs-search/SKILL.md)，不是第 0 步仪式。算子参数/数据流协议不清时，让 [cam-operator-spec-reconstruction](../cam-operator-spec-reconstruction/SKILL.md) 供 evidence；诊断仍由本 Skill 主导。

### `hang`

优先假说：`Alloc`/`Free` 不成对、跨流水合同不成对、核内 outer loop / 等不到的 flag。  
不是“卡死 = 没 Free”。AIC+AIV / 通信再链 MC2，不要把 CrossCore 写进普通 Vector 默认树。

远程 completion / flag **收不齐死等** 时，先拆假说，不要先改协议语义：

```text
1. publisher 发出的字是否真的落到对端
   （inner loop DataCopyPad 源 UB 被下一轮 SetValue 覆盖 → ）
2. waiter 的 expected 粒度是否等于 publisher 的 publish 粒度
   （slice overlap skip vs group-end 整桶 DONE → 假阴性 skip 或永远对不上）
3. 下一发看到的字是不是这一发的 publish
   （one-shot leftover / 后级 payload 踩 handshake → 假就绪 → ）
```

完成字 / flag 自旋收不齐时，**先查 publisher 侧 UB 生命周期，再查跨 launch leftover，再查协议**：

| 假说 | 什么时候升权 | 不要先改 |
| --- | --- | --- |
| loop-carried UB reuse | `SetValue` → `DataCopyPad` → 同一 UB 再 `SetValue`，迭代间无 `MTE3_S` | 加更多 remote flag、改 expected 公式 |
| completion grain mismatch | publisher 按 group/bucket 写一次；waiter 用 recv slice overlap 决定等不等 | 把 per-slot 检测套到 group-end 信号上 |
| leftover / false-ready | **第一发过、第二发 hang**；handshake overlay 在后级 payload；flag 不 consume / 不双 bank / 不清平面 | 加 flag、改 Classify、扩 IPC |

细则：[pipeline](../../../../knowledge/cam/synchronization/pipeline-events-and-ordering.md)；[adversarial statics §8](../../../../knowledge/cam/engineering/implementation-adversarial-statics.md)。

`507014` 还要先排除：Host 已 FALLBACK 到 baseline、`timeout` 没杀干净子进程、长 iter + msprof 触发默认 aicore watchdog。高 util 长时间 ≠ 死锁。见 [on-device](../../../../knowledge/cam/engineering/npu-on-device-validation.md)。

### `crash`

Segfault / Abort：优先保留 coredump，并用 GDB 定位 Host / runtime 崩溃位置。  
怀疑偶发越界 / 多核踩踏：mssanitizer 是候选手段。  
先确认进程死了，再走这条；507035 经 stream sync 回来仍是 `runtime-error`。

```text
tool
  ≠
diagnosis
```

---

## 5. 先读哪张 Knowledge

| 在查 | 读 | 不要在这里再发明 |
| --- | --- | --- |
| UB / 核数是否抄死 | [hierarchy](../../../../knowledge/cam/hardware/ascend950/core-and-memory-hierarchy.md) | “950 UB = 248KB” |
| tile / buffer / 对齐回传 | [tiling-from-shape](../../../../knowledge/cam/engineering/tiling-from-shape.md) | 新的切分手册 |
| DataCopy vs Pad、effective vs aligned | [copy](../../../../knowledge/cam/memory/memory-copy-and-alignment.md) | “Pad.blockLen 必须 32B” |
| readiness / ordering | [pipeline](../../../../knowledge/cam/synchronization/pipeline-events-and-ordering.md) | “全 0 = 同步” |
| `num`≠`depth`、Alloc/Free | [TQue/TBuf](../../../../knowledge/cam/memory/ub-tque-tbuf-and-double-buffer.md) | hang = 没 Free |
| silently 错、repeat 截断 | [mask-repeat](../../../../knowledge/cam/ascendc/vector/mask-repeat-and-kernel-limits.md) | “Level-0 一拍一定 256B” |
| 561003 vs 选路 | [delivery](../../../../knowledge/cam/engineering/custom-op-delivery-call-and-selected-path.md) | kernel not found = 选错 op |
| 上板分层 / 异步 507xxx / runtime facts | [on-device](../../../../knowledge/cam/engineering/npu-on-device-validation.md) · [iteration](../cam-operator-run/SKILL.md) | 507015 = 新 kernel hang；推测 aicNum；完整 e2e 当第一 locator |
| 第一发过、第二发 hang / leftover flag | [adversarial statics §8](../../../../knowledge/cam/engineering/implementation-adversarial-statics.md) | “加 flag / 改 Classify” |

超限 / 不对齐 / API 不合法：回到 tiling 的 **revise**，或 kernel 内加 outer loop。不要只改一个魔法常数。

---

## 6. Decision Rules

```text
MUST     先 classify，再取证，再排假说
MUST     先冻结当前可重复的 failure contract，再改代码
         （优先最小复现；暂时缩不小，至少固定 code identity /
          command / shape·dtype·inputs / environment / failing observation）
MUST     一次只做一个可判别检查
MUST     改完 retest
MUST NOT 把症状表或错误码写成根因
MUST NOT 为排障改写 accepted Knowledge
MUST NOT 无信息增益时继续同质修改
MUST NOT 无 NPU 时要求 npu-smi 才能思考
MUST NOT 上板没有 ITERATION 卡 / FIRST BAD L 就把 507014/507015 写成新 kernel hang
MUST NOT 把 synchronize 的 Python 行号当成 kernel fault location
MUST NOT 用推测的 aicNum / window / offset 推导根因；先 dump
MUST NOT 静态“看起来有竞态”且没有 Observable 就 patch
MUST NOT 把上一份 BINARY 的 L2+ PASS 带到新 OPP
MUST NOT 用 NON-DIAGNOSTIC（一次改两个及以上主变量）的 run 当下根因
MUST NOT 把旧成功日志的 HCCL_BUFFSIZE / 卡号 / conda / harness 当成本次机器合同
MUST NOT 在 Host 未 admitted 或 FIRST BAD < L3 时，扩 IPC / 改 publication / 清双 bank
MUST NOT 第一发过就把新 flag 协议当成 leftover-safe；第二发 hang 先查 leftover / 假就绪，不要先加 flag

IF 没跑完或返回码非 0
THEN 不进 wrong-result

IF 全 0 / 随机
THEN readiness → 对齐 → Get/SetValue   （recommendation）

IF 507035
THEN 访存 / buffer / 对齐 / copy-shape 假说树
THEN 只读 copy Card 核单位；MUST NOT 套“Pad.blockLen=32B”

IF 561003
THEN 安装 / SEL / vendor / SOC
THEN MUST NOT 写成 vLLM 选路

IF 改完输出完全不变
THEN 先检验二进制是否更新（cache 是假说，不是第 0 步仪式）

IF 连续步骤没有新观察
THEN 停试错，切二分 / dump / 或让 [instrumentation](../cam-operator-instrumentation/SKILL.md) 供阶段 timing evidence
     （诊断仍由本 Skill 主导；打点不解释根因）

IF hang 且第一发过、第二发起不来
THEN leftover / false-ready 升权；MUST NOT 先改 Classify 或加 remote flag

IF 人在 NPU 机器上且是 507014 / 507015 / device error
THEN 先补 [iteration](../cam-operator-run/SKILL.md) 卡（FIRST BAD L）
THEN MUST NOT 在本算子未启动或 Host 未 admitted 时改 publication

IF 要改 kernel 语句
THEN 先交证据卡（Hypothesis / Observable / Expected A/B）；没有 Observable 只许设计检查
```

plog / DumpTensor / GDB / mssanitizer / 清 cache 都是 **手段**，按当前路径需要再打开。步骤不要堆在本文件。

路径细则以后按需放 `references/runtime-error.md`、`wrong-result.md`、`hang.md`、`crash.md`。现在缺文件就直接读上表 Knowledge。

跨安全域怎么搬代码、日志和 patch：见 [correctness-debug workflow](../../../../workflows/cam/operator/correctness-debug/README.md)。诊断本身仍走本 Skill。
