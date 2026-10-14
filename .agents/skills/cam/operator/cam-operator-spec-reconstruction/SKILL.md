---
name: cam-operator-spec-reconstruction
description: 无可靠设计文档时，从调用链、测试/golden、tiling 与 kernel 交叉重建可开发的 Operator Contract。先冻结 R0 Target Context（repo/commit/mode/硬件）。用户要写新算子但只有仓库/论文/接口名、或参数语义不清时使用。不要从 kernel 第一行硬啃；不要把变量名写成事实。
---

# Operator Spec Reconstruction

status: **accepted**

本 Skill 是 **语义重建工序**。没有可靠设计文档时，从代码、测试、调用链和运行协议交叉证明，产出一份 **可开发的 Operator Contract**。

不是检索 CANN API，也不是开始写核。

```text
cam-operator-docs-search
  = 某个 API / 头文件 / CANN 版本的合同是什么

cam-operator-spec-reconstruction
  = 这个算子做什么；每个参数/tensor 的语义、顺序、约束是什么

读过源码
  ≠
重建了合同

变量名
  ≠
参数语义

evidence is valid
  ≠
evidence is applicable to this target

同一条调用链上的透传
  ≠
独立证据

当前实现的 shape / workspace
  ≠
逻辑约束

paper 公式
  ≠
这个仓库的 tensor 协议
```

---

## 什么时候用

- 要开发或移植一个算子，但没有可靠设计文档（只有仓库、论文、issue、接口名）
- 用户或 Agent 说不清某个输入是什么、index 指谁、rank 之间什么关系
- [cam-operator-development](../cam-operator-development/SKILL.md) 还缺 Purpose / I/O / 数据生命周期
- [cam-operator-debug](../cam-operator-debug/SKILL.md) 需要核对「这个 tensor 按协议应该是什么」，而不是已经在查 API 单位

```text
correctness / API 合同未知
  → cam-operator-docs-search

算子语义 / 参数协议未知
  → 本 Skill

无 blocking unknown，只缺怎么切 tile / 怎么写核
  → cam-operator-development
```

---

## 什么时候不要当 primary route

- 用户已经给出完整、可开发的语义（Purpose / I/O / shape / index / 数学式），且与现有调用一致
- 只问 `DataCopyPad` / `TQue` / 某个 CANN overload → [cam-operator-docs-search](../cam-operator-docs-search/SKILL.md)
- 已经在跑、返回码非 0、结果错 → [cam-operator-debug](../cam-operator-debug/SKILL.md) 主导；需要协议对照时再叫本 Skill 取证
- 正确性已过、要解释快慢 → [cam-operator-optimization](../cam-operator-optimization/SKILL.md)

不要用本 Skill 写 AscendC，也不要把重建结果写进 `knowledge/`。当次 Contract 是 **目标工程的任务产物**，不是 Weaver Card。默认落到：

```text
<target-repo>/docs/ascendweaver/<operator>_operator_contract.md
```

目标仓没有 `docs/` 惯例时用 `<target-repo>/.ascendweaver/<operator>_operator_contract.md`。回复里仍须给出全文；跨会话 / 跨安全域以落盘文件为准。

---

## R0 — Target Context

开始收集证据前先冻结本轮目标。缺 R0 不得升 fact。

```text
Target Context

source:
  repo:
  local_path:
  branch:
  commit:

target:
  operator:
  call surface:     Python / torch.ops / aclnn / ...
  mode / variant:   本轮实现的那一条，不是仓库里所有模式
  hardware:
  CANN version:

scope:
  本轮支持什么
  明确不支持什么

reference:
  primary caller:
  primary test/golden:
```

```text
MoonEP main@abc / normal combine / Ascend950
  与
MoonEP old@xyz / low_latency / CUDA
  不能直接交叉投票
```

另一 commit、另一 mode、另一硬件、GPU reference 上的观察可以当 **contrast**，不得当作本轮 fact 的第二票。

### Target environment resolution

`hardware` / `CANN version` / runtime environment 必须来自任务合同，不能从「仓库现在能编什么」推断。

权威来源（有则冻结；按优先级，后者不得覆盖前者除非用户改口）：

```text
1. 用户明确需求
2. 本任务明确设计文档 / Plan
3. 当前目标分支针对该任务的显式 build / CI contract
```

以下只能当 evidence / reference，**不能单独冻结 target**：

```text
- repo 默认 SOC
- sibling operator 的 SOC / UB / AIC/AIV 常量
- 当前 shell 默认 CANN
- 历史实现环境
- 可用的某个 container
```

```text
repo supports X
  ≠
this operator targets X

sibling kernel hardware constants
  ≠
this operator hardware contract
```

缺权威来源时，`hardware` / `CANN` 保持 **unknown**，不得升 fact。不要把「工程默认 A2、可选 Ascend950」写成「本次目标 = A2」。

CANN 具体 patch 必须在声明的编译容器里读 `version.info` / `version.cfg` / `ascend_toolkit_install.info` 冻结，不要口头写成 `9.1.0`。

```text
IF target SOC / CANN 会影响
   API legality / memory hierarchy / synchronization /
   tiling / compile path
AND target environment 仍 unknown
THEN environment 是 blocking unknown
     不得进入 Design Proposal / Gate A
```

---

## 证据等级

每一条声称必须落在 `fact` / `inference` / `unknown` 之一。禁止把「我觉得」写成陈述句。不另标 confidence；强弱写在证据里。

```text
fact
  = authoritative first-party contract / reference semantics
    OR
    ≥2 independent implementation evidences agree
  AND
    no unresolved contradiction

inference
  = 只有单一实现观察，且它本身并不定义语义
    或多处弱证据同向

unknown
  = 仅名字 / 注释 / 论文映射猜测
    或证据冲突未解决
```

| 档 | 才能怎么用 |
| --- | --- |
| **fact** | 可写入 Inputs / Outputs / 数学语义，当作实现合同 |
| **inference** | 可写入合同，但必须标 `inference`，并写缺哪类证据 |
| **unknown** | 必须进 Unknowns，并标 blocking / non-blocking |

一手 contract 的例子：对外接口规范写明 `src_idx[i] = original token index`；或仓库里 **golden 本身就是** reference semantics（例如 `out[src_idx[i]] += expert_out[i] * weight[i]`，且没有另一份定义）。这种 **一处也可以是 fact**。

kernel 里「这个 buffer 被读成 `[N,H]`」如果没说明 N 是谁，只是实现观察 → 最多 `inference`。

冲突时 **分别记录**，不要选一个更顺手的写成 fact。证据写到文件与符号，不要写「源码里看到的」。

人工设计文档（`docs/*`、用户指定 spec）**文件默认不可改**，但其中的句子仍要分级：

```text
immutable human file
  ≠
every sentence is a frozen design constraint

ABI / semantic freeze     → fact（实现必须满足）
implementation sketch     → 可偏离，记 Design Proposal
example / historical note → 不是 ABI
```

不得把 sketch 升成 fact，也不得为了和实现一致去改该文件。

### 独立证据

独立证据 = **不同语义角色**对同一结论提供约束，不是同一个值沿调用链被机械透传。

```text
独立（可交叉）
  wrapper shape + golden 数学使用
  kernel index 用法 + 下游消费者如何解释
  producer contract + consumer contract

不独立（一条 provenance chain）
  Python wrapper → C++ binding → kernel 参数列表
  若只是原样传参，算一票，不是三票
```

两个 `.cpp` 文件 ≠ 两处独立证据。

### blocking vs non-blocking unknown

Unknowns 必须再分成两档。不是「有 unknown 就不能写核」。

**blocking unknown** — 会影响当前目标路径的：

- 数学语义
- I/O shape
- index ownership
- memory safety
- distributed protocol
- correctness

→ **不得**开始实现。

**non-blocking unknown** — 与当前目标路径无关，或可以在 contract 里明确固定 scope 排除（例如某 reserve 字段仅另一 mode 使用；某 workspace 字段名字来源不清，但 shape / ownership / 读写协议已恢复）。

→ 可以开始实现，但必须记录 **assumption / scope**。不得把 non-blocking 默默当成 fact。

---

## 默认 evidence traversal（①→⑦）

不要只读 kernel。①→⑦ 是 **默认遍历顺序**，不是强制的文件访问顺序。

入口缺失时，允许从已知锚点反向或正向追踪（例如只有 kernel symbol → grep binding → 再找到 Python；或测试直接给 C++ API、没有 Python wrapper）。

某步没有材料就标 **未找到**。最终 **R0–R6** 所需证据必须补齐或明确未找到。

真正强制的是：

```text
不要只读 kernel
必须建立 caller / consumer / lifecycle evidence
```

```text
① 入口
   Python / torch.ops / aclnn / 对外 API

        ↓

② 调用者与消费者
   谁构造输入？谁消费输出？下游 shape 是什么？

        ↓

③ Test / Golden
   最容易恢复数学语义。优先读 golden、参考实现、数值对照，而不是注释。

        ↓

④ Shape / Tiling / Host
   哪些是逻辑关系（T、K、H、num_recv），哪些只是这次实现的对齐/workspace。

        ↓

⑤ Kernel
   真实数据流、index 计算、通信/workspace 协议。

        ↓

⑥ 相邻算子
   Dispatch ↔ Expert ↔ Combine（或等价前后级）。先恢复生命周期。

        ↓

⑦ 交叉验证
   同一结论尽量找到不同语义角色的约束。升 fact 前对一下是否冲突。
```

MoE / EP / 通算类：

```text
先重建数据生命周期
  再读 kernel
```

生命周期没写出来，不得开始写 Combine / Dispatch / 通信核。

---

## 交叉证明链

对每个关键参数沿这条链找证据。链上的透传只算同一 provenance；要交叉，去 golden / 消费者 / 另一角色。

```text
Python call
    ↓
framework wrapper
    ↓
C++ binding
    ↓
Host op / tiling
    ↓
kernel entry
    ↓
communication / workspace protocol
    ↓
test / golden / 下游消费者
```

记录格式（示例，**不是**某个仓库的冻结事实）：

```text
参数: <name>
shape/dtype: …
当前推断语义: …
档: fact | inference | unknown
unknown_kind: blocking | non-blocking | n/a
evidence:
  wrapper: path + 符号
  kernel:  path + 怎么被读/写
  test:    golden 怎么用它
  downstream: 输出如何被消费
冲突: 无 | 列出
```

---

## Semantic Dataflow（必出）

Operator Contract 之前，先写出 **一个 token / 一条样本** 怎么走完整条链路。

单机 topk 示例（只说明图该长什么样）：

```text
token t
  ├── expert e0  →  routed row r0  →  expert_out[r0]
  └── expert e1  →  routed row r1  →  expert_out[r1]

out[t] = Σ_k weight[t,k] * expert_out[r_k]
```

有 EP / 多 rank 证据时再扩展，**不要**无证据补 rank 协议：

```text
logical token
    ↓
expert ownership
    ↓
destination rank
    ↓
rank-local receive slot
    ↓
expert compute
    ↓
return slot
    ↓
original token order
```

```text
画出了 kernel 里的 offset
  ≠
重建了数据生命周期
```

---

## 必须产出的 Operator Contract

回复和落盘文件必须先有 **Target Context（R0）**，再包含下面 14 块。缺一块就写 **未重建**，不要留空假装没有。

1. Purpose
2. Mathematical / logical semantics
3. Inputs
4. Outputs
5. Shape relations
6. Dtype contracts
7. Data layout / ordering
8. Index semantics
9. Distributed semantics
10. State / workspace / communication protocol
11. Dynamic constraints
12. Reference implementation / golden
13. Unknowns（每条标 blocking / non-blocking + 理由）
14. Evidence map

参数表必须能区分「现在推断」和「证据」：

| 参数 | shape/dtype | 当前推断语义 | 档 | 证据 |
| --- | --- | --- | --- | --- |
| x | [T,H] bf16 | 原 token hidden | fact | golden 公式（reference semantics） |
| foo | … | 可能是 rank-local offset | unknown / non-blocking | 仅名字，一处使用；当前 mode 不用 |

Shape 要分开写：

```text
逻辑约束     例如 out 行数 = 原 token 数
实现约束     例如 workspace 按这次 tiling 对齐到 512
动态约束     例如 num_recv 随 rank/专家分布变化
```

Distributed / workspace：没有通信或 workspace 证据，写 **无 / 未找到**，不要从「这是 MoE」推一套协议。

写 Mathematical / logical semantics 时必须分层：

```text
logical / golden
  = 实现无关的数学结果（对谁求和、decode 什么）

factorization
  = 某条实现如何拆成 prologue / skip / partial reduction
    它实现同一逻辑和，但不是 golden 的定义

logical equivalence
  ≠
finite-precision execution equivalence

(a+b)+(c+d) = a+b+c+d
  只是实数代数
  中间 bf16/fp16 cast、split-K、跨 rank 分段归约、fusion/unfusion
  都可以插入 rounding boundary
  不得据此写成 bitwise / 数值严格等价
```

正确性验收走任务/参考的 tolerance 合同，见 [tolerance-source](../../../../knowledge/cam/engineering/tolerance-source.md)。

```text
Operator Contract freeze
  = semantic contract + unresolved semantic facts

NPU transport / launch / UB / barrier / ABI freeze
  = Design Proposal

Contract freeze 不应持有会被 Design Proposal 决策关闭的
implementation-state truth（选哪条 barrier、block_dim、packed vs two-pointer）。
否则同一个事实两个 owner，Design 更新后 Contract 必 stale。
```

---

## 门禁 R0–R6

R0–R6 是 **本 Skill 重建工序** 的闭环，不是所有源码阅读的通用方法。

| | 必须 |
| --- | --- |
| **R0** | Target Context 已冻结（repo / branch / commit / operator / mode / hardware / CANN / primary caller·golden）。hardware / CANN 必须来自用户需求、本任务 Plan、或该任务的显式 build/CI contract；repo 默认 / sibling / 当前 shell 不能单独冻结 target |
| **R1** | 入口与调用者已定位，或明确 **未找到**；不是只读 kernel 做总结 |
| **R2** | 已写出 Semantic Dataflow，或明确写「生命周期未重建」 |
| **R3** | 合同里每条参数都有 `fact` / `inference` / `unknown` + 证据；unknown 标 blocking / non-blocking |
| **R4** | 标成 **fact** 的项：有 authoritative first-party contract / reference semantics，**或**至少两处 **对本 Target 适用** 的独立证据交叉支持；且无未记录冲突 |
| **R5** | Unknowns 单列；inference 不得写成无标记陈述句 |
| **R6** | 存在前后级算子时，已用来核对生命周期；没有则写「无相邻实现」 |

缺一条就不得说「需求已经清楚」。存在 **blocking unknown** 时不得开始写核。Contract 必须落盘到目标仓上述路径。

---

## Decision Rules

```text
MUST     先冻结 Target Context（R0），再收集证据
MUST     hardware / CANN / runtime 只从用户需求、本任务 Plan、或该任务显式 build/CI contract 冻结
MUST     建立 caller / consumer / lifecycle evidence；默认按 ①→⑦ 遍历
MUST     入口缺失时从已知锚点追踪，但 R0–R6 仍须闭环或标未找到
MUST     产出完整 Operator Contract + Semantic Dataflow，并落盘到目标仓
MUST     每条声称标 fact / inference / unknown
MUST     unknown 分成 blocking / non-blocking，并写理由
MUST NOT 把变量名、注释、论文摘要写成 fact
MUST NOT 把调用链透传数成多处独立证据
MUST NOT 把不同 commit / mode / 硬件 / CUDA reference 的证据交叉投成本轮 fact
MUST NOT 把 repo 默认 SOC / sibling 硬件常量 / 当前 shell CANN / 某个可用容器升成本次 operator target
MUST NOT 把当前 kernel 的 workspace/对齐写成逻辑语义
MUST NOT 把 factorization（prologue / skip-negative / split-K / 分段归约）的代数恒等写成 bitwise 或“数值严格等价”，而不检查中间 dtype / rounding boundary
MUST NOT 无证据补 rank / EP / 通信协议
MUST NOT 存在 blocking unknown 时开始写核
MUST NOT 把当次 Contract 升成 Weaver Knowledge
MUST NOT 把 target-specific 执行拓扑公式（`GetBlockIdx` / `GetSubBlockNum` / `core_ratio` / AIC·AIV）在无本 launch first-party 证据时证明为等价后改写

IF 用户已给出完整可开发语义且与调用一致
THEN 本 Skill 不是 primary route；把已给语义抄成 Contract 即可

IF 只有仓库或论文、没有设计文档
THEN 本 Skill 是开发前的 primary route

IF 证据来自另一 commit / mode / 硬件
THEN 只作 contrast，不得当本轮 fact 的交叉票

IF 两处对本 Target 适用的证据冲突
THEN 分别记录，保持 unknown 或拆开，不要合并

IF 相邻 Dispatch/Combine 对不上
THEN 生命周期标未重建，不要先写其中一个核

IF 只恢复了 Host 参数列表、没有 golden / 对外规范 / 消费方
THEN 数学语义最多 inference

IF 存在 blocking unknown
THEN 不得交给 cam-operator-development 写核

IF target SOC / CANN 会影响 API legality / memory hierarchy / synchronization / tiling / compile path
AND hardware 或 CANN 仍 unknown
THEN environment 保持 blocking；不得进入 Design Proposal / Gate A

IF 仅 non-blocking unknown
THEN 可以写核，但必须带着 assumption / scope
```

---

## 和 Weaver 其它层

| 要做的事 | 走 |
| --- | --- |
| CANN API / 头文件 / overload | `cam-operator-docs-search` |
| 无 blocking unknown（含 target SOC/CANN 已从任务合同冻结），开始设计与实现 | `cam-operator-development`（Gate A → 实现 → Gate B） |
| 跑失败、结果错 | `cam-operator-debug`（协议不清时再叫本 Skill） |
| 该不该测、怎么解释 | `cam-operator-optimization` |
| 阶段 timing | `instrumentation` |

本 Skill **不**解释 pingpong，**不**把参考实现的 tile 当成必须复刻的切分，**不**把 GPU kernel 的共享内存布局写成 Ascend 合同。

---

## 输出

回复必须：

1. 逐条写 R0–R6：**已满足 / 未满足 + 风险**
2. 给出 Target Context + Semantic Dataflow
3. 给出 14 块 Operator Contract（含参数表）
4. 列出 Unknowns：每条标 **blocking / non-blocking** 和理由；blocking 的必须挡住写核
5. 列出读过的入口 / 测试 / kernel / 相邻算子路径（含从哪一锚点开始追踪）
6. 落盘路径：目标仓 `docs/ascendweaver/` 或 `.ascendweaver/`
