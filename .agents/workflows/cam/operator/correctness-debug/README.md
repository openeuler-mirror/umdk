# Correctness-debug workflow

status: **accepted**

本页只串 **蓝区 ↔ 内网** 的正确性闭环。怎么分桶、排假说、设计可判别检查：走 [cam-operator-debug Skill](../../../../skills/cam/operator/cam-operator-debug/SKILL.md)。不要在这里再写 wrong-result 树或错误码表。

```text
蓝区写代码 / 根据回传修复
        ↓ 人工跨安全域搬运
内网编译、上板、收集观察
        ↓ 人工回传 patch / 日志 / failure contract
蓝区按 Skill 诊断、设计检查或改一处
        ↓ 再搬运合入后的 revision
内网按同一条 contract retest 该 revision
```

---

## 先问什么

```text
1. 现在人在蓝区还是内网？这一侧能证明什么、不能声称什么？
2. 这个 observation 是哪一版代码产生的？
3. 当前 failure contract 能不能重复？优先缩最小；缩不小也要固定。
4. 这次回传带了观察，还是只有“修好了”？
```

不要先问“蓝区能不能先报精度已过”。

---

## Failure contract

跨域搬运的最小包裹。诊断细节仍按 Skill。

```text
stable reproduction
  → preferably minimal reproduction
```

至少固定：

| 字段 | 必须能回答 |
| --- | --- |
| **code identity** | 这个 observation 是哪一版代码产生的 |
| command | 怎么编、怎么跑；跨域后命令可变，语义不能变 |
| shape / dtype / fixed input or seed | 失败那一组 |
| environment | CANN、SOC、容器、critical env、rank / world size |
| failing observation | 返回码、是否跑完、输出形态、hang/crash |

`code identity` 不必每次填满，但必须能指认版本。够用其一或组合：

```text
repo / branch
base commit
applied patch / diff identity
source tree hash
generated artifact identity
```

```text
蓝区 revision A
  → 内网 local patch B
  → 蓝区重构成 patch C
command / shape / environment 相同
  ≠
测的是同一版代码
```

有就附上：plog / compile log / patch.diff / 等价 command / 已试过但无信息增益的步骤。  
不要只回一句“对齐问题”或“已经好了”。

---

## 谁做什么

### 蓝区

可以：写代码、静态检查、读 Card、按已回传的日志 classify / 排假说、**设计**一个 smallest discriminating check、静态证据够了再改一处、准备下一趟搬运。  
无 NPU 时 Runtime / Correctness 标 **未测**。不要要求 `npu-smi`。

```text
design a check
  ≠
execute the check

蓝区编译过
  ≠
正确性通过
```

需要上板 / Dump / FP32↔FP16 / plog / 确认 hang 的检查：蓝区只写入 contract，搬进内网执行。

### 内网

可以：编译、上板、**执行**蓝区设计的检查、按 Skill 做必须在板上的最小检查、本地试修、retest。  
默认 **不** 向蓝区 Git push。输出给人工搬：patch、日志、更新后的 failure contract（含 code identity）、改了什么、还没测什么。  
上板验证走 [cam-operator-run](../../../../skills/cam/operator/cam-operator-run/SKILL.md)。怎么选卡、确认 OPP、L0–L9、异步 507xxx：读 [on-device](../../../../knowledge/cam/engineering/npu-on-device-validation.md)。不要把占卡 / HCCL / Host 未放行写成蓝区要修的 kernel hang。

一次最小 case 变对 ≠ 原失败场景都解决了。那是 Skill 的 `fix ≠ validation`，在哪一侧都成立。

### 人工

只做跨安全域搬运。不要在搬运时改合同字段，也不要把性能报告塞进这一页的正确性闭环。

性能采集 / 打点走 `cam-operator-optimization`，不在本流程。

---

## 一趟闭环

```text
1  蓝区
   冻结 failure contract（或从回传读入），写上 code identity
   走 cam-operator-debug：
     classify → ranked hypotheses
     → 设计一个 smallest discriminating check
     → 静态证据已经足够：做一处修复
     → 否则把 check 一起搬进内网
        ↓
2  人工把源码 / 脚本 / contract 搬进内网
        ↓
3  内网
   按同一 failure contract 复现
   路径/环境迫使命令变化时：记录等价 command，
     不得静默改变测试语义
     （operator / shape / dtype / input·seed /
      rank·world size / critical env / expected observation）
   执行需要 runtime 的 check
   记录新观察（包括“与蓝区预期一致/不一致”）和当时的 code identity
   若本地试修：同样一次一处，并留下 patch（新的 identity）
        ↓
4  人工把 patch + 日志 + 更新后的 contract 搬回蓝区
        ↓
5  蓝区
   合入有效修复（理解原因，不要盲合）→ 得到最终 revision
   若观察改变了“是否跑完 / 返回码 / 是否还在跑”
     → 重新 classify，不要并行开第二套流程
        ↓
6  内网 retest
   = 测蓝区最终合入后重新搬入的 revision
   ≠ 默认复用内网之前那个 local fixed tree
   同一条 semantic contract
   + 至少一条原先失败用例（若有）
```

没有新观察就不要再搬一趟同质修改。那是盲试，不是闭环。

---

## 不要写进本页

| 不要 | 去哪 |
| --- | --- |
| wrong-result 五族、507035 假说树 | [cam-operator-debug](../../../../skills/cam/operator/cam-operator-debug/SKILL.md) |
| DataCopy / EnQue / tile 合同 | Batch 2 Knowledge |
| DumpTensor / GDB / mssanitizer 步骤 | 手段；Skill 已说 tool ≠ diagnosis |
| 四个 `references/*.md` | 等真实任务证明主 Skill 太薄再补 |
| 内网直推蓝区、蓝区报加速比 | 仓库默认工作流禁止 |

---

## Sources

| Field | Value |
| --- | --- |
| 闭环职责 | 本页[谁做什么](#谁做什么)与[一趟闭环](#一趟闭环) |
| 诊断模型 | [cam-operator-debug SKILL](../../../../skills/cam/operator/cam-operator-debug/SKILL.md) |
| 蓝区无 NPU | [NPU on-device validation](../../../../knowledge/cam/engineering/npu-on-device-validation.md) |
| Last written | 2026-08-22 |
| status | accepted |
