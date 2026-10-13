# Upstream procedure (not the Weaver router)

Provenance: imported from an earlier personal instrumentation skill. The
canonical maintained copy is now this repository's
`.agents/skills/cam/operator/cam-operator-instrumentation/`.
UMDK / `cam_wangyibo_dev_91` / `comm_operator` paths in this file are **that repo’s layout**, not AscendWeaver defaults.
Agent: obey G1–G5 and the 1–7 flow here; enter via [../SKILL.md](../SKILL.md).

---
name: ascend-operator-instrumentation
description: 面向**任意昇腾算子**进行打点改造：插桩 TRACE_POINT/MoeTracing、profiling 数据链路与 Chrome trace 工具链。**Agent 执行时先读正文「Agent 速查」门禁 G1–G5**（全链路、profiling 为最后输出、sample 落盘与绝对路径）。遵循函数级粒度、就地改造、少增文件；禁止 xxx_profiling 第二算子名；保持原 Op/`torch.ops` 名与输入签名（返回值扩展在同一名下）。可复用结论写回 skill（「Skill 自维护」）。用户提到算子打点、MoeTracing、TRACE_POINT、profiling、Chrome trace、更新 skill 时使用。
---

# 昇腾算子自动打点

## Agent 速查（执行本 skill 时先读）

**红线**：用户未明确说「只要改源码里的 TRACE / 不要 GM / 不要改 Op 输出与 pybind」时，**禁止只改 `op_kernel` 或只插桩不交联调脚本**。须满足下表 **G1–G5**；任一缺失须在回复中写明「未完成项 + 后续风险」，不得宣称已闭环。

| 门禁 | 必须满足 |
|------|----------|
| **G1 预处理** | 团队 **`compile_ascend_proj.sh`（或等价）** 已接入 **`trace_preprocessor.py` hook**；**当次编译**在构建树生成 **`point_map.json`**，且与**当前运行的 OPP/核**同源 |
| **G2 输出位次** | **`profiling_data` 为全部 Tensor「数据输出」中的最后一个**（主输出 `1…N`，再第 `N+1` 路 profiling）。**`op_host` / infer / tiling（若描述输出）/ 类 `Init` / `__global__` / `aclnnInner_*` / 手写 `pregen/.../aclnn_*` / `EXEC_NPU_CMD` 实参** 顺序一致；禁止只改其中一层 |
| **G3 编译** | 用项目**常用整条命令**跑通 **OPP**（及若有的 **pybind whl**）。**不等于**仅通过 `validate_trace_points.py` / `check_compile_safety.py` |
| **G4 联调与后处理** | 在既有 **`examples/*_sample.py` 和/或 `test_*.py`** 中：**设备同步**（如 `torch_npu.npu.synchronize`）→ **`trace_utils.save_profiling_data`**；若生成 Chrome：调用 **`trace_collector.py`**，且 **`point_map.json` 满足 G1**。**不得**「算子已多一路输出，但脚本仍按旧 arity 解包且从不落盘」 |
| **G5 落盘路径** | 传给 `save_profiling_data` / `trace_collector` 的 **`profiling_dir`、`chrome_trace`、`point_map`**：在 **`multiprocessing.spawn` 或等价并行之前** 一律 **`Path(...).expanduser().resolve()` 为绝对路径**。相对路径在 `save_profiling_data` 内会拼到 **`trace_utils.py` 所在目录**，与 shell cwd 不一致 → 易出现 **No rank\*.pt** |

**模式 A / B（与步骤 7 一致）**：**A** = `profiling_data` **OPTIONAL**，Python 侧可不增返回值个数；**B** = 同一 `torch.ops` 名，**返回值最后一项**为 profiling。**用户要落盘 / Chrome** 时优先 **B** 或在 sample 中显式接 optional 内核参数；OpDef **REQUIRED** 时禁止用 nullptr 规避。

**阅读顺序**：本段门禁 → 下文「目标」与「全链路操作性定义」→ **必须执行的流程 1–7** → 细节章节（MoeTracing、搬运规格、编译门禁、常见陷阱）。

---

## 目标

根据自然语言需求，为目标算子生成可落地的算子侧打点代码。

边界约束：
- 本 skill **负责** 算子代码插桩 + profiling 数据采集/解析工具链的完整闭环。
- 本 skill **不修改** 算子的业务逻辑（matmul、通信等功能代码），仅新增 profiling 相关代码。
- 本 skill **需要支持** 在仅有算子代码时，自动补齐打点所需工程脚本、编译接入、以及从 profiling tensor 到 Chrome Trace JSON 的完整处理链路。
- **就地改造、少增文件**：优先改现有编译脚本、示例与 UT；避免平行维护新 `sh`、新 `run_*`、新整文件测试副本（细则见步骤 6–7 与下表）。
- **同一算子、同一接口名**：profiling 视为对**原算子**的增强，**禁止**再注册名为 **`xxx_profiling`**、**`*_with_profiling`** 或任何「看起来像另一个算子」的 **Op / `torch.ops` 入口**；**算子在图与 Python 侧的注册名保持不变**（若工程允许 arity +1，仅在**同一**名下多返回 profiling 张量；输入形参名与顺序也尽量不变，新增输出走既有扩展约定而非改名分叉）。

**默认交付标准（本 skill 执行时按此闭环，除非用户明确只要「仅插桩、不要 GM」）**：
- **算子侧**：在 `*_base.h` 中 **`ENABLE_MOE_PROFILING` 默认为 `1`**（关闭设备侧写入改为 `0` 并**重编核**；禁止依赖「不向设备传 profiling 张量」规避，与 REQUIRED 契约一致时尤其如此）；**`profiling_data`（或工程约定的同名输出）与主输出同级**（OpDef / infer / pybind / 核形参与 `Init` 顺序一致），核入口栈 buffer、`SetMoeProfilePtr`、**GM 写回**齐全。
- **`profiling_data` 在「数据输出」中的位置（易执行错、须写死）**：凡本 skill 走 **模式 B / REQUIRED**、或用户要求 **可采集 GM profiling** 时，**在所有与 GE/设备绑定的输出列表里，`profiling_data` 必须是最后一个 Output**（主输出 `1…N` 在前，**第 N+1 个且仅最后一个**为 profiling）。**Infer / tiling 中该输出的索引、`aclnnInner_*` 与手写 `pregen/.../aclnn_*.cpp` 形参顺序、`EXEC_NPU_CMD` 实参、`__global__`/`Init` 的 GM 槽位**须与同序；**workspace / tiling 缓冲等非 Tensor 输出**若与 Tensor 输出混排，以**该算子工程既有约定**为准，但 **profiling 张量不得插在主输出中间**。禁止只改 `op_host` 而漏改 infer/pregen/pybind/核入口任一处导致「看似编过、运行时错槽」。
- **编译**：在团队实际使用的 **`compile_ascend_proj.sh`（或等价）** 中已部署 **`trace_preprocessor.py`** hook（`# TRACE_PREPROCESSOR_HOOK_START/END`）；本仓库 UMDK 路径为 **`umdk/build/cam/comm_operator/compile_ascend_proj.sh`**，工具链脚本与 skill **`scripts/`** 对齐（可用 `bootstrap_trace_toolchain.py` 同步）。
- **测试**：在既有 **`*_sample.py` / `test_*.py`** 上扩展——**返回值 arity** 与 **`torch.ops` 解包**兼容多一路 profiling；**`torch_npu.npu.synchronize`（或等价）后**再落盘；可选 **`--point_map` + `trace_collector.py`** 生成 Chrome trace（具体 CLI 以目标仓库已存在的示例脚本为准）。

**用户用语与默认范围（避免只做「半套」）**  
- 用户仅说 **「打点 / 插桩 / trace / profiling / 性能点位」** 且**未**写明 **「只要改源码里的 TRACE_POINT 字符串、不要改 Op 输出 / 不要 GM / 不要动 pybind」** 等缩范围指令时，**一律按上文「默认交付标准」执行全链路**（算子 + profiling 张量绑定 + 编译预处理 + 示例或 UT 解包）。  
- 仅当用户**明确**缩小范围（例如「只加点位、本迭代不接 profiling 输出」）时，才可省略 GM / Op 变更，并应在回复中说明后续补齐项与风险。

**「全链路」操作性定义（避免只改少数文件就交差）**  
以下视为**同一交付物**，缺任一项即属半套（须在回复中列出未完成项）：**①** 编译管线中的 **`trace_preprocessor.py` hook**（生成与当次 OPP 一致的 `point_map.json`）；**②** `op_host` / **infer** / **tiling（若有输出描述）** 与 **核 `Init`/`__global__`** 的输出顺序一致，且 **profiling 为最后一路数据输出**（见上条）；**③** **`aclnnInner_*` 与手写 `pregen/.../aclnn_*` 对齐**；**④** **pybind** 多路返回或 `EXEC_NPU_CMD` 与之一致；**⑤** 既有 **`examples/*_sample.py` 或 `test_*.py`**：在 **`torch_npu.npu.synchronize`（或等价）之后** 调用 **`save_profiling_data`**，且父进程或文档可 **`trace_collector.py` → `chrome_trace.json`**（与 **`point_map.json` 同源**）。**仅 kernel 内 `TRACE_POINT` + 工具链脚本存在，但 sample/UT 仍不解包、不落盘、不接 collector —— 不算完成本 skill 默认交付。**

**推荐执行顺序（与下方步骤编号对应）**：扫描与规划（1→2→3）→ 插桩（4）→ 静态校验（5）→ 部署工具链与编译接入（6）→ Profile 测试脚本分叉（7，可与 6 并行准备，但须在 pybind/算子已暴露 profiling 输出之后才有意义）。

## Skill 自维护（元规则）

与本 skill 范围相关的讨论（排障、形状、ABI、profiling 与主路径关系等）若得出 **可复用、非一次性** 的结论，**应在同一会话或用户确认后写回本仓库 skill**，避免经验只留在聊天记录里。

- **写哪里**：主路由编辑 `.agents/skills/cam/operator/cam-operator-instrumentation/SKILL.md`；过长细节写入本目录的 `references/` 并在 `SKILL.md` 中链接。
- **写什么**：短条目、可执行检查项、易错的「不要 / 必须」、与代码路径/常量名的对应；**不要**整段粘贴 plog 或冗长堆栈。
- **本仓库 UMDK 与 Skill 同步**：若修改 **`.agents/skills/cam/operator/cam-operator-instrumentation/scripts/`** 下的 `trace_preprocessor.py`、`trace_utils.py`、`trace_save.py`、`trace_collector.py`、`validate_trace_points.py`、`check_compile_safety.py`、`inspect_rank_pt.py`、`bootstrap_trace_toolchain.py`，应**同步更新** **`umdk/build/cam/comm_operator/`** 下同名文件（若仓库内另有**对照/金标树**（本仓常见为并行目录下的 `build/cam/comm_operator/`），应与之对齐或文档说明有意差异）。批量同步可用：``python3 .agents/skills/cam/operator/cam-operator-instrumentation/scripts/bootstrap_trace_toolchain.py --build-dir build/cam/comm_operator``（从 UMDK 仓根运行，以仓内 Skill 为源刷新构建副本）。
- **何时写**：用户明确要求「记成规则 / 写进 skill」时必做；若新结论 **修正** skill 里旧表述（例如 optional vs REQUIRED），应直接改原文并保持一致性。
- **触发词**：用户说「记录规则」「经验更新到 skill」「探讨的结论落盘」等，按本条执行。

**近期已并入本 skill 的探讨结论（示例索引，便于检索）**

| 主题 | 要点 |
|------|------|
| **Agent 门禁 G1–G5** | 文首 **「Agent 速查」**；默认交付先逐条满足，回复对照 **「输出约定」** 声明；**G5** 与 `save_profiling_data` 相对路径陷阱见 **「常见陷阱」**。 |
| **`point_map.json` 与 Chrome 解析** | 必须与**当前已安装 OPP/核**为**同一次** `trace_preprocessor` 产物；路径填**真实文件**（勿用 `/path/to/...` 占位）。Host 落盘 profiling 须在 **NPU `synchronize`（或等价）之后**。`skipped_no_mapping` 高而 `rank*.pt` 非空 ⇒ **映射与二进制不一致**，非「没打点」。详见下文 **「point_map 与 Chrome 解析契约（通用）」**。 |
| profiling 输出地位（示例：多输出算子） | 若采用独立 `profiling_data`：**与主输出同级**绑定（OpDef/pybind/核 `__global__`/`Init` 顺序一致）；REQUIRED 时禁止向设备传空 profiling；关设备侧写入用宏 + 重编核。若工程选择「复用既有 GM / optional」须与图语义一致，**勿混用**两种绑定。 |
| 核写回与 host 可见性 | 设备写 profiling GM 后，若 host 读数异常或陈旧，可按平台补充 cache 一致性操作（如 **`DataCacheCleanAndInvalid`** 等），以目标 CANN/AscendC 文档为准。 |
| 混合核入口同步 | 1C2V 等场景下，若在 `SetMoeProfilePtr` 前后或首条 `MoeTracing` 前出现边界异常，可按算子语义在 AIC/AIV 间补 **CrossCore 屏障**，避免 trace 与执行顺序错位。 |
| **大块实现 / `#include` 子树（易漏检）** | 入口 **`op_kernel/<入口>.h`** 往往只调度；**真正耗时的 matmul / epilogue / 通信 / 分核 `operator()`** 常在 **`gemm/`、`kernel/`、`epilogue/`、`raw_distributed/` 等子目录头文件**中。必须从入口 **递归扫全 `op_kernel/`**，对这些翻译单元打点；**禁止**只改入口壳子。自检：对目标算子目录 **`grep -E 'MoeTracing|TRACE_POINT' .../op_kernel`**，长耗时路径上应有与「打点密度」匹配的命中。若仓库另有**参考树**（如 `*_trace/`、legacy 目录），可对照查漏，**交工以当前构建所用源码树为准**。 |
| 编译接入形态 | **改造已有编译脚本**，用标记块插入 `trace_preprocessor.py`；**不**新增平行「专用编译 sh」作为唯一入口。工具链优先放在与 `compile_*.sh` 同目录的可提交路径；`bootstrap` / `apply_trace_scaffold` 仅在其他仓无副本或一次性接入时使用。 |
| 就地改造与文件数量 | **尽量少新建文件**：在既有 `*_sample.py`、`compile_*.sh`、`test_<op>.py` 上扩展；工具链与预处理脚本优先与现有 build 目录同仓提交。 |
| 算子命名与接口 | **禁止**单独算子名 **`xxx_profiling`** / **`*_with_profiling`**（及同类变体）；**保持原算子注册名与 `torch.ops` 名不变**，profiling 为同算子改造（多一路输出时用 **同一 Op 名** + 文档化的返回值扩展，而非第二个算子）。 |
| `MIX_AIC_1_2_SLOTS_PER_GROUP` | `1 + GetSubBlockNum()`，本任务 1C2V 下常数为 `1 + 2`；Infer 中拆成 `MIX_AIC_1_2_SUBBLOCK_NUM` 与 `1 + …` 避免魔法数 `3`。 |
| `MAX_INFER_GETBLOCKNUM_UB = 128` | Infer 无 `GetBlockNum()`；为防低估 profiling GM；运行时常见 24 与上界无关；宁可略大占 GM，不可估小。 |
| **默认全链路 / `ENABLE_MOE_PROFILING`** | 交工默认含 **profiling 输出（或与工程一致的绑定方式）+ 预处理 hook + 示例或 UT 解包**；设备侧宏默认 **`1`**。**Infer 与动态输出**：若主输出行数/形状依赖运行时计数、infer 难以与 tiling 一致，可**仅对 `profiling_data` 在 infer 中强制 shape/dtype**，其余输出仍由图或 tiling 推导（须在工程内验证 GE/运行时无冲突）；此为**工程权衡**，非所有算子必需。 |
| **AIV-only / cann-recipes-infer** | 纯 AIV 核（入口对 AIC `return`）写回用 `GetBlockIdx()*PROF_SIZE_PER_CORE`；落盘设 **`MOE_CORE_NUM_LIST=48`**（A3）勿用默认 `[24,48]`。该仓无 msopgen copy_ops：在 **`cmake/func.cmake` `add_ops_src_copy` 后**对 `build/binary/<soc>/src/<op>/` 跑 preprocessor；`point_map.json` 落在该拷贝目录。Mode A：`profiling_data` OPTIONAL + torch kwarg，主返回值 arity 不变。 |
| **A5（Ascend950）36C+72V** | 物理核 **36 Cube + 72 Vector**。AIV-only 算子（如 `CamMoeDispatchNormalA5`）写回槽数按 **72 AIV**；`trace_utils` 用 **`MOE_A5=1` 或 `MOE_CORE_NUM_LIST=72`**。Infer/分配上界可用 `MAX_INFER_AIV_NUM_UB=128`。编译用 **cann91 / Ascend950**（本环境容器 `cam_wangyibo_dev_91`），勿假定 cann8.5 容器能编 ascend950。 |
| **A5 cycle→us（clock-divisor）** | 见下表 **verified toolchain configuration**。数字是某套 `trace_collector` 上验证过的配置，**不是**芯片时钟不变量。 |
| **忠实记时：`PIPE_ALL` 后取样** | 成对 B/E 的正确语义是 **`PIPE_ALL` → `GetSystemCycle`(begin) → `RUN_FUNC` → `PIPE_ALL` → `GetSystemCycle`(end)**。`GetSystemCycle` **必须在 barrier 之后**取。禁止写成 `MoeTracingWithCycle(data, GetSystemCycle())`（C++ 实参先于函数体求值 → 先取样再 `PIPE_ALL`，区间会吃进前序残留、丢掉本函数真正做完的时间）。实现与自检见 **「忠实记时顺序」**。 |

### verified toolchain configuration（clock-divisor）

```text
validated tool configuration
  ≠
hardware invariant
```

按 **当前 SOC + 本仓 `scripts/trace_collector.py` 版本** 取一行。换平台或换 collector 先对表，不要把旧值当硬件合同。

| SOC / 称呼 | toolchain | trace_collector | clock-divisor | evidence |
| --- | --- | --- | --- | --- |
| A3 / legacy（原 skill 常用环境） | 原 instrumentation skill 实践 | 本仓 `scripts/trace_collector.py`（合入时） | 50 | 原 skill 表；未在本仓复测 |
| Ascend950 / A5 | 原 skill：cann91 / `cam_wangyibo_dev_91` | 同上；`MOE_CLOCK_DIVISOR=1000` 或 `MOE_A5=1` | 1000 | 原 skill 表；未在本仓复测 |

其它 SOC：标 **unknown**，先读 collector `--help` / 环境变量，不要默抄 50 或 1000。

## 输入

- 目标算子路径，例如 `src/.../op_kernel/<op>.h`（或仓库约定的 `ascend_kernels/<op>/` 根目录）。
- **自然语言需求**：若未显式缩小范围，默认按 **「默认交付标准」** 与 **「用户用语与默认范围」** 执行（见文首）。
- 打点风格：`MoeTracing(TRACE_POINT("label", "B/E"))` 或带上下文 `MoeTracing(TRACE_POINT("label", "B/E"), extraId, index)`。
- 约束条件：
  - 函数级粒度（见下方"打点密度与均匀性要求"）
  - 根节点名称固定为 `processing`
  - 最大深度为 7（实际按语义需要决定，不要人为卡在浅层）
  - 对深层或低价值调用链执行智能合并

## 插桩覆盖必达清单（交工前自检）

以下与具体算子目录结构无关；**不得**只改「最外层调度头文件 / 单文件入口」即视为完成插桩。

1. **Kernel 入口**：`op_kernel` 下实际参与编译的 device 入口（通常为 `*.cpp` 中的 `__global__` / `__aicore__` 函数）——含 profiling 栈 buffer、与 GM 写回等与本 skill 约定一致的逻辑时，必须接入且与 `op_host` 参数个数一致。
2. **入口头文件 + 递归 `#include` 可达的全部实现**：在**该算子** `op_kernel/`（含任意子目录）内，凡实现 **AIC / AIV 分核主流程阶段**的翻译单元（含模板 `operator()<AscendC::AIC>` / `operator()<AscendC::AIV>`、分核 `Process`、通信、epilogue、与入口链路上的大块计算/融合逻辑等），**均须具备与语义匹配的 B/E 点位**；仅最外层已打点、**深层实现头文件未打点**视为未完成。易漏检形态：**入口头只做转发**，大块逻辑在子目录头文件中——须 **逐层 `#include` 跟到底**，不得以「文件名像数学库」为由跳过（见上表 **大块实现 / `#include` 子树**）。
3. **`op_host` / `infer` / pybind**：profiling 输出、形状推导、Python 解包 arity 等按本 skill 其他章节执行；凡在 OpDef 中将 **`profiling_data`（或等价名）标为 `REQUIRED`** 的算子，均须满足下文 **「profiling_data 与主输出同等工程地位」** 全条（禁止 nullptr optional、核 `__global__` 与类 `Init` / `aclnn` 形参顺序一致等）。
4. **密度门槛**：见下文「打点密度与均匀性要求」——**按每种核类型（AIC、AIV）分别**核对可见语义标签数；未达标时优先在「大块实现」内补**阶段边界**（见步骤 4 与常见陷阱），而不是在入口重复堆叠同义点位。

## 必须执行的流程

1. **扫描目标代码**
   - 从入口文件出发，**递归跟随 `#include` 进入同算子目录下的所有头文件**，直到遍历完整个算子内部代码树。不能只看入口 `.h`，必须读取其直接或间接包含的所有实现文件。
   - 识别主流程阶段与函数边界；特别关注 **模板实例化调用链**：如果入口函数调用了模板类并最终执行 `operator()()`，该 `operator()` 同样属于主流程阶段边界，必须跟进到对应头文件。
   - 将 **`#include` 拉起的、参与编译的** 所有子目录头文件列入待打点清单；对 **子目录中文件名含 `workspace` / `kernel` / `gemm` / `epilogue` 等大块实现** 尤须逐文件打开核对（与上条「易漏检」一致），**不得**因模板深或行数多而跳过。
   - 识别 **AIC / AIV 分核执行路径**：如果算子使用混合核（1C2V 等），AIC 分支和 AIV 分支各自是独立的主流程，需要分别打点。
   - 对于 1C2V 等模式，**必须检查 `operator()<AIV>()` 内部是否存在角色分工**（如 send core / recv core / compute core / share quant core）。不同 AIV 核可能通过 `aivIdx` 或 `GetSubBlockIdx()` 走完全不同的分支，每种角色的主要工作阶段都需要独立打点。
   - 尽量保留已存在且合法的点位。

2. **构建打点树**
   - L1 必须是 `processing`。
   - L2 至 L7 必须来源于当前算子真实语义（不要把 `dispatch/combine` 当作全局默认词）；合并规则见步骤 3，语义需要时用到 L6/L7 是正常的。
   - 对 AIC/AIV 分核执行路径，分别用 `<phase> aic` / `<phase> aiv` 作为 L2/L3 区分。
   - 对 expert group 循环、stage 循环等带索引的重复结构，打点时必须传递索引参数（见下方 MoeTracing 规格）。

3. **应用智能合并规则**
   - 超过 7 层的调用，折叠到最近的 L7 祖先节点。
   - 对无同步/无通信边界的薄封装函数与 helper 进行合并。
   - 对热点语义（`wait`、`sync`、`send`、`recv`、`copy`、`quant`、`dequant`）保留独立点位。

4. **插入代码**
   - 使用稳定命名的 `B/E` 成对点位（函数外包一层即可）：`MoeTracing(... "B")` → `RUN_FUNC` → `MoeTracing(... "E")`。忠实记时由 **`MoeTracing` 内部** `PIPE_ALL` 后再 `GetSystemCycle` 保证；**调用点不要**再手写 `GetSystemCycle()` 当实参，也不要在点位外再叠一层多余的 `PIPE_ALL`（见 **「忠实记时顺序」**）。
   - 保证 begin/end 词法嵌套正确。
   - **"最内层循环"指 tile 级别的矩阵计算循环（如 matmul 块内沿 K 的迭代、细粒度 epilogue tile 循环），不要在其中打点**。但 expert group 循环、stage 循环属于阶段边界，必须在循环体入口/出口打点。
   - 区分「阶段边界」与「tile 内层」——**同一头文件里可能同时存在二者，不得以目录名或文件名猜测并整文件跳过**：
     - ✅ 需要打点：分核主流程的 **`operator()<AIC>` / `operator()<AIV>`（或等价的分核入口）** 的整体阶段边界；expert / stage 等**粗粒度**循环体上的入口与出口；AIC↔AIV 同步与等待；独立语义的 epilogue、通信、dispatch/combine 子阶段等。
     - ❌ 不要打点：块内 matmul/epilogue **单次 tile** 的内层搬运与沿 K 的紧循环、孤立单次 `DataCopy` 等无独立阶段语义的位置。
     - **判断标准**：若某函数/入口是 **本分核上某一整段业务的调度或阶段边界**（典型为分核 `operator()`、或等价的大阶段入口），则打点；若仅为 **单次 tile 或单次微内核调用的内层实现**，则不打点。文件名、子目录名**不作为**是否跳过的依据。

5. **校验**
   - 对改动文件运行 `scripts/validate_trace_points.py`，检查点位命名与 B/E 配对。
   - 若仓库内**同一算子存在多套源码树**（例如金标目录与产品目录），建议**对每一套各自的 `op_kernel`（或等价目录）各跑一遍**上述脚本，避免分叉漂移。
   - 运行 `scripts/check_compile_safety.py <operator_dir>`，静态检查插桩是否会引入编译错误。此脚本检查：花括号平衡、预处理指令配对（`#if`/`#endif`）、MoeTracing 头文件可达性、TRACE_POINT 参数语法、变量作用域、profiling guard 闭合、kernel 参数与 op_host 注册的一致性。
   - **步骤 5 的定位**：主要覆盖**算子源码树内**的常见静态错误；**不能**替代完整 OPP / `cust_opapi` / pybind 工程编译。例如 **`aclnnInner_*`（自动生成）与仓库内手写 `pregen/.../aclnn_*.cpp` 签名不一致**、`EXEC_NPU_CMD` 宏对参数左值的要求、CPack 安装路径缺失等，脚本未必能检出。
   - 如果校验失败，修正问题后重新运行。两个脚本都通过后，**仍须**用目标仓库的 **`build.sh` / `compile_ascend_proj.sh`（或 CI 等价命令）跑通一次完整编译**作为最终门禁（见下文「编译与打包门禁」）。

6. **部署工具链并接入编译（必须执行，不可跳过）**
   - 此步骤不是可选的"缺省场景"，而是打点流程的必要组成部分。即使插桩代码已正确插入，如果工具链脚本未部署、预处理未接入编译，打点数据无法采集和解析。
   - **少新文件、改已有入口（优先原则）**：**不要**为打点单独再维护一条「新的编译 `sh`」或平行入口，替代团队已在用的命令。正确做法是：在**现有** `compile_ascend_proj.sh`（或 CI 调用的等价脚本）里，于 `copy_ops`/源码拷入构建树之后、`./build.sh` 之前，插入**一段**预处理调用，并用 `# TRACE_PREPROCESSOR_HOOK_START` / `# TRACE_PREPROCESSOR_HOOK_END` 包裹，便于幂等与审查。日常编译仍只跑**原**命令；`apply_trace_scaffold.sh` 仅是**一次性接入助手**（跑完 bootstrap + patch + verify），**不是**长期编译入口。
   - **工具链放哪**：若仓库已把 `trace_preprocessor.py` / `trace_utils.py` / `trace_collector.py` 等与编译脚本放在**同一可提交目录**（例如本仓库 `umdk/build/cam/comm_operator/`），hook 内用 `dirname "${BASH_SOURCE[0]}"` 解析到的目录调用即可，**无需**再 `bootstrap` 复制一份到别处，避免重复文件与路径漂移。仅当目标仓**没有**可提交的副本、且不希望把 `.py` 纳入版本库时，才用 `bootstrap_trace_toolchain.py` 拷到指定 `build_dir`。
   - **发现 build 目录**：在项目中搜索编译脚本（如 `compile*.sh`、`build*.sh`、`Makefile`、`CMakeLists.txt`），定位算子的 build 目录。常见位置如 `build/`、`scripts/` 等，不要假设目录名称。
   - **部署脚本（按需）**：无仓内副本时，运行 `bootstrap_trace_toolchain.py` 将下列脚本复制到目标 build 目录：`trace_preprocessor.py`、`trace_utils.py`、`trace_save.py`、`trace_collector.py`、`validate_trace_points.py`、`check_compile_safety.py`、`inspect_rank_pt.py`（以脚本内 `TOOLCHAIN_FILES` 为准）。
   - **接入编译**：运行 `patch_build_pipeline.py` 在**现有**编译脚本中注入预处理 hook；anchor 不匹配时，**手工**在同一脚本、同一相对顺序插入命令并加 `# TRACE_PREPROCESSOR_HOOK_START` / `END` 标记。
   - **校验部署**：运行 `verify_trace_scaffold.py` 确认脚本文件存在且编译 hook 已就位。
   - 不覆盖用户已有脚本；已存在时只做缺失补齐或可控更新。
   - **完整编译门禁**：工具链部署完成后，必须在实际使用的环境（容器 / CI / 本机）中执行**与团队一致的一条完整编译**（含算子包与 pybind，若项目如此组织）。仅「预处理成功」或仅步骤 5 通过，**不等于**产物可安装、可 import。常见工程问题见下文「编译与打包门禁（工程侧）」。

7. **Profile 测试脚本分叉（默认交付的组成部分；非「有空再做」）**
   - 与本段相关的交付门禁：**G4**（同步后落盘、collector 与 point_map 同源）、**G5**（`profiling_dir` 等 **`resolve()`**）。不满足则默认交付不完整。
   - **Python 面两种模式（勿混为一谈）**：
     - **模式 A（保持原返回值个数）**：图 / `op_host` 注册 **OPTIONAL** `profiling_data`（或等价名）时，公开 pybind 可仍只返回原先主输出；在 C++ 里通过 `aclnn*GetWorkspaceSize` 向 Inner 传入**空 optional / nullptr** 表示本次不采 profiling。原 UT、原 `torch.ops` arity **不变**。**注意**：一旦某算子在 OpDef 中将 `profiling_data` 标为 **REQUIRED**，则**禁止**再使用该 nullptr 路径，否则图语义、GE 绑定与设备参数不一致。
     - **模式 B（同一算子名、返回值 arity +1）**：在 **Op 注册名 / `torch.ops` 名与输入签名均不变** 的前提下，仅在**同一**算子名上扩展返回值（多一路 `profiling_data`）。**禁止**新增 **`xxx_profiling`**、**`*_with_profiling`** 等第二套算子或第二套 `torch.ops` 名（那是「另一个算子」，与本原则冲突）。调用方用 `..., _ = op(...)` 忽略最后一项即可保持业务逻辑不变；落盘与 Chrome 在**团队已有或本 skill 扩展的** `*_sample.py` 中用 **`--profiling_dir`**（写 `rank*.pt`）、可选 **`--point_map`** + **`--chrome_trace`**（spawn 结束后 **`subprocess`** 调 `trace_collector.py`）完成，避免再增 `run_*` / `*_profile.py` 整文件。
   - **多主输出算子：`profiling_data` 与主输出同等工程地位（REQUIRED 时强制契约）**  
     打点 / profiling 的 **GM 输出** 必须与**该算子全部主输出**在图与绑定上**同级**，不得单独做成「可选旁路」导致向设备传 `nullptr` 或与主输出参数生命周期不一致。设主输出共 **N** 路，profiling 为第 **N+1** 路 GM 输出（具体枚举名以 `op_host` 为准）。实现检查清单：
     1. **`op_host` OpDef**（`op_host/<op>.cpp` 或团队等价路径）：`Output("profiling_data")` 使用 **`ParamType(REQUIRED)`**，与主输出同级。
     2. **InferShape / InferDataType**（`op_host/<op>_infer.cpp` 等）：对 profiling 输出索引做与主输出相同的 **nullptr 门禁**；**始终**设置其维度与 dtype，不得依赖「可选输出可能不存在」分支。
     3. **pybind**（`pybind/<op>.cpp` 等）：**始终**分配并向 `aclnn<OpName>` / `EXEC_NPU_CMD` 传入 profiling 的 `at::Tensor`（与主输出同为实张量）。**禁止**用 `c10::nullopt`、环境变量等方式向设备侧传入「空 profiling GM」以规避绑定。
     4. **设备类 `Init`**（`op_kernel/<入口>.h`）：GM 形参顺序为 **主输出 1…N，再 `profiling_data`，再 `workspace`/tiling 等**——须与 OpDef / `aclnn` 一致（具体是否紧挨 workspace 以该算子既有约定为准，但**不得**与核入口乱序）。
     5. **`__global__` 核函数入口**（`op_kernel/<op>.cpp` 等）：与 OpDef / `Init` **同序**；改序后必须 **全量重编算子包 / OPP** 并做一次运行验证（plog 参数槽与 DFX），避免与旧二进制混用导致错参。
     6. **关闭设备侧 trace 写入**：通过 **`ENABLE_MOE_PROFILING`**（在 `<op>_base.h` 或团队等价 base 头）与**重编核**控制核内是否写入；**不要**依赖「不传 profiling 张量」——在 REQUIRED 契约下该做法非法且易与参数槽位/调试结论混淆。
   - **目的**：历史脚本若只解包前 N 个主输出，需在升级后改为多解包一位（可用 `_` 丢弃）；专门采集脚本显式接收 profiling 张量并 `save_profiling_data`。
   - **禁止**：为适配 profiling 在 **profile 用途之外** 把 `trace_utils` 硬塞进核心数值 UT 的主路径。原 UT 仍以数值断言为主；若必须兼容旧 arity，可在调用处用 `*head, _ = op(...)` 或固定长度解包。
   - **推荐（少新文件）**：在**原有** `examples/<op>_sample.py` 或团队 driver（非 pytest）中扩展：对 **`torch.ops...<原算子名>(...)`** 使用 `len(outs)` 分支，向 `forward` 返回元组**末尾**附带 `profiling`（或 `None`）；`__main__` 增加 profiling / trace 相关 CLI；子进程内 `save_profiling_data`，父进程在 `mp.spawn(..., join=True)` 之后可用 `subprocess` 调用 `trace_collector.py`。**算子名与接口名不变**；**不要**注册 **`xxx_profiling`** / **`xxx_with_profiling`**。若仅有 pytest UT、无 sample，再在**同一份** `test_<op>.py` 里增加辅助函数（仍优于新建整文件副本）。
   - **命名与位置**：优先改现有 `*_sample.py` / 团队已有 driver；确需 pytest 专用断言时再在同一目录的 `test_<op>.py` 内加函数，避免另建 `test_<op>_profile.py` 除非团队明确要求分拆文件。
   - **必改内容**：
     - 对主入口 `torch.ops.<lib>.<op>(...)` 在 **`len(outs)`** 上兼容「旧 arity / 新 arity（多一路 profiling）」；最后一项为 profiling 时参与落盘。
     - 封装算子的 `nn.Module` 的 `_apply_ops` 若把 profiling 传到 `forward`，下游解包须与元组长度一致；数值对拍仍只比较主输出，可用 `_` 忽略 profiling。
     - **SmallOps / 对照路径**：baseline 不返回 profiling 时保持原元组长度不变；带 profiling 的路径在对比时只对主输出子集 `assert_close`。
   - **与工具链对接**：`build/.../trace_utils.py` 的 `save_profiling_data`；**模式**为：若设 **`--profiling_dir`**，在 **`torch_npu.npu.synchronize`（或等价）之后** 再 `save_profiling_data`；`__main__` 在 **`--profiling_dir` 且 `--point_map`** 时用 **`subprocess`** 调用 **`trace_collector.py`** 写 **`chrome_trace.json`**（输出路径可用 **`--chrome_trace`**）。**本仓库**可在 `umdk/src/cam/examples/` 下查找已接入上述 CLI 的 sample 作参照（文件名随算子而变）。
   - **无 NPU 静态校验**：可在 sample 或 UT 中增加 **`--trace_checks`**（或等价入口），内部调用 `validate_trace_points.py` 与 `check_compile_safety.py`，脚本路径优先解析到仓内已提交的 `comm_operator` 工具链目录。
   - **`trace_utils` 导入**：将含 `trace_utils.py` 的目录加入 `sys.path` 后再 `import`；目录不存在时打印提示并跳过（见 sample 实现）。
   - **环境说明**：`save_profiling_data` 的 `base_h_path` 指向 `<op>_base.h`（`ENABLE_MOE_PROFILING` / `PROF_SIZE_PER_CORE`）；sample 默认尝试仓库内相对路径。
   - **pytest**：无单独 `test_*_profile.py` 时，在 **`test_<op>.py`** 内增加无 NPU 的校验函数即可。

## MoeTracing 运行时规格

MoeTracing 不是简单的空宏。当项目的 base 头文件中缺少 MoeTracing 定义时，必须按以下规格在算子已有的 `_base.h` 文件中补齐（不要新建单独的头文件）。

### 宏定义

```cpp
#define ENABLE_MOE_PROFILING 1
#define PROF_SIZE_PER_CORE 2048
#define ENABLE_MOE_PROFILING_BARRIER true
```

### per-core profiling buffer 指针

每个核拥有独立的 profiling buffer，通过 block-local 指针访问：

```cpp
__BLOCK_LOCAL__ __inline__ int64_t* g_moeProfilePtr;

__aicore__ inline int64_t* GetMoeProfilePtr(uint32_t idx = 0)
{
    return &g_moeProfilePtr[idx];
}
```

如果算子存在 AIC/AIV 分核编译（`SPLIT_CORE_CUBE` / `SPLIT_CORE_VEC`），需要为每种核类型声明独立的指针变量（`g_moeProfilePtrCube` / `g_moeProfilePtrVec`），并在 `GetMoeProfilePtr()` 中根据编译宏选择。

### 忠实记时顺序（硬规则）

昇腾上 `GetSystemCycle()` 取的是**取样那一刻**的时钟，**不会**自动等到尚未完成的 MTE/Vector/Cube 做完。要忠实记录某段函数耗时，顺序必须是：

```text
PIPE_ALL
GET_BEGIN_CYCLE
RUN_FUNC
PIPE_ALL
GET_END_CYCLE
```

含义：
- **begin 前** `PIPE_ALL`：排空前序残留，再打开始时间 → 区间不含上一段尾巴。
- **end 前** `PIPE_ALL`：等本函数发出的流水真正做完，再打结束时间 → 区间含本函数完成时间，而不是 issue 时间。

B/E 成对调用 `MoeTracing` 时，上述三明治由 **`MoeTracing` 各执行一次「barrier 后取样」** 拼出来，调用点只需：

```cpp
MoeTracing(TRACE_POINT("label", "B"));
RUN_FUNC
MoeTracing(TRACE_POINT("label", "E"));
```

**禁止（反模式）**：把 `GetSystemCycle()` 当作 `MoeTracingWithCycle` 的实参。C++ **先求实参再进函数体**，实际变成 `GET_CYCLE → PIPE_ALL → 写入旧 cycle`：begin 偏早、end 也偏早，Chrome 会把前序等待算进当前函数，并把本函数真正做完的时间丢在 E 点之后。

交工前对 `_base.h` 自检：`MoeTracing` 体内必须是 **先 `PipeBarrier<PIPE_ALL>`（若 sync）再 `GetSystemCycle`**；`grep 'MoeTracingWithCycle.*GetSystemCycle'` 不应在默认路径上命中。

### MoeTracing 函数实现

MoeTracing 是 **模板函数**，不是宏。模板参数 `sync` 控制是否在**取样前**插入 `PipeBarrier<PIPE_ALL>()`（默认 `ENABLE_MOE_PROFILING_BARRIER == true`）。

`MoeTracingWithCycle` **只写 buffer、不 barrier、不取样**。cycle 必须已按「barrier 后取样」准备好；默认路径不要从调用点传入 `GetSystemCycle()`。旧签名上的 `sync` 模板参数若仍保留，**忽略它**，不要再在写入前 barrier。

```cpp
__aicore__ inline void MoeTracingWithCycle(int64_t data, int64_t cycle)
{
#if ENABLE_MOE_PROFILING
    int64_t *profileData = GetMoeProfilePtr();
    profileData[profileData[0]++] = data;
    profileData[PROF_SIZE_PER_CORE - profileData[0]] = cycle;
#endif
}
```

Buffer 布局：`profileData[0]` 是写入索引，**正向写 point_id 数据，反向写 cycle 时间戳**。

### 三种调用重载

```cpp
// 基础调用：先 PIPE_ALL（若 sync），再取样，再写入。禁止把 GetSystemCycle() 提到本函数之外当实参。
template <bool sync = ENABLE_MOE_PROFILING_BARRIER>
__aicore__ inline void MoeTracing(int64_t data)
{
#if ENABLE_MOE_PROFILING
    if constexpr (sync) {
        AscendC::PipeBarrier<PIPE_ALL>();
    }
    int64_t cycle = AscendC::GetSystemCycle();
    MoeTracingWithCycle(data, cycle);
#endif
}

// 带索引：将 index 编码到 data 高 32 位，用于区分不同 expert group / stage
template <bool sync = ENABLE_MOE_PROFILING_BARRIER>
__aicore__ inline void MoeTracing(int64_t data, uint32_t index)
{
    MoeTracing<sync>(data | (int64_t)(((uint64_t)index) << 32));
}

// 带 extraId + index：用于同时传递 stageId 和循环索引
template <bool sync = ENABLE_MOE_PROFILING_BARRIER>
__aicore__ inline void MoeTracing(int64_t data, uint32_t extraId, uint32_t index)
{
    MoeTracing<sync>(data, (extraId | (index << 8)));
}
```

已有 `_base.h` 若仍是 `MoeTracingWithCycle<sync>(data, AscendC::GetSystemCycle())`，**必须改成上面的顺序**后再打点；只插 B/E、不改取样顺序，trace 时间轴不可信。

### 调用示例

```cpp
// 基础打点（前缀/后缀随算子语义命名，下为示意）
MoeTracing(TRACE_POINT("dispatch-phase1 aic", "B"));

// 带 groupIdx（区分不同 expert / tile 组）
MoeTracing(TRACE_POINT("dispatch-phase1 moe-process", "B"), 0, groupIdx);

// 强制 barrier 后再取样（覆盖默认 sync 参数）
MoeTracing<true>(TRACE_POINT("combine-phase combine-barrier-all", "E"));
```

## 命名规则

- 通用根标签固定为 `processing`。
- 阶段标签必须从当前算子语义中提取。
- 标签采用 **空格分隔的层级路径**，前缀表示所属阶段，后缀表示具体子阶段。例如 `"dispatch-phase1 aic"` 表示「dispatch-phase1」主阶段下 AIC 分支。
- 名称描述"做什么"，不要过度绑定实现细节。
- 在语义不变时，尽量保持命名稳定。

示例（名称仅示意，须与当前算子真实阶段一致）：
- `processing`
- `dispatch-phase1`
- `dispatch-phase1 aic`、`dispatch-phase1 aiv`
- `dispatch-phase1 moe-process`（带 groupIdx）
- `dispatch-phase1 wait-token`（带 groupIdx）
- `combine-phase block-epilogue waiting`（带 stageId）
- `combine-phase block-epilogue calc`（带 stageId）
- `combine-phase combine-send`、`combine-phase combine-recv`

## Profiling 数据搬运规格

打点数据写入 per-core 栈上 buffer 后，需要一条完整链路将其搬到 Host 侧。本 skill 要求在算子框架上**显式新增一个 profiling 输出 tensor**，而不是复用已有输入 tensor 的 GM 地址。**默认交付（G2）**：该输出在 **Op 注册的所有 Tensor 输出中排在最后**（第 `N+1` 路）。**ParamType** 可为 OPTIONAL（模式 A）或 REQUIRED（模式 B / 强制采数）；下文代码片段用 OPTIONAL 仅为示意语法，**位次规则不因 OPTIONAL/REQUIRED 改变**。Python 侧 **「图多一路 optional」 vs 「返回值多一项」** 见步骤 7。

### 1. 算子框架层：新增 profiling 输出（在既有 output 之后多注册一个）

在 `op_host` 算子定义中在**全部主输出之后**再注册 profiling（示意可为 OPTIONAL，实际以工程与模式为准）：

```cpp
// op_host/<op>.cpp — 算子注册
this->Output("profiling_data")
    .ParamType(OPTIONAL)
    .DataType({ge::DT_INT64, ge::DT_INT64, ge::DT_INT64, ge::DT_INT64})
    .Format({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND})
    .UnknownShapeFormat({ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND, ge::FORMAT_ND});
```

在 `op_host/<op>_infer.cpp` 中推导 shape：

**`totalCores` 必须等于 AIC 核数 + AIV 核数，不能只取其中一种。** kernel 侧 buffer 布局为：AIC 核写 `[0, aicNum)` 区间，AIV 核写 `[aicNum, aicNum + aivNum)` 区间。如果 `totalCores` 只取了 AIC 数量，AIV 核的写入会越界。

**禁止硬编码核数。** 不同硬件型号的核数不同（如 24C+48V=72、20C+40V=60），硬编码任何具体数字都会在其他型号上出错。正确做法按优先级：

1. **tiling 函数**（推荐）：通过 `platform_ascendc::PlatformAscendC(context.GetPlatformInfo())` 获取 `GetCoreNumAic()` 和 `GetCoreNumAiv()`，已有的 tiling 流程通常已包含此逻辑。
2. **kernel 入口**：通过 `AscendC::GetBlockNum()` 获取实际 AIC 核数，AIV 核数 = `GetBlockNum() * GetSubBlockNum()`（1C2V 下 SubBlockNum=2）。
3. **infer / pybind 侧**：`InferShapeContext` 没有平台查询 API，**不能在 infer 里读到实机的 `GetBlockNum()`**，只能写一个**对运行时 `GetBlockNum()` 的上界**来定 profiling 一维长度。对 **`KERNEL_TYPE_MIX_AIC_1_2`**，kernel 里逻辑槽数约为 **`GetBlockNum() * (1 + GetSubBlockNum())`**（常见 1C2V：`SubBlockNum=2` ⇒ **每路 AIC 组对应 3 个槽**）。这与「物理上有多少颗 Cube」不是同一个数：例如单卡 **24 Cube + 48 Vector** 时，若运行时 `GetBlockNum()` 为 24，则只需 **72** 个槽；历史上若误把「槽数上界」当成「只有 Cube 数」、且该数 **小于** `3 * GetBlockNum()`，AIV 侧 `(GetBlockNum() + GetBlockIdx())` 才可能越界。工程内常量如 **`MAX_INFER_GETBLOCKNUM_UB`** 是对 **`GetBlockNum()` 的 infer 上界约定**，须与 **pybind 分配的元素个数**一致，**不是**从硅片规格直接读出的核数；常见写法 `MAX_PROFILING_CORE_SLOTS = MAX_INFER_GETBLOCKNUM_UB * MIX_AIC_1_2_SLOTS_PER_GROUP`（系数随核类型而变）。

```cpp
// op_host/<op>_infer.cpp — infer 上界（命名与工程内已有算子对齐即可）
constexpr uint32_t MAX_INFER_GETBLOCKNUM_UB = 128;
constexpr uint32_t MIX_AIC_1_2_SLOTS_PER_GROUP = 3;
constexpr uint32_t MAX_PROFILING_CORE_SLOTS = MAX_INFER_GETBLOCKNUM_UB * MIX_AIC_1_2_SLOTS_PER_GROUP;
gert::Shape *profilingShape = context->GetOutputShape(OUTPUT_PROFILING_DATA);
profilingShape->SetDimNum(1);
profilingShape->SetDim(0, MAX_PROFILING_CORE_SLOTS * PROF_SIZE_PER_CORE);
context->SetOutputDataType(OUTPUT_PROFILING_DATA, ge::DT_INT64);
```

```cpp
// pybind — 模式 B：元素个数与 infer 完全一致；每槽 PROF_SIZE_PER_CORE 如 2048
constexpr int64_t kProfilingElems = static_cast<int64_t>(MAX_PROFILING_CORE_SLOTS) * PROF_SIZE_PER_CORE;
at::Tensor profilingData = at::zeros({kProfilingElems}, opts.dtype(at::kLong));
return {mainOut0, mainOut1, profilingData};  // 主输出个数因算子而异；须与 infer 元素个数一致
```

### 1.1 `aclnn` 外层包装与 `aclnnInner_*`（自动生成）的签名对齐

在 `op_host` 中**增加、删除或调整任一 Output（含 OPTIONAL）** 后，工具链生成的 **`build_out/autogen/aclnnInner_<Op>*.h/.cpp`** 中 `aclnnInner<Op>GetWorkspaceSize` / `aclnnInner<Op>` 的参数列表会随之变化。

若仓库中另有**手写维护**的对外封装（常见于 `pregen/build_out/autogen/aclnn_<op>.h`、`aclnn_<op>.cpp`，或等价路径），其形参顺序与类型必须与 **当前** `aclnnInner_*` **逐参一致**（含 optional profiling 的 `const aclTensor*` 等），否则 **`cust_opapi` 等目标会在完整编译阶段才报错**，`check_compile_safety.py` 未必覆盖。

**交工前自检**：改完 `op_host` / `infer` 后，打开最新一次 msopgen 或编译产物中的 `aclnnInner_*` 声明，与 `pregen/.../aclnn_*.h` 中 `aclnn<Op>GetWorkspaceSize` 对比；外层实现应只做薄转发（含将 optional 原样传入 Inner）。

```cpp
// 示意：Inner 已含 profilingDataOutOptional 时，外层必须多传一格再接到 workspaceSize
return aclnnInnerMyOpGetWorkspaceSize(/* ... */, lastMainOutputOut,
    profilingDataOutOptional, workspaceSize, executor);
```

### 2. Kernel 入口（`.cpp`）：buffer 初始化 + 搬出

在 kernel 入口函数中，算子执行**前后**分别处理 profiling buffer：

**执行前**——在栈上分配 buffer、初始化写索引和起始时间戳、设置指针：

```cpp
#if ENABLE_MOE_PROFILING
    int64_t profData[PROF_SIZE_PER_CORE];
    profData[0] = 1;
    profData[PROF_SIZE_PER_CORE - 1] = AscendC::GetSystemCycle();
    SetMoeProfilePtr(&profData[0]);
#endif
```

**执行后**——将栈上 buffer 逐条写到 profiling output tensor 的 GM 地址：

```cpp
#if ENABLE_MOE_PROFILING
    AscendC::GlobalTensor<int64_t> profGlobal;
    profGlobal.SetGlobalBuffer((__gm__ int64_t *)(profiling_data));
    // AIC 核写前半段，AIV 核写后半段
    AscendC::GlobalTensor<int64_t> coreGlobal;
    if (g_coreType == AscendC::AIC) {
        coreGlobal = profGlobal[AscendC::GetBlockIdx() * PROF_SIZE_PER_CORE];
    } else {
        coreGlobal = profGlobal[(AscendC::GetBlockNum() + AscendC::GetBlockIdx()) * PROF_SIZE_PER_CORE];
    }
    for (unsigned i = 0; i < profData[0]; ++i) {
        coreGlobal(i) = profData[i];
        coreGlobal(PROF_SIZE_PER_CORE - i - 1) = profData[PROF_SIZE_PER_CORE - i - 1];
    }
    // DataCacheCleanAndInvalid 确保 host 可读
#endif
```

辅助函数 `SetMoeProfilePtr` 的定义放在 `.cpp` 入口文件中，根据分核编译宏选择正确的 block-local 指针：

```cpp
__aicore__ inline void SetMoeProfilePtr(int64_t *profilePtr)
{
#if __CCE_AICORE__ == 220 || defined(__DAV_C310__) || defined(__DAV_310R6__)
#ifdef SPLIT_CORE_CUBE
    g_moeProfilePtrCube = profilePtr;
#elif defined(SPLIT_CORE_VEC)
    g_moeProfilePtrVec = profilePtr;
#else
    g_moeProfilePtr = profilePtr;
#endif
#else
    g_moeProfilePtr = profilePtr;
#endif
}
```

### 3. Host 侧（Python）：读取 + 保存

`trace_utils.py` 中 `save_profiling_data` 需要：
- 从 `_base.h` 读取 `PROF_SIZE_PER_CORE` 与 `ENABLE_MOE_PROFILING`（若实现里提供 `base_h_path` 参数，**新算子应传入当前算子的 `<op>_base.h` 绝对路径**，避免工具链内写死的相对路径仍指向示例算子）。
- 将 profiling tensor reshape 为 `(total_cores, PROF_SIZE_PER_CORE)`；`get_core_num_list()` 等若仍为示例中的硬编码或环境变量，需与目标硬件/tiling 一致，否则分组索引会越界或切分错误。
- 按 AIC/AIV 核类型分组（考虑 1C2V 映射）
- 保存为 `rank{id}.pt` 供后续解析工具使用

```python
from pathlib import Path
import trace_utils

profiling = profiling_data.cpu()
out_dir = str(Path("./prof_out").resolve())  # 第三参为输出目录，须绝对路径（见 G5）
op_base_h = Path("/repo/.../src/.../<op>_base.h").resolve()
trace_utils.save_profiling_data(profiling, rank_id, out_dir, base_h_path=str(op_base_h) if op_base_h.is_file() else None)
```

### 3.1 Pybind：`EXEC_NPU_CMD` 与 optional 参数的左值约束

若 pybind 通过 `EXEC_NPU_CMD(aclnnXxx, ...)` 调用 `aclnnXxxGetWorkspaceSize`，宏内部通常会对实参做 `ConvertTypes(...)` 一类展开，**要求可绑定到非 const 左值引用**（具体以项目内 `pytorch_npu_helper.hpp` 为准）。

因此向 `aclnn*GetWorkspaceSize` 多传一个 **optional profiling tensor** 时：

- **禁止**写成 `c10::optional<at::Tensor>()` 等**纯右值**直接塞进宏参数列表（典型编译错误：无法绑定到 `optional&`）。
- **应**在宏外声明具名变量，例如 `c10::optional<at::Tensor> profilingDataOptional;`（默认不采），再传入 `EXEC_NPU_CMD(..., profilingDataOptional)`；若本次要采 profiling，则先对该变量赋值再调用。

模式 A（见步骤 7）下常用「空 optional + 原 return 个数不变」；模式 B 再与「多返回一个 `at::Tensor`」的 pybind 示意配合。

## 编译与打包门禁（工程侧）

本节与打点语义无关，但为「步骤 6 + 完整编译」中反复出现的工程问题；不同仓库脚本名可能不同，以实际 `compile*.sh` / `build.sh` 为准。

- **CANN / msopgen 须在 PATH 中**：`msopgen`、`ccec` 等通常依赖 `source ${ASCEND_HOME_PATH}/bin/setenv.bash`（或项目规定的 setenv）。在 **docker exec 非登录 shell**、CI 裸 `bash -lc` 等场景下，若编译脚本先调用 `msopgen` 再 source，会导致 **`msopgen: command not found`**；应在**首次**调用 `msopgen` **之前**注入环境（由项目统一改 `compile_ascend_proj.sh` 等，或由执行者在同一 shell 中先 source）。
- **源码属主与构建用户**：`msopgen` 可能对输入 JSON 做「当前用户须为文件 owner」校验。容器内若以 **root** 编译、仓库挂载为普通用户属主，会报错；应以与挂载卷**一致的用户**（如 `docker exec --user <uid>:<gid>`）执行编译，或按团队规范在镜像内对齐属主。
- **`AddCustom.json` 与 `msopgen`（UMDK 实践）**：`msopgen gen -i .../AddCustom.json` 可能报 **`You are not the owner of path ...`**。本仓库在 **`umdk/build/cam/comm_operator/compile_ascend_proj.sh`** 中于 **`msopgen` 之前** 对 **`./ascend_kernels/AddCustom.json`** 尝试 **`chown $(id -u):$(id -g)`**，失败则 **`sudo chown`**。若以 **root** 成功 `chown`，该文件在工作区可能变为 **root 属主**；若希望挂载卷仍归开发者，优先 **`docker exec -u <与卷一致的 uid>`** 跑整条编译，或事后 **`chown` 回开发用户**。
- **`build_out` 清理与占位目录**：部分 msopgen 工程的 `build.sh` 会对 `build_out` 做 `rm -rf build_out/*` 后再 `cmake --build`。若 CPack / `cmake_install.cmake` 仍引用 **`op_kernel/binary/config/`** 等路径，而工具链未生成该目录，会在 **package** 阶段失败；可在 **`--target binary` 之后、`package`（或等价）之前** 由项目脚本 `mkdir -p` 占位（空目录即可），具体路径以生成工程为准。
- **门禁顺序**：工具链部署（步骤 6）→ **完整编译通过**（算子包 + 若有的 pybind wheel）→ 再视情况跑步骤 7 / 设备侧 UT。勿将「仅 validate / check_compile_safety 通过」误认为已满足交付。

### UMDK `comm_operator`：pybind whl 标准产物路径（勿默认写 `/tmp`）

与 **`umdk/build/cam/comm_operator/build_pybind.sh`** 一致，wheel 输出目录为 **`${MODULE_BUILD_OUT_PATH}/dist`**，即仓库内：

- **`umdk/output/cam/comm_operator/dist/`** — 成功构建后在此生成 **`umdk_cam_op_lib-*.whl`**。

**推荐命令**（在 **`umdk/build/cam`** 下，仅编 pybind、不跑算子 `msopgen`）：

```bash
./build.sh comm_operator -p
```

安装：

```bash
pip install --force-reinstall umdk/output/cam/comm_operator/dist/umdk_cam_op_lib-*.whl
```

手工执行 `python3 setup.py bdist_wheel` 时，**`--dist-dir` 应指向上述 `dist`（可先 `mkdir -p`）**，**不要**随意写到 **`/tmp`**，以免与 CI、文档和归档路径脱节。

算子 OPP **`.run`** 由 **`compile_ascend_proj.sh`** 等完整算子链路生成，通常落在 **`umdk/output/cam/comm_operator/run/`**（如 **`CAM_ascend910_93_debian_aarch64.run`**，SOC 名随 `-c` 变化）。**whl 与 `.run` 需分别安装**；仅升级 whl 而不升级已装 OPP 时，注意版本是否匹配。

### `import umdk_cam_op_lib`：`libcam.so` 与 Ascend / 驱动库

部分环境打出的 **`umdk_cam_op_lib*.so`** 在 ELF **`DT_NEEDED`** 中会依赖 **`libcam.so`**（CAM host 侧产物）。若运行时 **`LD_LIBRARY_PATH`** 未包含其所在目录，会报 **`ImportError: libcam.so: cannot open shared object file`**。

- 将含 **`libcam.so`** 的目录加入 **`LD_LIBRARY_PATH`**（常见为各团队 **`comm_operator` host 编译输出目录**，例如部分树布局下的 **`umdk/src/cam/comm_operator/build`**，以实际产物为准）。
- **本仓库部分示例**在模块加载时调用 **`_prepend_cam_op_native_lib_path()`** 一类辅助：支持环境变量 **`UMDK_CAM_NATIVE_LIB_DIR`**，并在 **`import torch_npu` / `import umdk_cam_op_lib` 之前** 写入 **`LD_LIBRARY_PATH`**（同一进程内、在扩展被 `dlopen` 前生效）；其它仓库按既有 driver 方式处理依赖路径即可。
- **`torch_npu`** 另需 Ascend CANN **`.../aarch64-linux/lib64`** 及 **`/usr/local/Ascend/driver/lib64`**（及常见子路径 **`.../driver/lib64/driver`**）等；**`docker exec` 非登录 shell** 若未继承镜像登录环境，需显式 **`export LD_LIBRARY_PATH=...`** 或与 **`${ASCEND_HOME_PATH}/bin/setenv.bash`** 一致。

### Python / `torch.ops`：模式 B 下返回值个数升级

- **模式 B**：pybind 在**同一算子名**上较旧版 **多返回一路 profiling tensor**（ arity = 原主输出数 + 1）。
- **旧 whl** 仍为旧 arity 时，若写死新长度解包会报错。处理：**重装**与当前 `pybind` / `op_host` 一致的 whl；或在调用处对 **`len(outs)`** 分支兼容（见步骤 7 与团队 sample），并在 **rank0** 提示需升级 whl。

### 端到端 profiling + Chrome（UMDK 可参考；其它仓替换为各自的 sample/driver）

- **通用约定**（路径、sync、`point_map`）见上文 **「point_map 与 Chrome 解析契约（通用）」**。
- **本仓库**：在 **`umdk/src/cam/examples/`** 下选择**已接入 profiling** 的 `*_sample.py`（非 pytest；常与数值对拍同文件）；典型 CLI：**`--profiling_dir`**（输出目录，内含 `rank*.pt`）、**`--point_map`**（**真实路径**的 `point_map.json`，与当次编译 OPP 同源）、可选 **`--chrome_trace`**。`trace_utils` / `trace_collector` 由 sample 内嵌路径解析到 **`umdk/build/cam/comm_operator`**；`save_profiling_data` 的 **`base_h`** 指向对应 **`<op>_base.h`**。具体默认路径以该 sample 文件头注释为准。
- **`MOE_USE_1C2V=1`** 时 **`trace_utils.get_core_num_list()`** 为 **`[24,24,24]`**，否则常见为 **`[24,48]`**；与硬件/核映射解读需一致。

## 打点密度与均匀性要求

- **目标标签数（按核类型分别统计）**：对 **AIC 与 AIV 各自**，在「该核实际会执行到的代码路径」上，应能观察到大约 **15～20 个不同的语义阶段名**（即互不相同的 `TRACE_POINT` 标签字符串个数，**不是**全算子 AIC+AIV 混在一起凑总数）。过少（例如某一核类型上**少于 10 个**）不利于看子阶段瓶颈；过多（例如**多于 30 个**）易占满 buffer 且 trace 难读。
- **均匀性**：按**当前算子**的真实主阶段划分（名称随算子语义而定，如 dispatch、多段 matmul、combine、量化等），各主阶段下的子标签数量应**大致均衡**。若某一主阶段已有多个子点位，而另一主阶段在对应核上仍只有入口/出口两点，说明后者打点不足，应深入该阶段所在实现（含分核 `operator()` 内部）补充子阶段。
- **"函数级粒度"的正确理解**：指每个有独立语义的阶段函数（如 `SendCoreFunc`、`RecvCoreFunc`、`CompCoreFunc`、`UpdateAndCleanInfo`），不是仅限于调用链第一层入口的 `operator()`。`operator()` 内部如果有多个语义明确的子函数调用，每个都应该有独立的 B/E 点位。
- **二级拆分**：即使一个子函数已经有了 B/E 点位（如 `某阶段 aiv send`），如果其内部仍有语义可分离的子阶段（如 count-prep vs token-DMA、spin-wait vs data-copy），也应在函数内进一步拆子标签（如 `… aiv send-count` + `… aiv send-token`）。典型的可拆分模式包括：
  - **count/status 广播** vs **payload 数据搬运**（dispatch、recv）
  - **spin-wait/polling** vs **实际计算或搬运**（recv-count、group-wait）
  - **shared expert** vs **routed expert** 的独立执行路径
  - **metadata load**（index/scale DataCopyPad）vs **per-token reduce 循环**（combine local-copy）
- **AIV 角色分工**：对于 1C2V 等混合核模式，`operator()<AIV>()` 内部可能通过 `aivIdx`、`GetSubBlockIdx()` 或角色标志（`isSendCore`、`isRecvCore`、`isCompCore`）将不同 AIV 核分配到不同工作路径。每种角色的主要工作阶段都需要独立打点，让 trace 中能区分各类 AIV 核的时间分布。
- **多变体对齐**：如果同一算子有多个 kernel 变体（如 deep-fuse vs shallow-dispatch），所有变体的 AIV `operator()` 都应该有相似粒度的子阶段标签。不能一个变体有 8 个子标签而另一个只有入口/出口。
- **自检方法**：打点完成后，**分别**列出 AIC 与 AIV 在各自可达路径上出现的**不同**标签名集合并计数。若某一核类型明显低于上述量级，或某一主业务阶段在该核上仍只有一对 B/E 而无子阶段，则须继续补充（优先大块实现头文件中的阶段边界，见上文「插桩覆盖必达清单」与步骤 4）。

## 容量与扰动约束

- 每核 profiling buffer 容量有限（`PROF_SIZE_PER_CORE`），禁止默认高密度铺点。
- 不要默认给每个小 helper 或最内层循环都加点。
- 优先保证可读性与稳定定位瓶颈能力，而不是追求全覆盖。

## 常见陷阱（快速自检）

- **`GetSystemCycle` 在 `PIPE_ALL` 之前取样（时间轴不忠实）**：`MoeTracingWithCycle(data, GetSystemCycle())` 会先算实参再 barrier，记录的是 issue 时刻不是完成时刻。B/E 区间会吃进前序残留、丢掉本函数 drain。**必须**：`MoeTracing` 内 `PipeBarrier<PIPE_ALL>()` 之后再 `GetSystemCycle()`；见 **「忠实记时顺序」**。改造已有 `_base.h` 时优先修这一处。
- **因「看起来像数学库/大块计算实现」而整文件跳过**：子目录或文件名**不能**作为免打点依据；凡含 **分核 `operator()<AIC/AIV>`（或等价阶段入口）** 且属于主流程的实现头文件，必须与 tile 内层区分并打点（见步骤 4）。
- **大块实现头未打点**：主耗时往往在 **`#include` 子树**的 workspace / kernel / gemm / epilogue 模板 **`operator()`** 内；仅打外层调度头会导致 trace 看不到真实子阶段——属**高频遗漏**，交工前按上文 **「大块实现 / `#include` 子树」** 与 `grep` 自检；若仓库有对照树可 diff，**交工以当前构建树为准**。
- **`aclnnInner_*` 已变、手写 `pregen/.../aclnn_*.cpp` 未改**：`op_host` 增删 output 后 Inner 签名已更新，外层仍少传 / 错传 `profilingDataOptional` 等参数 → **`cust_opapi` 编译失败**；见上文「§1.1」交工前自检。
- **`EXEC_NPU_CMD` 传入 `optional` 临时量**：见上文「§3.1」，须使用具名 `c10::optional<at::Tensor>` 变量。
- **infer/pybind 硬编码核数**：用安全上界或动态逻辑；与 kernel 侧 per-core 写入区间一致。
- **Python 解包 arity**：仅在使用**模式 B**（步骤 7）时 fusion / profile 脚本比原先多接一个 profiling 张量；原 UT 不解包改时拷贝为 `test_<op>_profile.py`。模式 A 下原 UT arity 不变。
- **`trace_utils` 静默不落盘**：`_base.h` 路径不对或 `ENABLE_MOE_PROFILING` 为 0；优先检查 `base_h_path` 与宏。
- **`save_profiling_data` 的相对路径与 cwd 不一致（高频误导）**：`trace_utils.save_profiling_data(..., output_dir)` 若 **`output_dir` 为相对路径**，实现会拼到 **`trace_utils.py` 所在目录**（常为 `build/cam/comm_operator`），**不是** shell 的当前工作目录。表现为：日志里 `Saved: .../comm_operator/.../rank*.pt`，而 `trace_collector` 或用户在 **`examples/`** 下传的 `./prof_out` 为空 → **No rank\*.pt**。**修复**：sample/driver 在 spawn 前将 **`profiling_dir` / `chrome_trace` / `point_map` 设为 `Path(...).resolve()` 绝对路径**，或调用方始终传绝对路径。
- **工具链未部署仍以为能出 trace**：步骤 6 未完成则没有预处理后的 `point_map.json` 与可复现的 point_id。
- **`point_map` 路径错误或占位符**：`load_mapping` 为空 → 全记录跳过；**错用旧工程 / 他机拷贝的 `point_map.json`** → `skipped_no_mapping` 极高，见上文「point_map 与 Chrome 解析契约」。
- **sync 前落盘 profiling**：见上文「Host 侧何时保存 profiling tensor」；与 map 错配症状不同（前者常表现为 pt 空或 counter≤1，后者 pt 正常但 decode 全跳过）。
- **落盘了冷启动第一次 combine（高频误导）**：若 sample 在精度检查的那一次 `compute` 后立刻 `save_profiling_data`，Chrome 里常见 **`combine-barrier` / 首轮通信异常长**（JIT、对称窗、跨卡 barrier 冷启动），看起来像「采到了第一次而不是稳态」。**修复（与 ascend-moonep `combine_prof` 一致）**：冷启动第一次只做正确性、**永不落盘**；需要 TRACE 时再 **`--profile-warmup`（≥1）+ 一次 dedicated final launch**，只保存最后一次的 `profiling_data`；若 prologue 会原地改写对称缓冲，final 前须 **republish 输入**。
- **未跑完整编译即认为可交付**：步骤 5 与静态脚本不覆盖 autogen / pybind / CPack 全链路；须满足上文「编译与打包门禁」。

## trace.json 生成流程

打点数据的完整处理链路（从设备到可视化）分 4 步：

### Step 1: 预处理（编译前）

`trace_preprocessor.py` 扫描源码，将 `TRACE_POINT("label", "B/E")` 替换为唯一整数 point_id，生成 `point_map.json`：

```bash
python <skill_root>/scripts/trace_preprocessor.py <operator_src_dir> <output_dir> --modify
```

输出 `point_map.json` 格式：
```json
{
  "points": {
    "1": {"label": "processing", "event_type": "B", "file": "...", "line": 415, "event_id": 1},
    "2": {"label": "dispatch-phase1 aic", "event_type": "B", ...}
  }
}
```

### Step 2: 运行算子采集 profiling tensor

算子执行后，Host 侧获取 profiling output tensor（通常为**最后一个** output，即比插桩前多出来的那一个），调用 `trace_utils.save_profiling_data` 拆分保存：

```python
import trace_utils
from pathlib import Path

profiling = profiling_data.cpu()
out_dir = str(Path("./prof_out").resolve())  # 须绝对路径；勿传未 resolve 的 "./xxx"
op_base_h = Path("/abs/or/repo/path/to/<op>_base.h").resolve()
trace_utils.save_profiling_data(profiling, rank_id, out_dir, base_h_path=str(op_base_h) if op_base_h.is_file() else None)
```

也可离线保存：
```bash
python <skill_root>/scripts/trace_save.py raw_profiling.pt --rank 0 --output profiling_data
```

### Step 3: 生成 Chrome Trace JSON

`trace_collector.py` 读取所有 `rank*.pt` + `point_map.json`，解析 64 位组合 ID（低 32 位 point_id + 高 32 位 extra_id），配对 B/E 事件，生成 Chrome Trace 格式：

```bash
python <skill_root>/scripts/trace_collector.py profiling_data point_map.json -o chrome_trace.json
```

支持参数：
- `--clock-divisor`：cycle → us 的 toolchain 配置。取值见上文 **verified toolchain configuration**，不要当硬件不变量。
- `--extra-mode seq`：extra_id 解析模式（`seq`=高 24 位序号+低 8 位 extra，`legacy`=整体使用）
- `--depth 0`：区间深度过滤（0=全部，1=仅叶子，2=叶子+父层）

### Step 4: 可视化

在 Chrome 浏览器打开 `chrome://tracing`，加载生成的 `chrome_trace.json`。
每个 rank 对应一个 process，每个核（AIC/AIV × core_id）对应一个 thread。

### point_map 与 Chrome 解析契约（通用）

本节与**具体算子名**无关；任意昇腾算子只要走 `TRACE_POINT` → 预处理器 → 设备写整型 ID → `trace_collector` 解码，均适用。

#### `point_map.json` 是什么、生成在哪里

- `trace_preprocessor.py` 扫描**参与当次编译的那份源码树**（常为 msopgen `copy_ops` 之后的生成目录），将 `TRACE_POINT("label","B"|"E")` 替换为**唯一整数 point_id**，并在**输出目录**（CLI 第二参，常与该生成工程根目录相同）写出 **`point_map.json`**（结构一般为 `{"points": {"1": {"label", "event_type", "file", "line", "event_id"}, ...}}`）。
- **设备侧写入的是预处理后的 point_id**；Host 侧用 JSON **按字符串键**（如 `"149"`）查 `event_type` / `label`。因此：
  - **解码用的 `point_map.json` 必须与当前运行的内核/OPP 来自同一次预处理 + 同一次编译**。换了一份源码再跑 preprocess、或拷贝了别台机器的 map、或只重装 whl 不重编算子，都会导致 **ID 对不上**。
- **典型落点**（形态因仓库而异，勿背死路径）：`<…>/build_tmp/<…>/<msopgen_project_name>/point_map.json`，与编译日志里预处理 hook 所操作的目录一致。在目标环境用 `find … -name point_map.json` 或查 `compile_*` 里 `trace_preprocessor` 的第二参数最可靠。

#### 使用时的路径（常见误操作）

- 传给 `trace_collector.py` 的第二个参数、或各仓 sample/driver 里的 `--point_map`，必须是 **`os.path` 上真实存在的文件**。
- 文档、注释里的 **`<repo>/...`、`build_tmp/.../point_map.json` 仅表示目录形态**；**禁止**把字面量 **`/path/to/...`** 当作参数——会表现为 `point_map` 加载失败、`point_map keys: 0`、或 `load_mapping` 返回空，进而 **全部记录被跳过**。
- 建议在调用前做 **`Path(path).is_file()`** 检查并给出清晰错误（各仓 sample 可按需加入）。

#### Host 侧何时保存 profiling tensor（与设备可见性）

- 设备把 profiling 写入 GM 后，若在 **未完成队列同步 / 设备到 Host 可见** 时就在 Python 里读张量并 `save`，可能读到**全零或计数不更新**的缓冲，`trace_collector` 解析条数为 0。
- **通用做法**：在算子执行返回后、落盘前调用 **`torch_npu.npu.synchronize(device_id)`**（或项目规定的等价同步），再 `cpu()` / `save_profiling_data`。具体插入点因框架而异（例如在 `forward` 外、`synchronize` 之后再写盘）。

#### 如何判断是「映射错了」还是「没采到数」

- 先用 **`inspect_rank_pt.py`**（见下表，与 `comm_operator` 同目录提交）检查 `rank*.pt`：各分组 tensor 的 **非零比例**、**`tensor[core,0]` 计数（counter）**；若大量核 **`counter > 1`**，说明 per-core 上有有效记录，**问题不在设备打点**。
- 再跑 **`trace_collector.py`**：看 **`otherData.skipped_no_mapping`**。若其值 **接近原始记录总数**，而 `point_map` 键数正常，多为 **base_point_id 与 JSON 键不一致**（错 map / 旧 map）。
- 工具在 stderr 打印的 **`diagnose:`** 行：`unique base_point_id in rank*.pt`、`point_map keys`、**`intersection`**。**`intersection` 为 0** 且两侧都非空时，可断定 **point_map 与当前内核不是一套**；应改指向**本次编译生成目录**中的 `point_map.json` 并重新生成 trace。
- **勿与「sync 时机」混淆**：全零 pt → 先查同步；pt 有数据、仅 Chrome 空且 **`skipped_no_mapping` 高** → 先查 **map 路径与版本**。

## 固定脚本

路径规范：
- 文档中的**编译/校验命令示例**优先使用**相对路径**（便于换机复现），**不依赖** Cursor 专属绝对路径。
- **例外（必守）**：`save_profiling_data`、`trace_collector`、sample 的 **`--profiling_dir` / `--chrome_trace` / `--point_map`** 在代码里须 **`resolve()` 成绝对路径**（见 **G5**）。勿在示例里暗示「相对路径一定相对当前 shell」。

### 本仓库 UMDK：`build/cam/comm_operator` 与 Skill 脚本的关系

Skill 在 **`.agents/skills/cam/operator/cam-operator-instrumentation/scripts/`** 下列出了**完整**工具集；若日常只引用 `<skill_root>/scripts/...` 而**不在算子编译目录提交副本**，会出现「文档里有很多脚本、工程里用不上」的割裂。

**本仓库约定**：

- **`umdk/build/cam/comm_operator/`**（与 `compile_ascend_proj.sh`、`build.sh` 同目录）应提交与 **编译预处理、profiling 落盘、Chrome 解析、插桩校验**直接相关的脚本；若本仓库另有对照树，**布局与其 `build/cam/comm_operator/` 对齐**，避免工具链分叉。
- **同名脚本以 Skill 为规范源**；修改行为时优先改 Skill 下文件，再**同步拷贝**到 `umdk/build/cam/comm_operator/`（或合并差异后两边一致）。

| 文件（`umdk/build/cam/comm_operator/`） | 作用 |
|----------------------------------------|------|
| `trace_preprocessor.py` | `TRACE_POINT` → `point_id`，生成 `point_map.json`（**`compile_ascend_proj.sh`** 中 hook 调用） |
| `trace_utils.py` | `save_profiling_data`、从 `*_base.h` 读 `PROF_SIZE_PER_CORE` 等 |
| `trace_save.py` | 离线原始 `.pt` → 按核拆分输出目录 |
| `trace_collector.py` | `profiling_data` 目录 + `point_map.json` → `chrome_trace.json`（stderr 含 `diagnose:` 与 `skipped_no_mapping` 提示） |
| `inspect_rank_pt.py` | 快速查看 `rank*.pt` 形状、非零、每核 counter，判断 pt 是否有有效 profiling（**不依赖**具体算子名） |
| `validate_trace_points.py` | 步骤 5：标签与 B/E 配对 |
| `check_compile_safety.py` | 步骤 5：静态安全检查 |
| `bootstrap_trace_toolchain.py` | 将上表所列 `TOOLCHAIN_FILES` 从**本脚本所在目录**同步到 ``--build-dir``（幂等；``--dry-run`` / ``--list``）；**规范源**与 Skill ``scripts/`` 同名文件一致 |
| `compile_ascend_proj.sh` / `build.sh` / `build_pybind.sh` / `set_conf.py` | 既有构建与预处理 hook |

**仅保留在 Skill 目录、一般不提交到 UMDK `comm_operator` 的脚手架**（新仓库一次性接入、草稿插桩）：`patch_build_pipeline.py`、`verify_trace_scaffold.py`、`apply_trace_scaffold.sh`、`generate_instrumentation_plan.py`、`instrument_operator.py`。**`bootstrap_trace_toolchain.py`** 在 **Skill 与 `umdk/build/cam/comm_operator/` 各有一份**，修改后应两边对齐。本仓库已对 **`compile_ascend_proj.sh`** 做预处理接入，一般**不必**再对 UMDK 跑 `apply_trace_scaffold`；给其他仓接入时仍从 Skill 路径执行。

**UMDK 内同步 Skill 工具链到本目录（示例）**：

```bash
# 从仓库根执行：用 Skill 目录为源，刷新 umdk/build/cam/comm_operator 下各脚本
python3 .agents/skills/cam/operator/cam-operator-instrumentation/scripts/bootstrap_trace_toolchain.py \
  --build-dir umdk/build/cam/comm_operator
```

**本仓库推荐调用方式（任选其一）**：

```bash
# 与工程同目录的副本（推荐；与对照树 layout 一致更佳）
cd umdk/build/cam/comm_operator
python3 validate_trace_points.py ../../../src/cam/comm_operator/ascend_kernels/<op>/op_kernel
python3 trace_collector.py <profiling_out_dir> <path/to/point_map.json> -o chrome_trace.json

# 或显式使用 Skill 路径（与下表「命令示例」一致）
python3 .agents/skills/cam/operator/cam-operator-instrumentation/scripts/validate_trace_points.py ...
```

**与「必须执行的流程」步骤对应（检索用）**：

| 步骤 | 脚本或产物 |
|------|----------------|
| 1–4 辅助（可选） | `generate_instrumentation_plan.py`、`instrument_operator.py` — 规划/草稿插桩，不能替代人工审查 |
| **5 校验** | `validate_trace_points.py`、`check_compile_safety.py`（**不替代**完整 OPP/pybind 编译；见步骤 5 说明与「编译与打包门禁」） |
| **6 工具链 + 编译接入** | **首选**：仓内已有 `trace_*.py` 时只改现有 `compile_*.sh` 注入 hook（见步骤 6）。**按需**：`bootstrap_trace_toolchain.py` → `patch_build_pipeline.py` 或手工 hook → `verify_trace_scaffold.py`；一次性 `apply_trace_scaffold.sh`。编译前在构建树拷贝目录跑 `trace_preprocessor.py ... --modify`，生成 `point_map.json`。**通过后须跑通目标仓库完整 `build.sh` / `compile_ascend_proj.sh`（或 CI 等价）** |
| **6（本仓库 UMDK 已接入）** | `umdk/build/cam/comm_operator/trace_preprocessor.py` 与 **`compile_ascend_proj.sh`** 内 **`# TRACE_PREPROCESSOR_HOOK_START/END`**：在 `copy_ops` 之后、`set_conf.py` 之前，对 **`${MODULE_BUILD_PATH}/${proj_name}`** 执行预处理（**只改当次 msopgen 生成树**，仓内 `src` 源码仍保留 `TRACE_POINT` 字符串）；`point_map.json` 落在该生成树根目录。脚本缺失时打印 WARNING 并跳过。 |
| 运行后解析 | `trace_save.py`（离线 `.pt`）、`trace_collector.py`（→ `chrome_trace.json`）— 见上文「trace.json 生成流程」 |
| **7 Profile UT / 联调** | 扩展既有 **`examples/*_sample.py`** / **`test_<op>.py`**：profiling 落盘、可选 Chrome、可选 **`--trace_checks`**；数值 UT 与 profile 入口分离（少增 `*_profile.py`）。见上文步骤 7 与「端到端 profiling + Chrome」 |

- 生成打点草案（函数树 + 合并决策）：
  - `python <skill_root>/scripts/generate_instrumentation_plan.py --root <operator_dir> --entry <entry_function>`
- 根据函数边界自动写入打点代码：
  - `python <skill_root>/scripts/instrument_operator.py --target <operator_src_file_or_dir> --root-label processing`
- 校验点位命名与 B/E 配对：
  - `python <skill_root>/scripts/validate_trace_points.py <file_or_dir>`
- 静态编译安全检查（花括号平衡、预处理配对、头文件可达、参数一致性等）：
  - `python <skill_root>/scripts/check_compile_safety.py <operator_dir>`
  - 加 `--strict` 将 warnings 也视为错误
- 预处理（编译前替换 TRACE_POINT 为整数 ID）：
  - `python <skill_root>/scripts/trace_preprocessor.py <operator_src_dir> <output_dir> --modify`
- 保存 profiling tensor（离线）：
  - `python <skill_root>/scripts/trace_save.py <raw_pt_file> --rank <rank_id> --output <profiling_data_dir>`
- 生成 Chrome Trace JSON：
  - `python <skill_root>/scripts/trace_collector.py <profiling_data_dir> <point_map.json> -o chrome_trace.json`
- 部署工具链脚本到 build 目录：
  - `python <skill_root>/scripts/bootstrap_trace_toolchain.py --build-dir <build_module_dir>`
- 对编译脚本打补丁并接入预处理（幂等）：
  - `python <skill_root>/scripts/patch_build_pipeline.py --compile-script <compile_script_path> --preprocessor-cmd "<cmd>"`
- 校验工具链与编译接入是否就绪：
  - `python <skill_root>/scripts/verify_trace_scaffold.py --build-dir <build_module_dir> --compile-script <compile_script_path>`
- 一键执行"部署工具链 + 编译接入 + 校验"：
  - `bash <skill_root>/scripts/apply_trace_scaffold.sh <skill_root> <build_module_dir> <compile_script_path>`

## 输出约定

完成后回复中**必须**包含：

**门禁对照（默认范围）**  
- 用 **G1–G5** 逐条声明 **已满足 / 未满足**；未满足须写原因与用户需补动作。

**技术与结果**  
- 插桩修改的文件列表（含 **`op_kernel/` 子树**，不仅是入口壳子）。
- 最终点位层级（L1 为 `processing`；合并关系可简述）。
- `validate_trace_points.py` 与 `check_compile_safety.py` 结果（或说明为何目标仓未跑）。
- **全链路改动摘要**：至少列出 **`op_host` / infer / tiling / 核入口 / pregen `aclnn_*` / pybind** 中是否已对齐 **G2**（profiling 最后一路、顺序一致）。
- 工具链：hook 所在脚本、`point_map.json` 典型路径形态；若 bootstrap 了哪些文件到 build 目录。
- **步骤 7**：改动的 **`examples/*_sample.py` / `test_*.py` 路径**；是否 **`synchronize` → `save_profiling_data`**；Chrome 是否 **`trace_collector` + 同源 point_map**；**路径是否已 `resolve()`**（G5）。
- **UMDK**：wheel 路径 **`umdk/output/cam/comm_operator/dist/`**、安装命令；**`libcam.so`** / **返回值个数** 见「编译与打包门禁」。
- 生成 **`chrome_trace.json`** 的命令行示例（参数用真实形态，避免 `/path/to` 占位误导）。
