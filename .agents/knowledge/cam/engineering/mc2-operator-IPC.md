# 昇腾 NPU 的 MC2（Matrix Computation & Communication）算子：跨卡窗口地址的获取与演进

> 
> 读者对象：想搞清楚 MC2 跨卡通信"窗口地址从哪来"的算子开发者。会讲清楚每一代的原理、代表算子的真实做法、以及代码该往哪写。

---

## 1. 背景：MC2 是什么，跨卡通信靠什么

### 1.1 MC2 = Matrix Computation & Communication

MC2 是昇腾 NPU 上**矩阵计算与通信融合**的一类算子。"M"是 Matrix，"C"×2 是 Computation 与 Communication。它把本来分两步的事——先跑一个通信算子（AlltoAll / AllReduce / ReduceScatter），再跑一个计算算子（MatMul / 重排 / 加权求和）——合并成一次算子下发。
这样做的好处有两层：

1. **减少一次 host 调度**：不用为通信单独在 host 侧构造子图、下发任务，通信调度下沉到设备侧。
2. **计算和通信流水并行**：计算（AIV）和跨卡搬运可以同时在跑，而不是串行等待。
典型 MC2 算子及各自融合的计算/通信：| 算子 | 计算部分 | 通信部分 |
| --- | --- | --- |
| `MatmulReduceScatter` | matmul | reduce-scatter |
| `QuantAllReduce` | 量化 + 累加 | allreduce |
| `MoeDistributeDispatch` | token 路由 + 重排 | alltoall |
| `MoeDistributeCombine` | 加权求和 | alltoall |

### 1.2 跨卡窗口（Window）与 IPC 地址

要在 AiCore（AIV 核）上直接读写**对端卡**的内存，不能靠 host 中转（太慢）。HCCL 的做法是：为每个通信域（用 `groupEp` 标识，比如一个 EP 组）在每张卡上分配一块**共享窗口（Window）**，通过硬件把这块窗口映射到对端卡的地址空间——于是"我在本地 A 卡上写地址 X"就能直接写到 B 卡的窗口里。
窗口内部通常分成两段：

- **状态区（State / Exp 区）**：放同步标志位 `flag`、计数器。接收方靠轮询 flag 判断"这块数据到了没"。
- **数据区（Data 区）**：放真正要传的 tensor 数据。
于是每个 MC2 算子都要回答同一个问题：**我要写给对端 rank 的那个窗口，起始地址是多少？每张卡的偏移怎么算？**
这一个问题，就是本报告的主题——"窗口地址（IPC 地址）的获取"。它随 HCCL 版本和芯片架构发生过三代变化，也是 MC2 算子从 A2/A3 移植到 A5 时最容易踩坑的地方（最典型的就是 A5 上 `SetCommEngine(2)` 直接报错）。

### 1.3 三个先决概念（初学者必读）

在进入三代之前，先明确三个贯穿全文的概念：
**① 一个 MC2 算子涉及两种"核"**

- **AIV**：AiCore，做计算（路由、重排、matmul），也能发起 MTE 数据搬运。绝大多数 MC2 算子的主体逻辑在 AIV 上。
- **AICPU**：通信驱动核，负责生成任务、调度 RDMA/MTE。它能读 AIV 写到 GM 的消息区，但不能像 AIV 那样高效地跑大量计算。
**② `SetCommEngine` 决定"谁驱动通信"**
算子 host 侧用 `AscendC::Mc2CcTilingConfig` 查 tiling，其中 `SetCommEngine(引擎值)` 指定用哪个核/引擎驱动通信。引擎值对应 `HcclAccelerator` 枚举（`types.h:29`）：

```
MAKE_ENUM(HcclAccelerator, DEFAULT, HOSTCPU_TS, AICPU_TS, AIV, AIV_ONLY, CCU_MS, CCU_SCHED, AICPU);
//                           0        1            2         3    4         5       6          7
```

## **③ `GetHcclContext` 是拿窗口地址的入口**
kernel 侧通过 `AscendC::GetHcclContext<HCCL_GROUP_ID_0>()` 拿到 HCCL 注入的窗口上下文（一个 GM 指针），强转成对应结构体后读窗口地址、rank 信息等。**这是模式①、②的共同入口**，模式③则不再依赖它。

## 2. 三代演进总览

按"**通信由谁驱动 + 窗口地址由谁给出**"这两个轴，三代如下：

| 代际 | 通信执行者 | 窗口地址由谁给出 | kernel 拿地址的方式 | 典型算子 |
| --- | --- | --- | --- | --- |
| **① HCCL AICPU 驱动** | AICPU（或 host） | HCCL 全托管，黑盒注入 | `GetHcclContext` → `HcclOpResParam` 树 | matmul_reduce_scatter, all_gather_matmul |
| **② HCCL MTE 驱动** | AIV（MTE） | HCCL 分配，算子显式算偏移 | `GetHcclContext` → `HcclCombinOpParam` 数组 | quant_all_reduce, moe_distribute_dispatch/combine |
| **③ 解耦** | 上层选 MTE/CCU/RDMA | 上层显式查询，经 context 张量下发 | 直接读 `mc2Context_->epHcclBuffer_[i]` | dispatch/combine_v3+ |
| **① → ② 的分界是通信执行者**：①里是 AICPU 在搬数据，②换成 AIV（MTE）。注意 AIV/MTE 引擎在 A2/A3 上也能用（如 `moe_distribute_combine` v1 就设了 `AIV_ENGINE`），所以这不是"芯片换代"，而是"算子选哪条数据面"。 |  |  |  |  |
| **② → ③ 的分界是地址责任**：②里窗口仍是 HCCL 在背后分配、`GetHcclContext` 注入；③里上层自己逐卡拿到 buffer 地址，打包进 context 张量传给 kernel，`GetHcclContext` 不再参与。 |  |  |  |  |

---

## 3. 三代模式详述

### 3.1 模式①：HCCL AICPU 驱动——AICPU（或 host）直接搬数据

#### 3.1.1 它解决什么问题

早期 MC2 算子要的是"把 matmul 和 reduce-scatter 简单融合起来，别多一次 host 调度"。数据面不用太激进——让 HCCL 的 AICPU（或 host 侧调度）负责通信就行。所以算子对"引擎"不操心，交给 HCCL 默认。
**判断方式**：看 tiling 里有没有 `SetCommEngine`。没有的，基本就是模式①——引擎交给 HCCL 默认（A2/A3 上通常是 HOST/AICPU）。

#### 3.1.2 代表算子及证据

`MatmulReduceScatter`（`matmul_reduce_scatter/op_host/op_tiling/matmul_reduce_scatter_tiling.cpp:625-631`）——它明确**不用** `SetCommEngine`：

```
const char *groupName = context->GetAttrs()->GetAttrPointer<char>(static_cast<int>(0));
const std::string rsConfig = GetRsConfig(tilingData);
AscendC::Mc2CcTilingConfig mc2CcTilingConfig(groupName, opType, rsConfig, 0);
mc2CcTilingConfig.GetTiling(tilingData.mc2InitTiling);
mc2CcTilingConfig.GetTiling(tilingData.mc2CcTiling);
```

同类的还有 `all_gather_matmul`、`ffn_to_attention`、`batch_mat_mul_reduce_scatter_allto_all`——都不显式指定引擎，走 HCCL 默认路径。

#### 3.1.3 窗口地址怎么来、kernel 怎么拿

窗口由 HCCL 在背后分配。kernel 侧用 `GetHcclContext` 拿注入的上下文。**在 A2/A3 上**，这个上下文是 `HcclOpResParam`，窗口信息分散在一棵 `remoteRes` 树里（`moe_distribute_base.h:196`）：

```
HcclOpResParam (本卡)
├─ localWindowsIn = 0xABCD0000   本卡窗口基址
├─ remoteRes[0].nextDevicePtr ->  HcclRankRelationResV2 { windowsIn = 0xEF010000 }
├─ remoteRes[1].nextDevicePtr ->  HcclRankRelationResV2 { windowsIn = 0xEF020000 }
└─ …（下标是目标 rank）
```

kernel 里要拿**对端 rank** 的窗口，得沿着树走两跳（AFD 的 `a2e.h:84` 就是这么做的）：

```
epWinContext_ = (__gm__ HcclOpResParam *)AscendC::GetHcclContext<HCCL_GROUP_ID_0>();
if (rankId == this->rank) {
    return (GM_ADDR)(epWinContext_->localWindowsIn);        // 本卡：直接读 local 字段
} else {
    // 对端：remoteRes[rankId] -> nextDevicePtr -> windowsIn，两次解引用
    return (GM_ADDR)(((HcclRankRelationResV2 *)(epWinContext_->remoteRes[rankId].nextDevicePtr))->windowsIn);
}
```

#### 3.1.4 局限

- **窗口地址不透明**：大小、布局在 tiling 阶段都看不到，调试靠 log。
- **载体结构随架构漂移**：A5 上 `HcclOpResParam` 换成了 `HcclCombinOpParam` 扁平数组（见模式②），算子要 `#ifdef` 条件编译。
- **引擎不可选**：默认引擎在不同 HCCL 版本、不同芯片上可能是不同的东西，算子控制不了。

---

### 3.2 模式②：HCCL MTE 驱动——数据搬运交给 MTE（AIV），AICPU 只做任务与元数据

#### 3.2.1 它解决什么问题

模式①里 AICPU 是真正的通信执行者。但对 dispatch/combine 这类**对时延敏感**的算子，AICPU 逐任务调度、每任务还有固定开销（后续讲 `BatchWrite` 时会看到），重复搬大量小 token 时很吃亏。
模式②把**数据搬运本身**交给 AIV 用 MTE 做：AIV 可以直接 `DataCopy` 把数据写进对端窗口，AICPU 只负责生成任务、调度通信、做元数据（tiling、gen_task）。这样"计算 + 搬运"都在 AIV 上，宿主侧几乎不介入。
**判断方式**：tiling 里显式 `SetCommEngine(AIV_ENGINE)`（=3）或者 `AIV_TYPE`（=3）。

#### 3.2.2 代表算子及证据

- `moe_distribute_dispatch` / `moe_distribute_combine`（v1、v2）——`SetCommEngine(mc2tiling::AIV_ENGINE)`。
- `quant_all_reduce` / `quant_reduce_scatter`——`SetCommEngine(AIV_TYPE)`，且注释直接写着 **"MTE方式必要适配"**（`quant_reduce_scatter_tiling.cpp:56`）。
以 `combine_v2` 为例（`moe_distribute_combine_v2_tiling.cpp:1627-1635`）：

```
AscendC::Mc2CcTilingConfig mc2CcTilingConfig(groupEp, opType1, algConfigAllToAllStr);
mc2CcTilingConfig.SetCommEngine(mc2tiling::AIV_ENGINE); // =3，MTE 引擎
mc2CcTilingConfig.GetTiling(tiling->mc2InitTiling);
mc2CcTilingConfig.GetTiling(tiling->mc2CcTiling1);
```

#### 3.2.3 窗口地址怎么来、kernel 怎么拿

在 **A5** 上，注入的窗口上下文是 `HcclCombinOpParam` 扁平数组（`comm_args.h:26-38`、`moe_distribute_base.h:204-220`）：

```
struct HcclCombinOpParam {
    uint64_t workSpace;                    // 通信工作空间基址
    uint64_t workSpaceSize;
    uint32_t rankId;                       // 本卡 rank ID
    uint32_t rankDim;                      // 总卡数
    uint64_t winSize;                      // 每个窗口大小
    uint64_t windowsIn[HCCL_MAX_RANK_NUM]; // 所有 rank 的窗口基址（扁平）
    uint64_t windowsOut[HCCL_MAX_RANK_NUM];
};
```

**读窗口地址**就变成了一次数组索引（`moe_distribute_base.h:482-491`）：

```
__aicore__ inline GM_ADDR GetBaseWindAddrByRankId(__gm__ HcclOpParam *winContext,
                                                   const int32_t rankId, const int32_t curRankId) {
    return (GM_ADDR)(winContext->windowsIn[rankId] + A5_MTE_STATE_WIN_SIZE + rankId * EP_RANK_OFFSET_STEP);
}
```

这里两个常量很重要（`moe_distribute_base.h:35-38`）：

- `A5_MTE_STATE_WIN_SIZE = 1MB`：每个 rank 窗口头部留 1MB 做状态区。
- `EP_RANK_OFFSET_STEP = 1024B`：每张卡的偏移步长，用来把多卡的数据区在地址空间里隔开。
所以 **A5 数据区起点 = `windowsIn[rankId] + 1MB + rankId * 1024`**。
（对比 A2/A3：数据区偏移是 `IPC_DATA_OFFSET = 2MB`——前 2MB 做 flag/状态区，之后是数据区。两种布局含义完全不同，移植时必须按架构分别处理。）

#### 3.2.4 一个具体例子：dispatch/combine 的"消息区 + AIV/AICPU 分工"

这里回到你问的那句分工。它**大体成立，但要补上"描述符"这一环**，并且要说清 A2/A3 和 A5 走的是两条不同的路。
**设计文档里的分工**（《MoeDistributeDispatch-Combine 算子设计介绍.md》1.3 节）说的就是：

1. **预处理（AIV）**：算每个 token 的路由，按目标 rank 重排，把数据在共享内存里的地址、长度通过 **GM 中的消息区** 传给同处 Device 侧的 AICPU。
2. **通信驱动（AICPU）**：AICPU 直接驱动 RDMA，"彻底摒弃传统需要 Host 侧构造子图、调度 RDMA 任务的繁琐流程"。
3. **通信等待与后处理（AIV）**：AIV 轮询接收 flag，确认数据到齐，再把共享内存数据按专家搬出、给下游 FFN。
**在 A2/A3 上，这个"消息区 + 描述符"是怎么实现的**——靠 `moe_distribute_dispatch_setup` 这个算子（`arch22`）：

- AIV 先把要发的 token 数据按目标 rank 重排，写进**本卡的发送窗口**。
- AIV 再为每个要发的 token 构造一个 `BatchWriteItem` 描述符（`moe_distribute_dispatch_setup_arch22.h:37`），里面填：`type`（数据类型）、`length`（本次搬运长度）、`srcAddrLow/High`（源地址 = 本卡 yOut 窗口）、`dstAddrLow/High`（目的地址 = 对端 rank 窗口）：

```
struct BatchWriteItem {
    uint64_t type;          // HcclDataType：INT8 / FP16 / ...
    uint32_t res1[5];
    uint32_t length;        // axisHCommu，本次搬运的数据长度
    uint32_t srcAddrLow;
    uint32_t srcAddrHigh;   // 源：本卡输出窗口 + 偏移
    uint32_t dstAddrLow;
    uint32_t dstAddrHigh;   // 目的：对端窗口 + 偏移
    uint32_t res2[4];
};
```

- 这些描述符被写到 **GM 的 `commCmdInfoOutGM_`**（这就是"消息区"），于是 AICPU 能读到它（`arch22` 里 `sendInfo_ = reinterpret_cast<BatchWriteItem *>(commCmdInfoOutGM_)`）。
- 最后 AIV 调用 `hccl.BatchWrite(...)` 把这个描述符数组交给 HCCL，HCCL 的 AICPU/通信侧拿到后**按描述符逐条驱动 RoCE**。设计文档给出：AICPU 下发单个通信任务到 RoCE 约 1~2us。
所以更准确的说法是：**AIV 负责"算路由、重排数据、把要发的地址和长度写进描述符、放进 GM 消息区，并调用 BatchWrite"；AICPU 负责"读这批描述符、真正驱动 RoCE 发送"**。文档里那句"AICPU 直接驱动 RDMA"指的是后半段，前半段的描述符是 AIV 生成的。
**在 A5（Ascend 950）上路径不同**：走 MTE 全互联（full_mesh），AIV 用 `DataCopy` 直接写对端窗口、用 `Flag`/`SetFlag` 做同步（`moe_distribute_dispatch_v2_a5_full_mesh.h` 里大量 `DataCopy(dstWinGMTensor, ...)` + `WaitFlag<HardEvent::MTE3_V>` / `SetFlag<HardEvent::MTE3_V>`），不再是"写描述符 → AICPU 驱动"那条链，而是 AIV 亲自把数据搬过去，AICPU 只做 gen_task 等元数据。
一句话总结模式②的两种硬件落实：| 平台 | 数据怎么过去 | 同步方式 |
| --- | --- | --- |
| A2/A3（arch22） | AIV 写描述符数组到 GM 消息区，`BatchWrite` 交给 AICPU 驱动 RoCE | AICPU 驱动 + flag |
| A5（arch35） | AIV 用 MTE `DataCopy` 直接写对端窗口 | `SetFlag`/`WaitFlag`（MTE3_V） |

#### 3.2.5 局限

- **窗口仍由 HCCL 分配**：算子拿到的是"已知偏移的现成窗口"，无法在 tiling 阶段按需扩缩。
- **结构随版本/架构耦合**：`HcclCombinOpParam` 内部布局随 CANN 版本和芯片可能变，算子要条件编译。
- **窗口偏移要自己算**：A5 的 `1MB + rankId*1024`、A2/A3 的 `2MB` 偏移都得写进 kernel，错了就是"结果不对但不报错"。

---

### 3.3 模式③：解耦——通信域地址由上层管理，经 context 张量下发

#### 3.3.1 它解决什么问题

模式①、②里**窗口地址始终由 HCCL 在背后分配**，算子对 "分配了多大的窗口、每卡地址在哪" 没有主动控制权。当算子想：

- 同时支持 MTE / CCU / RDMA 多种引擎，
- 按动态 batch、弹性专家预分配更大窗口，
- 不因 CANN 版本升级而重编译（`HcclCombinOpParam` 布局一变就要改），
就需要把"地址"这件事从 HCCL 黑盒里**拿出来交给上层**。

#### 3.3.2 上层怎么拿地址：`Mc2Context::GetMc2ContextTensor`

`ops-transformer/mc2/common/op_api/mc2_context.cpp` 提供一个统一入口，一次拿到"每卡 buffer 地址 + buffer 大小"：

```
aclnnStatus Mc2Context::GetMc2ContextTensor(const char *groupEp, const char *opName,
                                            uint64_t &hcclBuffSize, aclTensor *&mc2Context) {
    // 1. 拿 HcclComm 句柄
    HcclComm hcclHandle;
    GetCommHandle(groupEp, &hcclHandle);
    // 2. 逐卡拿 buffer 地址（见 3.3.3）
    Mc2MoeContext mc2ContextStruct;
    GetHcclCommResource(hcclHandle, engine, protocol, &mc2ContextStruct);
    // 3. 在 HCCL 里建一块 context 设备内存，把结构体拷进去
    HcclEngineCtxCreate(hcclHandle, opName, engine, sizeof(Mc2MoeContext), &ctx);
    HcclEngineCtxCopy(hcclHandle, engine, opName, &mc2ContextStruct, sizeof(Mc2MoeContext), 0);
    // 4. 包装成 aclTensor 返回（kernel 把它当输入读）
    mc2Context = aclCreateTensor(..., ctx, ...);
    hcclBuffSize = hcclBuffSize_;   // 每卡窗口大小
}
```

#### 3.3.3 逐卡地址怎么填：`GetHcclCommResource`

关键实现（`mc2_context.cpp:266-301`）：本卡用 `HcclGetHcclBuffer`，对端用 `HcclChannelGetHcclBuffer`（后者要先用 `HcclChannelAcquire` 对每个对端拿一个 channel 句柄）：

```
for (uint32_t i = 0; i < epRankSize_; ++i) {
    void *tempBuffer = nullptr;
    uint64_t bufSize = 0;
    if (i == rankId) {
        // 本卡：直接拿 HCCL 的 buffer
        HcclGetHcclBuffer(hcclHandle, &tempBuffer, &hcclBuffSize_);
    } else {
        // 对端：通过 channel 拿
        uint32_t idx = (i < rankId) ? i : (i - 1);
        HcclChannelGetHcclBuffer(hcclHandle, channels[idx], &tempBuffer, &bufSize);
    }
    // 加上逐卡偏移，存进 context
    mc2ContextStruct->epHcclBuffer_[i] = reinterpret_cast<uint64_t>(tempBuffer) + i * EP_RANK_OFFSET_STEP;
}
```

这里用到的 `HcclChannelAcquire`、`HcclGetHcclBuffer`、`HcclChannelGetHcclBuffer` 是 HCCL 提供的**显式查询 API**。模式①、②里这些查询由 `GetTiling` 内部隐式完成；模式③把它暴露给上层，于是上层可以逐卡看到地址。

#### 3.3.4 context 结构：`Mc2MoeContext`

`mc2/common/op_kernel/mc2_moe_context.h:22-30`：

```
struct Mc2MoeContext {
    uint32_t epRankId;                          // 本卡 rank ID
    uint32_t rankSizePerServer;                 // 每服务器卡数
    uint64_t kfcContextAddr;                    // KFC 方案上下文
    uint64_t epHcclBuffer_[HCCL_MAX_RANK_SIZE]; // 每张卡的 buffer 基址（最多 1024 卡）
    uint64_t hcommHandle_[HCCL_MAX_RANK_SIZE];  // ROCE/URMA 句柄
};
```

`epHcclBuffer_[i]` 就是第 `i` 张卡的窗口基址（已含 `i * EP_RANK_OFFSET_STEP` 偏移）。结构大小由 `HCCL_MAX_RANK_SIZE=1024` 决定（两个 `uint64[1024]` 约 16KB）；它在 HCCL 里经 `HcclEngineCtxCreate` 分配设备内存，上层只拿指针。

#### 3.3.5 kernel 侧怎么消费：`isMc2Context_` 分支

同一个 kernel 可以同时支持"走 `GetHcclContext`"（模式②）和"走 context 张量"（模式③），用 `isMc2Context_` 区分（`moe_distribute_combine_v2_a5_mte.h:442-456`）：

```
if (isMc2Context_) {
    // 模式③：读 Mc2MoeContext
    mc2Context_ = (__gm__ Mc2MoeContext *)mc2Context;
    epRankIdHccl = mc2Context_->epRankId;
    statusDataSpaceGm_ = (GM_ADDR)(mc2Context_->epHcclBuffer_[epRankIdHccl]);
} else {
    // 模式②：读 HcclCombinOpParam
    auto contextGM0 = AscendC::GetHcclContext<HCCL_GROUP_ID_0>();
    epWinContext_ = (__gm__ Mc2Kernel::HcclOpParam *)contextGM0;
}
```

访问对端窗口时（`moe_distribute_combine_v2_a5_mte.h:128-140`）：

```
__aicore__ inline GM_ADDR GetWindAddrByRankId(int32_t rankId) {
    if (isMc2Context_) {
        // 模式③：直接读 context 里的数组下标
        return (GM_ADDR)mc2Context_->epHcclBuffer_[rankId] + STATE_SIZE + winDataSizeOffsetEp_;
    } else {
        // 模式②：用 GetBaseWindAddrByRankId 算偏移
        return Mc2Kernel::GetBaseWindAddrByRankId(epWinContext_, rankId, epRankIdOriginal_) + winDataSizeOffsetEp_;
    }
}
```

**对比一下两种取地址**：模式②要一层层算（数组索引 + 1MB state区 + rank 步长），模式③直接 `epHcclBuffer_[rankId]` 一把取到基址。模式③"地址在上层可见、可打印、可改"。

#### 3.3.6 `hcclBuffSize` 是什么、用来干嘛

`hcclBuffSize` 是**每张卡窗口的大小**（不是所有卡总和）。它有两个用途：

1. **tiling 阶段**：算子算出自己需要的窗口大小 `totalWinSize`，跟它比。
2. **kernel 运行时**：用 `CheckWindowSize` 校验（`check_winsize.h`），不足就报异常：

```
__aicore__ inline void CheckWindowSize(uint64_t tilingWinSizeBytes, uint64_t realWinSizeBytes,
                                       TPipe *tpipe_, GM_ADDR exceptionAddr) {
    if (unlikely(realWinSizeBytes < tilingWinSizeBytes)) {
        // 窗口不足：触发异常
        DataCopy(exceptionLocal[1], exceptionGlobal, 1);
    }
}
```

`realWinSizeBytes` 来自 `hcclBuffSize`，`tilingWinSizeBytes` 由算子自己算（比如 `batchSize * hiddenSize * topk * sizeof(T)`）。这就是模式③"上层管理、按需扩缩"的体现——窗口多大、够不够，都是上层在管。

#### 3.3.7 API 层怎么分流（同算子支持两条路径）

`moe_distribute_combine_v2_base.cpp:185-207` 展示了同个算子怎么在一个 API 里分流：

```
const static bool is950 = GetCurrentPlatformInfo().GetCurNpuArch() == NpuArch::DAV_3510;
if (!is950 || (commAlg != nullptr && std::strcmp(commAlg, "ccu") == 0)) {
    // 模式②：AIV/MTE 路径（或 CCU），kernel 走 GetHcclContext
    getWorkspaceSizesRes = aclnnInnerMoeDistributeCombineV2GetWorkspaceSize(...);
} else {
    // 模式③：解耦，先用 Mc2Context 拿每卡 buffer 地址
    uint64_t hcclBuffSize = 0;
    Mc2Aclnn::Mc2Context::GetMc2ContextTensor(groupEp, "moe_distribute_v2", hcclBuffSize, mc2Context);
    getWorkspaceSizesRes = aclnnInnerMoeDistributeCombineV3GetWorkspaceSize(mc2Context, ..., hcclBuffSize, ...);
}
```

## 注意：**A5 上才开解耦分支**（`is950`）。A2/A3 仍走模式②的 `BatchWrite`/MTE 路径；CCU 算法也不走解耦（`commAlg == "ccu"` 时仍走 V2）。

## 4. 三代对比

| 维度 | ① HCCL AICPU 驱动 | ② HCCL MTE 驱动 | ③ 解耦（上层管理） |
| --- | --- | --- | --- |
| **通信执行者** | AICPU（或 host） | AIV（MTE） | 上层选 MTE/CCU/RDMA |
| **AICPU 角色** | 通信执行者，直接搬数据 | 只做任务/元数据（gen_task、描述符） | 视引擎而定 |
| **谁负责拿地址** | HCCL 注入 `GetHcclContext` | HCCL 分配，算子显式算偏移 | 上层用 HCCL Channel API 显式查询 |
| **窗口载体** | A2/A3 `HcclOpResParam` 树 / A5 `HcclCombinOpParam` | A5 `HcclCombinOpParam` 扁平数组（A2/A3 树亦可） | `Mc2MoeContext` + `epHcclBuffer_` |
| **Tiling 依赖** | `Mc2CcTilingConfig::GetTiling`（引擎交给 HCCL） | `...GetTiling` + `SetCommEngine(AIV=3)` | 先 `Mc2Context::GetMc2ContextTensor` |
| **取地址方式** | `GetHcclContext` → 树两次解引用 / 数组一次索引 | `GetHcclContext` → 数组一次索引 + 算偏移 | 直接 `mc2Context_->epHcclBuffer_[i]` |
| **引擎选择** | 默认（A2/A3 通常 HOST/AICPU） | 显式指定（AIV=3 MTE，A5 上 CCU=6） | 上层取 context 时指定 |
| **与 HCCL 耦合** | 强（直接消费 HCCL 结构） | 强（消费 `HcclCombinOpParam`） | 弱（`Mc2MoeContext` 由算子定义） |
| **典型算子** | matmul_reduce_scatter, all_gather_matmul, ffn_to_attention | moe_distribute_dispatch/combine, quant_all_reduce | dispatch/combine_v3+ |
| **适用平台** | A2/A3 为主 | A2/A3 与 A5 都行 | 目前 A5 为主 |

### 责任边界演进

| 责任 | ① | ② | ③ |
| --- | --- | --- | --- |
| **窗口分配** | HCCL | HCCL | HCCL（底层 buffer 池） |
| **地址查询** | HCCL（黑盒） | HCCL（黑盒） | 上层（显式 API） |
| **地址注入** | HCCL → kernel | HCCL → kernel | 上层 → context 张量 → kernel |
| **数据搬运** | AICPU | MTE | 上层选（MTE/CCU/RDMA） |
| **窗口大小控制** | HCCL 动态扩容 | HCCL 动态扩容 | 上层预分配 + 校验 |
| **引擎选择** | HCCL 默认 | Tiling（`SetCommEngine`） | 上层（取 context 时指定） |

---

## 5. 关键判据：A5 上 `SetCommEngine` 怎么选 + 常见坑

这是从 A2/A3 移植到 A5 时最实际的坑，单独成节。

### 5.1 引擎选谁

`mc2_tiling_utils.h:51-58` 用注释直接列了每个引擎值在 A2/A3 vs A5 的支持情况：
**A2/A3 支持、A5 不支持的引擎**：

- `HOSTCPU_TS (=1)` / `HOST_TS` —— A5 不支持
- `AICPU_TS (=2)` —— A5 不支持
- `AIV_ONLY (=4)`、`CCU_MS (=5)` —— A5 不支持
- `AICPU_UB/ROCE (=7)` —— A5 不支持
- `DEFAULT (=0)` —— A5 上行为与 A2/A3 不同
**A5 支持的引擎**：
- `AIV (=3)` —— MTE 数据面，dispatch/combine、quant_all_reduce 等在 A5 上的核心选择
- `CCU_SCHED (=6)` —— CCU 调度路径（部分算子）

### 5.2 判例：为什么会 `SetCommEngine(2)` 失败

A5 上若仍用 A2/A3 的 `SetCommEngine(2)`（AICPU_TS），HCCL 的 `GetTilingAccelerator` 检查到 A5 不支持该引擎，直接返回 `HCCL_E_NOT_SUPPORT`，资源分配失败，表现为：

```
[ERROR] HcclAllocComResourceByTiling ... ret=5 (HCCL_E_NOT_SUPPORT)
```

修法：按芯片分支用 AIV。AFD 插件就是这么做的（`a2e_tiling.cpp:88-99`）：

```
auto platform = platform_ascendc::PlatformAscendC(context->GetPlatformInfo());
if (platform.GetSocVersion() == platform_ascendc::SocVersion::ASCEND950) {
    mc2CcTilingConfig.SetCommEngine(3);   // AIV = HcclAccelerator::AIV
}
```

### 5.3 窗口偏移判据

- **A5**：数据区起点 = `windowsIn[rankId] + 1MB(state区) + rankId * 1024`。
- **A2/A3**：数据区起点 = `localWindowsIn + 2MB`（对端则经 `remoteRes` 树取 `windowsIn`，再按需加自己的偏移）。
写 kernel 时按架构分别处理，别混用——**混用的典型症状是"结果不对但几乎不报错"**（算错位置写到了别的窗口）。

### 5.4 排查方法

1. 报 `ret=5` → 检查 tiling 的 `SetCommEngine` 值在 A5 上是否受支持。
2. **改了源码但行为没变** → 往往不是代码问题，是**跑的还是旧的 tiling 库**。核对运行时 vendor 目录里 `libcust_opmaster_rt2.0.so` 的时间戳是不是最新编出来的。
3. **分配能过但数据错** → 多半是窗口偏移算错了（A5 的 `1MB + rank*1024` 和 A2/A3 的 `2MB` 混了）。

---

## 6. 参考代码与文档

### CANN 9.1.0 头文件

- `hccl_tiling.h:24` —— `Mc2CcTilingConfig` 类定义
- `hccl_tiling.h:46` —— `SetCommEngine` 方法
- `hccl_tilingdata.h` —— `Mc2InitTiling`（64B）/ `Mc2CcTiling`（512B）不透明描述头
- `types.h:29` —— `HcclAccelerator` 枚举（AIV=3）
- `kernel_common.h:208` —— `GetHcclContext` 函数

### ops-transformer 仓库

- `mc2/common/op_kernel/moe_distribute_base.h:35-38` —— `EP_RANK_OFFSET_STEP` / `A5_MTE_STATE_WIN_SIZE`
- `mc2/common/op_kernel/moe_distribute_base.h:196-220` —— `HcclOpResParam` / `HcclCombinOpParam` 结构
- `mc2/common/op_kernel/moe_distribute_base.h:460-522` —— A5 / A2+A3 地址计算 helper 条件编译
- `mc2/common/op_kernel/mc2_moe_context.h:22-30` —— `Mc2MoeContext` 结构
- `mc2/common/op_host/op_tiling/mc2_tiling_utils.h:51-58` —— 引擎取值及 A5 支持注释
- `mc2/common/op_api/mc2_context.cpp:266-301` —— `GetHcclCommResource` 逐卡地址填充
- `mc2/matmul_reduce_scatter/op_host/op_tiling/matmul_reduce_scatter_tiling.cpp:625-631` —— 模式①（不显式设引擎）
- `mc2/quant_reduce_scatter/op_host/op_tiling/quant_reduce_scatter_tiling.cpp:56` —— 模式②（`SetCommEngine(AIV_TYPE)`，"MTE方式必要适配"）
- `mc2/moe_distribute_dispatch_setup/op_kernel/arch22/moe_distribute_dispatch_setup_arch22.h:37, 335, 453` —— `BatchWriteItem` 结构 / 描述符写 GM / `BatchWrite` 下发
- `mc2/moe_distribute_dispatch_v2/op_kernel/arch35/moe_distribute_dispatch_v2_a5_full_mesh.h` —— A5 MTE `DataCopy` + `Flag` 同步
- `mc2/moe_distribute_combine_v2/op_kernel/arch35/moe_distribute_combine_v2_a5_mte.h:128-140, 442-456` —— `isMc2Context_` 分支
- `mc2/moe_distribute_combine_v2/op_host/op_tiling/moe_distribute_combine_v2_tiling.cpp:1628` —— `SetCommEngine(AIV_ENGINE)`
- `mc2/moe_distribute_combine_v2/op_api/moe_distribute_combine_v2_base.cpp:185-207` —— 模式②/③ API 分流
- `mc2/moe_distribute_dispatch_v2/docs/MoeDistributeDispatch-Combine算子设计介绍.md` —— 设计文档（AIV/AICPU 分工、BatchWrite 描述符、FLAG 双循环等）

### AFD 插件

- `csrc/npu/a2e/op_host/a2e_tiling.cpp:88-99` —— A5 `SetCommEngine(3)` 修复
- `csrc/npu/a2e/op_kernel/comm_args.h:26-38` —— A5 `HcclCombinOpParam` 结构
- `csrc/npu/a2e/op_kernel/a2e.h:82-84, 161-169` —— 读 context / `winBaseOf` 地址计算

---

## 7. 结论

MC2（Matrix Computation & Communication）算子的跨卡窗口地址获取，三代演进核心是**两件事的逐步移交**：

1. **通信执行权**：AICPU → AIV（MTE）。模式① AICPU 直接搬数据；模式② AIV 用 MTE 搬、AICPU 只做任务和元数据。
2. **地址管理权**：HCCL → 上层。模式②窗口仍由 HCCL 分配、`GetHcclContext` 注入；模式③上层逐卡拿到地址、经 context 张量下发。
**给算子开发者的实操要点**：

- **tiling 侧**：用 `Mc2CcTilingConfig` + `SetCommEngine` 选引擎。A5 上走 MTE 用 `3`（AIV），CCU 用 `6`；别用 A2/A3 的 `2`（AICPU_TS）。
- **kernel 侧**：模式①/②用 `GetHcclContext` 拿窗口上下文，注意 A5 是扁平数组、A2/A3 是树，偏移（`1MB + rank*1024` vs `2MB`）别混。模式③直接读 context 张量里的 `epHcclBuffer_[i]`。
- **上层侧**：模式③用 `Mc2Context::GetMc2ContextTensor` 一次拿到每卡地址 + `hcclBuffSize`，kernel 不再依赖 `GetHcclContext`。
- **三个最常踩的坑**：A5 上 `SetCommEngine(2)` 报 `ret=5`；改了源码没同步 tiling 库；窗口偏移按错架构算导致数据错位但不报错。
理解了"引擎选谁 + 地址谁说了算"，写、移、调、排 MC2 算子都会顺很多。
