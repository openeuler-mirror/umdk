# CAM API指南
## CAM简介
CAM是Huawei昇腾NPU超节点通信加速器(Communication Accelerator for Maxtrix)的简称，提供EP（Expert Parallelism）通信加速库、PD（Prefill & Decode）分离场景高性能KVCache传输和KVC池化、AFD（Attention-FFN Disaggregation）通信加速库、RL(Reinforcement Learning)权重传输等特性。

## CAM架构
（To be done）

## CAM API
### 1. 高性能EP通信库
CAM在umdk_cam_op_lib库中提供高性能Python通信和通算融合接口供用户使用，用户可以方便的在主流昇腾推理框架（如vllm-ascend, sglang-kernel-npu等）导入该通信库并调用接口使用。
#### 1.1 Dispatch & Combine类接口
 #### 1.1.1 get_dispatch_layout ▶
##### 1.1.1.1 接口原型 
```python
get_dispatch_layout(
    Tensor topk_idx, 
    int num_experts, 
    int num_ranks)
-> output: tuple(Tensor, Tensor)
```
##### 1.1.1.2 接口描述 
![get_dispatch_layout示意图](figures/get_dispatch_layout_a3.png)
A3代际Prefill阶段Dispatch使用的前置接口，用以在当前rank将Token拓展TopK份之后按照专家粒度重排，方便后续的分发操作。该接口需配合moe_dispatch_prefill和moe_combine_prefill使用。
##### 1.1.1.3 入参 
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|topk_idx|Tensor|必选|形状:(batch_size, topk)， int64类型，取值范围：[0, num_experts)|目标专家的ID信息|
|num_experts|int|必选|取值范围：(0, 512]|MOE专家数|
|num_ranks|int|必选|取值范围：[1, 384]|EP通信域rank数|
##### 1.1.1.4 返回值 
函数返回值是一个2个Tensor构成的Tuple，分别存放：num_tokens_per_expert和send_token_idx.
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|num_tokens_per_expert|Tensor|形状：（num_experts）|当前rank上发送给每个专家的token个数|
|send_token_idx|Tensor|形状：(batch_size, top_k)|当前rank上，发送给每个专家的token在以专家重排分桶后，其在桶里的第几个位置|
##### 1.1.1.5 约束和注意事项 ⚠️
1. 入参形状需严格满足上述入参描述中的形状定义。
2. 当前接口只支持A3环境调用。
4. 当前接口不支持并发调用。
5. 当前接口不支持入图使用。
6. 除满足上述形状约束外，其他参数取值要求：
 - top_k取值范围：(0， 16]
 - batch_size取值范围：(0, 8000]
 - 需要满足: num_experts % num_ranks == 0
 - 需要满足：num_experts >= num_ranks

 #### 1.1.2 moe_dispatch_prefill ▶
##### 1.1.2.1 接口原型 
```python
moe_dispatch_prefill(
    Tensor x, 
    Tensor topk_idx, 
    Tensor topk_weights, 
    Tensor num_tokens_per_expert, 
    Tensor send_token_idx_small, 
    str group_ep, 
    int rank, 
    int num_ranks, 
    bool use_quant) 
-> output: tuple(Tensor, Tensor, Tensor, Tensor, Tensor)
```
##### 1.1.2.2 接口描述 
![moe_dispatch_prefill示意图](figures/moe_dispatch_prefill_a3.png)
A3代际Prefill阶段Dispatch接口，将Token按照topk_idx的规则发送给对应专家。
##### 1.1.2.3 入参 
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|必选|形状:(batch_size, hidden_size), 支持bf16, float16类型|本卡发送的token|
|topk_idx|Tensor|必选|形状:(batch_size, topk)， 数据类型为int64，取值范围：[0, num_experts)|每个token的目标专家ID信息|
|topk_weights|Tensor|必选|形状:(batch_size, topk)， 数据类型为float32|每个token的topk个目标专家的权重信息|
|num_tokens_per_expert|Tensor|必选|形状：（num_experts），数据类型为int|当前rank上发送给每个专家的token个数，必须为get_dispatch_layout的出参num_tokens_per_expert，不可篡改|
|send_token_idx_small|Tensor|必选|形状：(batch_size, top_k), 数据类型为int|当前rank上，发送给每个专家的token在以专家重排分桶后，其在桶里的第几个位置，必须为get_dispatch_layout的出参send_token_idx，不可篡改|
|group_ep|str|必选|--|HCCL通信域名称|
|rank|int|必选|[0, num_ranks)|本卡在通信域中的rankID|
|num_ranks|int|必选|[2, 384]|EP通信域rank数|
|use_quant|bool|必选|True: 开启量化； False: 关闭量化|Dispatch量化指示符|
##### 1.1.2.4 返回值 
函数返回值是一个5个Tensor构成的Tuple，分别存放：recv_x, dynamic_scales_out, expand_idx_out, recv_count, recv_tokens_per_expert.
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|recv_x|Tensor|形状：(recv_token_num, hidden_size), 其中recv_token_num为本卡收到的token个数。当use_quant为true时，数据类型为int8, false时数据类型与入参x一致|当前rank上收到的token信息|
|dynamic_scales_out|Tensor|形状：(recv_token_num), 数据类型为float.当use_quant为false时该值没有意义。|当前rank上收到token的动态量化scale信息|
|expand_idx_out|Tensor|形状：(recv_token_num * 3), 数据类型为int|本卡收到的token信息三元组，每组三个数的含义依次为：token的源rank, token在源rank的序号（BS视角），token在源rank时topk专家扩展重排后的序号（专家视角）|
|recv_count|Tensor|形状：(num_experts), 数据类型为int|当前rank上每个专家从每个rank收到的收到token数，为前缀和|
|recv_tokens_per_expert|Tensor|形状：(local_expert_num), 数据类型为int64|当前rank上每个专家收到的token信息|
##### 1.1.2.5 约束和注意事项 ⚠️
1. 入参形状需严格满足上述入参描述中的形状定义。
2. 当前接口只支持A3环境调用。
3. 当前接口不支持并发调用。
4. 当前接口不支持入图使用。
5. 除满足上述形状约束外，其他参数取值要求：
 - 需要满足：BS取值范围[1, 8K]
 - 需要满足: num_ranks取值范围[2, 384]
 - 需要满足: num_experts取值范围(0, 512]
 - 需要满足: topk取值范围(0, 16]
 - 需要满足: (num_experts % num_ranks) == 0
 - 需要满足: 配置全局宏HCCL_BUFFSIZE=4096
 - 需要满足：num_experts >= num_ranks

 #### 1.1.3 moe_combine_prefill ▶
##### 1.1.3.1 接口原型 
```python
moe_combine_prefill(
    Tensor x, 
    Tensor topk_idx, 
    Tensor topk_weights, 
    Tensor src_idx, 
    Tensor send_head,
    str group_ep, 
    int rank, 
    int num_ranks) 
-> output: Tensor
```
##### 1.1.3.2 接口描述 
![moe_combine_prefill示意图](figures/moe_combine_prefill_a3.png)
A3代际Prefill阶段Combine接口，将按照topk_idx的规则发送给对应专家的token，按照topk_weights指定的权重收回。
##### 1.1.3.3 入参 
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|必选|形状:(recv_token_num, hidden_size), 支持bf16, float16类型|本卡dispatch阶段收集到的token|
|topk_idx|Tensor|必选|形状:(batch_size, topk)， 数据类型为int64，取值范围：[0, num_experts)|每个token的目标专家ID信息|
|topk_weights|Tensor|必选|形状:(batch_size, topk)， 数据类型为float32|每个token的topk个目标专家的权重信息|
|src_idx|Tensor|必选|形状：(recv_token_num * 3), 数据类型为int|本卡收到的token信息三元组，每组三个数的含义依次为：token的源rank, token在源rank的序号（BS视角），token在源rank时topk专家扩展重排后的序号（专家视角）。必须为moe_dispatch_prefill的出参expand_idx_out，不可篡改|
|send_head|Tensor|必选|形状：(num_experts), 数据类型为int|当前rank上每个专家从其他rank收到的token数前缀和。必须为moe_dispatch_prefill的出参recv_count，不可篡改|
|group_ep|str|必选|--|HCCL通信域名称|
|rank|int|必选|[0, num_ranks)|本卡在通信域中的rankID|
|num_ranks|int|必选|[2, 384]|EP通信域rank数|
##### 1.1.3.4 返回值 
函数返回值是一个Tensor，存放combine_x信息。
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|combine_x|Tensor|形状：(batch_size, hidden_size)。数据类型与x一致|当前rank上收到的token信息|
##### 1.1.3.5 约束和注意事项 ⚠️
1. 入参形状需严格满足上述入参描述中的形状定义。
2. 当前接口只支持A3环境调用。
3. 当前接口不支持并发调用。
4. 当前接口不支持入图使用。
5. 除满足上述形状约束外，其他参数取值要求：
 - 需要满足：BS取值范围[1, 8K]
 - 需要满足: num_ranks取值范围[2, 384]
 - 需要满足: num_experts取值范围(0, 512]
 - 需要满足: topk取值范围(0, 16]
 - 需要满足: (num_experts % num_ranks) == 0
 - 需要满足: 配置全局宏HCCL_BUFFSIZE=4096
 - 需要满足：num_experts >= num_ranks
6. combine_x精度校验标准
 - 非量化场景下平均相对误差为千分之五
 - 量化场景下平均相对误差为百分之一

 #### 1.1.4 fused_deep_moe ▶
##### 1.1.4.1 接口原型 
```python
fused_deep_moe(
    Tensor x, 
    Tensor expert_ids, 
    Tensor[] gmm1_weight, 
    Tensor[] gmm1_weight_scale, 
    Tensor[] gmm2_weight, 
    Tensor[] gmm2_weight_scale, 
    Tensor expert_scales, 
    Tensor? share_gmm1_weight, 
    Tensor? share_gmm1_weight_scale, 
    Tensor? share_gmm2_weight, 
    Tensor? share_gmm2_weight_scale, 
    Tensor? expert_smooth_scales,
    Tensor? share_smooth_scales,
    Tensor? x_active_mask, 
    str group_ep, 
    int ep_rank_size, 
    int ep_rank_id, 
    int moe_expert_num, 
    int quant_mode, 
    int global_bs) 
-> output: Tensor[]
```
##### 1.1.4.2 接口描述 
用于MoE Decode阶段的通算大融合算子，通过融合[Dispatch + FFN(GMM1 + Swiglu + GMM2) + Combine]实现高效的模型推理和专家选择，（可选）同时支持内置共享专家计算，适用于分布式推理场景。
##### 1.1.4.3 入参 
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|必选|形状:(batch_size, token_length), 支持bf16, float16类型|本卡dispatch阶段待处理的token|
|expert_ids|Tensor|必选|形状:(batch_size, topk)， 数据类型为int32, 取值范围[-1, num_experts)，-1用于占位使用，一个token不允许重复发给同一个专家|每个token的目标专家ID信息|
|gmm1_weight|Tensor[]|必选|耦合模式下，只有一个Tensor, 形状:(localExpertNum, token_length, gmm1_hidden_size); 分离模式下，包含localExpertNum个Tensor, 每个Tensor形状：（token_length, gmm1_hidden_size），数据类型为int8|GMM1的权重矩阵列表，支持耦合模式和分离模式|
|gmm1_weight_scale|Tensor[]|必选|耦合模式下，只有一个Tensor, 形状:(localExpertNum, gmm1_hidden_size); 分离模式下，包含localExpertNum个Tensor, 每个Tensor形状：（gmm1_hidden_size），数据类型为float32或与x数据类型一致|GMM1的权重矩阵量化时使用的缩放系数列表，支持耦合模式和分离模式|
|gmm2_weight|Tensor[]|必选|耦合模式下，只有一个Tensor, 形状:(localExpertNum, gmm1_hidden_size/2, token_length); 分离模式下，包含localExpertNum个Tensor, 每个Tensor形状：（gmm1_hidden_size/2, token_length），数据类型为int8|GMM2的权重矩阵列表，支持耦合模式和分离模式|
|gmm2_weight_scale|Tensor[]|必选|耦合模式下，只有一个Tensor, 形状:(localExpertNum, token_length); 分离模式下，包含localExpertNum个Tensor, 每个Tensor形状：（token_length），数据类型为float32或与x数据类型一致|GMM2的权重矩阵量化时使用的缩放系数列表，支持耦合模式和分离模式|
|expert_scales|Tensor|必选|形状：(batch_size, topk), 数据类型为float32|每个专家的权重，combine阶段使用|
|share_gmm1_weight|Tensor|可选|形状：（token_length, share_mm1_hidden_size），数据类型为int8|共享专家MM1的权重矩阵|
|share_gmm1_weight_scale|Tensor|可选|形状：（share_mm1_hidden_size），数据类型为与gmm1_weight_scale一致|共享专家MM1的权重矩阵量化时使用的缩放系数|
|share_gmm2_weight|Tensor|可选|形状：（share_mm1_hidden_size/2, token_length），数据类型为int8|共享专家MM2的权重矩阵|
|share_gmm2_weight_scale|Tensor|可选|形状：（token_length），数据类型为与gmm2_weight_scale一致|共享专家MM2的权重矩阵量化时使用的缩放系数|
|expert_smooth_scales|Tensor|可选|形状：(moe_expert_num，token_length)，数据类型为float32|各个路由专家的smooth quant平滑因子|
|share_smooth_scales|Tensor|可选|形状：(token_length)，数据类型为float32|共享专家的smooth quant平滑因子|
|x_active_mask|Tensor|可选|形状： (batch_size)，数据类型bool，取值范围[true, false]，true值一定要在false之前|dispatch分发token时的mask，true代表正常分发该token，false代表不分发|
|group_ep|str|必选|字符串长度范围：(0, 128), 且需要保证是有效的通信域名称|HCCL通信域名称|
|ep_rank_size|int|必选|需要满足：(ep_rank_size * MoeExpertNumPerRank) ≤ 512且ep_rank_size > 0|EP通信域大小|
|ep_rank_id|int|必选|[0, ep_rank_size)|本卡在通信域中的rankID|
|moe_expert_num|int|必选|需要满足：moe_expert_num % ep_rank_size == 0|MOE专家数量|
|quant_mode|int|必选|预留入参，当前只支持传0|量化模式|
|global_bs|int|必选|若所有卡的token数量一致，可以传入0或者batch_size * ep_rank_size; 若所有卡的token数量不一致，需要传入max_batch_size * ep_rank_size|所有卡的最大token总数|
##### 1.1.4.4 返回值 
函数返回值是一个Tensor列表，存放combine_x和expert_token_nums信息。
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|combine_x|Tensor|形状：(batch_size, token_length)。数据类型与x一致|当前rank上token经各个专家处理后汇聚的结果|
|share_output|Tensor|形状：(batch_size, token_length)。数据类型与x一致|内置共享专家处理后的结果，即使不进行共享专家计算，也会返回该值占位|
|expert_token_nums|Tensor|形状：(local_expert_num)。数据类型为int64|本卡各个专家收到的token数量|
##### 1.1.4.5 约束和注意事项 ⚠️
1. 入参形状需严格满足上述入参描述中的形状定义。
2. 当前接口只支持A3环境调用。
3. 当前接口不支持并发调用。极端情况下在单次forward中连续调用相同算子会产生未定义行为，这种场景需要在算子执行间添加torch.npu.synchronize()避免潜在的异步时序问题。
4. 当前接口图模式只支持AclGraph模式。
5. 不支持外置共享专家（即有的卡只放置共享专家）。
6. Batch_size小于16时非目标场景，其性能相对于小算子拼接可能劣化，建议性能对比后决策使用。
7. 除满足上述形状约束外，其他参数取值要求：
 - 需要满足：BS取值范围[0, 256]
 - 需要满足: token_length取值范围[1024， 7168]且(token_length % 256) == 0
 - 需要满足: gmm1_hidden_size取值范围[1024， 6144]且(gmm1_hidden_size % 1024) == 0
 - 需要满足: share_gmm1_hidden_size取值范围[1024， 6144]且(share_gmm1_hidden_size % 1024) == 0
 - 需要满足: topk取值范围[0, 12]且应保证小于等于专家数
 - 需要满足：global_bs ≥ 0 且保证（global_bs % ep_rank_size） == 0
 - 需要满足: gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale四个入参的模式必须统一，不能一部分耦合模式一部分分离模式
 - 需要满足: HCCL_BUFFSIZE环境变量配置应不小于[(ep_rank_size * max_batch_size * moe_expert_num_per_rank * total_length * sizeof(x) * 2) / 1024 / 1024]向上取整
 - 需要满足: 若要进行内置共享专家计算，则共享专家所需的share_gmm1_weight、share_gmm1_weight_scale、share_gmm2_weight、share_gmm2_weight_scale需同时存在
- 需要满足: 若要进行smooth quant，需传入expert_smooth_scales，若同时进行内置共享专家计算则share_smooth_scales也必须存在

#### 1.2 Zero-Buffer Dispatch & Combine 类接口
基于 SHMEM 实现的 Zero-Buffer DeepEP 风格 Prefill 接口，可通过 PyTorch eager 模式调用。逻辑链路为：`get_dispatch_layout_zb` →（内部 notify +）`moe_dispatch_normal_zb` → 专家计算 → `moe_combine_normal_zb`。当前库对外推荐入口为 `umdk_cam_op_lib.ZbBuffer`（封装 layout / dispatch / combine，并管理 SHMEM 与 `comm_meta_ptr`）；下列接口描述对应其底层算子语义与约束。

 #### 1.2.1 get_dispatch_layout_zb ▶
##### 1.2.1.1 接口原型
```python
umdk_cam_op_lib.get_dispatch_layout_zb(
    Tensor topk_idx,
    int num_experts,
    int num_ranks
) -> output: Tuple[Tensor, Tensor]
```
##### 1.2.1.2 接口描述
`get_dispatch_layout_zb`：Zero-Buffer 路径下根据每个 token 的 topK 专家索引，统计发往各专家的 token 数，并计算每个 `(token, topk)` 在目标专家视角下的本地发送序号，供后续 notify / `moe_dispatch_normal_zb` 使用。底层调用 `aclnnDispatchLayoutZeroBuffer`。
##### 1.2.1.3 入参
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|topk_idx|Tensor|必选|形状：`(batchSize, topK)`，数据类型 `torch.int64`|目标专家 id|
|num_experts|int|必选|MOE 路由专家数|专家总数|
|num_ranks|int|必选|通信域 rank 数|EP 通信域大小|
##### 1.2.1.4 返回值
返回由 2 个 Tensor 构成的 Tuple：`number_tokens_per_expert`、`send_token_idx`。
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|number_tokens_per_expert|Tensor|形状：`(num_experts,)`，数据类型 `torch.int`|当前 rank 发给每个专家的 token 个数|
|send_token_idx|Tensor|形状：`(batchSize, topK)`，数据类型 `torch.int`|当前 rank 发给每个专家的 token，为对应专家从当前 rank 接收的第几个|
##### 1.2.1.5 约束和注意事项 ⚠️
1. `num_ranks` 取值范围：`[1, 384]`。`num_ranks=1` 时 layout 可算出正确结果，但无法继续调用后续 notify / dispatch / combine。
2. `num_experts` 取值范围：`(0, 512]`。
3. `topk` 取值范围：`(0, 16]`。
4. `topk_idx` 中数值取值范围：`[0, num_experts)`。
5. `batchSize` 取值范围：`[1, 8000]`。
6. `num_experts % num_ranks == 0`，且 `num_experts >= num_ranks`。
7. 不支持 A2 环境（仅 A3）。
8. 输出必须直接交给后续 ZB 链路使用，不可自行改写后再传入。

 #### 1.2.2 moe_dispatch_normal_zb ▶
##### 1.2.2.1 接口原型
```python
umdk_cam_op_lib.moe_dispatch_normal_zb(
    Tensor x,
    Tensor topk_idx,
    Tensor send_token_idx,
    Tensor num_tokens_per_expert,
    int ep_world_size,
    int ep_rank_id,
    int moe_expert_num,
    int quant_mode,
    int global_bs,
    int comm_meta_ptr
) -> output: Tuple[Tensor, Tensor, Tensor, Tensor, Tensor]
```
##### 1.2.2.2 接口描述
`moe_dispatch_normal_zb`：Zero-Buffer 路径下的 normal dispatch 算子，将入参 `x` 按 `topk_idx` 规则发送给对应专家；通信窗口由 `comm_meta_ptr` 指向的 Zero-Buffer / SHMEM 元数据管理。语义对齐 `moe_dispatch_prefill`；在单个 Python 接口内依次完成 notify 与 dispatch，底层调用 `aclnnNotifyDispatchZeroBuffer`、`aclnnMoeDispatchNormalZeroBuffer`。
##### 1.2.2.3 入参
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|必选|形状：`(batchSize, h)`，支持 bf16、float16|本卡发送的 token|
|topk_idx|Tensor|必选|形状：`(bs, topK)`，数据类型 `torch.int32`|每个 token 的 topk 专家索引|
|send_token_idx|Tensor|必选|形状：`(batchSize, topK)`，数据类型 `torch.int`|必须直接使用 `get_dispatch_layout_zb` 的输出 `send_token_idx`|
|num_tokens_per_expert|Tensor|必选|形状：`(moe_expert_num,)`，数据类型 `torch.int`；须位于 SHMEM 对称内存|必须直接使用 `get_dispatch_layout_zb` 的输出 `num_tokens_per_expert`|
|ep_world_size|int|必选|EP 通信域卡数|通信域大小|
|ep_rank_id|int|必选|本卡 rankId|`[0, ep_world_size)`|
|moe_expert_num|int|必选|MOE 路由专家数|专家总数|
|quant_mode|int|必选|`0`：不量化；`2`：动态量化|量化模式|
|global_bs|int|必选|通常为 `max_batch_size * ep_world_size`，须为正|按上界分配 recv 缓冲，避免 notify 后 host sync|
|comm_meta_ptr|int|必选|Zero-Buffer / SHMEM 初始化后得到的 meta 区地址指针|通信元数据指针|
##### 1.2.2.4 返回值
返回由 5 个 Tensor 构成的 Tuple：`recv_x`、`dynamic_scales_out`、`put_offset`、`total_recv_tokens`、`recv_tokens_per_expert`。
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|recv_x|Tensor|形状：`(global_bs, h)`；`quant_mode=2` 时为 `torch.int8`，否则与 `x` 一致；位于 SHMEM|本卡收到的 token；有效长度需结合 `total_recv_tokens` 截断|
|dynamic_scales_out|Tensor|形状：`(global_bs,)`，数据类型 `torch.float`|`quant_mode=2` 时为实际量化 scale（SHMEM）；`quant_mode=0` 时无意义|
|put_offset|Tensor|形状：`(moe_expert_num, ep_world_size)`，数据类型 `torch.int`|各专家对各 rank 的写入偏移，由内部 notify 产生；combine 时作为 `ep_recv_counts` 使用|
|total_recv_tokens|Tensor|形状：`(1,)`，数据类型 `torch.int`|本卡实际接收 token 数，用于对 `recv_x` / scales 等截断|
|recv_tokens_per_expert|Tensor|形状：`(moe_expert_num / ep_world_size,)`，数据类型 `torch.int64`|本卡各本地专家实际接收的 token 数|
##### 1.2.2.5 约束和注意事项 ⚠️
1. `batchSize` 取值范围：`[1, 8000]`。
2. `ep_world_size` 取值范围：`[2, 384]`。
3. `ep_rank_id` 取值范围：`[0, ep_world_size)`。
4. `moe_expert_num` 取值范围：`(0, 512]`。
5. `topk` 取值范围：`(0, 16]`。
6. `topk_idx` 中数值取值范围：`[0, moe_expert_num)`。
7. `h` 取值范围：`[1024, 7168]`。
8. `moe_expert_num % ep_world_size == 0`，且 `moe_expert_num >= ep_world_size`。
9. `global_bs` 必须大于 0。
10. `send_token_idx` / `num_tokens_per_expert` 必须直接使用 `get_dispatch_layout_zb` 的输出。
11. 调用前需完成 Zero-Buffer / SHMEM 初始化，保证 `comm_meta_ptr` 有效。
12. 返回的 `recv_x`、`dynamic_scales_out` 按 `global_bs` 上界分配；业务侧应按实际 `total_recv_tokens` 截断后再做专家计算与 combine。
13. 不支持 A2 环境（仅 A3）。

 #### 1.2.3 moe_combine_normal_zb ▶
##### 1.2.3.1 接口原型
```python
umdk_cam_op_lib.moe_combine_normal_zb(
    Tensor recv_x,
    Tensor ep_recv_counts,
    Tensor recv_topk_weights,
    Tensor topk_idx,
    Tensor send_token_idx,
    int comm_meta_ptr,
    int ep_world_size,
    int ep_rank_id,
    int tp_world_size,
    int tp_rank_id,
    int moe_expert_num,
    int global_bs
) -> combine_x: Tensor
```
##### 1.2.3.2 接口描述
`moe_combine_normal_zb`：Zero-Buffer 路径下的 normal combine 算子，将入参 `recv_x` 按与 dispatch 相反的方向、按 `recv_topk_weights` 指定权重收集合并为 `combine_x`。语义对齐 `moe_combine_prefill`，底层调用 `aclnnMoeCombineNormalZeroBuffer`。
##### 1.2.3.3 入参
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|recv_x|Tensor|必选|形状：`(recv_token_num, h)`，支持 bf16、float16|本卡 dispatch 阶段接收并经专家计算后的 token|
|ep_recv_counts|Tensor|必选|形状通常为 `(moe_expert_num, ep_world_size)`，数据类型 `torch.int`|各专家对各 rank 的接收计数/偏移；ZB 链路中通常直接复用 dispatch 内部 notify 产生的 `put_offset`|
|recv_topk_weights|Tensor|必选|形状：`(bs, topK)`，数据类型 `torch.float32`|每个 token 的 topk 专家权重|
|topk_idx|Tensor|必选|形状：`(bs, topK)`，数据类型 `torch.int32`|每个 token 的 topk 专家索引|
|send_token_idx|Tensor|可选|形状：`(batchSize, topK)`，数据类型 `torch.int`；不需要时传 `None`|须为 `get_dispatch_layout_zb` 的出参|
|comm_meta_ptr|int|必选|与 dispatch 侧同源初始化结果|Zero-Buffer / SHMEM 元数据指针|
|ep_world_size|int|必选|EP 通信域卡数|通信域大小|
|ep_rank_id|int|必选|本卡 rankId|`[0, ep_world_size)`|
|tp_world_size|int|必选|常规传 `1`|TP 域大小|
|tp_rank_id|int|必选|常规传 `0`|TP rankId|
|moe_expert_num|int|必选|MOE 路由专家数|专家总数|
|global_bs|int|必选|EP 通信域全局 BS 大小|全局 batch 上界|
##### 1.2.3.4 返回值
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|combine_x|Tensor|形状：`(batchSize, h)`，数据类型与 `recv_x` 一致；`batchSize` 取自 `recv_topk_weights.size(0)`|本卡收回并加权合并后的 token|
##### 1.2.3.5 约束和注意事项 ⚠️
1. `batchSize` 取值范围：`[1, 8000]`。
2. `ep_world_size` 取值范围：`[2, 384]`。
3. `ep_rank_id` 取值范围：`[0, ep_world_size)`。
4. `moe_expert_num` 取值范围：`(0, 512]`。
5. `topk` 取值范围：`(0, 16]`。
6. `topk_idx` 中数值取值范围：`[0, moe_expert_num)`。
7. `h` 取值范围：`[1024, 7168]`。
8. `moe_expert_num % ep_world_size == 0`，且 `moe_expert_num >= ep_world_size`。
9. `recv_x` 应与 `moe_dispatch_normal_zb` 有效接收区间一致（按 `total_recv_tokens` 截断后的专家输出）。
10. `ep_recv_counts` 必须直接使用 dispatch 内部 notify 的 `put_offset`（或等价 ep send/recv counts）。
11. `send_token_idx` 若传入，必须直接使用 `get_dispatch_layout_zb` 的出参。
12. 调用前需保证 `comm_meta_ptr` 有效，且与 dispatch 使用同一通信域初始化结果。
13. 不支持 A2 环境（仅 A3）。

 #### 1.2.4 zb_fused_deep_moe ▶
##### 1.2.4.1 接口原型
```python
ZbBuffer.zb_fused_deep_moe(
    Tensor x,
    Tensor expert_ids,
    Tensor[] gmm1_weight,
    Tensor[] gmm1_weight_scale,
    Tensor[] gmm2_weight,
    Tensor[] gmm2_weight_scale,
    Tensor expert_scales,
    Tensor? share_gmm1_weight,
    Tensor? share_gmm1_weight_scale,
    Tensor? share_gmm2_weight,
    Tensor? share_gmm2_weight_scale,
    Tensor? expert_smooth_scales,
    Tensor? share_smooth_scales,
    Tensor? x_active_mask,
    Tensor[] gmm1_bias,
    Tensor[] gmm2_bias,
    Tensor? share_gmm1_bias,
    Tensor? share_gmm2_bias,
    str group_ep,
    int ep_rank_size,
    int ep_rank_id,
    int moe_expert_num,
    int quant_mode,
    int global_bs
) -> output: Tuple[Tensor, Tensor, Tensor]
```
##### 1.2.4.2 接口描述
Zero-Buffer（SHMEM）路径下的通算大融合算子，融合 [Dispatch + FFN(GMM1 + SwiGLU + GMM2) + Combine]，通过 SHMEM 共享内存直写替代 HCCL 数据平面，支持 W8A8 / W4A8 两种量化模式（W4A8 以 `gmm1_bias` 输入是否存在自动识别）、内置共享专家与多轮 round buffer 复用。需先完成 `ZbBuffer` 初始化并提供 SHMEM 池（`local_mem_size`），底层调用 `aclnnFusedDeepMoeZb`；`ext_info`、`shmem_workspace`、`shmem_workspace_size` 三个 attr 由 `ZbBuffer` 内部自动注入，用户无需传入。
##### 1.2.4.3 入参
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|必选|形状：`(batch_size, token_length)`，支持 bf16、float16，FORMAT_ND|本卡 dispatch 阶段待处理的 token|
|expert_ids|Tensor|必选|形状：`(batch_size, topk)`，数据类型 `torch.int32`，取值范围 `[-1, moe_expert_num)`，-1 用于占位，一个 token 不允许重复发给同一个专家|每个 token 的目标专家 ID 信息|
|gmm1_weight|Tensor[]|必选|耦合模式下仅有 1 个 Tensor，形状：`(local_expert_num, token_length, gmm1_hidden_size)`；分离模式下包含 `local_expert_num` 个 Tensor，每个形状：`(token_length, gmm1_hidden_size)`；W8A8 为 `torch.int8`，W4A8 为 `torch.int32`（INT4 打包，隐藏维按 `gmm1_hidden_size/8` 存储）|GMM1 权重矩阵列表，支持耦合/分离两种模式|
|gmm1_weight_scale|Tensor[]|必选|耦合模式下仅有 1 个 Tensor，形状：`(local_expert_num, gmm1_hidden_size)`；分离模式下包含 `local_expert_num` 个 Tensor，每个形状：`(gmm1_hidden_size)`；数据类型 float32/bf16/fp16|GMM1 权重量化缩放系数，模式须与 gmm1_weight 一致|
|gmm2_weight|Tensor[]|必选|耦合模式下仅有 1 个 Tensor，形状：`(local_expert_num, gmm1_hidden_size/2, token_length)`；分离模式下包含 `local_expert_num` 个 Tensor，每个形状：`(gmm1_hidden_size/2, token_length)`；W8A8 为 `torch.int8`，W4A8 为 `torch.int32`（隐藏维按 `gmm1_hidden_size/2` 存储，INT4 打包时输出维按 1/8 压缩）|GMM2 权重矩阵列表，支持耦合/分离两种模式|
|gmm2_weight_scale|Tensor[]|必选|耦合模式下仅有 1 个 Tensor，形状：`(local_expert_num, token_length)`；分离模式下包含 `local_expert_num` 个 Tensor，每个形状：`(token_length)`；数据类型 float32/bf16/fp16|GMM2 权重量化缩放系数，模式须与 gmm2_weight 一致|
|expert_scales|Tensor|必选|形状：`(batch_size, topk)`，数据类型 `torch.float32`|每个 token 的 topk 个专家权重，combine 阶段使用|
|share_gmm1_weight|Tensor?|可选|形状：`(token_length, share_mm1_hidden_size)`，W8A8 为 `torch.int8`，W4A8 为 `torch.int32`|共享专家 MM1 权重矩阵|
|share_gmm1_weight_scale|Tensor?|可选|形状：`(share_mm1_hidden_size)`，数据类型须与 gmm1_weight_scale 一致|共享专家 MM1 权重量化缩放系数|
|share_gmm2_weight|Tensor?|可选|形状：`(share_mm1_hidden_size/2, token_length)`，W8A8 为 `torch.int8`，W4A8 为 `torch.int32`|共享专家 MM2 权重矩阵|
|share_gmm2_weight_scale|Tensor?|可选|形状：`(token_length)`，数据类型须与 gmm2_weight_scale 一致|共享专家 MM2 权重量化缩放系数|
|expert_smooth_scales|Tensor?|可选|形状：`(moe_expert_num, token_length)`，数据类型 `torch.float32`|各个路由专家的 smooth quant 平滑因子|
|share_smooth_scales|Tensor?|可选|形状：`(token_length)`，数据类型 `torch.float32`|共享专家的 smooth quant 平滑因子|
|x_active_mask|Tensor?|可选|形状：`(batch_size)`，数据类型 bool，取值范围 `[true, false]`，true 值必须排在 false 之前|dispatch 分发 token 时的 mask，true 代表正常分发，false 代表不分发|
|gmm1_bias|Tensor[]|W4A8 必选|耦合模式下仅有 1 个 Tensor，形状：`(local_expert_num, gmm1_hidden_size)`；分离模式下包含 `local_expert_num` 个 Tensor，每个形状：`(gmm1_hidden_size)`；数据类型 `torch.float32`|W4A8 反量化补偿矩阵，`8.0 × Σ(INT4 权重) × weight_scale`，W8A8 传空 TensorList|
|gmm2_bias|Tensor[]|W4A8 必选|耦合模式下仅有 1 个 Tensor，形状：`(local_expert_num, token_length)`；分离模式下包含 `local_expert_num` 个 Tensor，每个形状：`(token_length)`；数据类型 `torch.float32`|W4A8 反量化补偿矩阵，`8.0 × Σ(INT4 权重) × weight_scale`，W8A8 传空 TensorList|
|share_gmm1_bias|Tensor?|可选|形状：`(share_mm1_hidden_size)`，数据类型 `torch.float32`|共享专家 MM1 的 W4A8 反量化补偿矩阵|
|share_gmm2_bias|Tensor?|可选|形状：`(token_length)`，数据类型 `torch.float32`|共享专家 MM2 的 W4A8 反量化补偿矩阵|
|group_ep|str|必选|Zero-Buffer 路径传空字符串 `""`|HCCL 通信域名称（预留；数据平面走 SHMEM 直写，无需真实通信域）|
|ep_rank_size|int|必选|> 0，且 `moe_expert_num_per_rank * ep_rank_size <= 512`|EP 通信域大小|
|ep_rank_id|int|必选|取值范围 `[0, ep_rank_size)`|本卡在通信域中的 rankID|
|moe_expert_num|int|必选|取值范围 `(0, 512]`，且 `moe_expert_num % ep_rank_size == 0`|MOE 路由专家数量|
|quant_mode|int|必选|预留入参，当前只支持传 0|量化模式；W4A8 由 gmm1_bias 输入存在性自动识别，不依赖该入参|
|global_bs|int|必选|若所有卡 token 数量一致，可传 0（等价于 `batch_size * ep_rank_size`）；否则须 > 0 且 `global_bs % ep_rank_size == 0`|所有卡的最大 token 总数|
##### 1.2.4.4 返回值
函数返回值是一个 3 个 Tensor 构成的 Tuple，分别存放：output、share_output、expert_token_nums。
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|output|Tensor|形状：`(batch_size, token_length)`，数据类型与 x 一致|当前 rank 上 token 经各个专家处理后汇聚的结果|
|share_output|Tensor|形状：`(batch_size, token_length)`，数据类型与 x 一致|内置共享专家处理后的结果，即使不进行共享专家计算也会返回占位值|
|expert_token_nums|Tensor|形状：`(moe_expert_num / ep_rank_size)`，数据类型 `torch.int64`|本卡各个本地专家收到的 token 数量|
##### 1.2.4.5 约束和注意事项 ⚠️
1. 入参形状需严格满足上述入参描述中的形状定义。
2. 仅支持 Zero-Buffer（ZERO_BUFFER）模式：`shmemWorkspacePtr` 必须非零，由 `ZbBuffer` 内部注入；调用前必须完成 `ZbBuffer` 初始化（`local_mem_size` 提供 SHMEM 池）。
3. 当前接口只支持 A3 环境调用。
4. 当前接口不支持并发调用。极端情况下在单次 forward 中连续调用相同算子会产生未定义行为，这种场景需要在算子执行间添加 `torch.npu.synchronize()` 避免潜在的异步时序问题。
5. 当前接口图模式只支持 AclGraph 模式。
6. 不支持外置共享专家（即有的卡只放置共享专家）。
7. 除满足上述形状约束外，其他参数取值要求：
 - 需要满足：batch_size 取值范围 `[0, 40960]`（Zero-Buffer 模式上界）
 - 需要满足：token_length 取值范围 `[512, 7168]`
 - 需要满足：gmm1_hidden_size 取值范围 `[1024, 6144]`
 - 需要满足：topk <= 12 且 topk <= moe_expert_num
 - 需要满足：moe_expert_num 取值范围 `(0, 512]` 且 `moe_expert_num % ep_rank_size == 0`
 - 需要满足：`moe_expert_num_per_rank * ep_rank_size <= 512`
 - 需要满足：`global_bs >= 0` 且 `global_bs % ep_rank_size == 0`（传 0 时自动按 `batch_size * ep_rank_size` 计算）
 - 需要满足：gmm1_weight、gmm1_weight_scale、gmm2_weight、gmm2_weight_scale 四个入参的模式必须统一，不能一部分耦合模式一部分分离模式
8. W4A8 模式：gmm1_bias、gmm2_bias 必须传入，且通过其存在性自动识别为 W4A8（`EXEC_FLAG_W4A8`）；W8A8 模式传空 TensorList。
9. 共享专家：若传入 share_gmm1_weight，则 share_gmm1_weight_scale、share_gmm2_weight、share_gmm2_weight_scale 必须同时存在；share 侧 scale 的数据类型必须与路由专家侧一致。
10. smooth quant：若传入 expert_smooth_scales（形状 `(moe_expert_num, token_length)`，float32），当同时启用共享专家时 share_smooth_scales（形状 `(token_length)`，float32）也必须存在。
11. x_active_mask：若传入，形状必须为 `(batch_size)` 且 true 值必须在 false 之前。
12. SHMEM 空间约束：`shmemWorkspaceSize` 必须大于 0，且不小于固定开销（专家 token 数元数据 + combineSend + roundInfo + 16MB 安全余量），否则报 `SHMEM workspace is too small`；round buffer 每轮 token 数由剩余空间推算，向下对齐 64（GMM1_EPIM），不足 64 时报错。
13. Zero-Buffer 路径数据平面走 SHMEM 直写，无需按 `moe_expert_num_per_rank * global_bs * h * sizeof(x) * 2` 配置大 HCCL_BUFFSIZE（该校验仅作用于非 Zero-Buffer 路径）。
