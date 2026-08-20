# CAM API指南
## CAM简介
CAM是Huawei昇腾NPU超节点通信加速器(Communication Accelerator for Maxtrix)的简称，提供EP（Expert Parallelism）通信加速库、PD（Prefill & Decode）分离场景高性能KVCache传输和KVC池化、AFD（Attention-FFN Disaggregation）通信加速库、RL(Reinforcement Learning)权重传输等特性。

## CAM架构
（To be done）

## CAM API
### 1. 高性能EP通信库
CAM在umdk_cam_op_lib库中提供高性能Python通信和通算融合接口供用户使用，用户可以方便的在主流昇腾推理框架（如vllm-ascend, sglang-kernel-npu等）导入该通信库并调用接口使用。

 #### 1.1.1 fused_deep_moe ▶
##### 1.1.1.1 接口原型 
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
    Tensor[] gmm1_bias,
    Tensor[] gmm2_bias,
    Tensor? share_gmm1_bias,
    Tensor? share_gmm2_bias,
    str group_ep, 
    int ep_rank_size, 
    int ep_rank_id, 
    int moe_expert_num, 
    int quant_mode, 
    int global_bs) 
-> output: Tensor[]
```
##### 1.1.1.2 接口描述 
用于MoE Decode阶段的通算大融合算子，通过融合[Dispatch + FFN(GMM1 + Swiglu + GMM2) + Combine]实现高效的模型推理和专家选择，（可选）同时支持内置共享专家计算，适用于分布式推理场景。
##### 1.1.1.3 入参 
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|必选|形状:(batch_size, token_length), 支持bf16, float16类型|本卡dispatch阶段待处理的token|
|expert_ids|Tensor|必选|形状:(batch_size, topk)， 数据类型为int32, 取值范围[-1, num_experts)，-1用于占位使用，一个token不允许重复发给同一个专家|每个token的目标专家ID信息|
|gmm1_weight|Tensor[]|必选|耦合模式下，只有一个Tensor, 形状:(localExpertNum, token_length, gmm1_hidden_size); 分离模式下，包含localExpertNum个Tensor, 每个Tensor形状：（token_length, gmm1_hidden_size），数据类型支持fp8_e4m3,fp8_e5m2,fp4_e2m1|GMM1的权重矩阵列表，支持耦合模式和分离模式|
|gmm1_weight_scale|Tensor[]|必选|耦合模式下，只有一个Tensor, 形状:(localExpertNum, token_length/32/2, gmm1_hidden_size, 2); 分离模式下，包含localExpertNum个Tensor, 每个Tensor形状：（token_length/32/2, gmm1_hidden_size, 2），数据类型为fp8_e8m0|GMM1的权重矩阵量化时使用的缩放系数列表，支持耦合模式和分离模式|
|gmm2_weight|Tensor[]|必选|耦合模式下，只有一个Tensor, 形状:(localExpertNum, gmm1_hidden_size/2, token_length); 分离模式下，包含localExpertNum个Tensor, 每个Tensor形状：（gmm1_hidden_size/2, token_length），数据类型支持fp8_e4m3,fp8_e5m2,fp4_e2m1|GMM2的权重矩阵列表，支持耦合模式和分离模式|
|gmm2_weight_scale|Tensor[]|必选|耦合模式下，只有一个Tensor, 形状:(localExpertNum, (gmm1_hidden_size/2)/32/2, token_length, 2); 分离模式下，包含localExpertNum个Tensor, 每个Tensor形状：（(gmm1_hidden_size/2)/32/2, token_length, 2），数据类型为fp8_e8m0|GMM2的权重矩阵量化时使用的缩放系数列表，支持耦合模式和分离模式|
|expert_scales|Tensor|必选|形状：(batch_size, topk), 数据类型为float32|每个专家的权重，combine阶段使用|
|share_gmm1_weight|Tensor|可选|形状：（token_length, share_gmm1_hidden_size），数据类型支持fp8_e4m3,fp8_e5m2,fp4_e2m1|共享专家MM1的权重矩阵|
|share_gmm1_weight_scale|Tensor|可选|形状：（token_length/32/2, share_gmm1_hidden_size, 2），数据类型为与gmm1_weight_scale一致|共享专家MM1的权重矩阵量化时使用的缩放系数|
|share_gmm2_weight|Tensor|可选|形状：（share_gmm1_hidden_size/2, token_length），数据类型支持fp8_e4m3,fp8_e5m2,fp4_e2m1|共享专家MM2的权重矩阵|
|share_gmm2_weight_scale|Tensor|可选|形状：（share_gmm1_hidden_size/2, token_length, 2），数据类型为与gmm2_weight_scale一致|共享专家MM2的权重矩阵量化时使用的缩放系数|
|expert_smooth_scales|Tensor|可选|形状：(moe_expert_num，token_length)，数据类型为float32|各个路由专家的smooth quant平滑因子|
|share_smooth_scales|Tensor|可选|形状：(token_length)，数据类型为float32|共享专家的smooth quant平滑因子|
|x_active_mask|Tensor|可选|形状： (batch_size)，数据类型bool，取值范围[true, false]，true值一定要在false之前|dispatch分发token时的mask，true代表正常分发该token，false代表不分发|
|gmm1_bias|Tensor[]|必选|形状：无约束，数据类型为float32|为保持接口一致增加的占位符，无任何作用，但需要传入一个包含float32 NPU Tensor的列表，建议直接传入\[expert_scales\]|
|gmm2_bias|Tensor[]|必选|形状：无约束，数据类型为float32|为保持接口一致增加的占位符，无任何作用，但需要传入一个包含float32 NPU Tensor的列表，建议直接传入\[expert_scales\]|
|share_gmm1_bias|Tensor|可选|形状：无约束，数据类型为float32|为保持接口一致增加的占位符，无任何作用，传None即可|
|share_gmm2_bias|Tensor|可选|形状：无约束，数据类型为float32|为保持接口一致增加的占位符，无任何作用，传None即可|
|group_ep|str|必选|字符串长度范围：(0, 128), 且需要保证是有效的通信域名称|HCCL通信域名称|
|ep_rank_size|int|必选|需要满足：(ep_rank_size * MoeExpertNumPerRank) ≤ 512且ep_rank_size > 0|EP通信域大小|
|ep_rank_id|int|必选|[0, ep_rank_size)|本卡在通信域中的rankID|
|moe_expert_num|int|必选|需要满足：moe_expert_num % ep_rank_size == 0|MOE专家数量|
|quant_mode|int|必选|预留入参，当前只支持传0|量化模式|
|global_bs|int|必选|若所有卡的token数量一致，可以传入0或者batch_size * ep_rank_size; 若所有卡的token数量不一致，需要传入max_batch_size * ep_rank_size|所有卡的最大token总数|
##### 1.1.1.4 返回值 
函数返回值是一个Tensor列表，存放combine_x和expert_token_nums信息。
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|combine_x|Tensor|形状：(batch_size, token_length)。数据类型与x一致|当前rank上token经各个专家处理后汇聚的结果|
|share_output|Tensor|形状：(batch_size, token_length)。数据类型与x一致|内置共享专家处理后的结果，即使不进行共享专家计算，也会返回该值占位|
|expert_token_nums|Tensor|形状：(local_expert_num)。数据类型为int64|本卡各个专家收到的token数量|
##### 1.1.1.5 约束和注意事项 ⚠️
1. 入参形状需严格满足上述入参描述中的形状定义。
2. 当前接口只支持Ascend950环境调用。
3. 当前接口不支持并发调用。极端情况下在单次forward中连续调用相同算子会产生未定义行为，这种场景需要在算子执行间添加torch.npu.synchronize()避免潜在的异步时序问题。
4. 当前接口图模式只支持AclGraph模式。
5. 不支持外置共享专家（即有的卡只放置共享专家）。
6. Batch_size小于16时非目标场景，其性能相对于小算子拼接可能劣化，建议性能对比后决策使用。
7. 当权重为fp8_e4m3,fp8_e5m2时，支持数据ND/NZ两种数据排布，当权重为fp4_e2m1时，仅支持数据ND排布。
8. 除满足上述形状约束外，其他参数取值要求：
 - 需要满足：BS取值范围[0, 256]
 - 需要满足: token_length取值范围[1024， 7168]且(token_length % 256) == 0
 - 需要满足: gmm1_hidden_size取值范围[1024， 6144]且(gmm1_hidden_size % 256) == 0
 - 需要满足: share_gmm1_hidden_size取值范围[1024， 6144]且(share_gmm1_hidden_size % 256) == 0
 - 需要满足: topk取值范围[0, 12]且应保证小于等于专家数
 - 需要满足：global_bs ≥ 0 且保证（global_bs % ep_rank_size） == 0
 - 需要满足: gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale四个入参的模式必须统一，不能一部分耦合模式一部分分离模式
 - 需要满足: HCCL_BUFFSIZE环境变量配置应不小于[ep_rank_size * max_batch_size * moe_expert_num_per_rank * (total_length * 1 + 512) / 1024 / 1024]向上取整
 - 需要满足: 若要进行内置共享专家计算，则共享专家所需的share_gmm1_weight、share_gmm1_weight_scale、share_gmm2_weight、share_gmm2_weight_scale需同时存在
 - 需要满足: 若要进行smooth quant，需传入expert_smooth_scales，若同时进行内置共享专家计算则share_smooth_scales也必须存在
