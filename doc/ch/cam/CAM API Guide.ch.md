# CAM API指南
## CAM简介
CAM是Huawei昇腾NPU超节点通信加速器(Communication Accelerator for Maxtrix)的简称，提供EP（Expert Parallelism）通信加速库、PD（Prefill & Decode）分离场景高性能KVCache传输和KVC池化、AFD（Attention-FFN Disaggregation）通信加速库、RL(Reinforcement Learning)权重传输等特性。

## CAM架构
（To be done）

## CAM API
### 1. 高性能EP通信库
CAM在umdk_cam_op_lib库中提供高性能Python通信和通算融合接口供用户使用，用户可以方便的在主流昇腾推理框架（如vllm-ascend, sglang-kernel-npu等）导入该通信库并调用接口使用。
#### 1.1 Dispatch & Combine类接口
#### 1.1.1 moe_dispatch_shmem ▶
##### 1.1.1.1 接口原型 
```python
moe_dispatch_shmem(
    Tensor x, 
    Tensor expert_ids, 
    Tensor scales, 
    Tensor x_active_mask, 
    int ep_world_size, 
    int ep_rank_id, 
    int moe_expert_num, 
    int tp_world_size, 
    int tp_rank_id, 
    int expert_shard_type, 
    int shared_expert_num, 
    int shared_expert_rank_num, 
    int quant_mode, 
    int global_bs, 
    int expert_token_nums_type, 
    int ext_info)
-> output: List[Tensor]
```
##### 1.1.1.2 接口描述 
基于SHMEM类内存的Dispatch接口，用以在EP通信阶段将token分发至不同的专家以供后续的操作。该接口需配合moe_combine_shmem配套使用。
##### 1.1.1.3 入参 
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|必选|形状:(batch_size, hidden_size)|输入Token|
|expert_ids|Tensor|必选|形状:(batch_size, top_k)|目的专家ID信息|
|scales|Tensor|可选|非空时为float类型，存在共享专家时形状:(m+1,h), 不存在共享专家时形状(m, h),其中m为共享专家数|量化参数|
|x_active_mask|Tensor|可选|暂不支持，传入None|--|
|ep_world_size|int|必选|只支持如下取值：[8, 16, 32, 64, 128, 144, 256, 288]|EP通信域内的rank数|
|ep_rank_id|int|必选|[0, ep_world_size-1]|EP通信域内rank ID号|
|moe_expert_num|int|必选|[1, 512]|MoE专家数|
|tp_world_size|int|必选|暂不支持，传入0|--|
|tp_rank_id|int|必选|暂不支持，传入0|--|
|expert_shard_type|int|必选|暂不支持，传入0|--|
|shared_expert_num|int|必选|不支持非1的值，传入1|共享专家数量|
|shared_expert_rank_num|int|必选|[0, ep_world_size-1]|共享专家卡号|
|quant_mode|int|必选|非量化传0，量化传2|量化模式|
|global_bs|int|必选|根据实际情况传入，由实际内存大小约束|EP通信域全局BS大小|
|expert_token_nums_type|int|必选|传入0：输出每个专家处理的token数量；传入1：输出每个专家处理的token前缀和。|输出expert_token_nums_out的数据格式|
|ext_info|int|必选|--|SHMEM初始化后返回的基地址指针|
##### 1.1.1.4 出参 
函数出参是一个由Tensor构成的List，依次存放：expand_x, dynamic_scales, expand_idx, expert_token_nums, ep_send_count, tp_send_count和expand_scales.
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|expand_x|Tensor|当前rank是共享专家时，形状:(rank_size * batch_size / shared_expert_num, hidden_size);当前rank是路由专家时，形状：(expert_num_per_rank * rank_size * batch_size, hidden_size)|每个rank上所有专家的token|
|dynamic_scales|Tensor|形状同expand_x的第一维，即:当前rank是共享专家时，形状:(rank_size * batch_size / shared_expert_num);当前rank是路由专家时，形状：(expert_num_per_rank * rank_size * batch_size)|量化参数信息|
|expand_idx|Tensor|形状：(batch_size, top_k)|在目标专家内，仅排序当前rank的token时，当前rank发出的token各自的排序ID|
|expert_token_nums|Tensor|(expert_num_on_rank)|当前rank上每个专家收到的token数|
|ep_send_count|Tensor|形状：(expert_num_per_rank * ep_world_size)|每个专家从每个rank收到的token数|
|tp_send_count|Tensor|--|暂不支持，无意义|
|expand_scales|Tensor|--|暂不支持，无意义|
##### 1.1.1.4 约束和注意事项 ⚠️
1. 入参形状需严格满足上述入参描述中的形状定义。
2. 当量化模式开启时，expand_x的数据类型为int8类型，而不开启量化时其数据类型为bfloat16类型。
3. 当前接口不支持A2环境调用。
4. 当前接口不支持并发调用。
5. 当前接口在GE图模式下不支持动态图， 不支持fullgraph=true的选项。
6. 当前x入参的输入格式不支持bfloat16类型。
7. 除满足上述形状约束外，其他参数取值要求：
 - top_k当前仅支持8
 - (moe_expert_num + shared_expert_rank_num) ≤ CAM_MAX_EXPERT_NUM, 当前最大专家数为512
 - 需要满足: moe_expert_num / (ep_world_size - shared_expert_rank_num)可以整除
 - 需要满足：moe_expert_num / (ep_world_size - shared_expert_rank_num) ≤ MAX_EXPERT_PER_RANK, 当前该值设置为32
 - 需要满足： (ep_world_size + block_num -1) / block_num ≤ MULTI_RANK_SIZE, 
 - 需要满足： 如果shared_expert_rank_num不为0，则ep_world_size需要为其整数倍，切ep_world_size ≠ shared_expert_rank_num.
 - 需要满足：(batch_size * hidden_size * ep_world_size * expert_num_per_rank * 2)小于ext_info指向的地址空间大小。
#### 1.1.1 moe_combine_shmem ▶
##### 1.1.1.1 接口原型 
```python
moe_combine_shmem(
    Tensor expand_x, 
    Tensor expert_ids, 
    Tensor expand_idx, 
    Tensor ep_send_counts, 
    Tensor expert_scales, 
    Tensor tp_send_counts, 
    Tensor x_active_mask, 
    Tensor activation_scale, 
    Tensor weight_scale, 
    Tensor group_list, 
    Tensor expand_scales, 
    int ep_world_size, 
    int ep_rank_id, 
    int moe_expert_num, 
    int tp_world_size, 
    int tp_rank_id, 
    int expert_shard_type, 
    int shared_expert_num, 
    int shared_expert_rank_num, 
    int global_bs, 
    int comm_quant_mode, 
    int ext_info, 
    int out_dtype, 
    int group_list_type)
-> output: Tensor
```
##### 1.1.1.2 接口描述 
基于SHMEM类内存的Combine接口，用以在EP通信阶段将分发至不同的专家的token回合以供后续的操作。该接口需配合moe_dispatch_shmem配套使用。
##### 1.1.1.3 入参 
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|expand_x|Tensor|必选|形状同dispatch的出参expand_x|dispatch分发至各专家上的token|
|expert_ids|Tensor|必选|形状:(batch_size, top_k)|目的专家ID信息|
|expand_idx|Tensor|必选|形状:(batch_size, top_k)|在目标专家内，仅排序当前rank的token时，按照rank发出的token各自的排序ID|
|ep_send_counts|Tensor|必选|形状:(expert_num_per_rank * ep_world_size)|每个专家从每个rank收到的token数|
|expert_scales|Tensor|必选|形状：（batch_size, top_k）|合并token时需要的权重|
|tp_send_count|Tensor|可选|暂不支持，传入int32类型的tensor[0]即可|--|
|x_active_mask|Tensor|可选|暂不支持，传入None|--|
|activation_scale|Tensor|可选|暂不支持，传入None|--|
|weight_scale|Tensor|可选|暂不支持，传入None|--|
|group_list|Tensor|可选|暂不支持，传入None|--|
|expand_scales|Tensor|可选|暂不支持，传入None|--|
|ep_world_size|int|必选|只支持如下取值：[8, 16, 32, 64, 128, 144, 256, 288]|EP通信域内的rank数|
|ep_rank_id|int|必选|[0, ep_world_size-1]|EP通信域内rank ID号|
|moe_expert_num|int|必选|[1, 512]|MoE专家数|
|tp_world_size|int|必选|暂不支持，传入1|--|
|tp_rank_id|int|必选|暂不支持，传入0|--|
|expert_shard_type|int|必选|暂不支持，传入0|--|
|shared_expert_num|int|必选|不支持非1的值，传入1|共享专家数量|
|shared_expert_rank_num|int|必选|[0, ep_world_size-1]|共享专家卡号|
|global_bs|int|必选|根据实际情况传入，由实际内存大小约束|EP通信域全局BS大小|
|out_dtype|int|必选|暂不支持，传入0|--|
|comm_quant_mode|int|必选|非量化传0，量化传2|量化模式|
|group_list_type|int|必选|暂不支持，传入0|--|
|ext_info|int|必选|--|SHMEM初始化后返回的基地址指针|
##### 1.1.1.4 出参 
函数出参是一个Tensor，存放expand_x信息。
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|expand_x|Tensor|形状:(batch_size, hidden_size)|合并后的token信息|
##### 1.1.1.4 约束和注意事项 ⚠️
1. 入参形状需严格满足上述入参描述中的形状定义。
2. 当前接口不支持A2环境调用。
3. 当前接口不支持并发调用。
4. 当前接口在GE图模式下不支持动态图， 不支持fullgraph=true的选项。
5. 除满足上述形状约束外，其他参数取值要求：
 - top_k当前仅支持8
 - (moe_expert_num + shared_expert_rank_num) ≤ CAM_MAX_EXPERT_NUM, 当前最大专家数为512
 - 需要满足: moe_expert_num / (ep_world_size - shared_expert_rank_num)可以整除
 - 需要满足：moe_expert_num / (ep_world_size - shared_expert_rank_num) ≤ MAX_EXPERT_PER_RANK, 当前该值设置为32
 - 需要满足： (ep_world_size + block_num -1) / block_num ≤ MULTI_RANK_SIZE, 
 - 需要满足： 如果shared_expert_rank_num不为0，则ep_world_size需要为其整数倍，切ep_world_size ≠ shared_expert_rank_num.
 - 需要满足：(batch_size * hidden_size * ep_world_size * expert_num_per_rank * 2)小于ext_info指向的地址空间大小。