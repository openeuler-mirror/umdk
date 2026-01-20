# CAM API Guide
## Introduction
 **CAM**  is short for  **C**ommunication  **A**cceleration for  **M**atrix on Ascend NPU. CAM provides EP (Expert Parallelism) communication kernels, high performance KVCache transfer for PD disaggregation and KVC pooling, AFD communication kernels, RL weights transfer and so on. CAM is easily to be run in single kernel mode or integrated into vllm or SGLang framework. 

## CAM Structure
（To be done）

## CAM API
### 1. EP Communication Kernels
UMDK provides high-performance Python interfaces for communication and fused computation-communication via "umdk_cam_op_lib". Users can use this lib in popular Ascend inference framework, such as vllm-ascend, sglang-kernel-npu, etc.
#### 1.1 Interfaces of Dispatch & Combine
#### 1.1.1 moe_dispatch_shmem ▶
##### 1.1.1.1 Prototype 
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
##### 1.1.1.2 Interface Description 
Dispatch interface based on SHMEM, which is used for token dispatch to different experts in EP communication phase. This interface should be used in conjunction with "moe_combine_shmem".
##### 1.1.1.3 Input Parameters
| **📌Parameter** | **🔧Type** | **✅Required/Optional** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|Required|Shape: (batch_size, hidden_size)|Input token|
|expert_ids|Tensor|Required|Shape: (batch_size, top_k)|Destination expert ID|
|scales|Tensor|Optional|Float type，Shape: (m+1,h) when shared expert exists, (m, h) when there is no shared expert, m is the shared expert number.|Quant parameters|
|x_active_mask|Tensor|Optional|Not supported，set to None|--|
|ep_world_size|int|Required|Supported values：[8, 16, 32, 64, 128, 144, 256, 288]|Rank size in EP Communicator|
|ep_rank_id|int|Required|[0, ep_world_size-1]|Rank ID in EP communicator|
|moe_expert_num|int|Required|[1, 512]|MoE expert number|
|tp_world_size|int|Required|Not supported，set to 0|--|
|tp_rank_id|int|Required|Not supported，set to 0|--|
|expert_shard_type|int|Required|Not supported，set to 0|--|
|shared_expert_num|int|Required|Only support 1, set to 1|Shared expert number|
|shared_expert_rank_num|int|Required|[0, ep_world_size-1]|Shared expert rank number|
|quant_mode|int|Required|set to 0 when no quant，set to 2 when quant|Quant mode|
|global_bs|int|Required|Value constrains by the total HBM buffer size.|Global BS value upper bound in the EP communicator|
|expert_token_nums_type|int|Required|0: Output is the token processing number of each expert；1：Output is the prefix sum of each expert's token processing number|expert_token_nums_out data format indicator|
|ext_info|int|Required|--|Basic address pointer return value after SHMEM initiation|
##### 1.1.1.4 Output Parameters 
Output is a List of Tensor, which stores the following value sequencially: expand_x, dynamic_scales, expand_idx, expert_token_nums, ep_send_count, tp_send_count and expand_scales.
| **📌Parameter** | **🔧Type** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|----------|
|expand_x|Tensor|Shape: (rank_size * batch_size / shared_expert_num, hidden_size) when the current rank is shared expert; Shape：(expert_num_per_rank * rank_size * batch_size, hidden_size) when the current rank is MoE expert|All expert tokens in the rank|
|dynamic_scales|Tensor|Shape is the same as the first dimension of expand_x, which is: (rank_size * batch_size / shared_expert_num) when the current rank is shared expert; (expert_num_per_rank * rank_size * batch_size) when the current rank is MoE expert|Quant parameters|
|expand_idx|Tensor|Shape：(batch_size, top_k)|In target expert, the send sequence ID when only consider the current rank|
|expert_token_nums|Tensor|(expert_num_on_rank)|Token receive number of each expert in this rank|
|ep_send_count|Tensor|Shape：(expert_num_per_rank * ep_world_size)|Token receive number of each expert from each rank|
|tp_send_count|Tensor|--|Not support|
|expand_scales|Tensor|--|Not support|
##### 1.1.1.4 Constraints and Precautions⚠️
1. Input Shape should satisfy the shape definition above.
2. expand_x data type is int8 when quan mode is on; expand_x data type is bfloat16 when quan mode is off.
3. Current interface do not support A2.
4. Current interface do not support concurrent usage.
5. Do not support dynamic graph when in GE mode; Do not support fullgraph=true.
6. Data type of x do not support bfloat16.
7. Other Constraits need to be satisfy:
 - top_k supports 8 only.
 - Required: (moe_expert_num + shared_expert_rank_num) ≤ CAM_MAX_EXPERT_NUM, where CAM_MAX_EXPERT_NUM is 512 currently.
 - Required: moe_expert_num % (ep_world_size - shared_expert_rank_num) == 0
 - Required：moe_expert_num / (ep_world_size - shared_expert_rank_num) ≤ MAX_EXPERT_PER_RANK, where MAX_EXPERT_PER_RANK is 32 currently. 
 - Required： if shared_expert_rank_num is not 0，ep_world_size % shared_expert_rank_num == 0，and ep_world_size ≠ shared_expert_rank_num.
 - Required：(batch_size * hidden_size * ep_world_size * expert_num_per_rank * 2) ≤ the space allocated by SHMEM, which is pointed by ext_info.
#### 1.1.1 moe_combine_shmem ▶
##### 1.1.1.1 Prototype 
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
##### 1.1.1.2 Inrterface Description 
Combine interface based on SHMEM, which is used for token combine from different experts in EP communication phase. This interface should be used in conjunction with "moe_dispatch_shmem".
##### 1.1.1.3 Input Parameters 
| **📌Parameter** | **🔧Type** | **✅Required/Optional** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|--------------|----------|
|expand_x|Tensor|Required|Shape: same as expand_x from dispatch output|Token to each expert from dispatch|
|expert_ids|Tensor|Required|Shape:(batch_size, top_k)|Target expert ID|
|expand_idx|Tensor|Required|Shape:(batch_size, top_k)|In target expert, token sequential ID based on current rank|
|ep_send_counts|Tensor|Required|Shape: (expert_num_per_rank * ep_world_size)|Token number from each expert in each rank|
|expert_scales|Tensor|Required|Shape：（batch_size, top_k）|Weights when combine token from each expert|
|tp_send_count|Tensor|Optional|Not support，set to tensor[0] as int8 type|--|
|x_active_mask|Tensor|Optional|Not support，set to None|--|
|activation_scale|Tensor|Optional|Not support，set to None|--|
|weight_scale|Tensor|Optional|Not support，set to None|--|
|group_list|Tensor|Optional|Not support，set to None|--|
|expand_scales|Tensor|Optional|Not support，set to None|--|
|ep_world_size|int|Required|Supported Value：[8, 16, 32, 64, 128, 144, 256, 288]|Rank number in EP communicator|
|ep_rank_id|int|Required|[0, ep_world_size-1]|rank ID in EP communicator|
|moe_expert_num|int|Required|[1, 512]|MoE expert number|
|tp_world_size|int|Required|Not support，set to 1|--|
|tp_rank_id|int|Required|Not support，set to 0|--|
|expert_shard_type|int|Required|Not support，set to 0|--|
|shared_expert_num|int|Required|Set to 1|Shared expert number|
|shared_expert_rank_num|int|Required|[0, ep_world_size-1]|Shared expert rank ID|
|global_bs|int|Required|Value constrains by the total HBM buffer size.|Global BS value upper bound in the EP communicator|
|out_dtype|int|Required|Not support，set to 0|--|
|comm_quant_mode|int|Required|Set to 0 when no quant, set to 2 when quant|Quant mode|
|group_list_type|int|Required|Not support，set to 0|--|
|ext_info|int|Required|--|Basic address pointer return value after SHMEM initiation|
##### 1.1.1.4 Output Parameters 
Output is a tensor，which stores expand_x。
| **📌Parameter** | **🔧Type** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|----------|
|expand_x|Tensor|Shape:(batch_size, hidden_size)|token combined from different experts|
##### 1.1.1.4 Constraints and Precautions⚠️
1. Input Shape should satisfy the shape definition above.
2. Current interface do not support A2.
3. Current interface do not support concurrent usage.
4. Do not support dynamic graph when in GE mode; Do not support fullgraph=true.
5. Other Constraits need to be satisfy:
 - top_k supports 8 only.
 - Required: (moe_expert_num + shared_expert_rank_num) ≤ CAM_MAX_EXPERT_NUM, where CAM_MAX_EXPERT_NUM is 512 currently.
 - Required: moe_expert_num % (ep_world_size - shared_expert_rank_num) == 0
 - Required：moe_expert_num / (ep_world_size - shared_expert_rank_num) ≤ MAX_EXPERT_PER_RANK, where MAX_EXPERT_PER_RANK is 32 currently. 
 - Required： if shared_expert_rank_num is not 0，ep_world_size % shared_expert_rank_num == 0，and ep_world_size ≠ shared_expert_rank_num.
 - Required：(batch_size * hidden_size * ep_world_size * expert_num_per_rank * 2) ≤ the space allocated by SHMEM, which is pointed by ext_info.