# CAM API Guide
## Introduction
 **CAM**  is short for  **C**ommunication  **A**cceleration for  **M**atrix on Ascend NPU. CAM provides EP (Expert Parallelism) communication kernels, high performance KVCache transfer for PD disaggregation and KVC pooling, AFD communication kernels, RL weights transfer and so on. CAM is easily to be run in single kernel mode or integrated into vllm or SGLang framework. 

## CAM Structure
（To be done）

## CAM API
### 1. EP Communication Kernels
UMDK provides high-performance Python interfaces for communication and fused computation-communication via "umdk_cam_op_lib". Users can use this lib in popular Ascend inference framework, such as vllm-ascend, sglang-kernel-npu, etc.
#### 1.1 Interfaces of Dispatch & Combine
 #### 1.1.1 get_dispatch_layout ▶
##### 1.1.1.1 Prototype 
```python
get_dispatch_layout(
    Tensor topk_idx, 
    int num_experts, 
    int num_ranks)
-> output: tuple(Tensor, Tensor)
```
##### 1.1.1.2 Interface Description 
![get_dispatch_layout diagram](figures/get_dispatch_layout_a3.png)
Interface used before dispatch in prefill phase for A3, which copies the current tokens in this rank TopK times and rearranges these tokens in experts' granularity. This interface should used with moe_dispatch_prefill and moe_combine_prefill.
##### 1.1.1.3 Input Parameters 
| **📌Parameter** | **🔧Type** | **✅Required/Optional** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|--------------|----------|
|topk_idx|Tensor|Required|Shape:(batch_size, topk)， int64 type，Range：[0, num_experts)|ID info for target experts|
|num_experts|int|Required|Range：(0, 512]|MOE experts number|
|num_ranks|int|Required|Range：[1, 384]|rank number in EP communication group|
##### 1.1.1.4 Return Value
Return value of this interface is a tuple made of 2 tensor, which stores num_tokens_per_expert and send_token_idx respectively.
| **📌Parameter** | **🔧Type** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|----------|
|num_tokens_per_expert|Tensor|Shape：（num_experts）|token value sent to each expert in this rank|
|send_token_idx|Tensor|Shape：(batch_size, top_k)|The position offset of each token after re-arrangement in experts' perspective|
##### 1.1.1.5 Constraints and Precautions ⚠️
1. Input Shape should satisfy the shape definition above.
2. Current interface supports A3 only.
3. Current interface does not support concurrent usage.
4. Do not support dynamic graph when in GE mode; Do not support fullgraph=true.
5. Other Constraints need to be satisfied:
 - top_k value range: (0, 16].
 - batch_size value range: (0, 8000]
 - Required: num_experts % num_ranks == 0
 - Required: num_experts >= num_ranks

 #### 1.1.2 moe_dispatch_prefill ▶
##### 1.1.2.1 Prototype
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
##### 1.1.2.2 Interface Description 
![moe_dispatch_prefill diagram](figures/moe_dispatch_prefill_a3.png)
Dispatch interface in prefill phase for A3, which sends the tokens to the target experts in the rules of topk_idx.
##### 1.1.2.3 Input Parameters 
| **📌Parameter** | **🔧Type** | **✅Required/Optional** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|Required|Shape:(batch_size, hidden_size), support bf16 and float16|token sent from current rank|
|topk_idx|Tensor|Required|Shape:(batch_size, topk)， int64 type，Range：[0, num_experts)|target ID of each token|
|topk_weights|Tensor|Required|Shape:(batch_size, topk)， float32 type|weights of target experts for each token|
|num_tokens_per_expert|Tensor|Required|Shape：（num_experts），int type|token number sent to each expert in current rank, must be output num_tokens_per_expert from get_dispatch_layout, cannot be modified|
|send_token_idx_small|Tensor|Required|Shape：(batch_size, top_k), int type|The position offset of each token after re-arrangement in experts' perspective, must be output send_token_idx from get_dispatch_layout, cannot be modified|
|group_ep|str|Required|--|name of HCCL communication group|
|rank|int|Required|[0, num_ranks)|rank ID in communication group|
|num_ranks|int|Required|[2, 384]|rank number of EP group|
|use_quant|bool|Required|True: use quant； False: do not use quant|Dispatch quant indicator|
##### 1.1.2.4 Return Value 
Return value is a tuple made of 5 tensors，which stores：recv_x, dynamic_scales_out, expand_idx_out, recv_count, recv_tokens_per_expert.
| **📌Parameter** | **🔧Type** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|----------|
|recv_x|Tensor|Shape：(recv_token_num, hidden_size), recv_token_num is the token number received by this rank. When use_quant is true, data type is int8, and data type is the same as input x when use_quant is false.|token received in current rank|
|dynamic_scales_out|Tensor|Shape：(recv_token_num), float type. This value has no meanings when use_quant is false.|dynamic quant scale infos for received tokens in current rank|
|expand_idx_out|Tensor|Shape：(recv_token_num * 3), int type|info triplet of token received by this rank, the three numbers of each triplet is: source rank, index of token in source rank(from BS's perspective), token offset after the re-arrangement in source rank in experts' perspective|
|recv_count|Tensor|Shape：(num_experts), int type|prefix-sum number of token received in this rank from each other ranks|
|recv_tokens_per_expert|Tensor|Shape：(local_expert_num), int64 type|token received by each expert in this rank|
##### 1.1.2.5 Constraints and Precautions ⚠️
1. Input Shape should satisfy the shape definition above.
2. Current interface supports A3 only.
3. Current interface does not support concurrent usage.
4. Do not support dynamic graph when in GE mode; Do not support fullgraph=true.
5. Other Constraints need to be satisfied:
 - top_k value range: (0, 16].
 - BS value range: [1, 8K]
 - num_ranks range: [2, 384]
 - num_experts range: (0, 512]
 - required: (num_experts % num_ranks) == 0
 - required: set HCCL_BUFFSIZE = 4096
 - Required: num_experts >= num_ranks

 #### 1.1.3 moe_combine_prefill ▶
##### 1.1.3.1 Prototype
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
##### 1.1.3.2 Interface Description
![moe_combine_prefill diagram](figures/moe_combine_prefill_a3.png)
combine interface in prefill phase for A3, which combines the token sent to each expert in topk_idx rules with weights given by topk_weights.
##### 1.1.3.3 Input Parameters
| **📌Parameter** | **🔧Type** | **✅Required/Optional** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|Required|Shape:(recv_token_num, hidden_size), support bf16 and float16 types|token received of this rank in dispatch phase|
|topk_idx|Tensor|Required|Shape:(batch_size, topk)， int64 type，Range：[0, num_experts)|target experts info for each token|
|topk_weights|Tensor|Required|Shape:(batch_size, topk)， float32 type|weights of topk experts for each token|
|src_idx|Tensor|Required|Shape：(recv_token_num * 3), int type|info triplet of token received by this rank, the three numbers of each triplet is: source rank, index of token in source rank(from BS's perspective), token offset after the re-arrangement in source rank in experts' perspective. Must be output expand_idx_out from moe_dispatch_prefill, cannot be modified|
|send_head|Tensor|Required|Shape：(num_experts), int type|prefix-sum number of token received in this rank from each other ranks. Must be output recv_count from moe_dispatch_prefill, cannot be modified|
|group_ep|str|Required|--|name of HCCL communication group|
|rank|int|Required|[0, num_ranks)|rank ID of current rank in EP group|
|num_ranks|int|Required|[2, 384]|rank number of EP group|
##### 1.1.3.4 Return Value 
Return value is a tensor，which stores combine_x。
| **📌Parameter** | **🔧Type** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|----------|
|combine_x|Tensor|Shape：(batch_size, hidden_size), data type is the same as x|token received in current rank|
##### 1.1.3.5 Constraints and Precautions ⚠️
1. Input Shape should satisfy the shape definition above.
2. Current interface supports A3 only.
3. Current interface does not support concurrent usage.
4. Do not support dynamic graph when in GE mode; Do not support fullgraph=true.
5. Other Constraints need to be satisfied:
 - top_k value range: (0, 16].
 - BS value range: [1, 8K]
 - num_ranks range: [2, 384]
 - num_experts range: (0, 512]
 - required: (num_experts % num_ranks) == 0
 - required: set HCCL_BUFFSIZE = 4096
 - Required: num_experts >= num_ranks
6. combine_x accuracy verification standards
 - Non-quantized scenarios: The average relative error shall be within 0.5%
 - Quantized scenarios: The average relative error shall be within 1%

 #### 1.1.4 fused_deep_moe ▶
##### 1.1.4.1 Prototype
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
##### 1.1.4.2 Interface Description
Fused computation-communication operator in MoE Decode phase for A3, which merges [Dispatch + FFN(GMM1 + Swiglu + GMM2) + Combine] ,(optional) and shared expert computation in the current card, into an operator for better inference performance.
##### 1.1.4.3 Input Parameters 
| **📌Parameter** | **🔧Type** | **✅Required/Optional** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|Required|Shape:(batch_size, token_length), support bf16 and float16 type|token to be sent of this rank in dispatch phase |
|expert_ids|Tensor|Required|Shape:(batch_size, topk)，int32 type, range: [-1, num_experts)，where -1 is used as a placeholder. A token cannot sent to an expert beyond one time.|target expert IDs of each token|
|gmm1_weight|Tensor[]|Required|In coupling mode，there is one tensor, Shape:(localExpertNum, token_length, gmm1_hidden_size); In separated mode，there are localExpertNum tensors, TensorShape：（token_length, gmm1_hidden_size; int8 type|GMM1 weight matrix，supports coupling mode and separated mode|
|gmm1_weight_scale|Tensor[]|Required|In coupling mode，there is one tensor, Shape:(localExpertNum, gmm1_hidden_size); In separated mode，there are localExpertNum tensors, each tensor Shape：（gmm1_hidden_size）; float32 type or the same type with x|GMM1 weight scale matrix，supports coupling mode and separated mode|
|gmm2_weight|Tensor[]|Required|In coupling mode，there is one tensor, Shape:(localExpertNum, gmm1_hidden_size/2, token_length); In separated mode，there are the localExpertNum tensors, each tensor Shape：（gmm1_hidden_size/2, token_length）; int8 type|GMM2 weight matrix，supports coupling mode and separated mode|
|gmm2_weight_scale|Tensor[]|Required|In coupling mode，there is one tensor, Shape:(localExpertNum, token_length); In separated mode，there are localExpertNum tensors, each tensor Shape：（token_length）; float32 type or the same type with x|GMM2 weight scale matrix，supports coupling mode and separated mode|
|expert_scales|Tensor|Required|Shape：(batch_size, topk), float32 type|weights of each expert，used in combine phase|
|share_gmm1_weight|Tensor|Optional|Shape：（token_length, share_gmm1_hidden_size）; int8 type|shared expert MM1 weight matrix|
|share_gmm1_weight_scale|Tensor|Optional|Shape：（share_gmm1_hidden_size）; the same type with gmm1_weight_scale|shared expert MM1 weight scale matrix|
|share_gmm2_weight|Tensor|Optional|Shape：（share_gmm1_hidden_size/2, token_length）; int8 type|shared expert MM2 weight matrix，supports coupling mode and separated mode|
|share_gmm2_weight_scale|Tensor|Optional|Shape：（token_length）; the same type with gmm2_weight_scale|shared expert MM2 weight scale|
|expert_smooth_scales|Tensor|Optional|Shape: (moe_expert_num, token_length), float32 type|smooth quant scales of routed experts|
|share_smooth_scales|Tensor|Optional|Shape: (token_length), float32 type|smooth quant scales of shared experts|
|x_active_mask|Tensor|Optional|Shape: (batch_size), bool type, value in[true, false], the true value must come before the false value|mask of input x. true means the token will be dispatched, false means the token will not be dispatched|
|group_ep|str|Required|Length of str：(0, 128), make sure it is valid|HCCL communication group name|
|ep_rank_size|int|Required|Required：(ep_rank_size * MoeExpertNumPerRank) ≤ 512, and ep_rank_size > 0|EP group size|
|ep_rank_id|int|Required|range: [0, ep_rank_size)|rank ID in EP group|
|moe_expert_num|int|Required|Required：moe_expert_num % ep_rank_size == 0|MOE expert number|
|quant_mode|int|Required|Reserved parameter, set to 0|quant mode|
|global_bs|int|Required|set to 0 or (batch_size * ep_rank_size) when token is the same in different ranks; set to (max_batch_size * ep_rank_size) otherwise.|max token number among all ranks|
##### 1.1.4.4 Return Value 
Return value is a list of tensors，which stores combine_x and expert_token_nums.
| **📌Parameter** | **🔧type** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|----------|
|combine_x|Tensor|Shape：(batch_size, token_length), the same type as input x|token after combination from experts in different ranks|
|share_output|Tensor|Shape：(batch_size, token_length), the same type as input x|token result from shared expert in current card. This output will exist as placeholder even though shared expert is not enabled|
|expert_token_nums|Tensor|Shape：(local_expert_num), int64 type|token number received by each expert in current rank|
##### 1.1.4.5 Constraints and Precautions ⚠️
1. Input Shape should satisfy the shape definition above.
2. Current interface supports A3 only.
3. Current interface does not support concurrent usage.In extreme cases, repeatedly calling the same operator in a single forward pass may result in undefined behavior. To avoid potential asynchronous timing issues in such scenarios, torch.npu.synchronize() should be added between operator executions.
4. Support aclgraph only when graph in on.
5. Do not support external shared experts, that is, shared experts are deployed on dedicated cards .
6. The performance may decline when batch_size is lower than 16, as it is not the target scenario.
7. Other Constraints need to be satisfied:
 - top_k range：[0， 12] and it should be lower than expert number.
 - BS range：[0，256]
 - num_experts range：(0， 512]
 - Required: token length range: [1024, 7168] and (hidden_size % 256) == 0
 - Required: gmm1_hidden_size range: [1024, 6144] and (gmm1_hidden_size % 1024) == 0
 - Required: share_gmm1_hidden_size range: [1024, 6144] and (share_gmm1_hidden_size % 1024) == 0
 - Required：HCCL_BUFFSIZE should be greater than [(ep_rank_size * max_batch_size * moe_expert_num_per_rank * total_length * sizeof(x) * 2) / 1024 / 1024], which should be round up to the nearest integer.
 - Required：global_bs ≥ 0 and（global_bs % ep_rank_size） == 0
 - Required: gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale should be in the same mode
 - Required: share_gmm1_weight, share_gmm1_weight_scale, share_gmm2_weight, share_gmm2_weight_scale must exist at the same time if shared expert computation is enabled
 - Required: expert_smooth_scales must exist if routed expert smooth quantization is enabled, furthermore, share_smooth_scales must exist if shared expert computation is enabled
