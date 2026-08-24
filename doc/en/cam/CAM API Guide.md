# CAM API Guide
## Introduction
 **CAM**  is short for  **C**ommunication  **A**cceleration for  **M**atrix on Ascend NPU. CAM provides EP (Expert Parallelism) communication kernels, high performance KVCache transfer for PD disaggregation and KVC pooling, AFD communication kernels, RL weights transfer and so on. CAM is easily to be run in single kernel mode or integrated into vllm or SGLang framework. 

## CAM Structure
（To be done）

## CAM API
### 1. EP Communication Kernels
UMDK provides high-performance Python interfaces for communication and fused computation-communication via "umdk_cam_op_lib". Users can use this lib in popular Ascend inference framework, such as vllm-ascend, sglang-kernel-npu, etc.

 #### 1.1.1 fused_deep_moe ▶
##### 1.1.1.1 Prototype
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
##### 1.1.1.2 Interface Description
Fused computation-communication operator for MoE Decode phase, which merges [Dispatch + FFN(GMM1 + Swiglu + GMM2) + Combine] to enable efficient model inference and expert selection, and (optionally) supports built-in shared expert computation, suitable for distributed inference scenarios.
##### 1.1.1.3 Input Parameters 
| **📌Parameter** | **🔧Type** | **✅Required/Optional** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|--------------|----------|
|x|Tensor|Required|Shape:(batch_size, token_length), support bf16 and float16 type|token to be sent of this rank in dispatch phase |
|expert_ids|Tensor|Required|Shape:(batch_size, topk)，int32 type, range: [-1, num_experts)，where -1 is used as a placeholder. A token cannot sent to an expert beyond one time.|target expert IDs of each token|
|gmm1_weight|Tensor[]|Required|In coupling mode，there is one tensor, Shape:(localExpertNum, token_length, gmm1_hidden_size); In separated mode，there are localExpertNum tensors, each tensor Shape：（token_length, gmm1_hidden_size），data type supports fp8_e4m3, fp8_e5m2, fp4_e2m1|GMM1 weight matrix list，supports coupling mode and separated mode|
|gmm1_weight_scale|Tensor[]|Required|In coupling mode，there is one tensor, Shape:(localExpertNum, token_length/32/2, gmm1_hidden_size, 2); In separated mode，there are localExpertNum tensors, each tensor Shape：（token_length/32/2, gmm1_hidden_size, 2），data type is fp8_e8m0|GMM1 weight scale matrix list，supports coupling mode and separated mode|
|gmm2_weight|Tensor[]|Required|In coupling mode，there is one tensor, Shape:(localExpertNum, gmm1_hidden_size/2, token_length); In separated mode，there are localExpertNum tensors, each tensor Shape：（gmm1_hidden_size/2, token_length），data type supports fp8_e4m3, fp8_e5m2, fp4_e2m1|GMM2 weight matrix list，supports coupling mode and separated mode|
|gmm2_weight_scale|Tensor[]|Required|In coupling mode，there is one tensor, Shape:(localExpertNum, (gmm1_hidden_size/2)/32/2, token_length, 2); In separated mode，there are localExpertNum tensors, each tensor Shape：（(gmm1_hidden_size/2)/32/2, token_length, 2），data type is fp8_e8m0|GMM2 weight scale matrix list，supports coupling mode and separated mode|
|expert_scales|Tensor|Required|Shape：(batch_size, topk), float32 type|weights of each expert，used in combine phase|
|share_gmm1_weight|Tensor|Optional|Shape：（token_length, share_gmm1_hidden_size），data type supports fp8_e4m3, fp8_e5m2, fp4_e2m1|shared expert MM1 weight matrix|
|share_gmm1_weight_scale|Tensor|Optional|Shape：（token_length/32/2, share_gmm1_hidden_size, 2），data type is the same as gmm1_weight_scale|shared expert MM1 weight scale matrix|
|share_gmm2_weight|Tensor|Optional|Shape：（share_gmm1_hidden_size/2, token_length），data type supports fp8_e4m3, fp8_e5m2, fp4_e2m1|shared expert MM2 weight matrix|
|share_gmm2_weight_scale|Tensor|Optional|Shape：（share_gmm1_hidden_size/2, token_length, 2），data type is the same as gmm2_weight_scale|shared expert MM2 weight scale|
|expert_smooth_scales|Tensor|Optional|Shape: (moe_expert_num, token_length), float32 type|smooth quant scales of routed experts|
|share_smooth_scales|Tensor|Optional|Shape: (token_length), float32 type|smooth quant scales of shared experts|
|x_active_mask|Tensor|Optional|Shape: (batch_size), bool type, value in[true, false], the true value must come before the false value|mask of input x. true means the token will be dispatched, false means the token will not be dispatched|
|gmm1_bias|Tensor[]|Required|Shape: no constraint, data type is float32|placeholder added to keep the interface consistent, has no effect, but a list containing a float32 NPU Tensor must be passed in, recommend to pass in \[expert_scales\] directly|
|gmm2_bias|Tensor[]|Required|Shape: no constraint, data type is float32|placeholder added to keep the interface consistent, has no effect, but a list containing a float32 NPU Tensor must be passed in, recommend to pass in \[expert_scales\] directly|
|share_gmm1_bias|Tensor|Optional|Shape: no constraint, data type is float32|placeholder added to keep the interface consistent, has no effect, passing None is fine|
|share_gmm2_bias|Tensor|Optional|Shape: no constraint, data type is float32|placeholder added to keep the interface consistent, has no effect, passing None is fine|
|group_ep|str|Required|Length of str：(0, 128), make sure it is valid|HCCL communication group name|
|ep_rank_size|int|Required|Required：(ep_rank_size * MoeExpertNumPerRank) ≤ 512, and ep_rank_size > 0|EP group size|
|ep_rank_id|int|Required|range: [0, ep_rank_size)|rank ID in EP group|
|moe_expert_num|int|Required|Required：moe_expert_num % ep_rank_size == 0|MOE expert number|
|quant_mode|int|Required|Reserved parameter, set to 0|quant mode|
|global_bs|int|Required|set to 0 or (batch_size * ep_rank_size) when token is the same in different ranks; set to (max_batch_size * ep_rank_size) otherwise.|max token number among all ranks|
##### 1.1.1.4 Return Value 
Return value is a list of tensors，which stores combine_x and expert_token_nums.
| **📌Parameter** | **🔧type** | **📋Value Range** | **📝Details** |
|----------|----------|--------------|----------|
|combine_x|Tensor|Shape：(batch_size, token_length), the same type as input x|token after combination from experts in different ranks|
|share_output|Tensor|Shape：(batch_size, token_length), the same type as input x|token result from shared expert in current card. This output will exist as placeholder even though shared expert is not enabled|
|expert_token_nums|Tensor|Shape：(local_expert_num), int64 type|token number received by each expert in current rank|
##### 1.1.1.5 Constraints and Precautions ⚠️
1. Input Shape should satisfy the shape definition above.
2. Current interface supports Ascend950 only.
3. Current interface does not support concurrent usage.In extreme cases, repeatedly calling the same operator in a single forward pass may result in undefined behavior. To avoid potential asynchronous timing issues in such scenarios, torch.npu.synchronize() should be added between operator executions.
4. Support aclgraph only when graph in on.
5. Do not support external shared experts, that is, shared experts are deployed on dedicated cards .
6. The performance may decline when batch_size is lower than 16, as it is not the target scenario.
7. When the weight data type is fp8_e4m3, both ND and NZ data layouts are supported; when the weight data type is fp4_e2m1 or fp8_e5m2, only ND layout is supported.
8. Other Constraints need to be satisfied:
 - top_k range：[0， 12] and it should be lower than expert number.
 - BS range：[0，256]
 - num_experts range：(0， 512]
 - Required: token length range: [1024, 7168] and (hidden_size % 256) == 0
 - Required: gmm1_hidden_size range: [1024, 6144] and (gmm1_hidden_size % 256) == 0
 - Required: share_gmm1_hidden_size range: [1024, 6144] and (share_gmm1_hidden_size % 256) == 0
 - Required：HCCL_BUFFSIZE should be no less than [ep_rank_size * max_batch_size * moe_expert_num_per_rank * (total_length * 1 + 512) / 1024 / 1024], rounded up to the nearest integer.
 - Required：global_bs ≥ 0 and（global_bs % ep_rank_size） == 0
 - Required: gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale should be in the same mode
 - Required: share_gmm1_weight, share_gmm1_weight_scale, share_gmm2_weight, share_gmm2_weight_scale must exist at the same time if shared expert computation is enabled
 - Required: expert_smooth_scales must exist if routed expert smooth quantization is enabled, furthermore, share_smooth_scales must exist if shared expert computation is enabled
