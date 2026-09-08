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
|expert_ids|Tensor|必选|形状:(batch_size, topk)， 数据类型为int32，取值范围[-INF, num_experts)，负数代表不发送，超过num_experts会引发异常，一个token不允许重复发给同一个专家|每个token的目标专家ID信息|
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
7. 当权重为fp8_e4m3时，支持数据ND/NZ两种数据排布，当权重为fp4_e2m1,fp8_e5m2时，仅支持数据ND排布。
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

### 2. KVCache Offload
CAM 在 umdk_cam_op_lib 库中提供 KVCache Offload 相关接口：Full KV Cache 保存在 Host memory，Selected KV Cache 保存在 HBM；根据 sparse attention 选择结果，仅搬运需要参与计算的 KV。

 #### 2.1.1 gather_selection_kv_cache ▶
##### 2.1.1.1 接口原型
```python
umdk_cam_op_lib.gather_selection_kv_cache(
    Tensor selection_k_rope,
    Tensor selection_kv_cache,
    Tensor selection_kv_block_table,
    Tensor selection_kv_block_status,
    Tensor selection_topk_indices,
    Tensor full_k_rope,
    Tensor full_kv_cache,
    Tensor full_kv_block_table,
    Tensor full_kv_actual_seq,
    Tensor full_q_actual_seq,
    int selection_topk_block_size=1
) -> output: Tensor
```
##### 2.1.1.2 接口描述
该接口用于 KVCache Offload 场景：
- Full KV Cache 保存在 Host memory；
- Selected KV Cache 保存在 HBM；
- 根据当前 sparse attention 选择结果，仅搬运需要参与计算的 KV。

根据 `selection_topk_indices` 指定的 TopK 索引，从 Host 侧 full KV Cache 中 gather 对应 KV 数据到 HBM 侧 selected KV workspace，并更新 selected 侧 block table、block status 等元数据。
##### 2.1.1.3 入参
| **📌参数** | **🔧类型** | **✅是否必选** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|--------------|----------|
|selection_k_rope|Tensor|必选|形状：`[S_BLOCK_NUM, BLOCK_SIZE, K_ROPE]`，数据类型支持 bf16/fp16/int8；int8 场景为空 Tensor（shape `[0]`，无 RoPE）|HBM 侧 Selected RoPE 写缓冲，原地更新|
|selection_kv_cache|Tensor|必选|形状：`[S_BLOCK_NUM, BLOCK_SIZE, KV_CACHE]`，数据类型支持 bf16/fp16/int8|HBM 侧 Selected KV 写缓冲，原地更新|
|selection_kv_block_table|Tensor|必选|形状：`[B*S*H, S_MAX_BLOCK_NUM]`，数据类型 int32；空闲位置为 -1|HBM 侧 Selected 逻辑 block 到物理 block ID 的映射表，原地更新|
|selection_kv_block_status|Tensor|必选|数据类型 int32；支持 BSND `[B, S, H, TOPK+1]` 或 TND `[B*S, H, TOPK+1]`|HBM 侧 Selected block 状态信息，原地更新|
|selection_topk_indices|Tensor|必选|数据类型 int32；full KV 坐标系；支持 BSND `[B, S, H, TOPK]` 或 TND `[B*S, H, TOPK]`|HBM 侧当前 sparse attention 选择的 TopK 索引|
|full_k_rope|Tensor|必选|形状：`[F_BLOCK_NUM, BLOCK_SIZE, K_ROPE]`，数据类型与 selected 侧一致；int8 场景为空 Tensor（shape `[0]`）|Host 侧全量 k_rope，作为 gather 读源；通过 `empty_with_swapped_memory` 分配，物理位于 Host DRAM，逻辑 device=npu|
|full_kv_cache|Tensor|必选|形状：`[F_BLOCK_NUM, BLOCK_SIZE, KV_CACHE]`，数据类型与 selected 侧一致|Host 侧全量 kv_cache，作为 gather 读源；通过 `empty_with_swapped_memory` 分配，物理位于 Host DRAM，逻辑 device=npu|
|full_kv_block_table|Tensor|必选|形状：`[B, F_MAX_BLOCK_NUM]`，数据类型 int32，必须为 2D 且 dim0 = B|HBM 侧 Full KV block index 映射表|
|full_kv_actual_seq|Tensor|必选|形状：`[B]`，数据类型 int32|HBM 侧各 batch full KV 有效长度（已缓存 Full KV token 数）|
|full_q_actual_seq|Tensor|必选|形状：`[B]`，数据类型 int32|HBM 侧各 batch query 有效长度（一般为 1）|
|selection_topk_block_size|int|可选|默认值 1；当前仅支持取 1|每个 TopK 索引覆盖的 token 数（每次搬运 KV 数）|
##### 2.1.1.4 返回值
函数返回 `selection_kv_actual_seq`。
| **📌参数** | **🔧类型** | **📋取值说明** | **📝描述** |
|----------|----------|--------------|----------|
|selection_kv_actual_seq|Tensor|形状：`[B*S*H]`，数据类型 int32|参与 SFA 计算的 KV 有效数量，供后续 SFA `actual_seq_lengths_kv` 使用|
##### 2.1.1.5 约束和注意事项 ⚠️
1. 需要满足：`32 < TOPK ≤ 2048`。
2. 需要满足：`S`、`H` 仅支持 1。
3. 需要满足：`selection_topk_block_size = 1`。
4. 需要满足：`S_BLOCK_NUM ≥ B*S*H*S_MAX_BLOCK_NUM`。
5. 当前接口仅支持 Ascend910 A3 环境调用。
6. 需要满足：`2 < B < 256`。
7. 需要满足：`K_ROPE ≤ 64`；`KV_CACHE ≤ 656`。
8. int8 时 `selection_k_rope` / `full_k_rope` 须为 shape `[0]` 的空 Tensor。
9. `full_kv_cache` 的 `BLOCK_SIZE` 必须与 `selection_kv_cache` 一致。
10. `full_kv_block_table` 必须为 2D，且 dim0 = B。
##### 2.1.1.6 符号说明
| **符号** | **含义** |
|----------|----------|
|B|Batch size|
|S|本步 query 序列长度（首版约束 S=1）|
|H|Attention head 数（当前仅支持 H=1，对应 MLA sparse head）|
|TOPK|本步 sparse 选择的 token（或 token 组）数量|
|BLOCK_SIZE|Paged KV 单个物理 block 可容纳的 token 数；selected / full 通常保持一致，例如 128|
|S_BLOCK_NUM|Selected 侧物理 block pool 大小，即 `selection_*` tensor 的 dim0|
|F_BLOCK_NUM|Full 侧物理 block pool 大小，即 Host 全量 KV cache 的 dim0|
|S_MAX_BLOCK_NUM|单个 `(B,S,H)` 逻辑序列在 selected 侧最多挂载的逻辑 block 数，即 `selection_kv_block_table` 列数|
|F_MAX_BLOCK_NUM|单个 batch 在 full 侧最多挂载的逻辑 block 数，即 `full_kv_block_table` 列数|
|K_ROPE|RoPE 维度，对应 `qk_rope_head_dim`；非 int8 场景独立存储|
|KV_CACHE|KV / NoPE 最后一维长度；非 int8 时约等于 `kv_lora_rank`，int8 时为 NoPE + RoPE + scale 拼接后的长度|
