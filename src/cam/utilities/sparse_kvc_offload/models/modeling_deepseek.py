# coding=utf-8
# Adapted from
# https://huggingface.co/deepseek-ai/DeepSeek-V3/blob/main/modeling_deepseek.py
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# Copyright 2023 DeepSeek-AI and The HuggingFace Inc. team. All rights reserved.
#
# This code is based on EleutherAI's GPT-NeoX library and the GPT-NeoX
# and OPT implementations in this library. It has been modified from its
# original forms to accommodate minor architectural differences compared
# to GPT-NeoX and OPT used by the Meta AI team that trained the model.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" PyTorch DeepSeek model."""
import os
from typing import List, Optional, Tuple, Union, Dict, Iterable, Set

import torch
import torch.nn.functional as F
import torch.utils.checkpoint

from torch import nn
import torch.distributed as dist

import torch_npu
import torchair as tng
import umdk_cam_op_lib

from transformers.cache_utils import Cache
from transformers.utils import (
    add_start_docstrings,
    add_start_docstrings_to_model_forward,
    logging,
)

from executor.utils import (
    override, get_init_attn_mask, align_up, calc_moe_hccl_buffer_size,
    init_comm_group, get_default_group, get_decode_mask)

from executor.model_loader.weight_utils import default_weight_loader
from executor.utils import npu_stream_switch, superkernel_scope
from module.linear import (
    ColumnParallelLinear,
    ReplicatedLinear,
    MergedColumnParallelLinear,
    RowParallelLinear,
    VocabParallelEmbedding
    )
from module.fuse_moe_gmm import FusedMoEGMM
from .configuration_deepseek import DeepseekV3Config
from .modules import (_prepare_4d_causal_attention_mask, one_hot, yarn_get_mscale,
                      DeepseekV3RMSNorm, apply_rotary_pos_emb, _init_rope, DEEPSEEKV3_START_DOCSTRING,
                      DEEPSEEKV3_INPUTS_DOCSTRING, DeepseekV3PreTrainedModel
                    )
from .indexer import Indexer
from .offload_cache import OffloadCache

logger = logging.get_logger(__name__)
moe_npu_events = [tng.ops.npu_create_tagged_event(tag=f"moe_evt_{i}") for i in range(2)]


class DeepseekV3DenseMLP(nn.Module):
    def __init__(self, config, runner_settings, prefix, **kwargs):
        super().__init__()
        self.runner_settings = runner_settings
        self.mm_quant_mode = (
            config.quant_config.mm_quant_mode
            if config.quant_config is not None
            else "w16a16")
        self.moe_ep_size = self.runner_settings.get("parallel_config").get("moe_ep_size", 1)
        self.moe_tp_size = self.runner_settings.get("parallel_config").get("moe_tp_size", 1)
        self.dense_tp_size = self.runner_settings.get("parallel_config").get("dense_tp_size", 1)
        self.config = config
        self.hidden_size = config.hidden_size
        self.hccl_comm_dict = kwargs.get("hccl_comm_dict", None)
        self.gate_up_proj = MergedColumnParallelLinear(
            input_size=self.hidden_size,
            output_sizes=[config.intermediate_size] * 2,
            bias=False,
            tp_size=self.dense_tp_size,
            tp_rank=dist.get_rank(self.hccl_comm_dict["dense_tp_group"]) if self.dense_tp_size > 1 else 0,
            quant_config=config.quant_config,
            prefix=f"{prefix}.gate_up_proj"
            )
        self.down_proj = RowParallelLinear(
            config.intermediate_size,
            config.hidden_size,
            bias=False,
            tp_size=self.dense_tp_size,
            tp_rank=dist.get_rank(self.hccl_comm_dict["dense_tp_group"]) if self.dense_tp_size > 1 else 0,
            quant_config=config.quant_config,
            prefix=f"{prefix}.down_proj")

    def forward(self, x, is_prefill=False):
        # input_DP + attention_TP + moe_EP
        if self.dense_tp_size > 1 and self.moe_ep_size > 1:
            bsz, q_len, _ = x.size()
            x_output = torch.empty([bsz * self.dense_tp_size, q_len, self.hidden_size], \
                                   dtype=x.dtype, device="npu")
            dist.all_gather_into_tensor(x_output, x, group=self.hccl_comm_dict.get("dense_tp_group", None))
            x = x_output

        if self.mm_quant_mode == "w8a8int8":
            down_proj = self.forward_w8a8int8(x)
        else:
            down_proj = self.forward_normal(x)

        if self.dense_tp_size > 1 and self.moe_ep_size > 1:
            mlp_res = down_proj.new_empty(bsz, q_len, down_proj.shape[-1])
            dist.reduce_scatter_tensor(mlp_res, down_proj, group=self.hccl_comm_dict.get("dense_tp_group", None))
            down_proj = mlp_res
        elif self.dense_tp_size > 1 and self.moe_tp_size > 1:
            dist.all_reduce(down_proj, group=self.hccl_comm_dict.get("dense_tp_group", None))

        return down_proj

    def forward_normal(self, x):
        merged_x = self.gate_up_proj(x)
        intermediate_hidden_states = torch_npu.npu_swiglu(merged_x)
        return self.down_proj(intermediate_hidden_states)

    def forward_w8a8int8(self, x):
        merged_x, pertoken_scale = self.gate_up_proj(x, out_dtype=torch.int32)
        intermediate_hidden_states, pertoken_scale = torch_npu.npu_dequant_swiglu_quant(
            merged_x, weight_scale=self.gate_up_proj.weight_scale,
            quant_scale=self.down_proj.smooth_scales,
            quant_mode=1, activate_left=True,
            activation_scale=pertoken_scale
        )
        return self.down_proj(intermediate_hidden_states, pertoken_scale)


class DeepseekV3SharedExpert(nn.Module):
    def __init__(self, config, runner_settings, is_moe_layer=False, prefix="", **kwargs):
        super().__init__()
        self.runner_settings = runner_settings
        self.mm_quant_mode = (
            config.quant_config.mm_quant_mode
            if config.quant_config is not None
            else "w16a16")
        self.moe_tp_size = self.runner_settings.get("parallel_config").get("moe_tp_size", 1)
        self.moe_ep_size = self.runner_settings.get("parallel_config").get("moe_ep_size", 1)
        self.config = config
        self.hidden_size = config.hidden_size
        self.is_moe_layer = is_moe_layer
        self.hccl_comm_dict = kwargs.get("hccl_comm_dict", None)
        self.gate_up_proj = MergedColumnParallelLinear(
            input_size=self.hidden_size,
            output_sizes=[config.moe_intermediate_size * config.n_shared_experts] * 2,
            bias=False,
            tp_size=self.moe_tp_size,
            tp_rank=dist.get_rank(self.hccl_comm_dict.get("moe_tp_group")) if self.moe_tp_size > 1 else 0,
            quant_config=config.quant_config,
            prefix=f"{prefix}.gate_up_proj")
        self.down_proj = RowParallelLinear(
            config.moe_intermediate_size * config.n_shared_experts,
            config.hidden_size,
            bias=False,
            tp_size=self.moe_tp_size,
            tp_rank=dist.get_rank(self.hccl_comm_dict["moe_tp_group"]) if self.moe_tp_size > 1 else 0,
            quant_config=config.quant_config,
            prefix=f"{prefix}.down_proj")
        if self.mm_quant_mode == "w8a8int8":
            self.down_proj_forward = self.forward_w8a8int8
        else:
            self.down_proj_forward = self.forward_normal

    def forward(self, x):
        down_proj = self.down_proj_forward(x)
        return down_proj

    def forward_normal(self, x):
        merged_x = self.gate_up_proj(x)
        intermediate_hidden_states = torch_npu.npu_swiglu(merged_x)
        return self.down_proj(intermediate_hidden_states)

    def forward_w8a8int8(self, x):
        merged_x, pertoken_scale = self.gate_up_proj(x, out_dtype=torch.int32)
        intermediate_hidden_states, pertoken_scale = torch_npu.npu_dequant_swiglu_quant(
            merged_x, weight_scale=self.gate_up_proj.weight_scale,
            quant_scale=self.down_proj.smooth_scales,
            quant_mode=1, activate_left=True,
            activation_scale=pertoken_scale
        )
        return self.down_proj(intermediate_hidden_states, pertoken_scale)


class DeepseekV3MoE(nn.Module):
    """
    A mixed expert module containing shared experts.
    """

    def __init__(self, config, runner_settings, prefix, **kwargs):
        super().__init__()
        self.config = config
        self.layer_idx = kwargs.get("layer_idx")
        self.runner_settings = runner_settings
        self.gmm_quant_mode = (
            config.quant_config.gmm_quant_mode
            if config.quant_config is not None
            else "w16a16")
        self.hidden_dim = config.hidden_size
        self.intermediate_size = config.moe_intermediate_size
        self.moe_tp_size = self.runner_settings.get("parallel_config").get("moe_tp_size", 1)
        self.moe_ep_size = self.runner_settings.get("parallel_config").get("moe_ep_size", 1)
        self.exe_mode = self.runner_settings.get("exe_mode", "eager")
        self.enable_multi_streams = runner_settings.get("model_config").get("enable_multi_streams", False)
        self.enable_aclgraph = runner_settings.get("exe_mode", "ge_graph") == "acl_graph"
        self.perfect_eplb = self.runner_settings.get("model_config").get("perfect_eplb", False)
        self.num_experts_per_tok = config.num_experts_per_tok
        # total experts num
        self.num_experts = config.n_routed_experts
        self.top_k = config.num_experts_per_tok

        self.intermediate_size_per_rank = self.intermediate_size // self.moe_tp_size
        self.shared_expert_rank_num = 0 # route and share on same card
        self.n_shared_experts = config.n_shared_experts
        self.n_routed_experts = config.n_routed_experts
        self.experts_per_rank = config.n_routed_experts // self.moe_ep_size
        self.hccl_comm_dict = kwargs.get("hccl_comm_dict", None)
        self.experts = FusedMoEGMM(
            num_experts=config.n_routed_experts,
            hidden_size=self.hidden_dim,
            intermediate_size=self.intermediate_size,
            # when W4A8 is enabled, gmm kernel needs an auxiliary matrix, it will be passed in as a bias
            bias=True if self.gmm_quant_mode == "w4a8int4" else False,
            quant_config=config.quant_config,
            tp_size=self.moe_tp_size,
            tp_rank=dist.get_rank(self.hccl_comm_dict["moe_tp_group"]) if self.moe_tp_size > 1 else 0,
            ep_size=self.moe_ep_size,
            ep_rank=dist.get_rank(self.hccl_comm_dict["moe_ep_group"]) if self.moe_ep_size > 1 else 0,
            prefix=f"{prefix}.experts",
        )

        self._init_gate(prefix)
        if config.n_shared_experts is not None:
            self.shared_experts = DeepseekV3SharedExpert(config, self.runner_settings,
                                        is_moe_layer=True, prefix=f"{prefix}.shared_experts", **kwargs)

        self.dispatch_kwargs = None
        self.combine_kwargs = None

    def _init_gate(self, prefix):
        self.top_k = self.config.num_experts_per_tok
        self.n_routed_experts = self.config.n_routed_experts
        self.routed_scaling_factor = self.config.routed_scaling_factor
        self.scoring_func = self.config.scoring_func
        self.topk_method = self.config.topk_method
        self.n_group = self.config.n_group
        self.topk_group = self.config.topk_group
        # topk selection algorithm
        self.norm_topk_prob = self.config.norm_topk_prob
        self.gate = ReplicatedLinear(self.config.hidden_size,
                                     self.n_routed_experts,
                                     bias=False,
                                     quant_config=None,
                                     params_dtype=torch.float32,
                                     prefix=f"{prefix}.gate")
        self._reset_parameters()
        if self.topk_method == "noaux_tc":
            self.gate.e_score_correction_bias = nn.Parameter(
                torch.empty((self.n_routed_experts), dtype=torch.float32)
            )
        else:
            self.gate.e_score_correction_bias = None

    def _reset_parameters(self) -> None:
        pass

    def _forward_gate(self, hidden_states):
        bsz, seq_len, h = hidden_states.shape
        # compute gating score
        hidden_states = hidden_states.view(-1, h)
        logits = self.gate(hidden_states)

        # use fused kernel, currently only support 256 or 384 experts
        if self.topk_method == "noaux_tc" and self.n_routed_experts in [256, 384]:
            topk_weight, topk_idx, _ = torch_npu.npu_moe_gating_top_k(
                logits,
                k=self.top_k,
                bias=self.gate.e_score_correction_bias.float(),
                k_group=self.topk_group,
                group_count=self.n_group,
                group_select_mode=1,
                renorm=0,       # 0: softmax->topk; 1: topk->softmax
                norm_type=1,    # 0: softmax; 1: sigmoid
                routed_scaling_factor=self.routed_scaling_factor,
                eps=float(1e-20)
            )
            return topk_idx, topk_weight, None

        if self.scoring_func == "sigmoid":
            scores = logits.sigmoid()
        elif self.scoring_func == "softmax":
            scores = logits.softmax(dim=-1, dtype=torch.float32)
        else:
            raise NotImplementedError(
                f"insupportable scoring function for MoE gating: {self.scoring_func}"
            )

        # select top-k experts
        if self.topk_method == "greedy":
            topk_weight, topk_idx = torch.topk(
                scores, k=self.top_k, dim=-1, sorted=False
            )
        elif self.topk_method == "group_limited_greedy":
            group_scores = (
                scores.view(bsz * seq_len, self.n_group, -1).max(dim=-1).values
            )  # [n, n_group]
            group_idx = torch.topk(
                group_scores, k=self.topk_group, dim=-1, sorted=False
            )[
                1
            ]  # [n, top_k_group]
            group_mask = torch.zeros_like(group_scores)  # [n, n_group]
            group_mask.scatter_(1, group_idx, 1)  # [n, n_group]
            score_mask = (
                group_mask.unsqueeze(-1)
                .expand(
                    bsz * seq_len, self.n_group, self.n_routed_experts // self.n_group
                )
                .reshape(bsz * seq_len, -1)
            )  # [n, e]
            tmp_scores = scores.masked_fill(~score_mask.bool(), 0.0)  # [n, e]
            topk_weight, topk_idx = torch.topk(
                tmp_scores, k=self.top_k, dim=-1, sorted=False
            )
        elif self.topk_method == "noaux_tc":
            assert not self.training
            scores_for_choice = scores.view(bsz * seq_len, -1) + self.gate.e_score_correction_bias.unsqueeze(0)
            group_scores = (
                scores_for_choice.view(bsz * seq_len, self.n_group, -1).topk(2, dim=-1)[0].sum(dim=-1)
            )  # [n, n_group]
            group_idx = torch.topk(
                group_scores, k=self.topk_group, dim=-1, sorted=False
            )[
                1
            ]  # [n, top_k_group]
            group_mask = one_hot(group_idx, self.n_group)  # [n, n_group]
            group_mask = torch.sum(group_mask, dim=1)  # [n, n_group]
            score_mask = (
                group_mask.unsqueeze(-1)
                .expand(
                    bsz * seq_len, self.n_group, self.n_routed_experts // self.n_group
                )
                .reshape(bsz * seq_len, -1)
            )  # [n, e]
            tmp_scores = scores_for_choice.masked_fill(~score_mask.bool(), 0.0)  # [n, e]
            _, topk_idx = torch.topk(
                tmp_scores, k=self.top_k, dim=-1, sorted=False
            )
            topk_weight = scores.gather(1, topk_idx)
        else:
            raise NotImplementedError(
                f"insupportable TopK function for MoE gating: {self.topk_method}"
            )

        # norm gate to sum 1
        if self.top_k > 1 and self.norm_topk_prob:
            denominator = topk_weight.sum(dim=-1, keepdim=True) + 1e-20
            topk_weight = topk_weight / denominator
        topk_weight = topk_weight * self.routed_scaling_factor # must multiply the scaling factor

        return topk_idx, topk_weight, None

    def set_mc2_kwargs(self):
        global_rank = dist.get_rank()
        mc2_group_name = self.hccl_comm_dict.get("moe_ep_group_mc2_name", None)
        self.dispatch_kwargs = {
                "x_active_mask": None,
                "expert_shard_type": 0,
                "shared_expert_rank_num": self.shared_expert_rank_num,
                "moe_expert_num": self.n_routed_experts,
                "global_bs": 0,
                "scales": self.experts.smooth_scale_1 if "a8" in self.gmm_quant_mode else None,
                "quant_mode": 2 if "a8" in self.gmm_quant_mode else 0,
                "group_ep": mc2_group_name,
                "ep_world_size": self.moe_ep_size,
                "ep_rank_id": global_rank // self.moe_tp_size,
                "group_tp": mc2_group_name,
                "tp_world_size": self.moe_tp_size,
                "tp_rank_id": global_rank % self.moe_tp_size,
                "comm_alg": "fullmesh_v2",
            }
        self.combine_kwargs = {
                "x_active_mask": None,
                "expert_shard_type": 0,
                "shared_expert_rank_num": self.shared_expert_rank_num,
                "moe_expert_num": self.n_routed_experts,
                "global_bs": 0,
                "group_ep": mc2_group_name,
                "ep_world_size": self.moe_ep_size,
                "ep_rank_id": global_rank // self.moe_tp_size,
                "group_tp": mc2_group_name,
                "tp_world_size": self.moe_tp_size,
                "tp_rank_id": global_rank % self.moe_tp_size
            }

    def forward(self, hidden_states, is_prefill=False, cur_topk_list=None):
        topk_idx, topk_weight, _ = self._forward_gate(hidden_states.float())
        if self.perfect_eplb:
            topk_idx = cur_topk_list
        topk_idx = topk_idx.to(torch.int32)
        # we convert 2d to 3d, and then 3d back to 2d to adapte fusion pass rule
        hidden_states_3d = hidden_states.unsqueeze(1)
        hidden_states = hidden_states_3d.squeeze(1)

        if self.n_shared_experts > 0:
            enable_multi_streams = self.enable_multi_streams and not is_prefill
            use_aclgraph_event = enable_multi_streams and self.enable_aclgraph
            if use_aclgraph_event:
                tng.ops.npu_record_tagged_stream(hidden_states, "11")
                tng.ops.npu_tagged_event_record(moe_npu_events[0])
            with npu_stream_switch(enable_multi_streams, "11"):
                if use_aclgraph_event:
                    tng.ops.npu_tagged_event_wait(moe_npu_events[0])
                # shared_expert use multi streams
                hidden_states_share = self.shared_experts(hidden_states.view(-1, hidden_states.shape[-1]))
                if use_aclgraph_event:
                    tng.ops.npu_tagged_event_record(moe_npu_events[1])
        else:
            use_aclgraph_event = False
            hidden_states_share = None

        if self.moe_tp_size > 1:
            # MOE TP
            return self.moe_infer_tp(hidden_states, topk_idx, topk_weight, hidden_states_share, is_prefill)
        else:
            # MOE EP
            if is_prefill:
                return self.moe_infer_double_routing(hidden_states, topk_idx, topk_weight, hidden_states_share)
            else:
                return self.moe_infer_dispatch_combine(hidden_states, topk_idx, topk_weight, hidden_states_share)

    def forward_gate_init_routing(self, hidden_states, cur_topk_list=None):
        # gate
        topk_idx, topk_weight, _ = self._forward_gate(hidden_states)
        if self.perfect_eplb:
            topk_idx = cur_topk_list
        topk_idx = topk_idx.to(torch.int32)

        # init_routing
        _, _, h = hidden_states.shape
        hidden_states = hidden_states.view(-1, h)
        expanded_x, expanded_row_idx, tokens_per_expert, pertoken_scale = torch_npu.npu_moe_init_routing_v2(
            hidden_states,
            expert_idx=topk_idx,
            active_num=topk_idx.shape[0] * topk_idx.shape[1],
            scale=self.experts.smooth_scale_1 if "a8" in self.gmm_quant_mode else None,
            expert_num=self.num_experts,
            expert_tokens_num_type=1,  # 0: cumsum mode(not supported now); 1: count mode
            expert_tokens_num_flag=True, active_expert_range=[0, self.num_experts],
            quant_mode=1 if "a8" in self.gmm_quant_mode else -1
            # -1: non-quant; 1: dynamic quant; 0: static quant(not supported now)
        )
        return expanded_x, expanded_row_idx, tokens_per_expert, pertoken_scale, topk_weight

    def forward_shared_expert(self, hidden_states, is_prefill):
        if self.n_shared_experts > 0:
            hidden_states_share = self.shared_experts(hidden_states.view(-1, hidden_states.shape[-1]))
        else:
            hidden_states_share = None
        return hidden_states_share

    def forward_expert(self, gathered_tokens, tokens_per_expert_group, gathered_pertoken_scale):
        # reroute
        hidden_states_ordered_by_experts, gathered_pertoken_scale, gathered_ids_unsort, tokens_per_local_expert = \
                torch_npu.npu_moe_re_routing(gathered_tokens, tokens_per_expert_group.view(self.moe_ep_size, -1),
                per_token_scales=gathered_pertoken_scale)

        # compute experts
        gmm_args = {
            "x": hidden_states_ordered_by_experts,
            "expert_tokens": tokens_per_local_expert,
            "group_list_type": 1,
        }

        if "a8" in self.gmm_quant_mode:
            gmm_args.update({"pertoken_scale": gathered_pertoken_scale})
        hidden_states_ordered_by_experts = self.experts(**gmm_args)
        # finalize-rerouting
        new_x = torch.index_select(hidden_states_ordered_by_experts, 0, gathered_ids_unsort.float().argsort().int())
        return new_x

    def forward_combine_double_routing(self, new_x, expanded_x, input_splits, output_splits):
        moe_ep_group = self.hccl_comm_dict.get("moe_ep_group", None)
        gathered_tokens = new_x.new_empty(*expanded_x.shape)
        dist.all_to_all_single(gathered_tokens, new_x, input_splits, output_splits, group=moe_ep_group)
        return gathered_tokens

    def forward_finalize_routing(self, hidden_states, gathered_tokens, hidden_states_share, topk_weight,
                                  expanded_row_idx):
        batch_size, sequence_length, h = hidden_states.shape
        # finalize-routing
        hidden_states = torch_npu.npu_moe_finalize_routing(
            gathered_tokens, skip1=hidden_states_share, skip2=None, bias=None,
            scales=topk_weight.to(gathered_tokens.dtype),
            expanded_src_to_dst_row=expanded_row_idx,
            export_for_source_row=None, drop_pad_mode=2
        )

        hidden_states = hidden_states.view(batch_size, sequence_length, h)
        return hidden_states

    def moe_infer_tp(self, x, topk_ids, topk_weight, hidden_states_share, is_prefill):
        batch_size, sequence_length, h = x.shape
        hidden_states = x.view(-1, h)
        routing_args = {
            "expert_idx": topk_ids,
            "active_num": batch_size * sequence_length * self.top_k,
            "expert_num": self.num_experts,
            "expert_tokens_num_type": 1,  # 0: cumsum mode(not supported now); 1: count mode
            "expert_tokens_num_flag": True,
            "active_expert_range": [0, self.num_experts],
            "quant_mode": -1
        }
        if "a8" in self.gmm_quant_mode:
            routing_args.update({
                "scale": self.experts.smooth_scale_1,
                "expert_tokens_num_type": 2,
                "quant_mode": 1,
                "row_idx_type": 0,
                "drop_pad_mode": 0
            })
        expanded_x, expanded_row_idx, tokens_per_expert, pertoken_scale = torch_npu.npu_moe_init_routing_v2(
            hidden_states, **routing_args
        )

        moe_args = {"group_list_type": 1}
        if "a8" in self.gmm_quant_mode:
            moe_args.update({
                "group_list_type": 2,
                "pertoken_scale": pertoken_scale
            })
        hidden_states_ordered_by_experts = self.experts(expanded_x, tokens_per_expert, **moe_args)
        enable_multi_streams = self.enable_multi_streams and not is_prefill
        use_aclgraph_event = enable_multi_streams and self.enable_aclgraph
        if use_aclgraph_event:
            tng.ops.npu_tagged_event_wait(moe_npu_events[1])
        hidden_states = torch_npu.npu_moe_finalize_routing(
            hidden_states_ordered_by_experts,
            skip1=hidden_states_share.view(-1, h), skip2=None,
            bias=None,
            scales=topk_weight.to(hidden_states_ordered_by_experts.dtype),
            expanded_src_to_dst_row=expanded_row_idx,
            export_for_source_row=None, drop_pad_mode=2
        )
        if self.moe_tp_size > 1:
            dist.all_reduce(hidden_states, group=self.hccl_comm_dict.get("moe_tp_group"))
        hidden_states = hidden_states.view(batch_size, -1, self.hidden_dim)
        return hidden_states

    def dispatch_double_routing(self, tokens_per_expert, expanded_x, pertoken_scale):
        moe_ep_group = self.hccl_comm_dict.get("moe_ep_group", None)
        tokens_per_expert_group = tokens_per_expert.new_empty(tokens_per_expert.shape[0])
        # (total_experts,)->(total_ranks*n_routed_experts_per_rank)
        dist.all_to_all_single(tokens_per_expert_group, tokens_per_expert, group=moe_ep_group)
        # combine tensors, do reduceSum and D2H togather
        combine_tokens = torch.stack([tokens_per_expert_group, tokens_per_expert], dim=0)
        # view: EP, E // EP
        combine_tokens = combine_tokens.view(2, self.moe_ep_size, -1).sum(2)
        all_tokens = combine_tokens[0].sum()
        combine_tokens_cpu = combine_tokens.cpu().tolist()
        input_splits = combine_tokens_cpu[1]
        output_splits = combine_tokens_cpu[0]
        gathered_tokens = expanded_x.new_empty(all_tokens.item(), expanded_x.shape[1])
        dist.all_to_all_single(gathered_tokens, expanded_x, output_splits, input_splits, group=moe_ep_group)

        gathered_pertoken_scale = None if pertoken_scale is None else\
                            pertoken_scale.new_empty(gathered_tokens.shape[0])
        if "a8" in self.gmm_quant_mode:
            dist.all_to_all_single(gathered_pertoken_scale, \
                                   pertoken_scale, output_splits, input_splits, group=moe_ep_group)
        return tokens_per_expert_group, gathered_tokens, gathered_pertoken_scale, input_splits, output_splits

    def moe_infer_double_routing(self, x, topk_ids, topk_weight, hidden_states_share):
        """
        pure ep strategy, for prefill stage mainly, only support eager mode
        """
        batch_size, sequence_length, h = x.shape
        x = x.view(-1, h)

        expanded_x, expanded_row_idx, tokens_per_expert, pertoken_scale = torch_npu.npu_moe_init_routing_v2(
            x,
            expert_idx=topk_ids,
            active_num=topk_ids.shape[0] * topk_ids.shape[1],
            scale=self.experts.smooth_scale_1 if "a8" in self.gmm_quant_mode else None,
            expert_num=self.num_experts,
            expert_tokens_num_type=1,  # 0: cumsum mode(not supported now); 1: count mode
            expert_tokens_num_flag=True, active_expert_range=[0, self.num_experts],
            quant_mode=1 if "a8" in self.gmm_quant_mode else -1
            # -1: non-quant; 1: dynamic quant; 0: static quant(not supported now)
        )

        tokens_per_expert_group, gathered_tokens, gathered_pertoken_scale, input_splits, output_splits =\
            self.dispatch_double_routing(tokens_per_expert, expanded_x, pertoken_scale)

        new_x = self.forward_expert(gathered_tokens, tokens_per_expert_group, gathered_pertoken_scale)

        gathered_tokens = self.forward_combine_double_routing(new_x, expanded_x, input_splits, output_splits)

        # finalize-routing
        hidden_states = torch_npu.npu_moe_finalize_routing(
            gathered_tokens, skip1=hidden_states_share, skip2=None, bias=None,
            scales=topk_weight.to(gathered_tokens.dtype),
            expanded_src_to_dst_row=expanded_row_idx,
            export_for_source_row=None, drop_pad_mode=2
        )

        return hidden_states.view(batch_size, -1, h)

    def moe_infer_dispatch_combine(self, x, topk_ids, topk_weight, hidden_states_share):
        """
        tp+ep mix strategy, for decode stage
        """
        batch_size, sequence_length, h = x.shape
        hidden_states = x.view(-1, h)
        self.set_mc2_kwargs()

        # moe dispatch
        dispatch_args = {
            "x": hidden_states,
            "expert_ids": topk_ids, # [n*topk]
            **self.dispatch_kwargs
        }
        output = torch_npu.npu_moe_distribute_dispatch_v2(**dispatch_args)
        expand_x, dynamic_scale, expand_idx, expert_token_num, ep_recv_counts, tp_recv_counts = output[:6]

        # compute experts
        gmm_args = {
            "x": expand_x,
            "expert_tokens": expert_token_num,
            "group_list_type": 1,
        }

        if "a8" in self.gmm_quant_mode:
            gmm_args.update({"pertoken_scale": dynamic_scale})

        hidden_states_ordered_by_experts = self.experts(**gmm_args)

        # is_prefill is always false in this branch
        use_aclgraph_event = self.enable_multi_streams and self.enable_aclgraph
        if use_aclgraph_event:
            tng.ops.npu_tagged_event_wait(moe_npu_events[1])

        # moe combine
        combine_args = {
            "expand_x": hidden_states_ordered_by_experts,
            "shared_expert_x": hidden_states_share,
            "expert_ids": topk_ids,
            "assist_info_for_combine": expand_idx,
            "expert_scales": topk_weight.to(torch.float32), # [n*topk]
            "ep_send_counts": ep_recv_counts,
            "tp_send_counts": tp_recv_counts,
            **self.combine_kwargs
        }
        hidden_states = torch_npu.npu_moe_distribute_combine_v2(**combine_args)

        hidden_states = hidden_states.view(batch_size, sequence_length, self.hidden_dim)
        return hidden_states


# Copied from transformers.models.llama.modeling_llama.LlamaAttention with Llama->DeepseekV3
class DeepseekIndexerAttention(nn.Module):
    def __init__(self, config: DeepseekV3Config, runner_settings: Dict, layer_idx: Optional[int] = None,
                 prefix: Optional[str] = "", **kwargs):
        super().__init__()
        self.config = config
        self.runner_settings = runner_settings
        self.mm_quant_mode = (
            config.quant_config.mm_quant_mode
            if config.quant_config is not None
            else "w16a16")
        self.batch_size = self.runner_settings.get("data_config").get("batch_size", 16)
        self.batch_size_per_rank = self.runner_settings.get("data_config").get("batch_size_per_rank", 1)
        self.attn_tp_size = self.runner_settings.get("parallel_config").get("attn_tp_size", 1)
        self.attn_dp_size = self.runner_settings.get("parallel_config").get("attn_dp_size", 1)
        self.oproj_tp_size = self.runner_settings.get("parallel_config").get("oproj_tp_size", 1)
        self.cp_size = self.runner_settings.get("parallel_config").get("cp_size", 1)
        self.moe_tp_size = self.runner_settings.get("parallel_config").get("moe_tp_size", 1)
        self.moe_ep_size = self.runner_settings.get("parallel_config").get("moe_ep_size", 1)
        self.layer_idx = layer_idx
        self.is_mtp = False
        if layer_idx == config.num_hidden_layers: # mtp model
            self.layer_idx = 0 # mtp model only has one layer of cache
            self.is_mtp = True
        if layer_idx is None:
            logger.warning_once(
                f"Instantiating {self.__class__.__name__} without passing `layer_idx` is not recommended and will "
                "to errors during the forward call, if caching is used. Please make sure to provide a `layer_idx` "
                "when creating this class."
            )

        self.attention_dropout = config.attention_dropout
        self.hidden_size = config.hidden_size
        self.num_heads = config.num_attention_heads
        self.num_heads_per_rank = self.num_heads // self.attn_tp_size
        self.num_key_value_heads_per_rank = 1
        self.rope_theta = config.rope_theta
        self.q_lora_rank = config.q_lora_rank
        self.qk_rope_head_dim = config.qk_rope_head_dim
        self.kv_lora_rank = config.kv_lora_rank
        self.v_head_dim = config.v_head_dim
        self.qk_nope_head_dim = config.qk_nope_head_dim
        self.q_head_dim = config.qk_nope_head_dim + config.qk_rope_head_dim  # 64

        self.is_causal = True
        self.hccl_comm_dict = kwargs.get("hccl_comm_dict", None)
        self.block_table = None
        self.prefill_block_table = None

        if self.q_lora_rank is None:
            self.q_proj = ColumnParallelLinear(self.hidden_size,
                                               self.num_heads * self.q_head_dim,
                                               bias=False,
                                               quant_config=config.quant_config,
                                               tp_size=self.attn_tp_size,
                                               tp_rank=dist.get_rank(self.hccl_comm_dict["attn_tp_group"])
                                               if self.attn_tp_size > 1 else 0,
                                               prefix=f"{prefix}.q_proj")
        else:
            self.q_a_proj = ReplicatedLinear(self.hidden_size,
                                             self.q_lora_rank,
                                             bias=False,
                                             quant_config=config.quant_config,
                                             prefix=f"{prefix}.q_a_proj")
            self.q_a_layernorm = DeepseekV3RMSNorm(config.q_lora_rank)
            self.q_b_proj = ColumnParallelLinear(config.q_lora_rank,
                                                 self.num_heads * self.q_head_dim,
                                                 bias=False,
                                                 quant_config=config.quant_config,
                                                 tp_size=self.attn_tp_size,
                                                 tp_rank=dist.get_rank(self.hccl_comm_dict["attn_tp_group"])
                                                 if self.attn_tp_size > 1 else 0,
                                                 prefix=f"{prefix}.q_b_proj")

        self.kv_a_proj_with_mqa = ReplicatedLinear(
                    self.hidden_size,
                    self.kv_lora_rank + self.qk_rope_head_dim,
                    bias=config.attention_bias,
                    quant_config=config.quant_config,
                    prefix=f"{prefix}.kv_a_proj_with_mqa")
        self.kv_a_layernorm = DeepseekV3RMSNorm(config.kv_lora_rank)

        self.kv_b_proj = ColumnParallelLinear(
            self.kv_lora_rank,
            self.num_heads * (self.qk_nope_head_dim + self.v_head_dim),
            bias=False,
            quant_config=config.quant_config,
            tp_size=self.attn_tp_size,
            tp_rank=dist.get_rank(self.hccl_comm_dict["attn_tp_group"]) if self.attn_tp_size > 1 else 0,
            prefix=f"{prefix}.kv_b_proj")

        kv_b_proj_weight = self.kv_b_proj.weight.T
        expected_shape = (
                self.kv_lora_rank,
                self.num_heads_per_rank * (self.qk_nope_head_dim + self.v_head_dim)
            )
        if kv_b_proj_weight.shape != expected_shape:
            raise RuntimeError(f"{kv_b_proj_weight.shape} != {expected_shape}")

        kv_b_proj_weight = kv_b_proj_weight.view(
            self.kv_lora_rank,
            self.num_heads_per_rank,
            self.qk_nope_head_dim + self.v_head_dim,
        )
        self.kv_b_proj_w_k_data, self.kv_b_proj_w_v_data = kv_b_proj_weight.split(
            [self.qk_nope_head_dim, self.v_head_dim], dim=-1)
        self.kv_b_proj_w_k_data = self.kv_b_proj_w_k_data.permute(1, 2, 0)
        self.kv_b_proj_w_v_data = self.kv_b_proj_w_v_data.transpose(0, 1)

        if self.oproj_tp_size == 1:
            self.o_proj = RowParallelLinear(self.num_heads * self.v_head_dim,
                                            config.hidden_size,
                                            tp_size=self.attn_tp_size,
                                            tp_rank=dist.get_rank(self.hccl_comm_dict["attn_tp_group"])
                                            if self.attn_tp_size > 1 else 0,
                                            bias=False,
                                            input_is_parallel=True,
                                            quant_config=config.quant_config,
                                            prefix=f"{prefix}.o_proj")
        else:
            self.o_proj = RowParallelLinear(self.num_heads * self.v_head_dim,
                                            config.hidden_size,
                                            tp_size=self.oproj_tp_size,
                                            tp_rank=dist.get_rank(self.hccl_comm_dict["oproj_tp_group"])
                                            if self.oproj_tp_size > 1 else 0,
                                            bias=False,
                                            input_is_parallel=True,
                                            quant_config=config.quant_config,
                                            prefix=f"{prefix}.o_proj")

        self.softmax_scale = self.q_head_dim ** (-0.5)
        if self.config.rope_scaling is not None:
            mscale_all_dim = self.config.rope_scaling.get("mscale_all_dim", 0)
            scaling_factor = self.config.rope_scaling["factor"]
            if mscale_all_dim:
                mscale = yarn_get_mscale(scaling_factor, mscale_all_dim)
                self.softmax_scale = self.softmax_scale * mscale * mscale

        max_length = self.runner_settings.get("model_config").get("pa_max_length", 2048)
        self.block_size = self.runner_settings.get("model_config").get("pa_block_size", 128)
        cache_len = max_length // self.block_size
        self.block_table = torch.arange(0, self.batch_size_per_rank * cache_len
                                        ).reshape(self.batch_size_per_rank, -1)
        self.block_table = self.block_table.to(dtype=torch.int32, device="npu")

        self.prefill_block_table = self.block_table
        prefill_mini_batch_size = runner_settings.get("model_config").get("prefill_mini_batch_size", 0)
        if prefill_mini_batch_size > 0:
            self.prefill_block_table = torch.arange(0, prefill_mini_batch_size * cache_len) \
                .reshape(prefill_mini_batch_size, -1).to(dtype=torch.int32, device="npu")

        self.enable_weight_nz = runner_settings.get("model_config").get("enable_weight_nz", True)

        self.indexer = Indexer(self.config, runner_settings, layer_idx, prefix=f"{prefix}.indexer", **kwargs)
        self.attn_func = self.apply_attention_fusion
        self.select_block_count = config.index_topk
        self.exe_mode = self.runner_settings.get("exe_mode", "eager")
        self.global_rank = kwargs.get("global_rank")
        self.enable_multi_streams = self.runner_settings.get("model_config").get("enable_multi_streams", False)
        self.kv_cache_quant_mode = config.quant_config.kv_cache_quant_mode \
            if config.quant_config is not None else "unquant"
        if self.kv_cache_quant_mode == "int8":
            self.ckv_a_alpha = torch.nn.Parameter(torch.ones(1, dtype=torch.float), requires_grad=False)
            # empty tensor input for kr_cache
            # Its shape can be specified arbitrarily, but one of its dimensions must be 0
            self.fake_kr_cache = torch.empty((1, 2, 1, 0), dtype=torch.bfloat16, device="npu")

        self.enable_offload = self.runner_settings.get("model_config").get("enable_offload", False)
        self.index_topk = self.config.index_topk
        self.last_dim = self.kv_lora_rank + self.qk_rope_head_dim * 2 + 4 * 4 \
            if self.kv_cache_quant_mode == "int8" else self.kv_lora_rank

    def mla_epilog(
        self,
        attn_output: torch.Tensor = None,
        absorb: bool = False
    ):
        if absorb:
            # input shape [N//attn_tp_size, T(bs*q_len), D]
            # output shape [T(bs*q_len), N//attn_tp_size, D]
            attn_output = torch.matmul(
                attn_output,
                self.kv_b_proj_w_v
            ).transpose(0, 1)
            # Note: Considering the fusion rules of TBMM, attn_output shape requires a 3-dim shape, and
            # with appropriate tensor stride for the later 'view' operation if oproj_tp_size > 1.
            # after reshape: [T(bs*q_len), 1, N//attn_tp_size*D]
            attn_output = attn_output.reshape(-1, 1, self.num_heads // self.attn_tp_size * self.v_head_dim)

        if self.oproj_tp_size > 1:
            # after view: (bs*q_len, oproj_tp_size, num_heads // oproj_tp_size * v_head_dim)
            attn_output = attn_output.view(-1, self.oproj_tp_size,
                                           self.num_heads // self.oproj_tp_size * self.v_head_dim)
            # after transpose: (oproj_tp_size, bs*q_len, num_heads // oproj_tp_size * v_head_dim)
            # after view: (oproj_tp_size * bs*q_len * num_heads // oproj_tp_size * v_head_dim)
            attn_output = attn_output.transpose(1, 0).contiguous().view(-1)
            all2all_output = torch.empty_like(attn_output)
            # after all2all: (oproj_tp_size * bs*q_len * num_heads // oproj_tp_size * v_head_dim)
            dist.all_to_all_single(all2all_output, attn_output,
                                   group=self.hccl_comm_dict.get("oproj_tp_group", None))
            # after view: (oproj_tp_size * bs*q_len, num_heads // oproj_tp_size * v_head_dim)
            attn_output = all2all_output.view(-1, self.num_heads // self.oproj_tp_size * self.v_head_dim)

        attn_output = self.o_proj(attn_output.reshape(attn_output.shape[0], -1))

        if self.oproj_tp_size > 1:
            reduce_scatter_output = torch.empty((attn_output.size()[0] // self.oproj_tp_size, attn_output.size()[1]),
                                                dtype=attn_output.dtype, device=attn_output.device)
            dist.reduce_scatter_tensor(reduce_scatter_output, attn_output,
                                       group=self.hccl_comm_dict.get("oproj_tp_group", None))
            attn_output = reduce_scatter_output

        if self.attn_tp_size > 1:
            dist.all_reduce(attn_output, group=self.hccl_comm_dict.get("attn_tp_group", None))

        return attn_output

    def forward(
        self,
        hidden_states: torch.Tensor,
        kv_len: torch.IntTensor = None,
        actual_seq_lengths_kv: torch.Tensor = None,
        actual_seq_lengths_q: torch.Tensor = None,
        cos_sin: torch.Tensor = None,
        position_ids: Optional[torch.LongTensor] = None,
        past_key_value: Optional[Cache] = None,
        past_key_values_indexer: Optional[Cache] = None,
        past_key_scales_indexer: Optional[Cache] = None,
        is_prefill: bool = True,
        output_attentions: bool = False,
        slot_mapping: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        offload_cache: Optional[OffloadCache] = None,
        **kwargs,
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor], Optional[Tuple[torch.Tensor]]]:
        '''
        Prefill stage:
            Attention calc needs to use [T(B*S), N, D] format
            hidden_states: [B, S, H] -> [1, T(B*S), H]
        Decode stage:
            Attention calc use [B, S, N, D] format
        '''
        batch_size, seq_len, _ = hidden_states.shape
        if is_prefill:
            hidden_states = hidden_states.flatten(0, 1).unsqueeze(0)
        input_kwargs = {
            "hidden_states": hidden_states,
            "cos_sin": cos_sin,
            "kv_len": kv_len,
            "position_ids": position_ids,
            "past_key_value": past_key_value,
            "past_key_values_indexer": past_key_values_indexer,
            "past_key_scales_indexer": past_key_scales_indexer,
            "actual_seq_lengths_kv": actual_seq_lengths_kv,
            "is_prefill": is_prefill,
            "slot_mapping": slot_mapping,
            "offload_cache": offload_cache,
            "prefill_extra_input_dict": prefill_extra_input_dict,
        }
        if self.cp_size > 1 and is_prefill:
            return self.forward_absorb_cp(**input_kwargs).view(batch_size, seq_len, -1)
        else:
            input_kwargs.update({"actual_seq_lengths_q": actual_seq_lengths_q})
            return self.forward_absorb(**input_kwargs).view(batch_size, seq_len, -1)

    def forward_absorb(
        self,
        hidden_states: torch.Tensor,
        kv_len: torch.IntTensor = None,
        actual_seq_lengths_kv: torch.Tensor = None,
        actual_seq_lengths_q: torch.Tensor = None,
        cos_sin: torch.Tensor = None,
        position_ids: Optional[torch.LongTensor] = None,
        past_key_value: Optional[Cache] = None,
        past_key_values_indexer: Optional[Cache] = None,
        past_key_scales_indexer: Optional[Cache] = None,
        is_prefill: bool = True,
        slot_mapping: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        offload_cache: Optional[OffloadCache] = None,
        **kwargs,
    ):
        # hidden_states Prefill:[1, B*S, H] Decode:[B, S, H]
        query_states, topk_indices = self.prepare_qkv(
            hidden_states=hidden_states,
            cos_sin=cos_sin,
            kv_len=kv_len,
            position_ids=position_ids,
            past_key_value=past_key_value,
            past_key_values_indexer=past_key_values_indexer,
            past_key_scales_indexer=past_key_scales_indexer,
            actual_seq_lengths_kv=actual_seq_lengths_kv,
            actual_seq_lengths_q=actual_seq_lengths_q,
            is_prefill=is_prefill,
            prefill_extra_input_dict=prefill_extra_input_dict,
            slot_mapping=slot_mapping,
            offload_cache=offload_cache
        )
        attn_output = self.attn_func(
            query_states=query_states,
            actual_seq_qlen=actual_seq_lengths_q,
            actual_seq_lengths_kv=actual_seq_lengths_kv,
            past_key_value=past_key_value,
            topk_indices=topk_indices,
            is_prefill=is_prefill,
            offload_cache=offload_cache
        )

        output = self.mla_epilog(attn_output, absorb=True)
        return output

    def forward_absorb_cp(
        self,
        hidden_states: torch.Tensor,
        kv_len: torch.IntTensor = None,
        actual_seq_lengths_kv: torch.Tensor = None,
        cos_sin: torch.Tensor = None,
        position_ids: Optional[torch.LongTensor] = None,
        past_key_value: Optional[Cache] = None,
        past_key_values_indexer: Optional[Cache] = None,
        past_key_scales_indexer: Optional[Cache] = None,
        is_prefill: bool = True,
        slot_mapping: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        offload_cache: Optional[OffloadCache] = None,
        **kwargs,
    ):
        # Prefill:[1, B*S, H] Decode:[B, S, H]
        query_states, topk_indices = self.prepare_qkv(
            hidden_states=hidden_states,
            cos_sin=cos_sin,
            kv_len=kv_len,
            position_ids=position_ids,
            past_key_value=past_key_value,
            past_key_values_indexer=past_key_values_indexer,
            past_key_scales_indexer=past_key_scales_indexer,
            actual_seq_lengths_kv=actual_seq_lengths_kv,
            is_prefill=is_prefill,
            prefill_extra_input_dict=prefill_extra_input_dict,
            slot_mapping=slot_mapping,
            offload_cache=offload_cache
        )
        # while enable cp, attention calc needs to split in half
        q_nope, q_rope = query_states
        bsz, seq_len, num_heads, _ = q_nope.shape
        q_nope_prev, q_nope_next = torch.split(q_nope.view(1, bsz * seq_len, num_heads, -1), bsz * seq_len // 2, dim=1)
        q_rope_prev, q_rope_next = torch.split(q_rope.view(1, bsz * seq_len, num_heads, -1), bsz * seq_len // 2, dim=1)
        topk_indices_prev, topk_indices_next = topk_indices
        query_states_prev = q_nope_prev, q_rope_prev
        query_states_next = q_nope_next, q_rope_next
        # query_states: [B,S,N,D], K: [B,S,1,D]
        attn_output_prev = self.attn_func(
            query_states=query_states_prev,
            actual_seq_qlen=prefill_extra_input_dict["actual_seq_q"],
            actual_seq_lengths_kv=prefill_extra_input_dict["kv_len_prev"],
            past_key_value=past_key_value,
            topk_indices=topk_indices_prev,
            is_prefill=is_prefill,
            offload_cache=offload_cache
        )
        attn_output_next = self.attn_func(
            query_states=query_states_next,
            actual_seq_qlen=prefill_extra_input_dict["actual_seq_q"],
            actual_seq_lengths_kv=prefill_extra_input_dict["kv_len_next"],
            past_key_value=past_key_value,
            topk_indices=topk_indices_next,
            is_prefill=is_prefill,
            offload_cache=offload_cache
        )
        attn_output = torch.cat([attn_output_prev, attn_output_next], dim=1)  # [T,N,D]

        output = self.mla_epilog(attn_output, absorb=True)
        return output

    def mlaprolog_prefill(
        self,
        hidden_states: torch.Tensor,
        cos_sin: torch.Tensor = None,
        past_key_value: Optional[Cache] = None,
        slot_mapping: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        c8_input_dict: Optional[Dict] = None,
        offload_cache: Optional[OffloadCache] = None,
    ):
        bsz, q_len, _ = hidden_states.size()
        mla_prolog_slot_mapping = slot_mapping
        if self.cp_size > 1:
            nope_cache = prefill_extra_input_dict['cp_tmp_kv_cache_nope']
            rope_cache = prefill_extra_input_dict['cp_tmp_kv_cache_rope']
            mla_prolog_slot_mapping = prefill_extra_input_dict['mla_prolog_slot_mapping']
            _, _, cos, sin = cos_sin
        else:
            nope_cache = past_key_value[self.layer_idx][0]
            rope_cache = past_key_value[self.layer_idx][1]
            if self.enable_offload:
                nope_cache = offload_cache.temp_kv_cache[0]
                rope_cache = offload_cache.temp_kv_cache[1]

            cos, sin = cos_sin

        cos = cos.view(-1, 1, 1, self.qk_rope_head_dim)
        sin = sin.view(-1, 1, 1, self.qk_rope_head_dim)

        dequant_scale_w_uq_qr = self.q_b_proj.weight_scale.view(1, -1) if \
                                self.config.quant_config is not None else None
        # when weight_quant_mode = 0, no quant applied, when 1 only qb quantization is enabled
        weight_quant_mode = 1 if self.config.quant_config is not None else 0
        mla_prolog_input_args = {
            "weight_dq": self.q_a_proj.weight,
            "weight_uq_qr": self.q_b_proj.weight,
            "weight_uk": self.kv_b_proj_w_k,
            "weight_dkv_kr": self.kv_a_proj_with_mqa.weight,
            "rmsnorm_gamma_cq": self.q_a_layernorm.weight,
            "rmsnorm_gamma_ckv": self.kv_a_layernorm.weight,
            "kv_cache": nope_cache,
            "kr_cache": rope_cache,
            "dequant_scale_w_uq_qr": dequant_scale_w_uq_qr,
            "rmsnorm_epsilon_cq": self.q_a_layernorm.variance_epsilon,
            "rmsnorm_epsilon_ckv": self.kv_a_layernorm.variance_epsilon,
            "query_norm_flag": True,
            "weight_quant_mode": weight_quant_mode
        }

        bsnd_bsz, bsnd_seq_len = nope_cache.shape[0], nope_cache.shape[1]
        if self.cp_size > 1:
            # when cp is enabled, mla_prolog_v3 update kv as BSND first
            # the real kvcache will be updated after kv allgather as PA_BSND
            cache_mode = "BSND"
            hidden_states = hidden_states.view(bsnd_bsz, bsnd_seq_len, -1)
            mla_prolog_input_args.update({
                "rope_sin": sin.view(bsnd_bsz, bsnd_seq_len, -1),
                "rope_cos": cos.view(bsnd_bsz, bsnd_seq_len, -1)
            })
        else:
            cache_mode = "PA_BSND"
            hidden_states = hidden_states.view(bsz * q_len, -1)
            mla_prolog_input_args.update({
                "cache_index": mla_prolog_slot_mapping.view(-1),
                "rope_sin": sin.squeeze(1).squeeze(1),
                "rope_cos": cos.squeeze(1).squeeze(1)
            })

        mla_prolog_input_args.update({
            "token_x": hidden_states,
            "cache_mode": cache_mode
        })

        # When kv_cache_c8 is enabled, nope_cache, rope_cache, and scales
        # are concatenated and passed via the k_nope input.
        # In this case, an empty tensor must be passed for the k_rope input.
        if self.kv_cache_quant_mode == "int8":
            mla_prolog_input_args.update({
                "kr_cache": self.fake_kr_cache,
                "kv_cache_quant_mode": 3,
                "query_quant_mode": 0,
                "ckvkr_repo_mode": 1,
                "quant_scale_repo_mode": 1,
                "tile_size": 128,
                "k_nope_clip_alpha": self.ckv_a_alpha
            })

        q_nope, q_pe, dequant_scale_q_nope, qr, dequant_q_norm = torch_npu.npu_mla_prolog_v3(
            **mla_prolog_input_args
        )

        if self.kv_cache_quant_mode == "int8":
            latent_cache = nope_cache.view(-1, nope_cache.shape[-1])
        else:
            latent_cache = torch.cat([
                nope_cache.view(-1, nope_cache.shape[-1]),
                rope_cache.view(-1, self.qk_rope_head_dim)], dim=-1)

        if self.cp_size > 1:
            # nope and rope is aligned by pa block, so need slice
            kv_all = latent_cache.new_empty([bsz * q_len * self.cp_size, latent_cache.shape[-1]])
            dist.all_gather_into_tensor(kv_all, latent_cache.view(bsz * q_len, -1), \
                                    group=self.hccl_comm_dict.get("cp_group", None))
            outputs_list = list(torch.split(kv_all, prefill_extra_input_dict["reverse_split_list"], dim=0))
            latent_cache = torch.cat(
                [outputs_list[i] for i in prefill_extra_input_dict["cp_reverse_index"]], dim=0
            ).view(bsz, -1, latent_cache.shape[-1])

            if self.enable_offload:
                nope_cache = offload_cache.temp_kv_cache[0]
                rope_cache = offload_cache.temp_kv_cache[1]
            else:
                nope_cache = past_key_value[self.layer_idx][0]
                rope_cache = past_key_value[self.layer_idx][1]

            indices = prefill_extra_input_dict["kv_scatter_update_indices"]
            if self.kv_cache_quant_mode == "int8":
                # The current implementation updates page attention to contiguous memory.
                torch_npu.scatter_update_(nope_cache.view(bsnd_bsz, -1, nope_cache.shape[-1]),
                                        indices,
                                        latent_cache.view(bsnd_bsz, -1, nope_cache.shape[-1]),
                                        axis=1)
            else:
                k_nope = latent_cache.view(-1, latent_cache.shape[-1])[:, : nope_cache.shape[-1]]
                k_pe = latent_cache.view(-1, latent_cache.shape[-1])[:, nope_cache.shape[-1]:]

                torch_npu.scatter_update_(nope_cache.view(bsnd_bsz, -1, self.kv_lora_rank),
                                      indices,
                                      k_nope.view(bsnd_bsz, -1, self.kv_lora_rank),
                                      axis=1)
                torch_npu.scatter_update_(rope_cache.view(bsnd_bsz, -1, self.qk_rope_head_dim),
                                      indices,
                                      k_pe.view(bsnd_bsz, -1, self.qk_rope_head_dim),
                                      axis=1)

        if weight_quant_mode == 1:
            c8_input_dict.update({'pertoken_scale': dequant_q_norm})

        return q_nope, q_pe, qr, nope_cache, rope_cache

    def mlaprolog_decode(
        self,
        hidden_states: torch.Tensor,
        cos_sin: torch.Tensor = None,
        past_key_value: Optional[Cache] = None,
        slot_mapping: Optional[torch.Tensor] = None,
        c8_input_dict: Optional[Dict] = None,
    ):
        bsz, q_len, _ = hidden_states.size()
        nope_cache = past_key_value[self.layer_idx][0]
        rope_cache = past_key_value[self.layer_idx][1]
        cos, sin = cos_sin
        cos = cos.view(-1, 1, 1, self.qk_rope_head_dim)
        sin = sin.view(-1, 1, 1, self.qk_rope_head_dim)
        hidden_states = hidden_states.view(bsz * q_len, -1)
        dequant_scale_w_uq_qr = self.q_b_proj.weight_scale.view(1, -1) if \
                                self.config.quant_config is not None else None
        # when weight_quant_mode = 0, no quant applied, when 1 only qb quantization is enabled
        weight_quant_mode = 1 if self.config.quant_config is not None else 0

        mla_prolog_input_args = {
            "token_x": hidden_states,
            "weight_dq": self.q_a_proj.weight,
            "weight_uq_qr": self.q_b_proj.weight,
            "weight_uk": self.kv_b_proj_w_k,
            "weight_dkv_kr": self.kv_a_proj_with_mqa.weight,
            "rmsnorm_gamma_cq": self.q_a_layernorm.weight,
            "rmsnorm_gamma_ckv": self.kv_a_layernorm.weight,
            "rope_sin": sin.squeeze(1).squeeze(1),
            "rope_cos": cos.squeeze(1).squeeze(1),
            "kv_cache": nope_cache,
            "kr_cache": rope_cache,
            "cache_index": slot_mapping.view(-1),
            "dequant_scale_w_uq_qr": dequant_scale_w_uq_qr,
            "rmsnorm_epsilon_cq": self.q_a_layernorm.variance_epsilon,
            "rmsnorm_epsilon_ckv": self.kv_a_layernorm.variance_epsilon,
            "cache_mode": "PA_BSND",
            "query_norm_flag": True,
            "weight_quant_mode": weight_quant_mode
        }

        if self.kv_cache_quant_mode == "int8":
            mla_prolog_input_args.update({
                "kr_cache": self.fake_kr_cache,
                "kv_cache_quant_mode": 3,
                "query_quant_mode": 0,
                "ckvkr_repo_mode": 1,
                "quant_scale_repo_mode": 1,
                "tile_size": 128,
                "k_nope_clip_alpha": self.ckv_a_alpha
            })

        q_nope, q_pe, dequant_scale_q_nope, qr, dequant_q_norm = torch_npu.npu_mla_prolog_v3(
            **mla_prolog_input_args
        )
        if weight_quant_mode == 1:
            c8_input_dict.update({'pertoken_scale': dequant_q_norm})
        return q_nope, q_pe, qr, nope_cache, rope_cache

    def prepare_qkv(
        self,
        hidden_states: torch.Tensor,
        cos_sin: torch.Tensor = None,
        kv_len: torch.IntTensor = None,
        position_ids: Optional[torch.LongTensor] = None,
        past_key_value: Optional[Cache] = None,
        past_key_values_indexer: Optional[Cache] = None,
        past_key_scales_indexer: Optional[Cache] = None,
        actual_seq_lengths_kv: Optional[torch.Tensor] = None,
        actual_seq_lengths_q: Optional[torch.Tensor] = None,
        is_prefill: bool = True,
        slot_mapping: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        offload_cache: Optional[OffloadCache] = None,
        **kwargs,
    ):
        bsz, seq, _ = hidden_states.shape

        c8_input_dict = {}
        if not is_prefill:
            q_nope, q_pe, qr, nope_cache, rope_cache = self.mlaprolog_decode(
                    hidden_states=hidden_states, cos_sin=cos_sin,
                    past_key_value=past_key_value, slot_mapping=slot_mapping,
                    c8_input_dict=c8_input_dict
                    )
        else:
            q_nope, q_pe, qr, nope_cache, rope_cache = self.mlaprolog_prefill(
                hidden_states=hidden_states, cos_sin=cos_sin,
                past_key_value=past_key_value, slot_mapping=slot_mapping,
                prefill_extra_input_dict=prefill_extra_input_dict, c8_input_dict=c8_input_dict,
                offload_cache=offload_cache
            )
            if self.enable_offload:
                offload_cache.d2h_event.record()
                with torch.npu.stream(offload_cache.d2h_stream):
                    offload_cache.d2h_event.wait()
                    # Prefill Stage, data is contiguous, use 'copy_' to offload
                    # all the cache of the current layer to the host memory.
                    nope_cache_dst = past_key_value[self.layer_idx][0].view(bsz, -1, 1, self.last_dim)
                    nope_cache_src = nope_cache.view(bsz, -1, 1, self.last_dim)
                    nope_cache_dst.copy_(nope_cache_src, non_blocking=True)
                    if not self.kv_cache_quant_mode == "int8":
                        rope_cache_dst = past_key_value[self.layer_idx][1].view(bsz, -1, 1, self.qk_rope_head_dim)
                        rope_cache_src = rope_cache.view(bsz, -1, 1, self.qk_rope_head_dim)
                        rope_cache_dst.copy_(rope_cache_src, non_blocking=True)
                    offload_cache.d2h_event.record()

        query_states = (q_nope.view(bsz, -1, self.num_heads_per_rank, self.kv_lora_rank), \
                    q_pe.view(bsz, -1, self.num_heads_per_rank, self.qk_rope_head_dim))  # 1,B*S,N,D -> B,S,N,D
        block_table = self.prefill_block_table if is_prefill else self.block_table
        topk_indices = self.indexer(hidden_states, qr, actual_seq_lengths_kv, kv_len, cos_sin, position_ids, \
                                    query_states, \
                                    past_key_values_indexer, past_key_scales_indexer, \
                                    slot_mapping, block_table, \
                                    actual_seq_lengths_q, prefill_extra_input_dict, c8_input_dict,
                                    is_prefill)

        return query_states, topk_indices

    def apply_attention_fusion(
        self,
        query_states, topk_indices,
        actual_seq_qlen: torch.Tensor = None,
        actual_seq_lengths_kv: torch.Tensor = None,
        past_key_value: Optional[Cache] = None,
        is_prefill: bool = True,
        offload_cache: Optional[OffloadCache] = None,
    ):
        # repeat k/v heads if n_kv_heads < n_heads
        q_nope, q_pe = query_states

        if self.enable_offload and is_prefill:
            k_nope = offload_cache.temp_kv_cache[0]
            k_pe = offload_cache.temp_kv_cache[1]
        else:
            k_nope = past_key_value[self.layer_idx][0]
            k_pe = past_key_value[self.layer_idx][1]

        bsz, q_len, num_heads, _ = q_nope.shape  # B,S,N,D

        q_nope = q_nope.contiguous().view(bsz * q_len, num_heads, -1) # B,S,N,D -> B*S,N,D
        q_pe = q_pe.contiguous().view(bsz * q_len, num_heads, -1) # B,S,N,D -> B*S,N,D
        block_table = self.prefill_block_table if is_prefill else self.block_table

        if self.enable_offload and not is_prefill:
            selection_k_rope = offload_cache.selected_key_values[self.layer_idx][1]
            selection_kv_cache = offload_cache.selected_key_values[self.layer_idx][0]
            full_kv_cache = k_nope.squeeze(2)
            full_k_rope = k_pe.squeeze(2) if not self.kv_cache_quant_mode == "int8" else offload_cache.empty_rope

            selection_kv_block_table = offload_cache.selection_kv_block_table[self.layer_idx]
            selection_kv_block_status = offload_cache.selection_kv_block_status[self.layer_idx]

            topk_indices = topk_indices.view(bsz, -1, 1, self.index_topk)
            selection_kv_actual_seq = torch.ops.umdk_cam_op_lib.gather_selection_kv_cache(
                selection_k_rope, selection_kv_cache,
                selection_kv_block_table, selection_kv_block_status,
                topk_indices, full_k_rope, full_kv_cache,
                block_table, actual_seq_lengths_kv,
                actual_seq_qlen, selection_topk_block_size=1)

            default_topk_indices = offload_cache.default_topk_indices
            sparse_indices = torch.where(default_topk_indices < selection_kv_actual_seq.unsqueeze(1), \
                                         default_topk_indices, -1)

            slc_fa_input_kwargs = {
                "query": q_nope,
                "sparse_indices": sparse_indices.view(-1, 1, self.index_topk), # [bsz*seq, 1, topk]
                "scale_value": self.softmax_scale,
                "actual_seq_lengths_query": torch.arange(1, bsz * q_len + 1, dtype=torch.int32, device="npu"),
                "actual_seq_lengths_kv": selection_kv_actual_seq, # [bsz*seq]
                "block_table": selection_kv_block_table,
                "sparse_block_size": 1,
                "layout_query": 'TND',
                "layout_kv": 'PA_BSND',
                "sparse_mode": 3,
                "attention_mode": 2
            }

            slc_fa_input_kwargs.update({
                "key": selection_kv_cache.unsqueeze(2),
                "value": selection_kv_cache.unsqueeze(2),
            })
            if not self.kv_cache_quant_mode == "int8":
                k_pe = selection_k_rope.unsqueeze(2)

        else:
            slc_fa_input_kwargs = {
                "query": q_nope,
                "key": k_nope,
                "value": k_nope,
                "sparse_indices": topk_indices,
                "scale_value": self.softmax_scale,
                "actual_seq_lengths_query": actual_seq_qlen.to(torch.int32),
                "actual_seq_lengths_kv": actual_seq_lengths_kv.to(torch.int32),
                "block_table": block_table,
                "sparse_block_size": 1,
                "layout_query": 'TND',  # default is BSND
                "layout_kv": 'PA_BSND',
                "sparse_mode": 3,
                "attention_mode": 2
            }

        if self.kv_cache_quant_mode == "int8":
            q = torch.cat([q_nope, q_pe], dim=-1).contiguous()
            slc_fa_input_kwargs.update({
                "query": q,
                "key_quant_mode": 2,
                "value_quant_mode": 2,
                "quant_scale_repo_mode": 1,
                "tile_size": 128,
                "rope_head_dim": 64,
                "key_dequant_scale": None,
                "value_dequant_scale": None
            })

            slc_fa_fusion = torch_npu.npu_kv_quant_sparse_flash_attention(**slc_fa_input_kwargs)

        else:
            slc_fa_input_kwargs.update({
                "query_rope": q_pe,
                "key_rope": k_pe,
            })
            slc_fa_fusion, _, _ = torch_npu.npu_sparse_flash_attention(**slc_fa_input_kwargs)

        slc_fa_fusion = slc_fa_fusion.transpose(0, 1)
        return slc_fa_fusion


class DeepseekV3DecoderLayer(nn.Module):
    def __init__(self, config: DeepseekV3Config, runner_settings: Dict, layer_idx: int, prefix: str, **kwargs):
        super().__init__()
        self.layer_idx = layer_idx
        self.runner_settings = runner_settings
        self.hidden_size = config.hidden_size
        self.enable_offload = self.runner_settings.get("model_config").get("enable_offload", False)

        self.self_attn = DeepseekIndexerAttention(
            config=config,
            runner_settings=self.runner_settings,
            layer_idx=layer_idx,
            prefix=f"{prefix}.self_attn",
            **kwargs)

        self.is_moe = config.n_routed_experts is not None and \
                layer_idx >= config.first_k_dense_replace and \
                layer_idx % config.moe_layer_freq == 0

        self.mlp = (
            DeepseekV3MoE(config, self.runner_settings, layer_idx=layer_idx, prefix=f"{prefix}.mlp", **kwargs)
            if self.is_moe
            else DeepseekV3DenseMLP(config, self.runner_settings, prefix=f"{prefix}.mlp", **kwargs)
        )
        self.input_layernorm = DeepseekV3RMSNorm(
            config.hidden_size, eps=config.rms_norm_eps
        )
        self.post_attention_layernorm = DeepseekV3RMSNorm(
            config.hidden_size, eps=config.rms_norm_eps
        )

    def forward(
        self,
        hidden_states: torch.Tensor,
        kv_len: torch.IntTensor,
        actual_seq_lengths_kv: torch.Tensor,
        cos_sin: torch.Tensor,
        actual_seq_lengths_q: Optional[torch.Tensor] = None,
        past_residual: Optional[torch.Tensor] = None,
        position_ids: Optional[torch.LongTensor] = None,
        past_key_value: Optional[Tuple[torch.Tensor]] = None,
        past_key_values_indexer: Optional[Tuple[torch.Tensor]] = None,
        past_key_scales_indexer: Optional[Tuple[torch.Tensor]] = None,
        is_prefill: Optional[bool] = False,
        cur_topk_list: Optional[torch.Tensor] = None,
        slot_mapping: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        offload_cache: Optional[OffloadCache] = None,
        **kwargs,
    ) -> Tuple[torch.FloatTensor]:
        hidden_states, residual = self.input_layernorm(hidden_states, past_residual)

        # Self Attention
        hidden_states = self.self_attn(
            hidden_states=hidden_states,
            kv_len=kv_len,
            actual_seq_lengths_kv=actual_seq_lengths_kv,
            cos_sin=cos_sin,
            actual_seq_lengths_q=actual_seq_lengths_q,
            position_ids=position_ids,
            past_key_value=past_key_value,
            past_key_values_indexer=past_key_values_indexer,
            past_key_scales_indexer=past_key_scales_indexer,
            is_prefill=is_prefill,
            slot_mapping=slot_mapping,
            prefill_extra_input_dict=prefill_extra_input_dict,
            offload_cache=offload_cache
        )

        # Fully Connected
        hidden_states, residual = self.post_attention_layernorm(hidden_states, residual)
        if self.is_moe:
            hidden_states = self.mlp(hidden_states, is_prefill=is_prefill, cur_topk_list=cur_topk_list)
        else:
            hidden_states = self.mlp(hidden_states)

        if is_prefill and self.enable_offload:
            offload_cache.d2h_event.wait()

        outputs = (residual, hidden_states)
        return outputs


@add_start_docstrings(
    "The bare DeepseekV3 Model outputting raw hidden-states without any specific head on top.",
    DEEPSEEKV3_START_DOCSTRING,
)
class DeepseekV3Model(DeepseekV3PreTrainedModel):
    """
    Transformer decoder consisting of *config.num_hidden_layers* layers. Each layer is a [`DeepseekV3DecoderLayer`]

    Args:
        config: DeepseekV3Config
    """

    def __init__(self, config: DeepseekV3Config, runner_settings: Dict, prefix: str, **kwargs):
        super().__init__(config)
        self.config = config
        self.runner_settings = runner_settings
        self.embed_tp_size = self.runner_settings.get("parallel_config").get("embed_tp_size", 1)
        self.embed_dp_size = self.runner_settings.get("parallel_config").get("embed_dp_size", 1)
        self.attn_tp_size = self.runner_settings.get("parallel_config").get("attn_tp_size", 1)
        self.cp_size = self.runner_settings.get("parallel_config").get("cp_size", 1)
        self.moe_ep_size = self.runner_settings.get("parallel_config").get("moe_ep_size", 1)
        self.padding_idx = config.pad_token_id
        self.vocab_size = config.vocab_size
        self.vocab_size_per_rank = self.vocab_size // self.embed_tp_size
        self.global_rank = kwargs.get("global_rank")
        self.enable_superkernel = self.runner_settings.get("model_config").get("enable_superkernel", False)
        self.enable_multi_streams = runner_settings.get("model_config").get("enable_multi_streams", False)
        self.world_size = self.runner_settings.get("world_size", 16)

        self.pa_max_length = self.runner_settings.get("model_config").get("pa_max_length", 2048)
        self.hccl_comm_dict = kwargs.get("hccl_comm_dict", None)
        self.max_position_embeddings = self.runner_settings.get("data_config").get("max_position_embeddings", 2048)

        is_mtp = kwargs.get("is_mtp")
        if not is_mtp:
            self.embed_tokens = VocabParallelEmbedding(
                self.vocab_size,
                config.hidden_size,
                self.padding_idx,
                torch.bfloat16,
                tp_size=self.embed_tp_size,
                tp_rank=dist.get_rank(self.hccl_comm_dict["embed_tp_group"]) if self.embed_tp_size > 1 else 0)
        else:
            self.embed_tokens = None

        self.layers = nn.ModuleList(
            [
                DeepseekV3DecoderLayer(
                    config,
                    self.runner_settings,
                    layer_idx,
                    prefix=f"model.layers.{layer_idx}",
                    **kwargs)
                for layer_idx in range(config.num_hidden_layers)
            ]
        )
        self._use_flash_attention_2 = config._attn_implementation == "flash_attention_2"
        self.norm = DeepseekV3RMSNorm(config.hidden_size, eps=config.rms_norm_eps)

        self.gradient_checkpointing = False
        # Initialize weights and apply final processing
        self.post_init()
        _init_rope(self)

    def get_input_embeddings(self):
        return self.embed_tokens

    def set_input_embeddings(self, value):
        self.embed_tokens = value

    def prepare_inputs_for_layer(self, inputs_embeds, input_ids):
        batch_size, seq_length = input_ids.shape

        step = batch_size * seq_length // self.attn_tp_size
        tp_rank = dist.get_rank(group=self.hccl_comm_dict.get("attn_tp_group", None)) % self.attn_tp_size
        end = step * (tp_rank + 1)

        inputs_embeds = inputs_embeds.view(batch_size * seq_length, self.config.hidden_size)
        hidden_states = inputs_embeds[step * tp_rank: end]

        # batch_size * seq_length: SP
        hidden_states = hidden_states.view(-1, step, self.config.hidden_size)

        return hidden_states

    def calc_input_embeddings(self, input_ids, is_prefill):
        batch_size, seq_length = input_ids.shape
        cp_size = self.cp_size if is_prefill else 1
        attn_dp_size = self.world_size // self.attn_tp_size // cp_size
        if self.embed_tp_size > 1:
            embed_tp_group = self.hccl_comm_dict.get("embed_tp_group", None)
            if attn_dp_size > self.embed_dp_size:
                allgather_ratio = self.embed_tp_size // self.attn_tp_size
                if input_ids.ndim == 1:
                    all_input_ids = input_ids.new_empty(seq_length * allgather_ratio)
                else:
                    all_input_ids = input_ids.new_empty(batch_size * allgather_ratio, seq_length)
                dist.all_gather_into_tensor(all_input_ids, input_ids, group=embed_tp_group)
                input_ids = all_input_ids

            new_input_ids = input_ids - (self.global_rank % self.embed_tp_size) * self.vocab_size_per_rank
            mask = (new_input_ids >= 0) & (new_input_ids < self.vocab_size_per_rank) # (bs, qlen)
            new_input_ids_per_rank = new_input_ids * mask
            inputs_embeds = self.embed_tokens(new_input_ids_per_rank) * mask.unsqueeze(-1)

            if attn_dp_size <= self.embed_dp_size:
                dist.all_reduce(inputs_embeds, group=embed_tp_group)
            else:
                if input_ids.ndim == 1:
                    inputs_embeds_attn = inputs_embeds.new_empty(seq_length, inputs_embeds.shape[-1])
                else:
                    inputs_embeds_attn = inputs_embeds.new_empty(batch_size, seq_length, inputs_embeds.shape[-1])
                dist.reduce_scatter_tensor(inputs_embeds_attn, inputs_embeds, group=embed_tp_group)
                inputs_embeds = inputs_embeds_attn
        else:
            inputs_embeds = self.embed_tokens(input_ids)
        hidden_states = inputs_embeds

        return hidden_states

    @add_start_docstrings_to_model_forward(DEEPSEEKV3_INPUTS_DOCSTRING)
    def forward(
        self,
        input_ids: torch.LongTensor,
        kv_len: torch.IntTensor = None,
        actual_seq_lengths_kv: list = None,
        actual_seq_lengths_q: Optional[torch.Tensor] = None,
        position_ids: Optional[torch.LongTensor] = None,
        past_key_values: Optional[List[torch.FloatTensor]] = None,
        past_key_values_indexer: Optional[List[torch.FloatTensor]] = None,
        past_key_scales_indexer: Optional[List[torch.FloatTensor]] = None,
        is_prefill: Optional[bool] = False,
        cur_topk_list: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        slot_mapping: Optional[torch.Tensor] = None,
        offload_cache: Optional[OffloadCache] = None,
    ):
        batch_size, seq_length = input_ids.shape

        inputs_embeds = self.calc_input_embeddings(input_ids, is_prefill)
        hidden_states = inputs_embeds

        cos_sin = self.rotary_emb(hidden_states, position_ids, kv_len, self.max_position_embeddings)

        if is_prefill and self.cp_size > 1:
            hidden_states_list = list(
                torch.split(hidden_states.flatten(0, 1), prefill_extra_input_dict["split_list"], dim=0))
            position_id_list = list(
                torch.split(position_ids.flatten(0, 1), prefill_extra_input_dict["split_list"], dim=-1))
            hidden_states = torch.cat(
                [hidden_states_list[i] for i in prefill_extra_input_dict["zigzag_index"]], dim=0
            ).view(batch_size, -1, hidden_states.shape[-1])
            position_ids_cur = torch.cat(
                [position_id_list[i] for i in prefill_extra_input_dict["zigzag_index"]], dim=-1
            ).view(batch_size, -1)
            cos_sin += self.rotary_emb(hidden_states, position_ids_cur, kv_len, self.max_position_embeddings)
        if is_prefill and self.attn_tp_size > 1 and self.moe_ep_size > 1:
            hidden_states = self.prepare_inputs_for_layer(inputs_embeds, input_ids)
        residual = None

        label = f'decode_layer'
        if self.enable_multi_streams:
            option = "stream-fusion=1"
        else:
            option = "option_xxx2"
        with superkernel_scope(self.enable_superkernel and not is_prefill, label, option):
            for decoder_layer in self.layers:
                residual, hidden_states = decoder_layer(
                    hidden_states,
                    kv_len,
                    actual_seq_lengths_kv,
                    cos_sin=cos_sin,
                    actual_seq_lengths_q=actual_seq_lengths_q,
                    past_residual=residual,
                    position_ids=position_ids,
                    past_key_value=past_key_values,
                    past_key_values_indexer=past_key_values_indexer,
                    past_key_scales_indexer=past_key_scales_indexer,
                    is_prefill=is_prefill,
                    cur_topk_list=cur_topk_list,
                    slot_mapping=slot_mapping,
                    prefill_extra_input_dict=prefill_extra_input_dict,
                    offload_cache=offload_cache
                )

        hidden_states, _ = self.norm(hidden_states, residual)

        return hidden_states


class DeepseekV3ModelMTPLayer(DeepseekV3Model):
    def __init__(self, config: DeepseekV3Config, runner_settings: Dict, layer_idx: int, prefix: str, **kwargs):
        super().__init__(config, runner_settings, prefix=prefix, **kwargs)
        self.mtp_start_layer_idx = config.num_hidden_layers
        self.layers = nn.ModuleDict(
            {
                str(self.mtp_start_layer_idx + i):
                DeepseekV3DecoderLayer(
                    config,
                    runner_settings,
                    layer_idx,
                    prefix=f"model.layers.{self.mtp_start_layer_idx + i}",
                    **kwargs)
                for i in range(config.num_nextn_predict_layers)
        })

    def forward(
        self,
        hidden_states: torch.Tensor,
        kv_len: torch.IntTensor,
        actual_seq_lengths_kv: list,
        cos_sin: torch.Tensor,
        actual_seq_lengths_q: Optional[torch.Tensor] = None,
        past_residual: Optional[torch.Tensor] = None,
        position_ids: Optional[torch.LongTensor] = None,
        past_key_value: Optional[Tuple[torch.Tensor]] = None,
        past_key_values_indexer: Optional[List[torch.Tensor]] = None,
        past_key_scales_indexer: Optional[List[torch.Tensor]] = None,
        is_prefill: Optional[bool] = False,
        cur_topk_list: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        slot_mapping: Optional[torch.Tensor] = None,
        mtp_layer_idx: Optional[int] = 0,
        offload_cache: Optional[OffloadCache] = None,
        **kwargs,
    ) -> torch.Tensor:
        return self.layers[str(self.mtp_start_layer_idx + mtp_layer_idx)](
            hidden_states,
            kv_len,
            actual_seq_lengths_kv,
            cos_sin=cos_sin,
            actual_seq_lengths_q=actual_seq_lengths_q,
            past_residual=past_residual,
            position_ids=position_ids,
            past_key_value=past_key_value,
            past_key_values_indexer=past_key_values_indexer,
            past_key_scales_indexer=past_key_scales_indexer,
            is_prefill=is_prefill,
            cur_topk_list=cur_topk_list,
            prefill_extra_input_dict=prefill_extra_input_dict,
            slot_mapping=slot_mapping,
            offload_cache=offload_cache
        )


class DeepseekV3ForCausalLM(DeepseekV3PreTrainedModel):
    _tied_weights_keys = ["lm_head.weight"]

    def __init__(self, config, runner_settings, is_mtp=False, prefix: str = ""):
        super().__init__(config)
        self.config = config
        self.runner_settings = runner_settings
        self.input_max_len = self.runner_settings.get("data_config").get("input_max_len", 32)
        self.get_parallel_settings()
        self.experts_per_rank = config.n_routed_experts // self.moe_ep_size
        self.top_k = config.num_experts_per_tok
        self.max_position_embeddings = self.runner_settings.get("data_config").get("max_position_embeddings", 2048)
        self.perfect_eplb = self.runner_settings.get("model_config").get("perfect_eplb", False)
        self.next_n = self.runner_settings.get("model_config").get("next_n", 0)
        self.is_mtp = is_mtp
        self.enable_cache_compile = self.runner_settings.get("model_config").get("enable_cache_compile", False)
        self.kv_cache_quant_mode = config.quant_config.kv_cache_quant_mode \
            if config.quant_config is not None else "unquant"
        self.enable_static_kernel = self.runner_settings.get("model_config").get("enable_static_kernel", False)
        self.enable_aclgraph = runner_settings.get("exe_mode", "ge_graph") == "acl_graph"

        self.local_rank = int(os.getenv("LOCAL_RANK", "0"))
        self.rank_offset = int(os.getenv("RANK_OFFSET", "0"))
        self.global_rank = self.local_rank + self.rank_offset
        self.world_size = self.runner_settings.get("world_size", 16)
        kwargs = {
                    "global_rank": self.global_rank,
                    "is_mtp": is_mtp
                }
        default_pg = get_default_group()
        if default_pg is not None:
            if dist.get_world_size() > 1:
                self.hccl_comm_dict = self.init_parallel_comm_group()
                kwargs.update({"hccl_comm_dict": self.hccl_comm_dict})
        self.batch_size_per_rank = self.runner_settings.get("data_config").get("batch_size_per_rank", 1)
        self.pa_max_length = self.runner_settings.get("model_config").get("pa_max_length", 2048)
        self.block_size = self.runner_settings.get("model_config").get("pa_block_size", 128)
        self.cache_len = self.pa_max_length // self.block_size
        self.kv_cache_num_block = self.cache_len * self.batch_size_per_rank
        self.kv_len_offset = torch.arange(0, self.batch_size_per_rank * self.pa_max_length,
                        self.pa_max_length, dtype=torch.int64, device="npu").view(-1, 1)

        mtp_layer_idx = config.num_hidden_layers # MTP is the last layer
        self.model = DeepseekV3ModelMTPLayer(config, self.runner_settings, mtp_layer_idx, prefix, **kwargs) \
                    if is_mtp else DeepseekV3Model(config, self.runner_settings, prefix, **kwargs)
        self.vocab_size = config.vocab_size
        if not is_mtp:
            self.lm_head = ColumnParallelLinear(
                input_size=config.hidden_size,
                output_size=config.vocab_size,
                bias=False,
                tp_size=self.lmhead_tp_size,
                tp_rank=dist.get_rank(self.hccl_comm_dict.get("lmhead_tp_group")) if self.lmhead_tp_size > 1 else 0,
                quant_config=None,
                prefix="lm_head"
                )
        else:
            self.lm_head = None

        # Initialize weights and apply final processing
        self.post_init()

        if self.enable_cache_compile:
            self.cached_decode = self.get_cached_graph()
        self.enable_prefill_multi_cycle = self.runner_settings.get("model_config").get("prefill_mini_batch_size", 0) > 0
        self.enable_offload = self.runner_settings.get("model_config").get("enable_offload", False)

    @staticmethod
    def _reorder_cache(past_key_values, beam_idx):
        reordered_past = ()
        for layer_past in past_key_values:
            reordered_past += (
                tuple(
                    past_state.index_select(0, beam_idx.to(past_state.device))
                    for past_state in layer_past
                ),
            )
        return reordered_past

    @staticmethod
    def _repeat_batch(tensor, repeat_num):
        if repeat_num == 1:
            return tensor
        return tensor.repeat(repeat_num, *[1] * (tensor.dim() - 1))

    def get_input_embeddings(self):
        return self.model.embed_tokens

    def set_input_embeddings(self, value):
        self.model.embed_tokens = value

    def get_output_embeddings(self):
        return self.lm_head

    def set_output_embeddings(self, new_embeddings):
        self.lm_head = new_embeddings

    def set_decoder(self, decoder):
        self.model = decoder

    def get_decoder(self):
        return self.model

    def get_parallel_settings(self):
        self.embed_tp_size = self.runner_settings.get("parallel_config").get("embed_tp_size", 1)
        self.attn_dp_size = self.runner_settings.get("parallel_config").get("attn_dp_size", 1)
        self.attn_tp_size = self.runner_settings.get("parallel_config").get("attn_tp_size", 1)
        self.oproj_tp_size = self.runner_settings.get("parallel_config").get("oproj_tp_size", 1)
        self.cp_size = self.runner_settings.get("parallel_config").get("cp_size", 1)
        self.moe_ep_size = self.runner_settings.get("parallel_config").get("moe_ep_size", 1)
        self.moe_tp_size = self.runner_settings.get("parallel_config").get("moe_tp_size", 1)
        self.lmhead_tp_size = self.runner_settings.get("parallel_config").get("lmhead_tp_size", self.embed_tp_size)
        self.moe_dp_size = self.runner_settings.get("parallel_config").get("moe_dp_size", 1)
        self.embed_dp_size = self.runner_settings.get("parallel_config").get("embed_dp_size", 1)
        self.dense_tp_size = self.runner_settings.get("parallel_config").get("dense_tp_size", 1)

    def get_cached_graph(self):
        tng.patch_for_hcom()
        tng_config = tng.CompilerConfig()
        tng_config.experimental_config.frozen_parameter = True
        tng_config.experimental_config.tiling_schedule_optimize = True
        tng_config.experimental_config.topology_sorting_strategy = "StableRDFS"
        case_name = "compile_cache/" + os.getenv("CASE_NAME")
        cache_model = self.main_decode
        if self.is_mtp:
            cache_model = self.main_decode_mtp
            case_name += "_spec"
        cache_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), case_name)
        if self.enable_aclgraph:
            tng_config.mode = "reduce-overhead"
            if self.enable_static_kernel:
                tng_config.experimental_config.aclgraph._aclnn_static_shape_kernel = True

        cached_decode = tng.inference.cache_compile(cache_model, cache_dir=cache_dir, config=tng_config,
                                                    dynamic=False, fullgraph=True, ge_cache=not self.enable_aclgraph)
        return cached_decode

    def init_parallel_comm_group(self):
        world_size = dist.get_world_size()
        global_rank = dist.get_rank()

        attn_tp_group = init_comm_group(
            global_rank=global_rank, group_num=self.attn_dp_size, world_size=world_size,
            group_stride=1, group_name="attn_tp_group")

        oproj_tp_group = init_comm_group(
            global_rank=global_rank, group_num=world_size // self.oproj_tp_size, world_size=world_size,
            group_stride=1, group_name="oproj_tp_group")

        if self.embed_tp_size == self.attn_tp_size:
            embed_tp_group = attn_tp_group
        else:
            embed_tp_group = init_comm_group(
                global_rank=global_rank, group_num=self.embed_dp_size, world_size=world_size,
                group_stride=1, group_name="embed_tp_group")

        if self.lmhead_tp_size == self.embed_tp_size:
            lmhead_tp_group = embed_tp_group
        else:
            lmhead_tp_group = init_comm_group(
                global_rank=global_rank, group_num=world_size // self.lmhead_tp_size, world_size=world_size,
                group_stride=1, group_name="lmhead_tp_group")

        if self.dense_tp_size == self.attn_tp_size:
            dense_tp_group = attn_tp_group
        else:
            dense_tp_group = init_comm_group(
                global_rank=global_rank, group_num=world_size // self.dense_tp_size, world_size=world_size,
                group_stride=1, group_name="dense_tp_group")

        if self.moe_tp_size == self.attn_tp_size:
            moe_tp_group = attn_tp_group
        else:
            moe_tp_group = init_comm_group(
                global_rank=global_rank, group_num=self.moe_dp_size, world_size=world_size,
                group_stride=1, group_name="moe_tp_group")

        hccl_buffer_size = calc_moe_hccl_buffer_size(self.runner_settings, self.config)
        moe_ep_group, moe_ep_group_name = init_comm_group(
            global_rank=global_rank, group_num=self.moe_tp_size, world_size=world_size,
            group_stride=self.moe_tp_size, group_name="moe_ep_group", return_name=True,
            hccl_buffer_size=hccl_buffer_size)

        hccl_buffer_size_mc2 = calc_moe_hccl_buffer_size(self.runner_settings, self.config, is_full_mesh_v2=True)
        moe_ep_group_mc2, moe_ep_group_mc2_name = init_comm_group(
            global_rank=global_rank, group_num=self.moe_tp_size, world_size=world_size,
            group_stride=self.moe_tp_size, group_name="moe_ep_group_mc2", return_name=True,
            hccl_buffer_size=hccl_buffer_size_mc2)

        cp_group = init_comm_group(
            global_rank=global_rank, group_num=world_size // self.cp_size, world_size=world_size,
            group_stride=1, group_name="cp_group")

        hccl_comm_dict = {
                "default_pg": get_default_group(),
                "attn_tp_group": attn_tp_group, "embed_tp_group": embed_tp_group,
                "moe_tp_group": moe_tp_group, "moe_ep_group": moe_ep_group,
                "moe_ep_group_name": moe_ep_group_name,
                "moe_ep_group_mc2": moe_ep_group_mc2,
                "moe_ep_group_mc2_name": moe_ep_group_mc2_name,
                "lmhead_tp_group": lmhead_tp_group,
                "dense_tp_group": dense_tp_group,
                "oproj_tp_group": oproj_tp_group,
                "cp_group": cp_group
            }
        return hccl_comm_dict

    def forward_lm_head(self, outputs, kv_len, is_prefill=True, prefill_extra_input_dict=None):
        bs, q_len, hidden_size = outputs.shape
        if self.cp_size > 1 and is_prefill:
            outputs_all = outputs.new_empty([bs * q_len * self.cp_size, hidden_size])
            dist.all_gather_into_tensor(outputs_all, outputs.view(bs * q_len, -1), \
                                    group=self.hccl_comm_dict.get("cp_group", None))
            outputs_list = list(torch.split(outputs_all, prefill_extra_input_dict["reverse_split_list"], dim=0))
            outputs = torch.cat(
                [outputs_list[i] for i in prefill_extra_input_dict["cp_reverse_index"]], dim=0
            ).view(bs, -1, hidden_size)
        if is_prefill:
            # attention: SP + TP，moe：DP + EP
            if self.attn_tp_size > 1 and self.moe_ep_size > 1:
                new_outputs = torch.zeros_like(outputs).repeat(self.attn_tp_size, 1, 1)
                dist.all_gather_into_tensor(new_outputs, outputs,
                                            group=self.hccl_comm_dict.get("attn_tp_group", None))
                outputs = new_outputs
            gather_index = kv_len - 1
            gather_index = gather_index.unsqueeze(1).unsqueeze(2).repeat(1, 1, outputs.shape[-1])
            outputs = torch.gather(outputs, 1, gather_index)
            q_len = 1 # prefill takes th last token
        else: # combine bs and q_len axes for lm_head
            outputs = outputs.view(bs * q_len, 1, hidden_size)

        if (self.attn_dp_size == 1) or (self.lmhead_tp_size == 1):
            hidden_states = outputs
        else:
            # allgather: (bs / attn_dp, hidden_size) -> (bs, hidden_size)
            hidden_states = torch.zeros_like(outputs).repeat(self.lmhead_tp_size, 1, 1)
            dist.all_gather_into_tensor(hidden_states, outputs,
                                        group=self.hccl_comm_dict.get("lmhead_tp_group", None))

        logits = self.lm_head(hidden_states) # (lmhead_tp_size * bs / attn_dp, 1, vocab_size / lmhead_tp_size)
        if self.lmhead_tp_size > 1: # -> (bs / attn_dp, 1, vocab_size)
            if self.attn_dp_size == 1:
                new_logits = torch.zeros_like(logits).repeat(self.lmhead_tp_size, 1, 1)
                dist.all_gather_into_tensor(new_logits, logits,
                                            group=self.hccl_comm_dict.get("lmhead_tp_group", None))
            else:
                new_logits = torch.zeros_like(logits).view(-1)
                dist.all_to_all_single(new_logits, logits.view(-1), \
                        group=self.hccl_comm_dict.get("lmhead_tp_group", None))

            # transpose: (lmhead_tp_size * bs / attn_dp, vocab_size / lmhead_tp_size) -> (bs / attn_dp, vocab_size)
            new_logits = new_logits.reshape(
                self.lmhead_tp_size, bs * q_len, logits.shape[1], -1).permute(1, 2, 0, 3)
            logits = new_logits.reshape(bs * q_len, logits.shape[1], self.config.vocab_size)
        logits = logits.reshape(bs, q_len, -1).float()
        return logits

    def prepare_prefill_extra_input(
        self,
        input_ids: torch.Tensor,
        kv_len: torch.Tensor,
    ):
        # The prefill stage requires the construction of some unique input parameters,
        # due to the potential adoption of optimization techniques such as CP.
        batch_size, seq_len = input_ids.shape
        kv_len = torch.tensor([seq_len for _ in range(batch_size)], device=kv_len.device, dtype=kv_len.dtype)
        prefill_extra_input_dict = {}
        bs_per_cp_group = kv_len.shape[-1]

        if self.cp_size > 1:
            # get zigzag index
            cp_segment_num = self.cp_size * 2
            seq_per_batch = torch.ceil(kv_len / (cp_segment_num))   # seq_len for each batch and segment
            split_list = seq_per_batch.repeat_interleave(cp_segment_num).int().tolist()
            prefill_extra_input_dict.update({"split_list": split_list})
            zigzag_index = list(range(self.global_rank,
                                    self.global_rank + bs_per_cp_group * cp_segment_num,
                                    cp_segment_num)) + \
                list(range(cp_segment_num - self.global_rank - 1,
                        bs_per_cp_group * cp_segment_num,
                        cp_segment_num))
            prefill_extra_input_dict.update({"zigzag_index": zigzag_index})

            # get zigzag reverse index
            cp_reverse_index = []
            for batch_id in range(bs_per_cp_group):
                cp_reverse_index.extend(
                    list(range(batch_id, cp_segment_num * bs_per_cp_group, 2 * bs_per_cp_group)) +\
                    list(range((cp_segment_num - 1) * bs_per_cp_group + batch_id, 0, -2 * bs_per_cp_group))
                    )
            prefill_extra_input_dict.update({"cp_reverse_index": cp_reverse_index})
            reverse_split_list = seq_per_batch.repeat_interleave(2).repeat(self.cp_size).view(-1).int().tolist()
            prefill_extra_input_dict.update({"reverse_split_list": reverse_split_list})

            kv_len = torch.ceil(kv_len / (self.cp_size * 2)).to(torch.int64)
            kv_len_prev = kv_len * (self.global_rank + 1)
            prefill_extra_input_dict.update({"kv_len_prev": kv_len_prev})
            kv_len_next = kv_len * (self.cp_size * 2 - self.global_rank)
            prefill_extra_input_dict.update({"kv_len_next": kv_len_next, "actual_seq_q": kv_len.cumsum(dim=-1)})

            cache_last_dim = self.config.kv_lora_rank + self.config.qk_rope_head_dim * 2 + 16 \
                if self.kv_cache_quant_mode == "int8" else self.config.kv_lora_rank
            cp_tmp_kv_cache_nope_shape = (
                            batch_size,
                            seq_len // self.cp_size,
                            1,
                            cache_last_dim
                        )  # B,S,N,D

            cp_tmp_kv_cache_rope_shape = (
                            batch_size,
                            seq_len // self.cp_size,
                            1,
                            self.config.qk_rope_head_dim
                        )  # B,S,N,D
            dtype = torch.int8 if self.kv_cache_quant_mode == "int8" else self.config.torch_dtype
            cp_tmp_kv_cache_nope = torch.zeros(cp_tmp_kv_cache_nope_shape, dtype=dtype, device=input_ids.device)
            prefill_extra_input_dict.update({"cp_tmp_kv_cache_nope": cp_tmp_kv_cache_nope})
            if not self.kv_cache_quant_mode == "int8":
                cp_tmp_kv_cache_rope = torch.zeros(cp_tmp_kv_cache_rope_shape, dtype=dtype, device=input_ids.device)
            else:
                cp_tmp_kv_cache_rope = None
            prefill_extra_input_dict.update({"cp_tmp_kv_cache_rope": cp_tmp_kv_cache_rope})

        mla_prolog_slot_mapping = torch.arange(batch_size * seq_len // self.cp_size,
                                               dtype=kv_len.dtype, device=input_ids.device)
        prefill_extra_input_dict.update({"mla_prolog_slot_mapping": mla_prolog_slot_mapping})

        kv_scatter_update_indices = torch.zeros((batch_size,), dtype=torch.int64).npu()
        prefill_extra_input_dict.update({"kv_scatter_update_indices": kv_scatter_update_indices})

        return prefill_extra_input_dict

    def forward(
        self,
        input_ids: torch.LongTensor = None,
        kv_len: torch.IntTensor = None,
        actual_seq_lengths_kv: list = None,
        actual_seq_lengths_q: Optional[torch.Tensor] = None,
        position_ids: Optional[torch.LongTensor] = None,
        past_key_values: Optional[List[torch.FloatTensor]] = None,
        past_key_values_indexer: Optional[List[torch.FloatTensor]] = None,
        past_key_scales_indexer: Optional[List[torch.FloatTensor]] = None,
        is_prefill: Optional[bool] = False,
        cur_topk_list: Optional[torch.Tensor] = None,
        prev_hidden_states: Optional[torch.Tensor] = None,
        slot_mapping: Optional[torch.Tensor] = None,
        offload_cache: Optional[OffloadCache] = None,
        **kwargs
    ):
        prefill_extra_input_dict = self.prepare_prefill_extra_input(
            input_ids, kv_len
        ) if is_prefill else None
        # decoder outputs consists of (dec_features, layer_state, dec_hidden, dec_attn)
        outputs = self.model(
            input_ids=input_ids,
            kv_len=kv_len,
            actual_seq_lengths_kv=actual_seq_lengths_kv,
            actual_seq_lengths_q=actual_seq_lengths_q,
            position_ids=position_ids,
            past_key_values=past_key_values,
            past_key_values_indexer=past_key_values_indexer,
            past_key_scales_indexer=past_key_scales_indexer,
            is_prefill=is_prefill,
            cur_topk_list=cur_topk_list,
            prefill_extra_input_dict=prefill_extra_input_dict,
            slot_mapping=slot_mapping,
            offload_cache=offload_cache
        ) # (bs / attn_dp, S, hidden_size)

        prev_hidden_states = outputs

        logits = self.forward_lm_head(outputs, kv_len, is_prefill, prefill_extra_input_dict)
        return logits, prev_hidden_states

    def prefill(
        self,
        **kwargs
    ):
        logits, prev_hidden_states = self.forward(
            is_prefill=True,
            **kwargs
        )
        return logits, prev_hidden_states

    def main_decode(
        self,
        **kwargs
    ):
        logits, prev_hidden_states = self.forward(
            is_prefill=False,
            **kwargs
        )
        return logits, prev_hidden_states

    def main_decode_mtp(
        self,
        **kwargs
    ):
        logits, prev_hidden_states = self.forward(
            is_prefill=False,
            **kwargs
        )
        return logits, prev_hidden_states

    def decode(
        self,
        **kwargs
    ):
        if self.enable_cache_compile:
            logits = self.cached_decode(**kwargs)
        else:
            logits = self.main_decode(**kwargs)
        return logits

    def init_cache(
        self,
        device,
        num_hidden_layers=61,
    ):
        cache_seq_len = self.max_position_embeddings
        dtype = torch.int8 if self.kv_cache_quant_mode == "int8" else self.config.torch_dtype

        # When the kvcache INT8 quantization is enabled
        # nope_cache, rope_cache, and nope_scale need to be concatenated for SFA/MLAprolog kernel in INT8 dtype.
        # kv_lora_rank(INT8) + qk_rope_head_dim(BF16) * 2(->INT8) + kv_scale(FP32) * 4(->INT8)
        cache_last_dim = self.config.kv_lora_rank + self.config.qk_rope_head_dim * 2 + 4 * 4 \
            if self.kv_cache_quant_mode == "int8" else self.config.kv_lora_rank
        past_key_values = ()
        cache_nope_shape = (
                        self.kv_cache_num_block,
                        self.block_size,
                        1,
                        cache_last_dim
                    )

        cache_rope_shape = (
                        self.kv_cache_num_block,
                        self.block_size,
                        1,
                        self.config.qk_rope_head_dim
                    )

        for _ in range(num_hidden_layers):
            cache_nope = torch.zeros(cache_nope_shape, dtype=dtype, device=device)
            if self.kv_cache_quant_mode == "int8":
                past_key_values += ((cache_nope, None),)
            else:
                cache_rope = torch.zeros(cache_rope_shape, dtype=dtype, device=device)
                past_key_values += ((cache_nope, cache_rope),)

        return past_key_values

    def init_cache_for_indexer(
        self,
        device,
        num_hidden_layers=61,
    ):
        cache_seq_len = self.max_position_embeddings
        dtype = torch.int8 if self.kv_cache_quant_mode == "int8" else self.config.torch_dtype

        past_key_values = ()
        past_key_scales = () if self.kv_cache_quant_mode == "int8" else None
        cache_key_shape = (
                        self.kv_cache_num_block,
                        self.block_size,
                        1,
                        self.config.index_head_dim
                    )
        cache_key_scales_shape = (
                        self.kv_cache_num_block,
                        self.block_size,
                        1
                    )

        for _ in range(num_hidden_layers):
            key_cache = torch.zeros(cache_key_shape, dtype=dtype, device=device)
            past_key_values += ((key_cache, ),)
            if self.kv_cache_quant_mode == "int8":
                key_scales_cache = torch.zeros(cache_key_scales_shape, dtype=torch.float16, device=device)
                past_key_scales += ((key_scales_cache, ),)

        return past_key_values, past_key_scales

    def gen_cur_topk_idx(
        self,
        is_prefill,
        batch_size,
        seq_len
    ):
        if not self.perfect_eplb:
            return None
        # if use perfect_eplb
        global_rank = dist.get_rank()
        if is_prefill:
            tokens_per_rank_prefill = batch_size * seq_len // self.attn_tp_size \
            if self.moe_ep_size != 1 else batch_size * seq_len * self.attn_dp_size
            step_prefill = tokens_per_rank_prefill * self.top_k
            cur_topk_list_prefill = [
                (i + global_rank) % self.config.n_routed_experts for i in range(step_prefill)]
            cur_topk_list = torch.Tensor(cur_topk_list_prefill).int().view(tokens_per_rank_prefill, -1).npu()
        else:
            if self.moe_tp_size > 1:
                tokens_per_rank_decode = batch_size * self.top_k * seq_len
                cur_topk_list_decode = []
                for offset in range(self.moe_ep_size):
                    for i in range(offset * self.experts_per_rank, \
                                   offset * self.experts_per_rank + tokens_per_rank_decode):
                        cur_topk_list_decode.append(i)
                cur_topk_list = torch.Tensor(cur_topk_list_decode).int().view(batch_size * seq_len, -1).npu()
            else:
                expanded_tokens = batch_size * self.top_k * seq_len  # Total tokens to be allocated to experts
                step_gap = self.config.n_routed_experts // self.moe_ep_size # Number of experts per rank
                expanded_offset = expanded_tokens * global_rank + global_rank # Token count offset
                cur_topk_list_decode = []
                # Allocate experts using round-robin algorithm
                for idx in range(expanded_tokens):
                    col = (expanded_offset + idx) % self.moe_ep_size  # Column index
                    row = (expanded_offset + idx) // self.moe_ep_size % step_gap  # Row index
                    expert_idx = row + col * step_gap  # Final expert index
                    cur_topk_list_decode.append(expert_idx)
                cur_topk_list = torch.Tensor(cur_topk_list_decode).int().view(batch_size * seq_len, -1).npu()
        return cur_topk_list

    def get_slot_mapping(
        self,
        kv_len,
        is_prefill,
        device
    ):
        '''
        Prefill:
        Attention input format is [T(B*S), N, D], every index for kv_cache update needs to
        add offset which represents interval between adjacent batches.
        '''
        batch_size = kv_len.shape[0]
        if is_prefill:
            all_tensors = []
            offset = self.pa_max_length
            for i, seq_len in enumerate(kv_len):
                new_index = torch.arange(offset * i, seq_len.item() + offset * i,
                                        dtype=kv_len.dtype, device=device)
                all_tensors.append(new_index)
            return torch.cat(all_tensors)
        else:
            return kv_len.view(batch_size, -1) + self.kv_len_offset[:batch_size]

    def get_actual_seq_lengths(
        self,
        kv_len,
        seq_len=1,
        is_prefill=True
    ):
        if is_prefill:
            actual_seq_lengths_kv = kv_len
        else:
            if seq_len > 1:
                last_kv = torch.max(kv_len, axis=1)[0]
                actual_seq_lengths_kv = last_kv
            else:
                actual_seq_lengths_kv = kv_len
        actual_seq_lengths_kv = actual_seq_lengths_kv.to(torch.int32)
        return actual_seq_lengths_kv

    def prepare_inputs_for_generation(
        self,
        input_ids,
        past_key_values=None,
        past_key_values_indexer=None,
        past_key_scales_indexer=None,
        attention_mask=None,
        is_prefill=None,
        kv_len=None,
        prev_hidden_states=None,
        offload_cache=None,
        **kwargs
    ):
        # input shape: [B, S]
        batch_size, seq_len = input_ids.size()
        # use reshape to avoid stride change, which will cause recompile in mtp case
        input_ids = input_ids.contiguous().reshape(batch_size, seq_len)

        if is_prefill:
            position_ids = attention_mask.long().cumsum(-1) - 1
            position_ids.masked_fill_(attention_mask == 0, 1)
            # Obtain the actual length of the request
            kv_len = torch.max(position_ids, axis=1)[0] + 1
            kv_len_withpad = torch.tensor(
                [seq_len for _ in range(batch_size)], device=kv_len.device, dtype=kv_len.dtype)
            actual_seq_lengths_kv = self.get_actual_seq_lengths(kv_len_withpad)
        else:
            actual_seq_lengths_kv = self.get_actual_seq_lengths(kv_len, seq_len, is_prefill)
            position_ids = kv_len.view(-1, seq_len) - 1

        actual_seq_lengths_q = torch.tensor([seq_len + i * seq_len for i in range(batch_size)],
                                            dtype=torch.int32).npu()

        slot_mapping = self.get_slot_mapping(kv_len_withpad if is_prefill else position_ids.to(kv_len.dtype),
                                             is_prefill, input_ids.device)

        model_inputs = {
            "input_ids": input_ids.to(torch.int32),
            "position_ids": position_ids,
            "past_key_values": past_key_values,
            "past_key_values_indexer": past_key_values_indexer,
            "past_key_scales_indexer": past_key_scales_indexer,
            "kv_len": kv_len,
            "actual_seq_lengths_kv": actual_seq_lengths_kv,
            "actual_seq_lengths_q": actual_seq_lengths_q,
            "prev_hidden_states": prev_hidden_states,
            "slot_mapping": slot_mapping,
        }
        if self.enable_offload:
            model_inputs.update({"offload_cache": offload_cache})
        return model_inputs

    def load_weights(self, weights: Iterable[Tuple[str, torch.Tensor]]) -> Set[str]:
        stacked_params_mapping = [
            # (param_name, shard_name, shard_id)
            ("gate_up_proj", "gate_proj", 0),
            ("gate_up_proj", "up_proj", 1),
        ]

        repeat_loaded_weights_mapping = [] # (origin_name: repeat_loaded_name)

        # Params for weights, int8 weight scales
        # (param_name, weight_name, expert_id, shard_id)
        expert_params_mapping = FusedMoEGMM.make_expert_params_mapping(
            ckpt_gate_proj_name="gate_proj",
            ckpt_down_proj_name="down_proj",
            ckpt_up_proj_name="up_proj",
            num_experts=self.config.n_routed_experts)

        params_dict = dict(self.named_parameters())
        loaded_params: Set[str] = set()
        for name, loaded_weight in weights:
            if "rotary_emb.inv_freq" in name:
                continue

            if self.config.architectures[0] == 'DeepseekV3ForCausalLM' and self.config.num_nextn_predict_layers > 0:
                mtp_prefix = [f"model.layers.{self.config.num_hidden_layers + layer_idx}"
                              for layer_idx in range(self.config.num_nextn_predict_layers)]
                if name.startswith(tuple(mtp_prefix)):
                    continue

            for (origin_name, repeat_loaded_name) in repeat_loaded_weights_mapping:
                if origin_name not in name:
                    continue
                if name.replace(origin_name, repeat_loaded_name) not in params_dict:
                    continue
                param = params_dict[name.replace(origin_name, repeat_loaded_name)]
                weight_loader = getattr(param, "weight_loader",
                                            default_weight_loader)
                weight_loader(param, loaded_weight)
                loaded_params.add(name.replace(origin_name, repeat_loaded_name))


            for (param_name, weight_name, shard_id) in stacked_params_mapping:
                # Skip non-stacked layers and experts (experts handled below).
                if weight_name not in name:
                    continue
                # We have mlp.experts[0].gate_proj in the checkpoint.
                # Since we handle the experts below in expert_params_mapping,
                # we need to skip here BEFORE we update the name, otherwise
                # name will be updated to mlp.experts[0].gate_up_proj, which
                # will then be updated below in expert_params_mapping
                # for mlp.experts[0].gate_gate_up_proj, which breaks load.
                if (("mlp.experts." in name) and name not in params_dict):
                    continue
                name = name.replace(weight_name, param_name)
                if name.endswith(".bias") and name not in params_dict:
                    continue

                if name not in params_dict:
                    continue
                param = params_dict[name]
                weight_loader = param.weight_loader
                weight_loader(param, loaded_weight, shard_id)
                break
            else:
                for mapping in expert_params_mapping:
                    param_name, weight_name, expert_id, shard_id = mapping
                    if weight_name not in name:
                        continue
                    name = name.replace(weight_name, param_name)

                    if name not in params_dict:
                        continue
                    param = params_dict[name]
                    weight_loader = param.weight_loader
                    weight_loader(param,
                                  loaded_weight,
                                  name,
                                  shard_id=shard_id,
                                  expert_id=expert_id)
                    break
                else:
                    if name.endswith(".bias") and name not in params_dict:
                        continue

                    if name not in params_dict:
                        continue
                    if name not in params_dict:
                        continue
                    param = params_dict[name]
                    weight_loader = getattr(param, "weight_loader",
                                            default_weight_loader)
                    weight_loader(param, loaded_weight)
            loaded_params.add(name)
        return loaded_params


class DeepseekV3ModelMTP(DeepseekV3ForCausalLM):

    def __init__(self, config: DeepseekV3Config, runner_settings: Dict, **kwargs):
        super().__init__(config, runner_settings, is_mtp=True)
        self.mtp_start_layer_idx = config.num_hidden_layers
        self.local_rank = int(os.getenv("LOCAL_RANK", "0"))
        self.rank_offset = int(os.getenv("RANK_OFFSET", "0"))
        self.global_rank = self.local_rank + self.rank_offset
        self.padding_idx = config.pad_token_id
        self.vocab_size = config.vocab_size
        self.vocab_size_per_rank = self.vocab_size // self.embed_tp_size
        self.ignore_share_weight = False

        # reuse embed_tokens, lm_head, rotary_emb from main model
        self.embed_tokens = None
        self.lm_head = None
        self.rotary_emb = None

        self.shared_head_norm = DeepseekV3RMSNorm(config.hidden_size, eps=config.rms_norm_eps)
        self.enorm = DeepseekV3RMSNorm(config.hidden_size, eps=config.rms_norm_eps)
        self.hnorm = DeepseekV3RMSNorm(config.hidden_size, eps=config.rms_norm_eps)
        # prev_hidden_states and input_hidden_state feature fusion
        self.eh_proj = ReplicatedLinear(
            2 * config.hidden_size,
            config.hidden_size,
            bias=False,
            quant_config=None,
            prefix=f"model.layers.{self.mtp_start_layer_idx}.eh_proj")

    @add_start_docstrings_to_model_forward(DEEPSEEKV3_INPUTS_DOCSTRING)
    @override
    def forward(
        self,
        input_ids: torch.LongTensor,
        kv_len: torch.IntTensor = None,
        actual_seq_lengths_kv: list = None,
        actual_seq_lengths_q: Optional[torch.Tensor] = None,
        prev_hidden_states: Optional[torch.Tensor] = None,
        position_ids: Optional[torch.LongTensor] = None,
        past_key_values: Optional[List[torch.FloatTensor]] = None,
        past_key_values_indexer: Optional[List[torch.Tensor]] = None,
        past_key_scales_indexer: Optional[List[torch.Tensor]] = None,
        is_prefill: Optional[bool] = False,
        cur_topk_list: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        slot_mapping: Optional[torch.Tensor] = None,
        offload_cache: Optional[OffloadCache] = None,
        **kwargs
    ):

        batch_size, seq_length = input_ids.shape
        if is_prefill:
            prefill_extra_input_dict = self.prepare_prefill_extra_input(
                input_ids, kv_len
            )
        hidden_states = self.model.calc_input_embeddings(input_ids, is_prefill)

        cos_sin = self.rotary_emb(hidden_states, position_ids, kv_len, self.max_position_embeddings)
        residual = None

        if is_prefill and self.cp_size > 1:
            hidden_states_list = list(
                torch.split(hidden_states.flatten(0, 1), prefill_extra_input_dict["split_list"], dim=0))
            position_id_list = list(
                torch.split(position_ids.flatten(0, 1), prefill_extra_input_dict["split_list"], dim=-1))
            hidden_states = torch.cat(
                [hidden_states_list[i] for i in prefill_extra_input_dict["zigzag_index"]], dim=0
            ).view(batch_size, -1, hidden_states.shape[-1])
            position_ids_cur = torch.cat(
                [position_id_list[i] for i in prefill_extra_input_dict["zigzag_index"]], dim=-1
            ).view(batch_size, -1)
            cos_sin += self.rotary_emb(hidden_states, position_ids_cur, kv_len, self.max_position_embeddings)

        hidden_states = self.enorm(hidden_states)
        prev_hidden_states = self.hnorm(prev_hidden_states)
        hidden_states_eh = torch.cat([hidden_states, prev_hidden_states], dim=-1)
        hidden_states = self.eh_proj(hidden_states_eh)

        residual, hidden_states = self.model(
            hidden_states,
            kv_len,
            actual_seq_lengths_kv,
            actual_seq_lengths_q=actual_seq_lengths_q,
            cos_sin=cos_sin,
            past_residual=residual,
            position_ids=position_ids,
            past_key_value=past_key_values,
            past_key_values_indexer=past_key_values_indexer,
            past_key_scales_indexer=past_key_scales_indexer,
            is_prefill=is_prefill,
            cur_topk_list=cur_topk_list,
            prefill_extra_input_dict=prefill_extra_input_dict,
            slot_mapping=slot_mapping,
            offload_cache=offload_cache
        )

        prev_hidden_states, _ = self.shared_head_norm(hidden_states, residual)

        outputs = prev_hidden_states
        logits = self.forward_lm_head(
            outputs=outputs, kv_len=kv_len, is_prefill=is_prefill, prefill_extra_input_dict=prefill_extra_input_dict)

        return logits, prev_hidden_states

    def load_weights(self, weights: Iterable[Tuple[str, torch.Tensor]]) -> Set[str]:
        stacked_params_mapping, mtp_unique_weight_mapping, expert_params_mapping, repeat_loaded_weights_mapping \
            = self._load_weight_map()

        params_dict = dict(self.named_parameters())
        loaded_params: Set[str] = set()
        for name, loaded_weight in weights:
            if "rotary_emb.inv_freq" in name:
                continue
            if self.ignore_share_weight and any(
                    substring in name for substring in ["embed_tokens.weight", "shared_head.head"]):
                continue
            spec_layer = get_spec_layer_idx_from_weight_name(self.config, name)
            if spec_layer is None:
                continue

            unique_weight_load = False
            for (param_name, weight_name) in mtp_unique_weight_mapping:
                if weight_name not in name:
                    continue
                param = params_dict[param_name + ".weight"]
                weight_loader = getattr(param, "weight_loader",
                                            default_weight_loader)
                weight_loader(param, loaded_weight)
                unique_weight_load = True
                loaded_params.add(param_name + ".weight")
            if unique_weight_load:
                continue

            for (origin_name, repeat_loaded_name) in repeat_loaded_weights_mapping:
                if origin_name not in name:
                    continue
                if name.replace(origin_name, repeat_loaded_name) not in params_dict:
                    continue
                param = params_dict[name.replace(origin_name, repeat_loaded_name)]
                weight_loader = getattr(param, "weight_loader",
                                            default_weight_loader)
                weight_loader(param, loaded_weight)
                loaded_params.add(name.replace(origin_name, repeat_loaded_name))

            for (param_name, weight_name, shard_id) in stacked_params_mapping:
                # Skip non-stacked layers and experts (experts handled below).
                if weight_name not in name:
                    continue
                # We have mlp.experts[0].gate_proj in the checkpoint.
                # Since we handle the experts below in expert_params_mapping,
                # we need to skip here BEFORE we update the name, otherwise
                # name will be updated to mlp.experts[0].gate_up_proj, which
                # will then be updated below in expert_params_mapping
                # for mlp.experts[0].gate_gate_up_proj, which breaks load.
                if (("mlp.experts." in name) and name not in params_dict):
                    continue
                name = name.replace(weight_name, param_name)
                if name.endswith(".bias") and name not in params_dict:
                    continue

                if name not in params_dict:
                    continue
                param = params_dict[name]
                weight_loader = param.weight_loader
                weight_loader(param, loaded_weight, shard_id)
                break
            else:
                for mapping in expert_params_mapping:
                    param_name, weight_name, expert_id, shard_id = mapping
                    if weight_name not in name:
                        continue
                    name = name.replace(weight_name, param_name)

                    if name not in params_dict:
                        continue
                    param = params_dict[name]
                    weight_loader = param.weight_loader
                    weight_loader(param,
                                  loaded_weight,
                                  name,
                                  shard_id=shard_id,
                                  expert_id=expert_id)
                    break
                else:
                    if name.endswith(".bias") and name not in params_dict:
                        continue

                    if name not in params_dict:
                        continue
                    param = params_dict[name]
                    weight_loader = getattr(param, "weight_loader",
                                            default_weight_loader)
                    weight_loader(param, loaded_weight)
            loaded_params.add(name)
        return loaded_params

    def _load_weight_map(self):
        stacked_params_mapping = [
            # (param_name, shard_name, shard_id)
            ("gate_up_proj", "gate_proj", 0),
            ("gate_up_proj", "up_proj", 1),
        ]

        mtp_unique_weight_mapping = [
            # (param_name, weight_name)
            ("shared_head_norm", "shared_head.norm"),
            ("enorm", "enorm"),
            ("hnorm", "hnorm"),
            ("eh_proj", "eh_proj")
        ]

        # Params for weights, int8 weight scales
        # (param_name, weight_name, expert_id, shard_id)
        expert_params_mapping = FusedMoEGMM.make_expert_params_mapping(
            ckpt_gate_proj_name="gate_proj",
            ckpt_down_proj_name="down_proj",
            ckpt_up_proj_name="up_proj",
            num_experts=self.config.n_routed_experts)

        repeat_loaded_weights_mapping = [] # (origin_name: repeat_loaded_name)
        return stacked_params_mapping, mtp_unique_weight_mapping, expert_params_mapping, repeat_loaded_weights_mapping


def get_spec_layer_idx_from_weight_name(config,
                                        weight_name: str) -> Optional[int]:
    if hasattr(config,
               "num_nextn_predict_layers") and (config.num_nextn_predict_layers
                                                > 0):
        layer_idx = config.num_hidden_layers
        for i in range(config.num_nextn_predict_layers):
            if weight_name.startswith(f"model.layers.{layer_idx+i}."):
                return layer_idx + i
    return None
