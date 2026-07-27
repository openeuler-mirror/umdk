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

""" PyTorch Index model."""
from typing import List, Optional, Tuple, Union, Dict

import torch
import torch.nn.functional as F
import torch.utils.checkpoint

from torch import nn
import torch.distributed as dist

import torch_npu
import torchair as tng
import umdk_cam_op_lib

from executor.utils import npu_stream_switch, get_had_pow2
from module.linear import ReplicatedLinear

indexer_npu_events = [tng.ops.npu_create_tagged_event(tag=f"indexer_evt_{i}") for i in range(4)]


class LayerNorm(nn.Module):
    def __init__(self, dim: int, eps: float = 1e-6):
        super().__init__()
        self.dim = dim
        self.eps = eps
        self.weight = nn.Parameter(torch.ones(dim))
        self.bias = nn.Parameter(torch.ones(dim))

    def forward(self, x: torch.Tensor):
        return F.layer_norm(x, (self.dim,), self.weight, self.bias, self.eps)


class Indexer(nn.Module):
    def __init__(self, config, runner_settings, layer_idx: Optional[int] = None,
                 prefix: Optional[str] = "", **kwargs):
        super().__init__()
        self.layer_idx = layer_idx
        if layer_idx == config.num_hidden_layers: # mtp model
            self.layer_idx = 0 # mtp model only has one layer of cache
        self.runner_settings = runner_settings
        self.hccl_comm_dict = kwargs.get("hccl_comm_dict", None)

        self.attn_tp_size = self.runner_settings.get("parallel_config").get("attn_tp_size", 1)
        self.cp_size = self.runner_settings.get("parallel_config").get("cp_size", 1)

        self.enable_multi_streams = runner_settings.get("model_config").get("enable_multi_streams", False)
        self.enable_gegraph = runner_settings.get("exe_mode", "ge_graph") == "ge_graph"
        self.enable_aclgraph = runner_settings.get("exe_mode", "ge_graph") == "acl_graph"
        self.enable_pypto = self.runner_settings.get("model_config").get("enable_pypto", False)
        self.pa_block_size = self.runner_settings.get("model_config").get("pa_block_size", 128)

        self.dim: int = config.hidden_size
        self.n_heads: int = config.index_n_heads
        self.n_local_heads = config.index_n_heads // self.attn_tp_size
        self.head_dim: int = config.index_head_dim
        self.rope_head_dim: int = config.qk_rope_head_dim
        self.index_topk: int = config.index_topk
        self.q_lora_rank: int = config.q_lora_rank
        self.kv_cache_quant_mode = config.quant_config.kv_cache_quant_mode \
            if config.quant_config is not None else "unquant"

        self.wq_b = ReplicatedLinear(self.q_lora_rank,
                                     self.n_heads * self.head_dim,
                                     bias=False,
                                     quant_config=config.quant_config,
                                     prefix=f"{prefix}.wq_b")
        self.wk = ReplicatedLinear(self.dim,
                                    self.head_dim,
                                    bias=False,
                                    quant_config=config.quant_config,
                                    prefix=f"{prefix}.wk")
        self.weights_proj = ReplicatedLinear(self.dim,
                                    self.n_heads,
                                    bias=False,
                                    quant_config=config.quant_config,
                                    prefix=f"{prefix}.weights_proj")
        self.k_norm = LayerNorm(self.head_dim)
        self.softmax_scale = self.head_dim ** -0.5
        self.hadamard_matrix = nn.Parameter(get_had_pow2(128), requires_grad=False)

    def apply_hadamard(self, inp):
        matrix = self.hadamard_matrix
        init_shape = inp.shape
        inp = inp.view(-1, matrix.shape[0])
        return inp.matmul(matrix).view( \
            init_shape).to(torch.float16)

    def forward(
        self,
        x: torch.Tensor,
        qr: torch.Tensor,
        actual_seq_lengths_kv: torch.Tensor,
        kv_len: torch.Tensor,
        cos_sin: torch.Tensor,
        position_ids: torch.Tensor,
        query_states: torch.Tensor,
        past_key_values_indexer: Optional[List[torch.FloatTensor]],
        past_key_scales_indexer: Optional[List[torch.FloatTensor]],
        slot_mapping: torch.Tensor,
        block_table: Optional[torch.Tensor] = None,
        actual_seq_lengths_q: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        c8_input_dict: Optional[Dict] = None,
        is_prefill: bool = True,
    ):
        input_args = {
            "x": x,
            "qr": qr,
            "actual_seq_lengths_kv": actual_seq_lengths_kv,
            "kv_len": kv_len,
            "cos_sin": cos_sin,
            "position_ids": position_ids,
            "query_states": query_states,
            "past_key_values_indexer": past_key_values_indexer,
            "past_key_scales_indexer": past_key_scales_indexer,
            "slot_mapping": slot_mapping,
            "block_table": block_table,
            "actual_seq_lengths_q": actual_seq_lengths_q,
            "prefill_extra_input_dict": prefill_extra_input_dict,
            "c8_input_dict": c8_input_dict,
            "is_prefill": is_prefill,
        }

        # indexer_prolog_pypto fusion ops only enabled under W8A8C8 scenario in decode stage
        enable_indexer_prolog_pypto = self.enable_pypto and self.kv_cache_quant_mode == "int8"
        if is_prefill or not enable_indexer_prolog_pypto:
            forward_func = self.prefill_decode_ascendc
        else:
            import custom_pypto
            forward_func = self.decode_indexer_prolog_pypto

        return forward_func(**input_args)

    def decode_indexer_prolog_pypto(
        self,
        x: torch.Tensor,
        qr: torch.Tensor,
        actual_seq_lengths_kv: torch.Tensor,
        kv_len: torch.Tensor,
        cos_sin: torch.Tensor,
        position_ids: torch.Tensor,
        query_states: torch.Tensor,
        past_key_values_indexer: Optional[List[torch.FloatTensor]],
        past_key_scales_indexer: Optional[List[torch.FloatTensor]],
        slot_mapping: torch.Tensor,
        block_table: Optional[torch.Tensor] = None,
        actual_seq_lengths_q: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        c8_input_dict: Optional[Dict] = None,
        is_prefill: bool = True,
    ):
        x = x.view(kv_len.shape[0], -1, self.dim)
        bsz, seqlen, _ = x.size()
        cos, sin = cos_sin
        cos = cos.view(-1, 1, 1, self.rope_head_dim)
        sin = sin.view(-1, 1, 1, self.rope_head_dim)

        past_key_states = past_key_values_indexer[self.layer_idx][0]
        past_key_scales = past_key_scales_indexer[self.layer_idx][0]

        res = torch.ops.custom_pypto.npu_lightning_indexer_prolog_pto(
            token_x=x.view(-1, self.dim),
            q_norm=qr.view(-1, self.q_lora_rank),
            q_norm_scale=c8_input_dict.get("pertoken_scale", None),
            wq_b=self.wq_b.weight,
            wq_b_scale=self.wq_b.weight_scale,
            wk=self.wk.weight,
            weights_proj=self.weights_proj.weight,
            ln_gamma_k=self.k_norm.weight,
            ln_beta_k=self.k_norm.bias,
            cos_idx_rope=cos.squeeze(1).squeeze(1),
            sin_idx_rope=sin.squeeze(1).squeeze(1),
            hadamard_q=self.hadamard_matrix,
            hadamard_k=self.hadamard_matrix,
            idx_k_cache=past_key_states,
            idx_k_scale_cache=past_key_scales,
            idx_k_cache_index=slot_mapping.view(-1),
            layernorm_epsilon_k=self.k_norm.eps,
            layout_query="TND",
            layout_key="PA_BSND"
        )
        q = res[0]
        query_dequant_scale = res[1]
        weights = res[2]

        li_ops_input = {}
        indexer_func = self.li_fusion
        li_ops_input.update({"key_dequant_scale": past_key_scales,
                              "query_dequant_scale": query_dequant_scale.view(-1, self.n_heads),
                                })
        li_ops_input.update({"actual_seq_lengths_query": actual_seq_lengths_q,
                            "actual_seq_lengths_kv": actual_seq_lengths_kv,
                            "k": past_key_states,
                            "block_table": block_table,
                            "is_prefill": is_prefill,
                            })
        li_ops_input.update({"q": q, "weights": weights})
        return indexer_func(**li_ops_input)

    def prefill_decode_ascendc(
        self,
        x: torch.Tensor,
        qr: torch.Tensor,
        actual_seq_lengths_kv: torch.Tensor,
        kv_len: torch.Tensor,
        cos_sin: torch.Tensor,
        position_ids: torch.Tensor,
        query_states: torch.Tensor,
        past_key_values_indexer: Optional[List[torch.FloatTensor]],
        past_key_scales_indexer: Optional[List[torch.FloatTensor]],
        slot_mapping: torch.Tensor,
        block_table: Optional[torch.Tensor] = None,
        actual_seq_lengths_q: Optional[torch.Tensor] = None,
        prefill_extra_input_dict: Optional[Dict] = None,
        c8_input_dict: Optional[Dict] = None,
        is_prefill: bool = True,
    ):
        x = x.view(kv_len.shape[0], -1, self.dim)
        bsz, seqlen, _ = x.size()
        if self.cp_size > 1 and is_prefill:
            _, _, cos, sin = cos_sin
        else:
            cos, sin = cos_sin
        cos = cos.view(-1, 1, 1, self.rope_head_dim)
        sin = sin.view(-1, 1, 1, self.rope_head_dim)
        enable_multi_streams = self.enable_multi_streams and not is_prefill

        if enable_multi_streams and self.enable_aclgraph:
            tng.ops.npu_record_tagged_stream(qr, "22")
            tng.ops.npu_record_tagged_stream(cos, "22")
            tng.ops.npu_record_tagged_stream(sin, "22")
            tng.ops.npu_tagged_event_record(indexer_npu_events[0])
        with npu_stream_switch(enable_multi_streams, "22"):
            # prolog for kv use multi streams
            if enable_multi_streams:
                if self.enable_aclgraph:
                    tng.ops.npu_tagged_event_wait(indexer_npu_events[0])
                else:
                    tng.scope.npu_wait_tensor(qr, query_states[0])
            # q process in new stream
            q_b = self.wq_b(qr, c8_input_dict.get("pertoken_scale", None)) # [b,s,1536] @ [1536,64*128] = [b,s,64*128]

            if enable_multi_streams and self.enable_aclgraph:
                tng.ops.npu_tagged_event_record(indexer_npu_events[1])

            q = q_b.view(bsz, seqlen, self.n_heads, self.head_dim)  # [b,s,64,128]
            q_pe, q_nope = torch.split(q, [self.rope_head_dim, \
                                        self.head_dim - self.rope_head_dim], dim=-1)  # [b,s,64,64+64]

            q_pe = q_pe.view(-1, self.n_heads, 1, self.rope_head_dim)
            # [b,s,n,d]
            q_pe = torch_npu.npu_rotary_mul(q_pe, cos, sin).view(bsz, -1, self.n_heads, self.rope_head_dim)
            q = torch.cat([q_pe, q_nope], dim=-1)
            if enable_multi_streams and self.enable_aclgraph:
                tng.ops.npu_tagged_event_record(indexer_npu_events[2])

        if enable_multi_streams and self.enable_aclgraph:
            tng.ops.npu_record_tagged_stream(x, "33")

        with npu_stream_switch(enable_multi_streams, "33"):
            if enable_multi_streams:
                if self.enable_aclgraph:
                    tng.ops.npu_tagged_event_wait(indexer_npu_events[1])
                else:
                    tng.scope.npu_wait_tensor(x, q_b)
            weights = self.weights_proj(x.view(-1, self.dim))
            if enable_multi_streams and self.enable_aclgraph:
                tng.ops.npu_tagged_event_record(indexer_npu_events[3])

        k_proj = self.wk(x)  # [b,s,7168] @ [7168,128] = [b,s,128]
        k = self.k_norm(k_proj)
        # [b,s,64+64]
        k_pe, k_nope = torch.split(k, [self.rope_head_dim, self.head_dim - self.rope_head_dim], dim=-1)
        k_pe = k_pe.view(-1, 1, 1, self.rope_head_dim)
        k_pe = torch_npu.npu_rotary_mul(k_pe, cos, sin).view(bsz, -1, 1, self.rope_head_dim) # [b,s,1,d]
        k = torch.cat([k_pe, k_nope.unsqueeze(2)], dim=-1)  # [b,s,1,128]
        key_dequant_scale = None
        indexer_input = {}

        if enable_multi_streams and self.enable_aclgraph:
            tng.ops.npu_tagged_event_wait(indexer_npu_events[2])
        if self.kv_cache_quant_mode == "int8":
            with npu_stream_switch(enable_multi_streams, "22"):
                # q quant
                q = self.apply_hadamard(q)
                q, query_dequant_scale = torch_npu.npu_dynamic_quant(q)
                query_dequant_scale = query_dequant_scale.type(torch.float16)
            # k quant
            k = self.apply_hadamard(k)
            k, key_dequant_scale = torch_npu.npu_dynamic_quant(k)
            key_dequant_scale = key_dequant_scale.type(torch.float16)

            if self.cp_size > 1 and is_prefill:
                k_scale_all = key_dequant_scale.new_empty([bsz * seqlen * self.cp_size, key_dequant_scale.shape[-1]])
                dist.all_gather_into_tensor(k_scale_all, key_dequant_scale.view(bsz * seqlen, -1), \
                                            group=self.hccl_comm_dict.get("cp_group", None))
                outputs_k_scale_list = list(
                    torch.split(k_scale_all, prefill_extra_input_dict["reverse_split_list"], dim=0))
                key_dequant_scale = torch.cat([outputs_k_scale_list[i] \
                                            for i in prefill_extra_input_dict["cp_reverse_index"]], dim=0)
                query_dequant_scale_prev, query_dequant_scale_next = torch.split(query_dequant_scale, \
                query_dequant_scale.size(1) // 2, dim=1)
                query_dequant_scale_prev = query_dequant_scale_prev.reshape(-1, self.n_heads)
                query_dequant_scale_next = query_dequant_scale_next.reshape(-1, self.n_heads)
                c8_input_dict.update({
                                    "query_dequant_scale_prev": query_dequant_scale_prev,
                                    "query_dequant_scale_next": query_dequant_scale_next,
                                    })

            if past_key_scales_indexer is not None:
                past_key_scales = past_key_scales_indexer[self.layer_idx][0]
                if is_prefill:
                    # scatter_update_ performs better in prefill stage
                    torch_npu.scatter_update_(past_key_scales.view(kv_len.shape[0], -1, past_key_scales.shape[-1]),
                                            prefill_extra_input_dict["kv_scatter_update_indices"],
                                            key_dequant_scale.view(kv_len.shape[0], -1, key_dequant_scale.shape[-1]),
                                            axis=1)
                else:
                    torch_npu.npu_scatter_nd_update_(past_key_scales.view(-1, 1),
                                                    slot_mapping.view(-1, 1),
                                                    key_dequant_scale.view(-1, key_dequant_scale.shape[-1]))
            indexer_input.update({"key_dequant_scale": past_key_scales,
                                   "query_dequant_scale": query_dequant_scale.view(-1, self.n_heads),
                                })
        if self.cp_size > 1 and is_prefill:
            kv_all = k.new_empty([bsz * seqlen * self.cp_size, k.shape[-1]])
            dist.all_gather_into_tensor(kv_all, k.view(bsz * seqlen, -1), \
                                    group=self.hccl_comm_dict.get("cp_group", None))
            outputs_list = list(torch.split(kv_all, prefill_extra_input_dict["reverse_split_list"], dim=0))
            k = torch.cat([outputs_list[i] for i in prefill_extra_input_dict["cp_reverse_index"]], dim=0)
        if past_key_values_indexer is not None:
            past_key_states = past_key_values_indexer[self.layer_idx][0]
            if is_prefill:
                torch_npu.scatter_update_(past_key_states.view(kv_len.shape[0], -1, past_key_states.shape[-1]),
                                        prefill_extra_input_dict["kv_scatter_update_indices"],
                                        k.view(kv_len.shape[0], -1, k.shape[-1]),
                                        axis=1)
            else:
                torch_npu.npu_scatter_nd_update_(past_key_states.view(-1, self.head_dim),
                                                slot_mapping.view(-1, 1),
                                                k.view(-1, k.shape[-1]))
        indexer_func = self.li_fusion
        indexer_input.update({"actual_seq_lengths_query": actual_seq_lengths_q,
                            "actual_seq_lengths_kv": actual_seq_lengths_kv,
                            "k": past_key_states,
                            "block_table": block_table,
                            "k_proj": k_proj,
                            "is_prefill": is_prefill,
                            })

        if enable_multi_streams and self.enable_aclgraph:
            tng.ops.npu_tagged_event_wait(indexer_npu_events[3])
        if self.cp_size > 1 and is_prefill:
            # [B, S, N, D] -> [T, N, D]
            x = x.flatten(0, 1).unsqueeze(0)
            q = q.flatten(0, 1).unsqueeze(0)
            weights = weights.view(bsz, -1, weights.shape[-1])
            weights_prev, weights_next = torch.split(weights, weights.size(1) // 2, dim=1)
            weights_prev = weights_prev.reshape(-1, weights_prev.shape[-1])
            weights_next = weights_next.reshape(-1, weights_next.shape[-1])
            q_prev, q_next = torch.split(q, q.size(1) // 2, dim=1)
            indexer_input.update({
                "q": q_prev.view(bsz, -1, self.n_heads, q.shape[-1]),
                "weights": weights_prev,
                })
            indexer_input.update({"actual_seq_lengths_kv": prefill_extra_input_dict["kv_len_prev"],
                                    "actual_seq_lengths_query": prefill_extra_input_dict["actual_seq_q"]})
            if self.kv_cache_quant_mode == "int8":
                indexer_input.update({"query_dequant_scale": c8_input_dict["query_dequant_scale_prev"]})
            topk_indices_prev = indexer_func(**indexer_input)
            indexer_input.update({
                "q": q_next.view(bsz, -1, self.n_heads, q.shape[-1]),
                "weights": weights_next,
                })
            indexer_input.update({"actual_seq_lengths_kv": prefill_extra_input_dict["kv_len_next"]})
            if self.kv_cache_quant_mode == "int8":
                indexer_input.update({"query_dequant_scale": c8_input_dict["query_dequant_scale_next"]})
            topk_indices_next = indexer_func(**indexer_input)
            return (topk_indices_prev, topk_indices_next)
        else:
            indexer_input.update({"q": q, "weights": weights})
            return indexer_func(**indexer_input)

    def li_fusion(
        self,
        q: torch.Tensor,
        k: torch.Tensor,
        weights: torch.Tensor,
        actual_seq_lengths_query: torch.Tensor,
        actual_seq_lengths_kv: torch.Tensor,
        block_table: Optional[torch.Tensor] = None,
        is_prefill: bool = True,
        **kwargs
    ):
        use_pto = self.enable_pypto and not is_prefill and not self.kv_cache_quant_mode == "int8"
        if not use_pto:
            q = q.view(-1, self.n_heads, self.head_dim)
            layout_query = 'TND'
        else:
            import custom_pypto
            layout_query = 'BSND'

        li_input_kwargs = {
            "key": k,
            "actual_seq_lengths_query": actual_seq_lengths_query.to(torch.int32),
            "actual_seq_lengths_key": actual_seq_lengths_kv.to(torch.int32),
            "block_table": block_table,
            "layout_key": 'PA_BSND',
            "sparse_count": self.index_topk,
            "sparse_mode": 3,
            "query": q,
            "weights": weights,
            "layout_query": layout_query,
        }
        if self.kv_cache_quant_mode == "int8":
            key_dequant_scale = kwargs.get("key_dequant_scale", None)
            query_dequant_scale = kwargs.get("query_dequant_scale", None)
            li_input_kwargs.update({
                "key_dequant_scale": key_dequant_scale,
                "key_quant_mode": 0,
                "query_dequant_scale": query_dequant_scale,
                "query_quant_mode": 0,
                "weights": weights.type(torch.float16),
            })
            return torch_npu.npu_quant_lightning_indexer(**li_input_kwargs)
        elif not use_pto:
            return torch_npu.npu_lightning_indexer(**li_input_kwargs)[0]
        else:
            topk_indices = torch.ops.custom_pypto.npu_lightning_indexer_pto(**li_input_kwargs)
            return topk_indices.view(-1, 1, self.index_topk)