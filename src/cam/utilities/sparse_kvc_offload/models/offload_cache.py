# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

import torch
import torch.nn as nn
import torch_npu


class OffloadCache(nn.Module):
    def __init__(self, runner_settings, model):
        super().__init__()
        self.runner_settings = runner_settings
        self.next_n = runner_settings.get("model_config").get("next_n", 0)

        self.config = model.config
        self.is_mtp = model.is_mtp

        self.num_hidden_layers = self.config.num_nextn_predict_layers if self.is_mtp else self.config.num_hidden_layers
        self.batch_size_per_rank = self.runner_settings.get("data_config").get("batch_size_per_rank", 1)
        self.index_topk = self.config.index_topk
        self.block_size = self.runner_settings.get("model_config").get("pa_block_size", 128)

        # num of selected blocks per query token
        self.s_maxblocknum = (self.index_topk + self.block_size - 1) // self.block_size
        self.next_n = self.runner_settings.get("model_config").get("next_n", 0)
        # bsz*seq
        batchseq = self.batch_size_per_rank * (1 + self.next_n)
        # total num of selected blocks
        self.selection_num_blocks = self.s_maxblocknum * batchseq

        self.selection_kv_block_table = ()
        for _ in range(self.num_hidden_layers):
            self.selection_kv_block_table += (torch.arange(0, self.selection_num_blocks
                                                     ).reshape(batchseq, -1).to(device="npu", dtype=torch.int32),)
        self.selection_kv_block_status = ()
        for _ in range(self.num_hidden_layers):
            size = (self.batch_size_per_rank, 1 + self.next_n, 1, self.index_topk + 1) # bsnd
            self.selection_kv_block_status += (torch.full(size, -1).to(device="npu", dtype=torch.int32),)

        self.d2h_stream = torch.npu.Stream(device="npu")
        self.d2h_event = torch.npu.Event(blocking=True, enable_timing=False)

        self.pa_max_length = self.runner_settings.get("model_config").get("pa_max_length", 2048)
        # num of blocks of full kv in each batch
        self.cache_len = self.pa_max_length // self.block_size
        self.kv_cache_num_block = self.cache_len * self.batch_size_per_rank

        self.prefill_mini_batch_size = runner_settings.get("model_config").get("prefill_mini_batch_size", 0)
        self.mini_batch = self.prefill_mini_batch_size \
            if self.prefill_mini_batch_size > 0 else self.batch_size_per_rank
        self.batch_len = self.cache_len * self.mini_batch

        self.default_topk_indices = torch.arange(self.index_topk, dtype=torch.int32, device="npu")\
                                    .view(1, -1).repeat(batchseq, 1)

        self.kv_cache_quant_mode = self.config.quant_config.kv_cache_quant_mode \
            if self.config.quant_config is not None else "unquant"
        self.empty_rope = torch.tensor([], dtype=torch.int8, device="npu")

    def init_cache(
        self,
        cache_device,
    ):
        dtype = torch.int8 if self.kv_cache_quant_mode == "int8" else self.config.torch_dtype

        past_key_values = ()
        self.temp_kv_cache = None
        self.selected_key_values = ()
        self.past_key_values_unmapped = ()

        # When the kvcache INT8 quantization is enabled
        # nope_cache, rope_cache, and nope_scale need to be concatenated for SFA/MLAprolog kernel in INT8 dtype.
        # kv_lora_rank(INT8) + qk_rope_head_dim(BF16) * 2(->INT8) + kv_scale(FP32) * 4(->INT8)
        cache_last_dim = self.config.kv_lora_rank + self.config.qk_rope_head_dim * 2 + 4 * 4 \
            if self.kv_cache_quant_mode == "int8" else self.config.kv_lora_rank

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

        # temp cache for prefill
        temp_nope = torch.zeros((
                    self.batch_len,
                    self.block_size,
                    1,
                    cache_last_dim
                ), dtype=dtype, device=cache_device)
        if self.kv_cache_quant_mode == "int8":
            temp_rope = torch.tensor([], dtype=torch.int8, device=cache_device)
        else:
            temp_rope = torch.zeros((
                        self.batch_len,
                        self.block_size,
                        1,
                        self.config.qk_rope_head_dim
                    ), dtype=dtype, device=cache_device)
        self.temp_kv_cache = (temp_nope, temp_rope,)

        for _ in range(self.num_hidden_layers):
            cache_nope = torch_npu.empty_with_swapped_memory(cache_nope_shape, dtype=dtype, device=cache_device)
            if self.kv_cache_quant_mode == "int8":
                cache_rope = None
            else:
                cache_rope = torch_npu.empty_with_swapped_memory(cache_rope_shape, dtype=dtype, device=cache_device)
            past_key_values += ((cache_nope, cache_rope),)

            selected_nope = torch.zeros((self.selection_num_blocks, self.block_size, cache_last_dim),
                                        dtype=dtype, device=cache_device)
            if self.kv_cache_quant_mode == "int8":
                selected_rope = torch.tensor([], dtype=torch.int8, device=cache_device)
            else:
                selected_rope = torch.zeros((self.selection_num_blocks, self.block_size, self.config.qk_rope_head_dim),
                                            dtype=dtype, device=cache_device)
            self.selected_key_values += ((selected_nope, selected_rope),)

        return past_key_values

    def reinit_status(self):
        for i in range(self.num_hidden_layers):
            status = self.selection_kv_block_status[i]
            status.fill_(-1)
