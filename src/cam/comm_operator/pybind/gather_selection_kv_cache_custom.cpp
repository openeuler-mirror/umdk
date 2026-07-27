/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: GatherSelectionKvCacheCustom pybind extension file
 * Create: 2026-07-25
 * Note:
 * History: 2026-07-25 create GatherSelectionKvCacheCustom pybind extension file
 */

#include <iostream>
#include <torch/library.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "pytorch_npu_helper.hpp"

// npu tensor max size
const int SIZE = 8;

at::Tensor construct_gather_selection_kv_cache_custom_output_tensor(
    const at::Tensor& selection_k_rope,
    const at::Tensor& selection_kv_cache, const at::Tensor& selection_kv_block_table,
    const at::Tensor& selection_kv_block_status, const at::Tensor& selection_topk_indices)
{
    c10::SmallVector<int64_t, SIZE> selection_kv_actual_seq_shape = {selection_kv_block_table.size(0)};
    at::Tensor out = at::empty(selection_kv_actual_seq_shape, selection_topk_indices.options());
    return out;
}

at::Tensor gather_selection_kv_cache_custom_npu(
    const at::Tensor& selection_k_rope,
    const at::Tensor& selection_kv_cache,
    const at::Tensor& selection_kv_block_table,
    const at::Tensor& selection_kv_block_status,
    const at::Tensor& selection_topk_indices,
    const at::Tensor& full_k_rope,
    const at::Tensor& full_kv_cache,
    const at::Tensor& full_kv_block_table,
    const at::Tensor& full_kv_actual_seq,
    const at::Tensor& full_q_actual_seq,
    int64_t selection_topk_block_size)
{
    at::Tensor selection_kv_actual_seq = construct_gather_selection_kv_cache_custom_output_tensor(
        selection_k_rope, selection_kv_cache, selection_kv_block_table, selection_kv_block_status,
        selection_topk_indices);

    EXEC_NPU_CMD(aclnnGatherSelectionKvCacheCustom,
                 selection_k_rope, selection_kv_cache, selection_kv_block_table,
                 selection_kv_block_status, selection_topk_indices, full_k_rope,
                 full_kv_cache, full_kv_block_table,
                 full_kv_actual_seq, full_q_actual_seq, selection_topk_block_size,
                 selection_kv_actual_seq);

    return selection_kv_actual_seq;
}

at::Tensor gather_selection_kv_cache_custom_meta(
    const at::Tensor& selection_k_rope,
    const at::Tensor& selection_kv_cache,
    const at::Tensor& selection_kv_block_table,
    const at::Tensor& selection_kv_block_status,
    const at::Tensor& selection_topk_indices,
    const at::Tensor& full_k_rope,
    const at::Tensor& full_kv_cache,
    const at::Tensor& full_kv_block_table,
    const at::Tensor& full_kv_actual_seq,
    const at::Tensor& full_q_actual_seq,
    int64_t selection_topk_block_size)
{
    return construct_gather_selection_kv_cache_custom_output_tensor(
        selection_k_rope, selection_kv_cache, selection_kv_block_table, selection_kv_block_status,
        selection_topk_indices);
}

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> gather_selection_kv_cache_custom_functional(
    const at::Tensor& selection_k_rope,
    const at::Tensor& selection_kv_cache,
    const at::Tensor& selection_kv_block_table,
    const at::Tensor& selection_kv_block_status,
    const at::Tensor& selection_topk_indices,
    const at::Tensor& full_k_rope,
    const at::Tensor& full_kv_cache,
    const at::Tensor& full_kv_block_table,
    const at::Tensor& full_kv_actual_seq,
    const at::Tensor& full_q_actual_seq,
    int64_t selection_topk_block_size)
{
    at::Tensor selection_kv_actual_seq = construct_gather_selection_kv_cache_custom_output_tensor(
        selection_k_rope, selection_kv_cache, selection_kv_block_table, selection_kv_block_status,
        selection_topk_indices);
    at::Tensor selection_k_rope_inplace = selection_k_rope.clone();
    at::Tensor selection_kv_cache_inplace = selection_kv_cache.clone();
    at::Tensor selection_kv_block_table_inplace = selection_kv_block_table.clone();
    at::Tensor selection_kv_block_status_inplace = selection_kv_block_status.clone();
    EXEC_NPU_CMD(aclnnGatherSelectionKvCacheCustom, selection_k_rope_inplace, selection_kv_cache_inplace,
        selection_kv_block_table_inplace, selection_kv_block_status_inplace, selection_topk_indices,
        full_k_rope, full_kv_cache, full_kv_block_table, full_kv_actual_seq, full_q_actual_seq,
        selection_topk_block_size, selection_kv_actual_seq);

    return std::tie(selection_kv_actual_seq, selection_k_rope_inplace, selection_kv_cache_inplace,
        selection_kv_block_table_inplace, selection_kv_block_status_inplace);
}

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor> gather_selection_kv_cache_custom_functional_meta(
    const at::Tensor& selection_k_rope,
    const at::Tensor& selection_kv_cache,
    const at::Tensor& selection_kv_block_table,
    const at::Tensor& selection_kv_block_status,
    const at::Tensor& selection_topk_indices,
    const at::Tensor& full_k_rope,
    const at::Tensor& full_kv_cache,
    const at::Tensor& full_kv_block_table,
    const at::Tensor& full_kv_actual_seq,
    const at::Tensor& full_q_actual_seq,
    int64_t selection_topk_block_size)
{
    at::Tensor output5 = construct_gather_selection_kv_cache_custom_output_tensor(
        selection_k_rope, selection_kv_cache, selection_kv_block_table, selection_kv_block_status,
        selection_topk_indices);
    at::Tensor output1 = at::empty_like(selection_k_rope);
    at::Tensor output2 = at::empty_like(selection_kv_cache);
    at::Tensor output3 = at::empty_like(selection_kv_block_table);
    at::Tensor output4 = at::empty_like(selection_kv_block_status);
    return std::make_tuple(output5, output1, output2, output3, output4);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m) {
    m.impl("gather_selection_kv_cache_custom", &gather_selection_kv_cache_custom_npu);
    m.impl("gather_selection_kv_cache_custom_functional", &gather_selection_kv_cache_custom_functional);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m) {
    m.impl("gather_selection_kv_cache_custom", &gather_selection_kv_cache_custom_meta);
    m.impl("gather_selection_kv_cache_custom_functional", &gather_selection_kv_cache_custom_functional_meta);
}
