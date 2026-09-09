/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: GatherSelectionSparseFlashAttention pybind extension
 */

#include <string>
#include <tuple>

#include <torch/extension.h>
#include <torch/library.h>
#include "pytorch_npu_helper.hpp"

namespace {
constexpr int64_t kSize = 8;
constexpr int64_t kQueryRankTnd = 3;
constexpr int64_t kQueryHeadDimAxis = 2;

at::Tensor ConstructAttentionOut(const at::Tensor &query, int64_t ropeHeadDim)
{
    TORCH_CHECK(query.dim() == kQueryRankTnd, "GSFA query must be TND rank-3, got ", query.dim());
    TORCH_CHECK(query.size(kQueryHeadDimAxis) > ropeHeadDim, "query D must exceed rope_head_dim");
    at::SmallVector<int64_t, kSize> outShape = {query.size(0), query.size(1),
                                                 query.size(kQueryHeadDimAxis) - ropeHeadDim};
    return at::empty(outShape, query.options());
}

at::Tensor ConstructSelectionActualSeq(const at::Tensor &selectionBlockTable)
{
    TORCH_CHECK(selectionBlockTable.dim() >= 1, "selection_kv_block_table rank must be >= 1");
    at::SmallVector<int64_t, kSize> outShape;
    for (int64_t i = 0; i + 1 < selectionBlockTable.dim(); ++i) {
        outShape.push_back(selectionBlockTable.size(i));
    }
    if (outShape.empty()) {
        outShape.push_back(1);
    }
    return at::empty(outShape, selectionBlockTable.options().dtype(at::kInt));
}

std::tuple<at::Tensor, at::Tensor> RunGsfa(
    const at::Tensor &query, at::Tensor &selectionKvCache, at::Tensor &selectionKvBlockTable,
    at::Tensor &selectionKvBlockStatus, const at::Tensor &selectionTopkIndices, const at::Tensor &fullKvCache,
    const at::Tensor &fullKvBlockTable, const at::Tensor &actualSeqLengthsQuery,
    const at::Tensor &fullKvActualSeq, const c10::optional<at::Tensor> &sinks, double scaleValue,
    int64_t keyQuantMode, int64_t valueQuantMode, int64_t sparseBlockSize, c10::string_view layoutQuery,
    c10::string_view layoutKv, int64_t sparseMode, int64_t preTokens, int64_t nextTokens, int64_t attentionMode,
    int64_t quantScaleRepoMode, int64_t tileSize, int64_t ropeHeadDim, int64_t selectionTopkBlockSize)
{
    TORCH_CHECK(query.numel() > 0, "query is empty");
    TORCH_CHECK(selectionKvCache.scalar_type() == at::kChar || selectionKvCache.scalar_type() == at::kByte,
                "selection_kv_cache must be INT8 packed KV");

    std::string layoutQueryStr(layoutQuery);
    std::string layoutKvStr(layoutKv);
    char *layoutQueryPtr = const_cast<char *>(layoutQueryStr.c_str());
    char *layoutKvPtr = const_cast<char *>(layoutKvStr.c_str());

    at::Tensor attentionOut = ConstructAttentionOut(query, ropeHeadDim);
    at::Tensor selectionActualSeq = ConstructSelectionActualSeq(selectionKvBlockTable);
    at::Tensor nullTensor;

    // EXEC_NPU_CMD's ConvertTypes requires lvalues; Inner ACLNN scale is double.
    EXEC_NPU_CMD(aclnnGatherSelectionSparseFlashAttention, query, selectionKvCache, selectionKvCache,
                 selectionTopkIndices, nullTensor, nullTensor, selectionKvBlockTable, actualSeqLengthsQuery,
                 fullKvActualSeq, sinks, selectionKvBlockStatus, fullKvCache, fullKvBlockTable, scaleValue,
                 keyQuantMode, valueQuantMode, sparseBlockSize, layoutQueryPtr, layoutKvPtr, sparseMode, preTokens,
                 nextTokens, attentionMode, quantScaleRepoMode, tileSize, ropeHeadDim, selectionTopkBlockSize,
                 attentionOut, selectionActualSeq);
    return std::make_tuple(attentionOut, selectionActualSeq);
}
} // namespace

std::tuple<at::Tensor, at::Tensor> gather_selection_sparse_flash_attention_npu(
    const at::Tensor &query, at::Tensor &selection_kv_cache, at::Tensor &selection_kv_block_table,
    at::Tensor &selection_kv_block_status, const at::Tensor &selection_topk_indices, const at::Tensor &full_kv_cache,
    const at::Tensor &full_kv_block_table, const at::Tensor &actual_seq_lengths_query,
    const at::Tensor &full_kv_actual_seq, const c10::optional<at::Tensor> &sinks, double scale_value,
    int64_t key_quant_mode, int64_t value_quant_mode, int64_t sparse_block_size, c10::string_view layout_query,
    c10::string_view layout_kv, int64_t sparse_mode, int64_t pre_tokens, int64_t next_tokens, int64_t attention_mode,
    int64_t quant_scale_repo_mode, int64_t tile_size, int64_t rope_head_dim, int64_t selection_topk_block_size)
{
    return RunGsfa(query, selection_kv_cache, selection_kv_block_table, selection_kv_block_status,
                   selection_topk_indices, full_kv_cache, full_kv_block_table, actual_seq_lengths_query,
                   full_kv_actual_seq, sinks, scale_value, key_quant_mode, value_quant_mode, sparse_block_size,
                   layout_query, layout_kv, sparse_mode, pre_tokens, next_tokens, attention_mode,
                   quant_scale_repo_mode, tile_size, rope_head_dim, selection_topk_block_size);
}

std::tuple<at::Tensor, at::Tensor> gather_selection_sparse_flash_attention_meta(
    const at::Tensor &query, at::Tensor &selection_kv_cache, at::Tensor &selection_kv_block_table,
    at::Tensor &selection_kv_block_status, const at::Tensor &selection_topk_indices, const at::Tensor &full_kv_cache,
    const at::Tensor &full_kv_block_table, const at::Tensor &actual_seq_lengths_query,
    const at::Tensor &full_kv_actual_seq, const c10::optional<at::Tensor> &sinks, double scale_value,
    int64_t key_quant_mode, int64_t value_quant_mode, int64_t sparse_block_size, c10::string_view layout_query,
    c10::string_view layout_kv, int64_t sparse_mode, int64_t pre_tokens, int64_t next_tokens, int64_t attention_mode,
    int64_t quant_scale_repo_mode, int64_t tile_size, int64_t rope_head_dim, int64_t selection_topk_block_size)
{
    (void)selection_kv_cache;
    (void)selection_kv_block_status;
    (void)selection_topk_indices;
    (void)full_kv_cache;
    (void)full_kv_block_table;
    (void)actual_seq_lengths_query;
    (void)full_kv_actual_seq;
    (void)sinks;
    (void)scale_value;
    (void)key_quant_mode;
    (void)value_quant_mode;
    (void)sparse_block_size;
    (void)layout_query;
    (void)layout_kv;
    (void)sparse_mode;
    (void)pre_tokens;
    (void)next_tokens;
    (void)attention_mode;
    (void)quant_scale_repo_mode;
    (void)tile_size;
    (void)selection_topk_block_size;
    return std::make_tuple(ConstructAttentionOut(query, rope_head_dim),
                           ConstructSelectionActualSeq(selection_kv_block_table));
}

using GsfaFunctionalOut = std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor, at::Tensor>;

GsfaFunctionalOut gather_selection_sparse_flash_attention_functional(
    const at::Tensor &query, const at::Tensor &selection_kv_cache, const at::Tensor &selection_kv_block_table,
    const at::Tensor &selection_kv_block_status, const at::Tensor &selection_topk_indices,
    const at::Tensor &full_kv_cache, const at::Tensor &full_kv_block_table,
    const at::Tensor &actual_seq_lengths_query, const at::Tensor &full_kv_actual_seq,
    const c10::optional<at::Tensor> &sinks, double scale_value, int64_t key_quant_mode, int64_t value_quant_mode,
    int64_t sparse_block_size, c10::string_view layout_query, c10::string_view layout_kv, int64_t sparse_mode,
    int64_t pre_tokens, int64_t next_tokens, int64_t attention_mode, int64_t quant_scale_repo_mode, int64_t tile_size,
    int64_t rope_head_dim, int64_t selection_topk_block_size)
{
    at::Tensor selectionKvCache = selection_kv_cache.clone();
    at::Tensor selectionKvBlockTable = selection_kv_block_table.clone();
    at::Tensor selectionKvBlockStatus = selection_kv_block_status.clone();
    auto outs = RunGsfa(query, selectionKvCache, selectionKvBlockTable, selectionKvBlockStatus, selection_topk_indices,
                        full_kv_cache, full_kv_block_table, actual_seq_lengths_query, full_kv_actual_seq, sinks,
                        scale_value, key_quant_mode, value_quant_mode, sparse_block_size, layout_query, layout_kv,
                        sparse_mode, pre_tokens, next_tokens, attention_mode, quant_scale_repo_mode, tile_size,
                        rope_head_dim, selection_topk_block_size);
    return std::make_tuple(std::get<0>(outs), selectionKvCache, selectionKvBlockTable, selectionKvBlockStatus,
                           std::get<1>(outs));
}

GsfaFunctionalOut gather_selection_sparse_flash_attention_functional_meta(
    const at::Tensor &query, const at::Tensor &selection_kv_cache, const at::Tensor &selection_kv_block_table,
    const at::Tensor &selection_kv_block_status, const at::Tensor &selection_topk_indices,
    const at::Tensor &full_kv_cache, const at::Tensor &full_kv_block_table,
    const at::Tensor &actual_seq_lengths_query, const at::Tensor &full_kv_actual_seq,
    const c10::optional<at::Tensor> &sinks, double scale_value, int64_t key_quant_mode, int64_t value_quant_mode,
    int64_t sparse_block_size, c10::string_view layout_query, c10::string_view layout_kv, int64_t sparse_mode,
    int64_t pre_tokens, int64_t next_tokens, int64_t attention_mode, int64_t quant_scale_repo_mode, int64_t tile_size,
    int64_t rope_head_dim, int64_t selection_topk_block_size)
{
    (void)selection_topk_indices;
    (void)full_kv_cache;
    (void)full_kv_block_table;
    (void)actual_seq_lengths_query;
    (void)full_kv_actual_seq;
    (void)sinks;
    (void)scale_value;
    (void)key_quant_mode;
    (void)value_quant_mode;
    (void)sparse_block_size;
    (void)layout_query;
    (void)layout_kv;
    (void)sparse_mode;
    (void)pre_tokens;
    (void)next_tokens;
    (void)attention_mode;
    (void)quant_scale_repo_mode;
    (void)tile_size;
    (void)selection_topk_block_size;
    return std::make_tuple(ConstructAttentionOut(query, rope_head_dim), at::empty_like(selection_kv_cache),
                           at::empty_like(selection_kv_block_table), at::empty_like(selection_kv_block_status),
                           ConstructSelectionActualSeq(selection_kv_block_table));
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("gather_selection_sparse_flash_attention", &gather_selection_sparse_flash_attention_npu);
    m.impl("gather_selection_sparse_flash_attention_functional",
           &gather_selection_sparse_flash_attention_functional);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, Meta, m)
{
    m.impl("gather_selection_sparse_flash_attention", &gather_selection_sparse_flash_attention_meta);
    m.impl("gather_selection_sparse_flash_attention_functional",
           &gather_selection_sparse_flash_attention_functional_meta);
}
