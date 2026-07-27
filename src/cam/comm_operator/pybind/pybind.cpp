/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add pybind
 * Create: 2025-12-10
 * Note:
 * History: 2025-12-10 add pybind
 */

#include <torch/extension.h>
#include "functions.h"
#include "ext_utils.h"
#include "buffer.h"

PYBIND11_MODULE(TORCH_EXTENSION_NAME, m)
{
    m.def("fused_deep_moe", &FusedDeepMoeImplAutograd, "fused_deep_moe");
    m.def("all2_all_detour", &all2_all_detour_impl_autograd, "all2_all_detour");
    m.def("reduce_scatter_detour", &reduce_scatter_detour_impl_autograd, "reduce_scatter_detour");
    m.def("cam_get_comm", &cam_get_comm, "cam_get_comm");
    m.def("cam_free_comm", &cam_free_comm, "cam_free_comm");
    m.def("cam_get_rank_size", &cam_get_rank_size, "cam_get_rank_size");
    m.def("cam_get_and_increase_magic", &cam_get_and_increase_magic, "cam_get_and_increase_magic");
    m.def("cam_get_magic", &cam_get_magic, "cam_get_magic");
    m.def("a2e", &A2eImplAutograd, "a2e");
    m.def("e2a", &E2aImplAutograd, "e2a");
    pybind11::class_<fused_deep_moe::Buffer>(m, "FusedDeepMoeBuffer")
        .def(pybind11::init<>())
        .def("init", &fused_deep_moe::Buffer::init,
             pybind11::arg("rank"), pybind11::arg("num_ranks"),
             pybind11::arg("memsize"), pybind11::arg("ip_port"))
        .def("zb_fused_deep_moe", &fused_deep_moe::Buffer::zb_fused_deep_moe)
        .def("is_initialized", &fused_deep_moe::Buffer::is_initialized)
        .def("get_ext_info", &fused_deep_moe::Buffer::get_ext_info)
        .def("get_shmem_workspace", &fused_deep_moe::Buffer::get_shmem_workspace);
    m.def("gather_selection_kv_cache", &gather_selection_kv_cache_npu, "gather_selection_kv_cache");
    m.def("gather_selection_kv_cache_custom", &gather_selection_kv_cache_custom_npu,
          "gather_selection_kv_cache_custom");
    m.def("quant_lightning_indexer", &quant_lightning_indexer_npu, "quant_lightning_indexer");
    m.def("swiglu_clip_quant", &swiglu_clip_quant_npu, "swiglu_clip_quant");
}

TORCH_LIBRARY(umdk_cam_op_lib, m) {
    m.def("fused_deep_moe(Tensor x, Tensor expert_ids, Tensor[] gmm1_weight, Tensor[] gmm1_weight_scale, \
    Tensor[] gmm2_weight, Tensor[] gmm2_weight_scale, Tensor expert_scales, \
    Tensor? share_gmm1_weight, Tensor? share_gmm1_weight_scale, \
    Tensor? share_gmm2_weight, Tensor? share_gmm2_weight_scale, \
    Tensor? expert_smooth_scales, Tensor? share_smooth_scales, Tensor? x_active_mask, \
    Tensor[] gmm1_bias, Tensor[] gmm2_bias, \
    Tensor? share_gmm1_bias, Tensor? share_gmm2_bias, \
    str group_ep, int ep_rank_size, int ep_rank_id, int moe_expert_num, \
    int quant_mode, int global_bs) -> Tensor[]");
    m.def("all2_all_detour(Tensor sendData, Tensor commRankIds, Tensor commArgs, int commId) -> Tensor");
    m.def("reduce_scatter_detour(Tensor sendData, Tensor commRankIds, Tensor commArgs, int commId, int op) -> Tensor");
    m.def("cam_get_comm(int comm_id, int rank, int group_size, str server_ip_port) -> Tensor");
    m.def("cam_free_comm(int comm_id) -> Tensor");
    m.def("a2e(Tensor x, Tensor? expert_ids, Tensor? scales, int batch_size, int hidden_size, \
    int topk, int expert_rank_size, int atten_rank_size, int rank, str group_ep, \
    int aiv_num, int compute_gate) -> Tensor[]");
    m.def("e2a(Tensor expand_x, Tensor atten_batch_size, int batch_size, int hidden_size, \
    int topk, int expert_rank_size,  int attention_rank_size, int rank, str group_ep, \
    int aiv_num) -> Tensor");
    m.def("gather_selection_kv_cache(Tensor(a!) selection_k_rope, Tensor(b!) selection_kv_cache, Tensor(c!) \
        selection_kv_block_table, Tensor(d!) selection_kv_block_status, Tensor selection_topk_indices, \
        Tensor full_k_rope, Tensor full_kv_cache, Tensor full_kv_block_table, Tensor full_kv_actual_seq, \
        Tensor full_q_actual_seq, *, int selection_topk_block_size=64) -> Tensor");
    m.def("gather_selection_kv_cache_functional(Tensor selection_k_rope, Tensor selection_kv_cache, \
        Tensor selection_kv_block_table, Tensor selection_kv_block_status, Tensor selection_topk_indices, \
        Tensor full_k_rope, Tensor full_kv_cache, Tensor full_kv_block_table, Tensor full_kv_actual_seq, \
        Tensor full_q_actual_seq, *, int selection_topk_block_size=64) -> (Tensor, Tensor, Tensor, Tensor, Tensor)");
    m.def("gather_selection_kv_cache_custom(Tensor(a!) selection_k_rope, Tensor(b!) selection_kv_cache, Tensor(c!) \
        selection_kv_block_table, Tensor(d!) selection_kv_block_status, Tensor selection_topk_indices, \
        Tensor full_k_rope, Tensor full_kv_cache, Tensor full_kv_block_table, Tensor full_kv_actual_seq, \
        Tensor full_q_actual_seq, *, int selection_topk_block_size=1) -> Tensor");
    m.def("gather_selection_kv_cache_custom_functional(Tensor selection_k_rope, Tensor selection_kv_cache, \
        Tensor selection_kv_block_table, Tensor selection_kv_block_status, Tensor selection_topk_indices, \
        Tensor full_k_rope, Tensor full_kv_cache, Tensor full_kv_block_table, Tensor full_kv_actual_seq, \
        Tensor full_q_actual_seq, *, int selection_topk_block_size=1) -> (Tensor, Tensor, Tensor, Tensor, Tensor)");
    m.def("quant_lightning_indexer(Tensor query, Tensor key, Tensor weights, Tensor query_dequant_scale, \
        Tensor key_dequant_scale, int query_quant_mode, int key_quant_mode, *, Tensor? actual_seq_lengths_query=None, \
        Tensor? actual_seq_lengths_key=None, Tensor? block_table=None, Tensor? metadata=None, str layout_query='BSND',\
        str layout_key='PA_BSND', int sparse_count=2048, int sparse_mode=3, int pre_tokens=9223372036854775807, \
        int next_tokens=9223372036854775807, int cmp_ratio=1, bool return_value=False, int? query_dtype=None, \
        int? key_dtype=None) -> (Tensor, Tensor)");
    m.def("swiglu_clip_quant(Tensor x, Tensor group_index, Tensor group_alpha, *, bool activate_left=False, \
        int quant_mode=1, int clamp_mode=1) -> (Tensor, Tensor)");
}
