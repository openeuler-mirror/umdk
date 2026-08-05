/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add pybind
 * Create: 2025-12-10
 * Note:
 * History: 2025-12-10 add pybind
 *          2026-08-05 expose ZbBuffer; drop per-op *_zb torch.ops
 */

#include "functions.h"
#include "zb_buffer.h"
#include <torch/extension.h>

PYBIND11_MODULE(TORCH_EXTENSION_NAME, m)
{
    m.def("fused_deep_moe", &FusedDeepMoeImplAutograd, "fused_deep_moe");
    m.def("get_dispatch_layout", &GetDispatchLayoutImplAutograd, "get_dispatch_layout");
    m.def("moe_dispatch_prefill", &MoeDispatchPrefillImplAutograd, "moe_dispatch_prefill");
    m.def("moe_combine_prefill", &MoeCombinePrefillImplAutograd, "moe_combine_prefill");

    pybind11::class_<cam_zb::ZbBuffer>(m, "ZbBuffer")
        .def(pybind11::init<int64_t, int64_t, int64_t, const std::string &, int64_t, int64_t, bool, int64_t>(),
            pybind11::arg("rank"), pybind11::arg("num_ranks"), pybind11::arg("local_mem_size"),
            pybind11::arg("ip_port"), pybind11::arg("hidden"), pybind11::arg("num_experts"),
            pybind11::arg("use_quant"), pybind11::arg("global_bs"),
            "ZB normal MoE session: owns SHMEM init + named tensor slots")
        .def("is_initialized", &cam_zb::ZbBuffer::is_initialized)
        .def("get_comm_meta_ptr", &cam_zb::ZbBuffer::get_comm_meta_ptr)
        .def("get_dispatch_layout", &cam_zb::ZbBuffer::get_dispatch_layout, pybind11::arg("topk_idx"))
        .def("dispatch", &cam_zb::ZbBuffer::dispatch, pybind11::arg("x"), pybind11::arg("topk_idx"),
            pybind11::arg("send_token_idx"), pybind11::arg("num_tokens_per_expert"), pybind11::arg("quant_mode"))
        .def("combine", &cam_zb::ZbBuffer::combine, pybind11::arg("expert_out"), pybind11::arg("topk_weights"),
            pybind11::arg("topk_idx"), pybind11::arg("handle"));
}

TORCH_LIBRARY(umdk_cam_op_lib, m)
{
    m.def("fused_deep_moe(Tensor x, Tensor expert_ids, Tensor[] gmm1_weight, Tensor[] gmm1_weight_scale, \
    Tensor[] gmm2_weight, Tensor[] gmm2_weight_scale, Tensor expert_scales, \
    Tensor? share_gmm1_weight, Tensor? share_gmm1_weight_scale, \
    Tensor? share_gmm2_weight, Tensor? share_gmm2_weight_scale, \
    Tensor? expert_smooth_scales, Tensor? share_smooth_scales, Tensor? x_active_mask, \
    str group_ep, int ep_rank_size, int ep_rank_id, int moe_expert_num, \
    int quant_mode, int global_bs) -> Tensor[]");
    m.def("get_dispatch_layout(Tensor topk_idx, int num_experts, int num_ranks) -> (Tensor, Tensor)");
    m.def("moe_dispatch_prefill(Tensor x, Tensor topk_idx, Tensor topk_weights, Tensor num_tokens_per_expert, \
    Tensor send_token_idx_small, str group_ep, int rank, int num_ranks, bool use_quant) \
    -> (Tensor, Tensor, Tensor, Tensor, Tensor)");
    m.def("moe_combine_prefill(Tensor x, Tensor topk_idx, Tensor topk_weights, Tensor src_idx, Tensor send_head, \
    str group_ep, int rank, int num_ranks) -> Tensor");
}
