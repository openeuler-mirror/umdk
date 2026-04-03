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

PYBIND11_MODULE(TORCH_EXTENSION_NAME, m)
{
    m.def("fused_deep_moe", &fused_deep_moe_impl_autograd, "fused_deep_moe");
    m.def("moe_dispatch_normal", &moe_dispatch_normal_impl_autograd, "moe_dispatch_normal");
    m.def("moe_combine_normal", &moe_combine_normal_impl_autograd, "moe_combine_normal");
    m.def("moe_dispatch_shmem", &moe_dispatch_shmem_impl_autograd, "moe_dispatch_shmem");
    m.def("moe_combine_shmem", &moe_combine_shmem_impl_autograd, "moe_combine_shmem");
    m.def("all2_all_detour", &all2_all_detour_impl_autograd, "all2_all_detour");
    m.def("reduce_scatter_detour", &reduce_scatter_detour_impl_autograd, "reduce_scatter_detour");
    m.def("cam_get_comm", &cam_get_comm, "cam_get_comm");
    m.def("cam_free_comm", &cam_free_comm, "cam_free_comm");
    m.def("cam_get_rank_size", &cam_get_rank_size, "cam_get_rank_size");
    m.def("cam_get_and_increase_magic", &cam_get_and_increase_magic, "cam_get_and_increase_magic");
    m.def("cam_get_magic", &cam_get_magic, "cam_get_magic");
    m.def("a2e", &A2eImplAutograd, "a2e");
    m.def("e2a", &E2aImplAutograd, "e2a");
}

TORCH_LIBRARY(umdk_cam_op_lib, m) {
    m.def("fused_deep_moe(Tensor x, Tensor expertIds, Tensor[] gmm1PermutedWeight, Tensor[] gmm1PermutedWeightScale, \
    Tensor[] gmm2Weight, Tensor[] gmm2WeightScale, Tensor? expertSmoothScalesOptional, Tensor? expertScalesOptional, \
    str groupEp, int epRankSize, int epRankId, int moeExpertNum, int sharedExpertNum, int sharedExpertRankNum, \
    int quantMode, int globalBs) -> Tensor[]");
    m.def("moe_dispatch_normal(Tensor x, Tensor topkIdx, Tensor sendOffset, Tensor sendTokenIdx, Tensor recvOffset, \
    Tensor recvCount, str groupEp, int epWorldSize, int epRankId, str groupTp, int tpWorldSize, int tpRankId, \
    int moeExpertNum, int quantMode, int globalBs) -> (Tensor, Tensor, Tensor)");
    m.def("moe_combine_normal(Tensor recvX, Tensor tokenSrcInfo, Tensor epRecvCounts, Tensor recvTopkWeights, \
    Tensor? tpRecvCounts, str epGroupName, int epWorldSize, int epRankId, str tpGroupName, int tpWorldSize, \
    int tpRankId, int moeExpertNum, int globalBs) -> Tensor");
    m.def("moe_dispatch_shmem(Tensor x, Tensor expertIds, Tensor? scales, Tensor? xActiveMask, \
    int epWorldSize, int epRankId, int moeExpertNum, int tpWorldSize, int tpRankId, \
    int expertShardType, int sharedExpertNum, int sharedExpertRankNum, int quantMode, int globalBS, int expertTokenNumsType, int extInfo) -> Tensor[]");
    m.def("moe_combine_shmem(Tensor expandX, Tensor expertIds, Tensor expandIdx, Tensor epSendCounts, \
    Tensor expertScales, Tensor? tpSendCounts, Tensor? xActiveMask, Tensor? activationScale, Tensor? weightScale, \
    Tensor? groupList, Tensor? expandScales, int epWorldSize, int epRankId, int moeExpertNum, int tpWorldSize, \
    int tpRankId, int expertShardType, int sharedExpertNum, int sharedExpertRankNum, int globalBS, int commQuantMode, \
    int extInfo, int outDtype, int groupListType) -> Tensor");
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
}
