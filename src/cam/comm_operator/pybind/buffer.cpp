/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: add zb_fused_deep_moe pybind
 * Create: 2026-05-30
 * Note:
 * History: 2026-05-30 add zb_fused_deep_moe pybind
 */

#include "buffer.h"
#include <iostream>
#include <stdexcept>
#include "shmem.h"
#include "pytorch_npu_helper.hpp"

using TensorVector = std::vector<at::Tensor>;
namespace fused_deep_moe {

constexpr uint64_t EXT_INFO_SIZE = 2 * 1024 * 1024;

Buffer::~Buffer() noexcept(false)
{
    if (initialized_) {
        if (ext_info_ptr_ != nullptr) {
            shmem_free(ext_info_ptr_);
            ext_info_ptr_ = nullptr;
        }
        if (shmem_workspace_ptr_ != nullptr) {
            shmem_free(shmem_workspace_ptr_);
            shmem_workspace_ptr_ = nullptr;
        }
        shmem_finalize();
        initialized_ = false;
    }
}

int32_t shmem_set_attr(int32_t my_pe, int32_t n_pes, uint64_t local_mem_size,
                       const char *ip_port, aclshmemx_uniqueid_t default_flag_uid,
                       aclshmemx_init_attr_t *attributes)
{
    size_t ip_len = 0;
    if (ip_port != nullptr) {
        ip_len = std::min(strlen(ip_port), static_cast<size_t>(ACLSHMEM_MAX_IP_PORT_LEN) - 1);
        std::copy_n(ip_port, ip_len, attributes->ip_port);
        if (attributes->ip_port[0] == '\0') {
            return ACLSHMEM_INVALID_VALUE;
        }
    }
    int attr_version = (1 << 16) + sizeof(aclshmemx_init_attr_t);
    attributes->my_pe = my_pe;
    attributes->n_pes = n_pes;
    attributes->local_mem_size = local_mem_size;
    attributes->ip_port[ip_len] = '\0';
    attributes->option_attr = {attr_version, ACLSHMEM_DATA_OP_MTE, DEFAULT_TIMEOUT,
                                DEFAULT_TIMEOUT, DEFAULT_TIMEOUT};
    attributes->comm_args = reinterpret_cast<void *>(&default_flag_uid);
    return ACLSHMEM_SUCCESS;
}
                                     

void Buffer::init(int rank, int num_ranks, uint64_t memsize, const std::string &ip_port)
{
    if (initialized_) {
        return;
    }

    rank_ = rank;
    num_ranks_ = num_ranks;

    // Shmem init
    int32_t status = 0;
    const char *ipport = ip_port.c_str();
    uint64_t local_mem_size = memsize;
    aclshmemx_set_conf_store_tls(false, nullptr, 0);
    aclshmemx_init_attr_t attributes;
    aclshmemx_uniqueid_t default_flag_uid = {};
    status = shmem_set_attr(rank, num_ranks, local_mem_size, ipport, default_flag_uid, &attributes);
    if (status != ACLSHMEM_SUCCESS) {
        throw std::runtime_error("shmem_set_attr failed");
    }
    status = aclshmemx_init_attr(ACLSHMEMX_INIT_WITH_DEFAULT, &attributes);
    if (status != ACLSHMEM_SUCCESS) {
        throw std::runtime_error("shmem_init_attr failed");
    }
    if (aclshmemx_init_status() != ACLSHMEM_STATUS_IS_INITIALIZED) {
        throw std::runtime_error("shmem not initialized");
    }

    ext_info_ptr_ = aclshmem_malloc(EXT_INFO_SIZE);
    if (ext_info_ptr_ == nullptr) {
        throw std::runtime_error("aclshmem_malloc ext_info failed");
    }

    shmem_workspace_size_ = local_mem_size - EXT_INFO_SIZE;
    shmem_workspace_ptr_ = aclshmem_malloc(shmem_workspace_size_);
    if (shmem_workspace_ptr_ == nullptr) {
        throw std::runtime_error("aclshmem_malloc shmem_workspace failed");
    }

    initialized_ = true;
}

int64_t Buffer::get_ext_info() const
{
    return reinterpret_cast<int64_t>(ext_info_ptr_);
}

int64_t Buffer::get_shmem_workspace() const
{
    return reinterpret_cast<int64_t>(shmem_workspace_ptr_);
}

bool Buffer::is_initialized() const
{
    return initialized_;
}

std::vector<at::Tensor> Buffer::zb_fused_deep_moe(
    const at::Tensor &x,
    const at::Tensor &expert_ids,
    const TensorVector &gmm1_weight,
    const TensorVector &gmm1_weight_scale,
    const TensorVector &gmm2_weight,
    const TensorVector &gmm2_weight_scale,
    const at::Tensor &expert_scales,
    const c10::optional<at::Tensor> &share_gmm1_weight,
    const c10::optional<at::Tensor> &share_gmm1_weight_scale,
    const c10::optional<at::Tensor> &share_gmm2_weight,
    const c10::optional<at::Tensor> &share_gmm2_weight_scale,
    const c10::optional<at::Tensor> &expert_smooth_scales,
    const c10::optional<at::Tensor> &share_smooth_scales,
    const c10::optional<at::Tensor> &x_active_mask,
    c10::string_view group_ep,
    int64_t ep_rank_size,
    int64_t ep_rank_id,
    int64_t moe_expert_num,
    int64_t quant_mode,
    int64_t global_bs)
{
    if (!initialized_) {
        throw std::runtime_error("Buffer not initialized, call init() first");
    }

    auto x_shape = x.sizes();
    int h = x_shape[1];
    int bs = x_shape[0];

    auto gmm1_weight_list = at::TensorList(gmm1_weight);
    auto gmm1_weight_scale_list = at::TensorList(gmm1_weight_scale);
    auto gmm2_weight_list = at::TensorList(gmm2_weight);
    auto gmm2_weight_scale_list = at::TensorList(gmm2_weight_scale);
    
    at::Tensor output = at::empty({bs, h}, x.options());
    at::Tensor share_output = at::empty({bs, h}, x.options());

    int64_t local_expert_num = moe_expert_num / ep_rank_size;
    auto opts = expert_ids.options().dtype(at::kLong);
    at::Tensor expert_token_nums = at::empty({local_expert_num}, opts);

    const std::string group_ep_str(group_ep.data(), group_ep.size());
    const char *group_ep_ptr = group_ep_str.c_str();

    int64_t ext_info = get_ext_info();
    int64_t shmem_workspace = get_shmem_workspace();

    EXEC_NPU_CMD(aclnnFusedDeepMoe,
        x, expert_ids, gmm1_weight_list, gmm1_weight_scale_list, gmm2_weight_list, gmm2_weight_scale_list,
        expert_scales,
        share_gmm1_weight, share_gmm1_weight_scale,
        share_gmm2_weight, share_gmm2_weight_scale,
        expert_smooth_scales, share_smooth_scales, x_active_mask,
        group_ep_ptr, ep_rank_size, ep_rank_id, moe_expert_num, quant_mode, global_bs,
        ext_info, shmem_workspace,
        output, share_output, expert_token_nums);

    return {output, share_output, expert_token_nums};
}

}  // namespace fused_deep_moe
