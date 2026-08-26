/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: ZB normal MoE session Buffer implementation
 * Create: 2026-08-05
 */

#include "zb_buffer.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "pytorch_npu_helper.hpp"
#include "torch_bind_exception.h"
#include "zb_shmem_utils.h"

#ifdef SHMEM_ENABLED
#include "shmem.h"
#endif

namespace cam_zb {
namespace {

constexpr int64_t DYNAMIC_QUANT_MODE = 2;
constexpr int64_t TP_WORLD_SIZE = 1;
constexpr int64_t TP_RANK_ID = 0;
constexpr int64_t SEND_PER_GROUP = 1;
constexpr int64_t MIN_EP_WORLD_SIZE = 2;  // ZB needs at least two EP ranks
constexpr int64_t TOPK_IDX_DIM = 2;       // topk_idx shape: [num_tokens, topk]
constexpr int LOCAL_RANK_SIZE = 8;

#ifdef SHMEM_ENABLED
inline int32_t SetShmemAttr(int32_t myPe, int32_t nPes, uint64_t localMemSize, const char *ipPort,
    aclshmemx_uniqueid_t *uid, aclshmemx_init_attr_t *attributes)
{
    size_t ipLen = 0;
    if (ipPort != nullptr) {
        ipLen = std::min(strlen(ipPort), static_cast<size_t>(ACLSHMEM_MAX_IP_PORT_LEN) - 1);
        std::copy_n(ipPort, ipLen, attributes->ip_port);
        if (attributes->ip_port[0] == '\0') {
            return ACLSHMEM_INVALID_VALUE;
        }
    }
    int attrVersion = (1 << 16) + static_cast<int>(sizeof(aclshmemx_init_attr_t));
    attributes->my_pe = myPe;
    attributes->n_pes = nPes;
    attributes->ip_port[ipLen] = '\0';
    attributes->local_mem_size = localMemSize;
    attributes->option_attr = {attrVersion, ACLSHMEM_DATA_OP_MTE, DEFAULT_TIMEOUT, DEFAULT_TIMEOUT, DEFAULT_TIMEOUT};
    attributes->comm_args = reinterpret_cast<void *>(uid);
    return ACLSHMEM_SUCCESS;
}
#endif

inline void FreeOwnedShmemTensor(at::Tensor &t)
{
#ifdef SHMEM_ENABLED
    if (t.defined() && t.numel() > 0) {
        void *ptr = t.data_ptr();
        t = at::Tensor();
        if (ptr != nullptr) {
            aclshmem_free(ptr);
        }
    } else {
        t = at::Tensor();
    }
#else
    t = at::Tensor();
#endif
}

}  // namespace

ZbBuffer::ZbBuffer(int64_t rank, int64_t numRanks, int64_t localMemSize, const std::string &ipPort, int64_t hidden,
    int64_t numExperts, bool useQuant, int64_t globalBs)
    : rank_(rank),
      numRanks_(numRanks),
      hidden_(hidden),
      numExperts_(numExperts),
      globalBs_(std::max<int64_t>(globalBs, 1)),
      useQuant_(useQuant)
{
    if (rank < 0 || numRanks < MIN_EP_WORLD_SIZE) {
        throw std::runtime_error("ZbBuffer: invalid rank / num_ranks");
    }
    if (hidden <= 0 || numExperts <= 0) {
        throw std::runtime_error("ZbBuffer: hidden and num_experts must be > 0");
    }
    if (numExperts % numRanks != 0) {
        throw std::runtime_error("ZbBuffer: num_experts must be divisible by num_ranks");
    }

    int32_t curDevice = -1;
    if (aclrtGetDevice(&curDevice) != ACL_SUCCESS || curDevice < 0) {
        throw std::runtime_error("ZbBuffer: aclrtGetDevice failed; call torch.npu.set_device before ZbBuffer");
    }
    deviceIndex_ = static_cast<int64_t>(curDevice);

    InitShmem(localMemSize, ipPort);
    initialized_ = true;
    try {
        PreallocateLayoutNotifySlots(NpuDevice());
    } catch (...) {
        FreeSlots();
        FinalizeShmem();
        initialized_ = false;
        throw;
    }
}

ZbBuffer::~ZbBuffer() noexcept(false)
{
    if (!initialized_) {
        return;
    }
    FreeSlots();
    FinalizeShmem();
    initialized_ = false;
}

void ZbBuffer::InitShmem(int64_t localMemSize, const std::string &ipPort)
{
#ifdef SHMEM_ENABLED
    int32_t status = aclshmemx_set_conf_store_tls(false, nullptr, 0);
    if (status != ACLSHMEM_SUCCESS) {
        throw std::runtime_error("ZbBuffer: aclshmemx_set_conf_store_tls failed");
    }

    aclshmemx_init_attr_t attributes{};
    static thread_local aclshmemx_uniqueid_t tlsUid{};
    tlsUid = {};
    status = SetShmemAttr(static_cast<int32_t>(rank_), static_cast<int32_t>(numRanks_),
        static_cast<uint64_t>(localMemSize), ipPort.c_str(), &tlsUid, &attributes);
    if (status != ACLSHMEM_SUCCESS) {
        throw std::runtime_error("ZbBuffer: set shmem attr failed");
    }
    status = aclshmemx_init_attr(ACLSHMEMX_INIT_WITH_DEFAULT, &attributes);
    if (status != ACLSHMEM_SUCCESS) {
        throw std::runtime_error("ZbBuffer: aclshmemx_init_attr failed");
    }
    if (aclshmemx_init_status() != ACLSHMEM_STATUS_IS_INITIALIZED) {
        throw std::runtime_error("ZbBuffer: shmem not initialized");
    }

    metaPtr_ = aclshmem_malloc(META_BYTES);
    if (metaPtr_ == nullptr) {
        throw std::runtime_error("ZbBuffer: aclshmem_malloc meta failed");
    }
    auto metaOpts = torch::TensorOptions().dtype(at::kByte).device(NpuDevice());
    auto metaView = at_npu::native::from_blob(metaPtr_, c10::IntArrayRef({static_cast<int64_t>(META_BYTES)}), metaOpts);
    metaView.zero_();
#else
    (void)localMemSize;
    (void)ipPort;
    throw std::runtime_error(
        "ZbBuffer requires SHMEM. Export SHMEM_HOME_PATH and rebuild umdk_cam_op_lib.");
#endif
}

void ZbBuffer::PreallocateLayoutNotifySlots(c10::Device device)
{
    const int64_t E = numExperts_;
    const int64_t R = numRanks_;

    numTokensPerExpert_ = CreateTensorFromShmem({E}, at::kInt, device);
    numTokensPerExpert_.zero_();

    recvData_ = CreateTensorFromShmem({R, E}, at::kInt, device);
}

void ZbBuffer::EnsureDispatchCombineSlots(at::ScalarType dtype, c10::Device device, int64_t topk)
{
    if (dtype != at::kBFloat16 && dtype != at::kHalf) {
        throw std::runtime_error("ZbBuffer: x dtype must be torch.bfloat16 or torch.float16");
    }
    if (topk <= 0) {
        throw std::runtime_error("ZbBuffer: topk must be > 0");
    }
    const int64_t localExperts = numExperts_ / numRanks_;
    const int64_t needSlots = globalBs_ * std::min(localExperts, topk);
    if (combineX_.defined()) {
        if (dtype != dtype_) {
            throw std::runtime_error("ZbBuffer: x dtype does not match Buffer session dtype from first dispatch");
        }
        if (needSlots > slotCount_) {
            throw std::runtime_error(
                "ZbBuffer: topk/localExperts require more SHMEM slots than first dispatch allocated");
        }
        return;
    }

    dtype_ = dtype;
    slotCount_ = needSlots;
    const int64_t H = hidden_;
    const int64_t T = slotCount_;
    combineX_ = CreateTensorFromShmem({T, H}, dtype_, device);
    if (useQuant_) {
        auto charOpts = torch::TensorOptions().dtype(at::kChar).device(device);
        expandx_ = at_npu::native::from_blob(combineX_.data_ptr(), c10::IntArrayRef({T, H}), charOpts);
        expandx_.zero_();
        scales_ = CreateTensorFromShmem({T}, at::kFloat, device);
        scales_.zero_();
    } else {
        expandx_ = combineX_;
        scales_ = at::empty({1}, at::dtype(at::kFloat).device(device));
    }
}

void ZbBuffer::FreeSlots()
{
    if (useQuant_) {
        expandx_ = at::Tensor();
        FreeOwnedShmemTensor(scales_);
    } else {
        expandx_ = at::Tensor();
    }
    FreeOwnedShmemTensor(combineX_);
    FreeOwnedShmemTensor(recvData_);
    FreeOwnedShmemTensor(numTokensPerExpert_);
    sendTokenIdx_ = at::Tensor();
    putOffset_ = at::Tensor();

#ifdef SHMEM_ENABLED
    if (metaPtr_ != nullptr) {
        aclshmem_free(metaPtr_);
        metaPtr_ = nullptr;
    }
#endif
}

void ZbBuffer::FinalizeShmem()
{
#ifdef SHMEM_ENABLED
    (void)aclshmem_finalize();
#endif
}

std::tuple<at::Tensor, at::Tensor> ZbBuffer::get_dispatch_layout(const at::Tensor &topkIdx)
{
    if (!initialized_) {
        throw std::runtime_error("ZbBuffer: not initialized");
    }

    at::Tensor topkIdxInt32 = topkIdx.scalar_type() == at::kInt ? topkIdx : topkIdx.to(at::kInt);
    TORCH_BIND_ASSERT(topkIdxInt32.dim() == TOPK_IDX_DIM);
    TORCH_BIND_ASSERT(topkIdxInt32.is_contiguous());

    int64_t numTokensI64 = topkIdxInt32.size(0);
    int64_t numTopkI64 = topkIdxInt32.size(1);
    int64_t localRanksizeI64 = LOCAL_RANK_SIZE;
    int64_t numRanksI64 = numRanks_;
    int64_t numExpertsI64 = numExperts_;
    auto serverNum = numRanks_ / LOCAL_RANK_SIZE;
    auto device = topkIdxInt32.device();

    numTokensPerExpert_.zero_();
    auto numTokensPerRank = at::zeros({numRanks_}, at::dtype(at::kInt).device(device));
    auto isTokenInRank = at::zeros({numTokensI64, numRanks_}, at::dtype(at::kInt).device(device));
    constexpr int64_t kLegacyMaxBatch = 4096;
    const int64_t layoutBatchCap = std::max(numTokensI64, kLegacyMaxBatch);
    const int64_t expertDataSize = 1 + layoutBatchCap;
    const int64_t notifySendDataSize =
        numExperts_ * expertDataSize + serverNum + layoutBatchCap * (1 + 2 * serverNum + numExperts_);
    sendTokenIdx_ = at::zeros({numTokensI64, numTopkI64}, at::dtype(at::kInt).device(device));
    auto notifySendData = at::zeros({notifySendDataSize}, at::dtype(at::kInt).device(device));

    EXEC_NPU_CMD(aclnnDispatchLayoutZb, topkIdxInt32, numTokensI64, numRanksI64, numExpertsI64, numTopkI64,
        localRanksizeI64, numTokensPerRank, numTokensPerExpert_, isTokenInRank, notifySendData, sendTokenIdx_);

    return std::make_tuple(numTokensPerExpert_, sendTokenIdx_);
}

std::tuple<at::Tensor, at::Tensor, at::Tensor> ZbBuffer::dispatch(const at::Tensor &x, const at::Tensor &topkIdx,
    const at::Tensor &sendTokenIdx, const at::Tensor &numTokensPerExpert, int64_t quantMode)
{
    if (!initialized_) {
        throw std::runtime_error("ZbBuffer: not initialized");
    }
    if ((quantMode == DYNAMIC_QUANT_MODE) != useQuant_) {
        throw std::runtime_error("ZbBuffer: quantMode does not match Buffer use_quant construction flag");
    }

    auto device = x.device();
    if (numTokensPerExpert_.defined() && device != numTokensPerExpert_.device()) {
        throw std::runtime_error("ZbBuffer: x device must match Buffer layout/notify slot device");
    }
    int64_t topkNum = topkIdx.size(1);
    EnsureDispatchCombineSlots(x.scalar_type(), device, topkNum);
    int64_t numLocalExperts = numExperts_ / numRanks_;
    int64_t localRankSize = numRanks_;
    int64_t localRankId = rank_ % localRankSize;
    int64_t sendCount = SEND_PER_GROUP * numExperts_;
    int64_t epWorldSize = numRanks_;
    int64_t epRankId = rank_;
    int64_t moeExpertNum = numExperts_;
    int64_t globalBs = globalBs_;
    int64_t tpWorldSize = TP_WORLD_SIZE;
    int64_t tpRankId = TP_RANK_ID;
    int64_t quantModeLocal = quantMode;

    sendTokenIdx_ = sendTokenIdx;

    auto totalRecvTokens = at::empty({1}, at::dtype(at::kInt).device(device));
    auto maxBs = at::empty({1}, at::dtype(at::kInt).device(device));
    auto recvTokensPerExpert = at::empty({numLocalExperts}, at::dtype(at::kLong).device(device));
    putOffset_ = at::zeros({numExperts_, numRanks_}, at::dtype(at::kInt).device(device));

    uint64_t commMetaPtrU64 = reinterpret_cast<uint64_t>(metaPtr_);
    EXEC_NPU_CMD(aclnnNotifyDispatchZb, numTokensPerExpert, sendCount, epWorldSize, epRankId, localRankSize,
        localRankId, topkNum, commMetaPtrU64, recvData_, totalRecvTokens, maxBs, recvTokensPerExpert, putOffset_);

    at::Tensor recvX = expandx_;
    at::Tensor recvXScales = useQuant_ ? scales_ : at::empty({1}, at::dtype(at::kFloat).device(device));

    EXEC_NPU_CMD(aclnnMoeDispatchNormalZb, x, topkIdx, sendTokenIdx, putOffset_, epWorldSize, epRankId, tpWorldSize,
        tpRankId, moeExpertNum, quantModeLocal, globalBs, commMetaPtrU64, recvX, recvXScales);

    int64_t actualRecv = static_cast<int64_t>(totalRecvTokens.item<int>());
    if (actualRecv <= 0) {
        actualRecv = 1;
    }
    recvX = recvX.slice(0, 0, actualRecv);
    if (useQuant_) {
        recvXScales = recvXScales.slice(0, 0, actualRecv);
    }

    return std::make_tuple(recvX, recvXScales, putOffset_);
}

at::Tensor ZbBuffer::combine(const at::Tensor &expertOut, const at::Tensor &topkWeights, const at::Tensor &topkIdx,
    const at::Tensor &handle)
{
    if (!initialized_) {
        throw std::runtime_error("ZbBuffer: not initialized");
    }
    if (!combineX_.defined()) {
        throw std::runtime_error("ZbBuffer: combine slot not allocated");
    }
    if (expertOut.size(0) > combineX_.size(0) || expertOut.size(1) != combineX_.size(1)) {
        throw std::runtime_error("ZbBuffer: expert_out shape exceeds combine SHMEM slot");
    }
    if (expertOut.scalar_type() != combineX_.scalar_type()) {
        throw std::runtime_error("ZbBuffer: expert_out dtype must match combine slot (bf16/fp16)");
    }

    at::Tensor shmemX = combineX_;
    if (expertOut.data_ptr() != combineX_.data_ptr()) {
        shmemX.slice(0, 0, expertOut.size(0)).copy_(expertOut);
    }

    at::Tensor epRecvCounts = handle.defined() ? handle : putOffset_;
    c10::optional<at::Tensor> sendTokenIdxOpt =
        sendTokenIdx_.defined() ? c10::optional<at::Tensor>(sendTokenIdx_) : c10::nullopt;
    c10::optional<at::Tensor> sendCostStats = c10::nullopt;

    auto combinedX = at::empty({topkWeights.size(0), expertOut.size(1)}, expertOut.options());
    uint64_t commMetaPtrU64 = reinterpret_cast<uint64_t>(metaPtr_);
    int64_t epWorldSize = numRanks_;
    int64_t epRankId = rank_;
    int64_t tpWorldSize = TP_WORLD_SIZE;
    int64_t tpRankId = TP_RANK_ID;
    int64_t moeExpertNum = numExperts_;
    int64_t globalBs = globalBs_;

    EXEC_NPU_CMD(aclnnMoeCombineNormalZb, shmemX, epRecvCounts, topkWeights, topkIdx, sendTokenIdxOpt, commMetaPtrU64,
        epWorldSize, epRankId, tpWorldSize, tpRankId, moeExpertNum, globalBs, combinedX, sendCostStats);
    return combinedX;
}

}  // namespace cam_zb
