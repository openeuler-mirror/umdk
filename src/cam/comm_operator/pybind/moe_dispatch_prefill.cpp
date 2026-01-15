/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: add moe_dispatch_prefill pybind extention file
 * Create: 2026-01-08
 * Note:
 * History: 2026-01-08 create moe_dispatch_prefill pybind extention file
 */

#include <unistd.h>
#include <hccl/hccl.h>
#include <torch/extension.h>
#include <torch/csrc/autograd/custom_function.h>
#include "torch_npu/csrc/core/npu/NPUStream.h"
#include "pytorch_npu_helper.hpp"
#include "utils.h"
#include <hccl/hccl.h>
#include <iostream>

using torch::autograd::AutogradContext;
using torch::autograd::Function;
using TensorVector = std::vector<at::Tensor>;
using namespace at;
using namespace std;

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillImplNpu(
    const at::Tensor& x,
    const at::Tensor& topkIdx,
    const at::Tensor& topkWeights,
    const at::Tensor& numTokensPerRank,
    const at::Tensor& isTokenInRank,
    at::Tensor& numTokensPerExpert,
    int64_t numWorstTokens,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks)
{
    std::vector<char> groupEpChrs(groupEp.begin(), groupEp.end());
    groupEpChrs.push_back('\0');
    char* groupEpPtr = &groupEpChrs[0];
    at::Tensor newX = x;

    // Type checks
    TORCH_BIND_ASSERT(isTokenInRank.scalar_type() == at::kBool);
    TORCH_BIND_ASSERT(numTokensPerExpert.scalar_type() == at::kInt);
    TORCH_BIND_ASSERT(numTokensPerRank.scalar_type() == at::kInt);

    // Shape and contiguous checks
    TORCH_BIND_ASSERT(newX.dim() == 2 and newX.is_contiguous());
    TORCH_BIND_ASSERT(isTokenInRank.dim() == 2 and isTokenInRank.is_contiguous());
    TORCH_BIND_ASSERT(isTokenInRank.size(0) == newX.size(0) and isTokenInRank.size(1) == numRanks);
    TORCH_BIND_ASSERT(numTokensPerExpert.dim() == 1 and numTokensPerExpert.is_contiguous());
    TORCH_BIND_ASSERT(numTokensPerExpert.size(0) % numRanks == 0);
    TORCH_BIND_ASSERT(numTokensPerRank.dim() == 1 and numTokensPerRank.is_contiguous());
    TORCH_BIND_ASSERT(numTokensPerRank.size(0) == numRanks);

    auto numTokens = static_cast<int>(newX.size(0));
    auto hidden = static_cast<int>(newX.size(1));
    auto numExperts = static_cast<int64_t>(numTokensPerExpert.size(0));
    auto numLocalExperts = static_cast<int>(numExperts / numRanks);

    // Top-k checks
    int numTopk = 0;
    numTopk = static_cast<int>(topkIdx.size(1));
    TORCH_BIND_ASSERT(numExperts > 0);
    TORCH_BIND_ASSERT(topkIdx.dim() == 2 and topkIdx.is_contiguous());
    TORCH_BIND_ASSERT(topkWeights.dim() == 2 and topkWeights.is_contiguous());
    TORCH_BIND_ASSERT(numTokens == topkIdx.size(0));
    TORCH_BIND_ASSERT(numTopk == topkWeights.size(1));
    TORCH_BIND_ASSERT(topkWeights.scalar_type() == at::kFloat);

    int sendPerGroup = 3;  // (send_to_expert_num, send_to_expert_offset, send_rank_tokens)

    auto sendData = at::empty({numExperts * sendPerGroup}, at::dtype(at::kInt).device(x.device()));
    int64_t sendCount = sendPerGroup * numLocalExperts * numRanks;

    auto sendDataOffset = at::empty({numExperts}, at::dtype(at::kInt).device(x.device()));
    at::Tensor recvData = at::empty({numExperts * sendPerGroup}, at::dtype(at::kInt).device(x.device()));

    int64_t localRankSize = numRanks;
    int64_t localRankId = rank % localRankSize;

    EXEC_NPU_CMD(aclnnNotifyDispatch,
        sendData,
        numTokensPerExpert, 
        sendCount,
        numTokens,
        groupEpPtr,  // commGroup
        numRanks,     // rankSize
        rank,          // rankId
        localRankSize,
        localRankId,
        sendDataOffset,
        recvData);

    auto optionsCpu = torch::TensorOptions().dtype(torch::kInt32).device(torch::kCPU);
    std::vector<int32_t> localExpertAcc(numExperts, 0);
    auto sendTokenIdxCpu = at::empty({numTokens, numTopk}, optionsCpu);
    auto sendTokenIdxPtr = sendTokenIdxCpu.data_ptr<int>();

    auto topkIdxCpu = topkIdx.to(at::kCPU);
    auto topkIdxPtr = topkIdxCpu.data_ptr<int64_t>();
    for (int i = 0; i < numTokens; ++i) {
        for (int j = 0; j < numTopk; ++j) {
            int64_t expertIdx = topkIdxPtr[i * numTopk + j];
            if (expertIdx >= 0) {
                int32_t cnt = localExpertAcc[expertIdx];
                sendTokenIdxPtr[i * numTopk + j] = cnt;
                localExpertAcc[expertIdx]++;
            }
        }
    }

    TORCH_BIND_ASSERT(recvData.dim() == 1 and recvData.is_contiguous());
    TORCH_BIND_ASSERT(recvData.size(0) % numExperts == 0);
    at::Tensor recvOffsetCpu = at::empty({numExperts}, optionsCpu);
    at::Tensor recvCountCpu = at::empty({numExperts}, optionsCpu);
    auto recvDataCpu = recvData.to(at::kCPU);
    auto recvDataPtr = recvDataCpu.data_ptr<int>();
    auto recvCountPtr = recvCountCpu.data_ptr<int>();
    auto recvOffsetPtr = recvOffsetCpu.data_ptr<int>();
    int64_t totalRecvTokens = 0;
    int64_t numMaxDispatchTokensPerRank = 0;
    std::vector<int64_t> numRecvTokensPerExpertList;

    for (int64_t localE = 0; localE < numLocalExperts; ++localE) {
        int64_t localExpertRecvTokens = 0;
        for (int64_t srcRank = 0; srcRank < numRanks; ++srcRank) {
            int64_t index = localE * numRanks + srcRank;
            int64_t pairIdx = sendPerGroup * (srcRank * numLocalExperts + localE);

            int recvCnt = recvDataPtr[pairIdx];                 // count from this srcRank for
                                                                    // this global_expert
            int recvOff = recvDataPtr[pairIdx + 1];             // offset in that srcRank's window
            int64_t sendNumTokens = recvDataPtr[pairIdx + 2];  // all bs from rank

            totalRecvTokens += recvCnt;
            recvCountPtr[index] = totalRecvTokens;
            recvOffsetPtr[index] = recvOff;
            numMaxDispatchTokensPerRank = std::max(numMaxDispatchTokensPerRank, sendNumTokens);

            localExpertRecvTokens += recvCnt;
        }
        numRecvTokensPerExpertList.push_back(localExpertRecvTokens);
    }
    auto option = torch::TensorOptions().dtype(torch::kInt64).device(torch::kCPU);
    at::Tensor numRecvTokensPerExpert = torch::from_blob(
        numRecvTokensPerExpertList.data(), {static_cast<int64_t>(numRecvTokensPerExpertList.size())}, option)
        .clone();

    at::Tensor expertIds = topkIdx.to(at::kInt);
    int64_t tpSize = 1;
    int64_t tpRank = 0;
    int64_t quantMode = 0;
    int64_t globalBs = static_cast<int64_t>(
        std::max(numMaxDispatchTokensPerRank * numRanks, static_cast<int64_t>(numWorstTokens)));

    auto sendTokenIdx = sendTokenIdxCpu.to(x.device());
    auto recvOffset = recvOffsetCpu.to(x.device());
    auto recvCount = recvCountCpu.to(x.device());

    int totalCnt = totalRecvTokens;
    if (totalCnt == 0) {
        totalCnt = 1;
    }
    auto expandxOut = at::empty({totalCnt, hidden}, x.options());
    auto dynamicScalesOut = at::empty({totalCnt}, at::dtype(at::kFloat).device(x.device()));
    auto expandIdxOut = at::empty({totalCnt * 3}, at::dtype(at::kInt).device(x.device()));

    EXEC_NPU_CMD(aclnnMoeDispatchNormal,
        newX,
        expertIds,
        sendDataOffset,
        sendTokenIdx,
        recvOffset,
        recvCount,
        groupEpPtr,  // commGroup
        numRanks,     // rankSize
        rank,          // rankId
        groupEpPtr,
        tpSize,
        tpRank,
        numExperts,
        quantMode,
        globalBs,
        expandxOut,
        dynamicScalesOut,
        expandIdxOut);

    // Return values
    return {expandxOut, expandIdxOut, recvCount, numRecvTokensPerExpert};
}

TensorVector MoeDispatchPrefillBackwardImplNpu(const at::Tensor &self)
{
    at::Tensor result = at::Tensor(self); // 创建输出内存
    return {result, result, result, result};
}

/* Normal类算子形状无法提前推导，不支持meta设备注册不支持GE使用 */
std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillImpl(
    const at::Tensor& x,
    const at::Tensor& topkIdx,
    const at::Tensor& topkWeights,
    const at::Tensor& numTokensPerRank,
    const at::Tensor& isTokenInRank,
    at::Tensor& numTokensPerExpert,
    int64_t numWorstTokens,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks)
{
    static auto op = torch::Dispatcher::singleton()
                        .findSchemaOrThrow("umdk_cam_op_lib::moe_dispatch_prefill", "")
                        .typed<decltype(MoeDispatchPrefillImpl)>();
    return op.call(x, topkIdx, topkWeights, numTokensPerRank, isTokenInRank, \
        numTokensPerExpert, numWorstTokens, groupEp, rank, numRanks);
}

// 通过继承torch::autograd::Function类实现前反向绑定
class ExtMoeDispatchPrefill : public torch::autograd::Function<ExtMoeDispatchPrefill> {
public:
    static TensorVector forward(
        AutogradContext *ctx, \
        const at::Tensor& x,
        const at::Tensor& topkIdx,
        const at::Tensor& topkWeights,
        const at::Tensor& numTokensPerRank,
        const at::Tensor& isTokenInRank,
        at::Tensor& numTokensPerExpert,
        int64_t numWorstTokens,
        c10::string_view groupEp,
        int64_t rank,
        int64_t numRanks)
    {
        at::AutoDispatchBelowADInplaceOrView guard;
        auto result = MoeDispatchPrefillImpl(x, topkIdx, topkWeights, numTokensPerRank, \
            isTokenInRank, numTokensPerExpert, numWorstTokens, groupEp, rank, numRanks);

        return {std::get<0>(result), std::get<1>(result), std::get<2>(result), std::get<3>(result)};
    }

    static TensorVector backward(
        AutogradContext *ctx, \
        TensorVector grad_outputs)
    {
        return {at::Tensor(), at::Tensor(), at::Tensor(), at::Tensor()};
    }
};

std::tuple<at::Tensor, at::Tensor, at::Tensor, at::Tensor> MoeDispatchPrefillImplAutograd(
    const at::Tensor& x,
    const at::Tensor& topkIdx,
    const at::Tensor& topkWeights,
    const at::Tensor& numTokensPerRank,
    const at::Tensor& isTokenInRank,
    at::Tensor& numTokensPerExpert,
    int64_t numWorstTokens,
    c10::string_view groupEp,
    int64_t rank,
    int64_t numRanks)
{
    auto result = ExtMoeDispatchPrefill::apply(x, topkIdx, topkWeights, numTokensPerRank, \
        isTokenInRank, numTokensPerExpert, numWorstTokens, groupEp, rank, numRanks);
    return std::make_tuple(result[0], result[1], result[2], result[3]);
}

// moe_dispatch_prefill
TORCH_LIBRARY_IMPL(umdk_cam_op_lib, PrivateUse1, m)
{
    m.impl("moe_dispatch_prefill", &MoeDispatchPrefillImplNpu);
    m.impl("moe_dispatch_prefill_backward", &MoeDispatchPrefillBackwardImplNpu);
}

TORCH_LIBRARY_IMPL(umdk_cam_op_lib, AutogradPrivateUse1, m)
{
    m.impl("moe_dispatch_prefill", &MoeDispatchPrefillImplAutograd);
}