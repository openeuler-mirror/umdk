/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: notify dispatch A2 interface part
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create notify dispatch A2 interface part
 */

#ifndef ACLNN_NOTIFY_DISPATCH_A2_H_
#define ACLNN_NOTIFY_DISPATCH_A2_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnNotifyDispatchA2GetWorkspaceSize
 * sendData : required
 * tokenPerExpertData : required
 * tmpData : required
 * sendCount : required
 * numTokens : required
 * topkNum : required
 * numExperts : required
 * commGroup : required
 * rankSize : required
 * rankId : required
 * localRankSize : required
 * localRankId : required
 * sendDataOffsetOut : required
 * recvDataOut : required
 * tokenServerIdxOut : required
 * tokenUniquePerServerOut : required
 * epRankTokenCntOut : required
 * localEpTokenCntOut : required
 * srcOffsetRankTokenIdxOut : required
 * dstOffsetRankTokenIdxOut : required
 * offsetInnerOut : required
 * countOuterOut : required
 * expandIdxOut : required
 * totalRecvTokensOut : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnNotifyDispatchA2GetWorkspaceSize(
    const aclTensor *sendData,
    const aclTensor *tokenPerExpertData,
    const aclTensor *tmpData,
    int64_t sendCount,
    int64_t numTokens,
    int64_t topkNum,
    int64_t numExperts,
    char *commGroup,
    int64_t rankSize,
    int64_t rankId,
    int64_t localRankSize,
    int64_t localRankId,
    const aclTensor *sendDataOffsetOut,
    const aclTensor *recvDataOut,
    const aclTensor *tokenServerIdxOut,
    const aclTensor *tokenUniquePerServerOut,
    const aclTensor *epRankTokenCntOut,
    const aclTensor *localEpTokenCntOut,
    const aclTensor *srcOffsetRankTokenIdxOut,
    const aclTensor *dstOffsetRankTokenIdxOut,
    const aclTensor *offsetInnerOut,
    const aclTensor *countOuterOut,
    const aclTensor *expandIdxOut,
    const aclTensor *totalRecvTokensOut,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

/* function: aclnnNotifyDispatchA2
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnNotifyDispatchA2(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
