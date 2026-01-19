/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dispatch normal A2 interface part
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create dispatch normal A2 interface part
 */

#ifndef ACLNN_DISPATCH_NORMAL_A2_H_
#define ACLNN_DISPATCH_NORMAL_A2_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnDispatchNormalA2GetWorkspaceSize
 * x : required
 * expertIds : required
 * scalesOptional : optional
 * xActiveMaskOptional : optional
 * expertScalesOptional : optional
 * tokenServerIdxOptional : optional
 * tokenServerCntOptional : optional
 * epRankTokenCntOptional : optional
 * srcOffsetRankTokenIdxOptional : optional
 * dstOffsetRankTokenIdxOptional : optional
 * groupEp : required
 * epWorldSize : required
 * epRankId : required
 * moeExpertNum : required
 * groupTpOptional : optional
 * tpWorldSize : optional
 * tpRankId : optional
 * expertShardType : optional
 * sharedExpertNum : optional
 * sharedExpertRankNum : optional
 * quantMode : optional
 * globalBs : optional
 * expertTokenNumsType : optional
 * recvXOut : required
 * dynamicScalesOut : required
 * expandIdxOut : required
 * expertTokenNumsOut : required
 * epRecvCountOut : required
 * expandScalesOut : required
 * dispatchWaitRecvCostStatsOutOptional : optional
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnDispatchNormalA2GetWorkspaceSize(
    const aclTensor *x,
    const aclTensor *expertIds,
    const aclTensor *scalesOptional,
    const aclTensor *xActiveMaskOptional,
    const aclTensor *expertScalesOptional,
    const aclTensor *tokenServerIdxOptional,
    const aclTensor *tokenServerCntOptional,
    const aclTensor *epRankTokenCntOptional,
    const aclTensor *srcOffsetRankTokenIdxOptional,
    const aclTensor *dstOffsetRankTokenIdxOptional,
    char *groupEp,
    int64_t epWorldSize,
    int64_t epRankId,
    int64_t moeExpertNum,
    char *groupTpOptional,
    int64_t tpWorldSize,
    int64_t tpRankId,
    int64_t expertShardType,
    int64_t sharedExpertNum,
    int64_t sharedExpertRankNum,
    int64_t quantMode,
    int64_t globalBs,
    int64_t expertTokenNumsType,
    const aclTensor *recvXOut,
    const aclTensor *dynamicScalesOut,
    const aclTensor *expandIdxOut,
    const aclTensor *expertTokenNumsOut,
    const aclTensor *epRecvCountOut,
    const aclTensor *expandScalesOut,
    const aclTensor *dispatchWaitRecvCostStatsOutOptional,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

/* function: aclnnDispatchNormalA2
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnDispatchNormalA2(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
