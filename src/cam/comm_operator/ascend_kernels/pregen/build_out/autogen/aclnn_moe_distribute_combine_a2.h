/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dispatch combine A2 interface part
 * Create: 2026-01-15
 * Note:
 * History: 2026-01-15 create combine normal A2 interface part
 */

#ifndef ACLNN_MOE_DISTRIBUTE_COMBINE_A2_H_
#define ACLNN_MOE_DISTRIBUTE_COMBINE_A2_H_

#include "aclnn/acl_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* function: aclnnMoeDistributeCombineA2GetWorkspaceSize
 * expandX : required
 * expertIds : required
 * expandIdx : required
 * epSendCounts : required
 * expertScales : required
 * tpSendCountsOptional : optional
 * xActiveMaskOptional : optional
 * activationScaleOptional : optional
 * weightScaleOptional : optional
 * groupListOptional : optional
 * expandScalesOptional : optional
 * offsetInner : required
 * offsetOuter : required
 * countOuter : required
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
 * globalBs : optional
 * outDtype : optional
 * commQuantMode : optional
 * groupListType : optional
 * out : required
 * workspaceSize : size of workspace(output).
 * executor : executor context(output).
 */
__attribute__((visibility("default"))) aclnnStatus aclnnMoeDistributeCombineA2GetWorkspaceSize(
    const aclTensor *expandX,
    const aclTensor *expertIds,
    const aclTensor *expandIdx,
    const aclTensor *epSendCounts,
    const aclTensor *expertScales,
    const aclTensor *tpSendCountsOptional,
    const aclTensor *xActiveMaskOptional,
    const aclTensor *activationScaleOptional,
    const aclTensor *weightScaleOptional,
    const aclTensor *groupListOptional,
    const aclTensor *expandScalesOptional,
    const aclTensor *offsetInner,
    const aclTensor *offsetOuter,
    const aclTensor *countOuter,
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
    int64_t globalBs,
    int64_t outDtype,
    int64_t commQuantMode,
    int64_t groupListType,
    const aclTensor *out,
    uint64_t *workspaceSize,
    aclOpExecutor **executor);

/* function: aclnnMoeDistributeCombineA2
 * workspace : workspace memory addr(input).
 * workspaceSize : size of workspace(input).
 * executor : executor context(input).
 * stream : acl stream.
 */
__attribute__((visibility("default"))) aclnnStatus aclnnMoeDistributeCombineA2(
    void *workspace,
    uint64_t workspaceSize,
    aclOpExecutor *executor,
    aclrtStream stream);

#ifdef __cplusplus
}
#endif

#endif
