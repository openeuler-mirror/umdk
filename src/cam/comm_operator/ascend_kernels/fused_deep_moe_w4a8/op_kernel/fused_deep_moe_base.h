/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Definition of communication group related structures
 * Create: 2025-07-19
 * Note:
 * History: 2025-07-19 Create a definition file for a distribution group related structure
 */
#ifndef FUSED_DEEP_MOE_BASE_H
#define FUSED_DEEP_MOE_BASE_H

#include "moe_distribute_base.h"

#define TemplateMC2TypeClass                                                                      \
    typename ExpandXType, typename W1ScaleType, typename W2ScaleType, typename ExpandIdxType, \
    bool IsNeedReduceScatter, uint32_t EXEC_FLAG
#define TemplateMC2TypeFunc ExpandXType, W1ScaleType, W2ScaleType, ExpandIdxType, IsNeedReduceScatter, EXEC_FLAG

#define TemplateDispatchTypeClass                                                                                  \
    typename XType, typename ExpandXOutType, bool StaticQuant, bool DynamicQuant, bool IsSmoothScaleExist, \
    bool IsNeedAllgater, uint32_t EXEC_FLAG
#define TemplateDispatchTypeFunc                                                  \
    XType, ExpandXOutType, StaticQuant, DynamicQuant, IsSmoothScaleExist, \
    IsNeedAllgater, EXEC_FLAG

constexpr int64_t SLEEP_CYCLE = 25;

__aicore__ inline void SPIN_WAIT_CYCLES()
{
    int64_t st = AscendC::GetSystemCycle();
    while (AscendC::GetSystemCycle() - st < (SLEEP_CYCLE)) {
        ;
    }
}

#endif  // FUSED_DEEP_MOE_BASE_H
