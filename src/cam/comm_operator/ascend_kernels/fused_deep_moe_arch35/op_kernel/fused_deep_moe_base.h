/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Definition of communication group related structures
 * Create: 2026-08-04
 * Note:
 * History: 2026-08-04 Create a definition file for a distribution group related structure
 */
#ifndef FUSED_DEEP_MOE_BASE_H
#define FUSED_DEEP_MOE_BASE_H

#include "op_kernel/moe_distribute_base.h"

#define TemplateMC2TypeClass                                                                      \
        typename ExpandXType, typename WeightType, bool WEIGHT_NZ, typename ExpandIdxType, \
        bool IsNeedReduceScatter, uint32_t EXEC_FLAG
#define TemplateMC2TypeFunc ExpandXType, WeightType, WEIGHT_NZ, ExpandIdxType, IsNeedReduceScatter, EXEC_FLAG

#define TemplateDispatchTypeClass                                                                                  \
            typename XType, typename ExpandXOutType, bool StaticQuant, bool DynamicQuant, bool IsSmoothScaleExist, \
            bool IsNeedAllgater, uint32_t EXEC_FLAG
#define TemplateDispatchTypeFunc                                                  \
            XType, ExpandXOutType, StaticQuant, DynamicQuant, IsSmoothScaleExist, \
            IsNeedAllgater, EXEC_FLAG

constexpr int64_t SLEEP_CYCLE = 50;

__aicore__ inline void SPIN_WAIT_CYCLES()
{
    AscendC::Nop<SLEEP_CYCLE>();
}

namespace IPCStateOffset {
    constexpr uint64_t AI_CORE_STATE_OFFSET = 0;
    namespace DispatchgGmm1 {
        constexpr uint64_t LOCAL_SEND_COUNT_OFFSET = 16 * 1024;
        constexpr uint64_t SEND_COUNT_FLAG_OFFSET = 20 * 1024;
        constexpr uint64_t MAX_SEND_COUNT_SIZE = 32 * 1024;
        constexpr uint64_t GROUP_TOKEN_NUM_OFFSET = 84 * 1024;
        constexpr uint64_t GROUP_INFO_SIZE = 32;
        constexpr uint64_t SOFT_SYNC_OFFSET = 212 * 1024;
        constexpr uint64_t SHARE_QUANT_SOFT_SYNC_OFFSET = 276 * 1024;
    }
    namespace Gmm2Combine {
        constexpr uint64_t SYNC_FLAG_OFFSET = 277 * 1024;
        constexpr uint64_t COMBINE_SEND_FLAG_OFFSET = 341 * 1024;
    }
    constexpr uint64_t SPACE_END_OFFSET = 373 * 1024;
}

#endif  // FUSED_DEEP_MOE_BASE_H
