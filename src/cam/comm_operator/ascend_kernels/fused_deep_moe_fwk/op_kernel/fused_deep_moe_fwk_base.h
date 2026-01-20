/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Definition of communication group related structures
 * Create: 2026-01-20
 */

#pragma once

#include "moe_distribute_base.h"

#define OPT_RANK_OFFSET 512

#define TemplateMC2TypeClass typename ExpandXType, typename ExpandIdxType, bool IsNeedReduceScatter, uint32_t EXEC_FLAG
#define TemplateMC2TypeFunc ExpandXType, ExpandIdxType, IsNeedReduceScatter, EXEC_FLAG

#define TemplateDispatchTypeClass                                                                                  \
            typename XType, typename ExpandXOutType, bool StaticQuant, bool DynamicQuant, bool IsSmoothScaleExist, \
            bool IsNeedAllgater, uint32_t EXEC_FLAG
#define TemplateDispatchTypeFunc                                                  \
            XType, ExpandXOutType, StaticQuant, DynamicQuant, IsSmoothScaleExist, \
            IsNeedAllgater, EXEC_FLAG
