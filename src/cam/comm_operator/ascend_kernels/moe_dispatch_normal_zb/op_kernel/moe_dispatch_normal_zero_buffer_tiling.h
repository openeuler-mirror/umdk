/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: MoeDispatchNormalZeroBuffer tiling data header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create MoeDispatchNormalZeroBuffer tiling data header file
 */
#ifndef MOE_DISPATCH_NORMAL_ZERO_BUFFER_TILING_H
#define MOE_DISPATCH_NORMAL_ZERO_BUFFER_TILING_H

struct MoeDispatchNormalZeroBufferInfo {
    uint32_t epWorldSize;   // epWorldSize
    uint32_t tpWorldSize;   // tpWorldSize
    uint32_t epRankId;      // epRankId
    uint32_t tpRankId;      // tpRankId
    uint32_t moeExpertNum;  // moe expert number
    uint32_t quantMode;     // quant mode
    uint32_t globalBs;      // globalBs = BS * worldSize
    uint32_t bs;            // bs
    uint32_t k;             // k
    uint32_t h;             // h
    uint32_t aivNum;        // aivNum
    bool isQuant;           // whether quant or not
    bool isEnableDiagnose;  // whether enable diagnose or not
    bool reserved2;         // reserved
    bool reserved3;         // reserved
    uint64_t totalUbSize;
    uint64_t totalWinSize;
};

struct MoeDispatchNormalZeroBufferTilingData {
    MoeDispatchNormalZeroBufferInfo moeDispatchNormalInfo;
    uint64_t zeroBufferPtr;  // zero buffer symmetric point
};

#endif
