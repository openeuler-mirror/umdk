/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: MoeDispatchNormalZb tiling data header file
 * Create: 2026-06-10
 * Note:
 * History: 2026-06-10 create MoeDispatchNormalZb tiling data header file
 */
#ifndef MOE_DISPATCH_NORMAL_ZB_TILING_H
#define MOE_DISPATCH_NORMAL_ZB_TILING_H

struct MoeDispatchNormalZbInfo {
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
    bool reserved1;         // reserved
    bool reserved2;         // reserved
    bool reserved3;         // reserved
    uint64_t totalUbSize;
    uint64_t totalWinSize;
};

struct MoeDispatchNormalZbTilingData {
    MoeDispatchNormalZbInfo moeDispatchNormalInfo;
    uint64_t commMetaPtr;  // SHMEM-symmetric comm meta GVA
};

#endif
