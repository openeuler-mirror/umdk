/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Stub for hccl/hccn_rping.h used in snc_ping unit tests
 */
#ifndef HCCL_HCCN_RPING_H_
#define HCCL_HCCN_RPING_H_

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* HccnRpingCtx;
typedef int HccnResult;

#define HCCN_SUCCESS 0
#define HCCN_E_AGAIN 1

#define HCCN_RPING_ADDR_TYPE_EID 1
#define HCCN_RPING_MODE_UB_RC    2

#define HCCN_RPING_TARGET_PAYLOAD_LEN 64

typedef struct {
    uint32_t srcPort;
    uint32_t sl;
    uint32_t tc;
    uint32_t port;
    uint32_t addrType;
    const char* srcEid;
    const char* dstEid;
    char payload[HCCN_RPING_TARGET_PAYLOAD_LEN];
    uint32_t payloadLen;
} HccnRpingTargetInfo;

typedef struct {
    uint32_t mode;
    uint32_t port;
    uint32_t npuNum;
    uint32_t bufferSize;
    const char* eid;
} HccnRpingInitAttr;

typedef struct {
    uint32_t txPkt;
    uint32_t rxPkt;
    uint32_t minRTT;
    uint32_t maxRTT;
    uint32_t avgRTT;
    uint32_t state;
} HccnRpingResultInfo;

HccnResult HccnRpingInit(uint32_t devId, const HccnRpingInitAttr* attr, HccnRpingCtx* ctx);
HccnResult HccnRpingDeinit(HccnRpingCtx ctx);
HccnResult HccnRpingAddTarget(HccnRpingCtx ctx, uint32_t count, const HccnRpingTargetInfo* targets);
HccnResult HccnRpingRemoveTarget(HccnRpingCtx ctx, uint32_t count, const HccnRpingTargetInfo* targets);
HccnResult HccnRpingBatchPingStart(HccnRpingCtx ctx, uint32_t pktNum, uint32_t interval, uint32_t timeout);
HccnResult HccnRpingBatchPingStop(HccnRpingCtx ctx);
HccnResult HccnRpingGetResult(HccnRpingCtx ctx, uint32_t count, const HccnRpingTargetInfo* targets, HccnRpingResultInfo* results);

#ifdef __cplusplus
}
#endif

#endif
