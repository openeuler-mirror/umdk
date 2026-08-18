/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-13
 */
#ifndef URMA_PING_H
#define URMA_PING_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C"{
#endif

#define IP_LEN 33

typedef struct {
    int devId;
    char eid[IP_LEN];
} UrmaPingEntity;

typedef struct {
    uint32_t txPkt;
    uint32_t rxPkt;
    uint32_t minRTT;
    uint32_t maxRTT;
    uint32_t avgRTT;
    uint32_t state;
} UrmaPingResult;

int UrmaPingInit(UrmaPingEntity* entities, int count);

int UrmaPingOne(int clientDevId, const char* clientEid, const char* serverEid, UrmaPingResult* result);

int UrmaPingDeinit(UrmaPingEntity* entities, int count);

#ifdef __cplusplus
}
#endif

#endif