/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: SNC (Supernode Network Controller) service
 * Create: 2026-07-13
 */
#ifndef SNC_PING_INNER_H
#define SNC_PING_INNER_H

#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "acl/acl.h"
#include "hccl/hccn_rping.h"
#include "snc_ping.h"

#define PKT_NUM 10
#define PING_PORT 13886
#define PING_NPU_NUM 128
#define PING_BUFFER_SIZE_PER_PKT 2048
#define PING_PAGE_SIZE 4096
#define PING_INTERVAL 1
#define PING_TIMEOUT 100
#define PING_GET_RESULT_MAX_RETRIES 120
#define PING_CALLER_WAIT_TIMEOUT_SEC 60
#define PING_QUEUE_WAIT_TIMEOUT_SEC 1

typedef struct {
    char eid[IP_LEN];
    HccnRpingCtx rpingCtx;
    bool isInited;
} SncPingEidCtx;

typedef struct {
    int clientDevId;
    char clientEid[IP_LEN];
    char serverEid[IP_LEN];
    SncPingResult* result;
    std::atomic<bool> done;
    std::atomic<bool> canceled;
    std::atomic<int> ret;
    std::mutex cvMutex;
    std::condition_variable cv;
} SncPingTask;

typedef struct {
    int devId;
    std::vector<SncPingEidCtx> eidCtxs;
    std::atomic<bool> isStop;
    std::thread* workerThread;
    std::mutex eidMutex;
    std::mutex queueMutex;
    std::condition_variable queueCv;
    std::queue<std::shared_ptr<SncPingTask>> taskQueue;
} SncPingDevThread;

#endif
