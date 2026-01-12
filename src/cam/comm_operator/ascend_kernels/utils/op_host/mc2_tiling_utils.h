/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: create mc2_tiling_utils header file
 * Create: 2026-01-13
 * Note:
 * History: 2026-01-13 create mc2_tiling_utils header file
 */

#ifndef __MC2_TILING_UTILS_H__
#define __MC2_TILING_UTILS_H__

#include <cstdint>
#include <map>
#include <string>

#include "error_log.h"
#include "register/tilingdata_base.h"
#include "tiling/tiling_api.h"

class Mc2TilingUtils {
public:
#define HCCL_BUFFSIZE "HCCL_BUFFSIZE"
    static uint64_t GetMaxWindowSize()
    {
        uint16_t defaultWindowSize = 200;
        if (getenv(HCCL_BUFFSIZE) == nullptr) {
            OP_LOGD("", "Env HCCL_BUFFSIZE don't set");
        } else {
            try {
                std::string envStr(getenv(HCCL_BUFFSIZE));
                defaultWindowSize = std::stoi(envStr);
            } catch (const std::invalid_argument &ia) {
                OP_LOGE("", "Invalid argument when parsing HCCL_BUFFSIZE: %s", ia.what());
            } catch (const std::out_of_range &oor) {
                OP_LOGE("", "Out of range when parsing HCCL_BUFFSIZE: %s", oor.what());
            }
        }
        const uint64_t maxWindowSize = static_cast<uint64_t>(defaultWindowSize) * 1024UL * 1024UL;
        OP_LOGI("", "Get maxWindowSize is %lu", maxWindowSize);
        return maxWindowSize;
    }
};

#endif