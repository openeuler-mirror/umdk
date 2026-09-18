/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: dfx log interface
 * Create: 2026-01-23
 * Note:
 * History: 2026-01-23 create log implementation file
 */

#ifndef OPS_LOG_H
#define OPS_LOG_H
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include "dfx_base.h"

/* base log */
#define OPS_LOG_D(OPS_DESC, ...) OPS_LOG_STUB_D(OPS_DESC, __VA_ARGS__)
#define OPS_LOG_I(OPS_DESC, ...) OPS_LOG_STUB_I(OPS_DESC, __VA_ARGS__)
#define OPS_LOG_W(OPS_DESC, ...) OPS_LOG_STUB_W(OPS_DESC, __VA_ARGS__)
#define OPS_LOG_E(OPS_DESC, ...) OPS_INNER_ERR_STUB("EZ9999", OPS_DESC, __VA_ARGS__)
#define OPS_LOG_E_WITHOUT_REPORT(OPS_DESC, ...) OPS_LOG_STUB_E(OPS_DESC, __VA_ARGS__)
#define OPS_LOG_EVENT(OPS_DESC, ...) OPS_LOG_STUB_EVENT(OPS_DESC, __VA_ARGS__)

/* conditional log */
#define OPS_LOG_D_IF(COND, OP_DESC, EXPR, ...) OPS_LOG_STUB_IF(COND, OPS_LOG_D(OP_DESC, __VA_ARGS__), EXPR)
#define OPS_LOG_I_IF(COND, OP_DESC, EXPR, ...) OPS_LOG_STUB_IF(COND, OPS_LOG_I(OP_DESC, __VA_ARGS__), EXPR)
#define OPS_LOG_W_IF(COND, OP_DESC, EXPR, ...) OPS_LOG_STUB_IF(COND, OPS_LOG_W(OP_DESC, __VA_ARGS__), EXPR)
#define OPS_LOG_E_IF(COND, OP_DESC, EXPR, ...) OPS_LOG_STUB_IF(COND, OPS_LOG_E(OP_DESC, __VA_ARGS__), EXPR)
#define OPS_LOG_EVENT_IF(COND, OP_DESC, EXPR, ...) OPS_LOG_STUB_IF(COND, OPS_LOG_EVENT(OP_DESC, __VA_ARGS__), EXPR)

#define OPS_LOG_E_IF_NULL(OPS_DESC, PTR, EXPR)                         \
    if (__builtin_expect((PTR) == nullptr, 0)) {                       \
        OPS_LOG_STUB_E(OPS_DESC, "%s is nullptr!", #PTR);              \
        OPS_CALL_ERR_STUB("EZ9999", OPS_DESC, "%s is nullptr!", #PTR); \
        EXPR;                                                          \
    }

#define OPS_CHECK(COND, LOG_FUNC, EXPR) \
    if (COND) {                         \
        LOG_FUNC;                       \
        EXPR;                           \
    }

#define OP_CHECK(COND, LOG_FUNC, EXPR) \
    if (COND) {                        \
        LOG_FUNC;                      \
        EXPR;                          \
    }

/* CAM comm-window / batch-size helpers (used by cam_moe_distribute_* op_host).
 * Distinct from Util::Mc2TilingUtils::GetMaxWindowSize (HCCL_BUFFSIZE semantics):
 * these read LCCL_BUFFER_SIZE, matching the CAM communication library window. */
namespace optiling {

constexpr char LCCL_BUFFER_SIZE[] = "LCCL_BUFFER_SIZE";
constexpr char BATCH_SIZE_FACTOR[] = "BATCH_SIZE_FACTOR";
constexpr int DEFAULT_BUFFER_SIZE = 2 * (200 + 4);  // 408MB
constexpr int MAX_BUFFER_SIZE = 32 * 1024;          // 32GB
constexpr float DEFAULT_BATCH_SIZE_FACTOR = 1.0;

static inline uint64_t GetMaxWindowSize()
{
    int size = DEFAULT_BUFFER_SIZE;
    auto env = std::getenv(LCCL_BUFFER_SIZE);
    if (env != nullptr) {
        try {
            std::string envStr(env);
            size = std::stoi(envStr);
            if (size > MAX_BUFFER_SIZE) {
                fprintf(stderr, "LCCL_BUFFER_SIZE %d larger than MAX %d, clamped\n", size, MAX_BUFFER_SIZE);
                size = MAX_BUFFER_SIZE;
            }
        } catch (...) {
            fprintf(stderr, "Unknown exception parsing LCCL_BUFFER_SIZE\n");
        }
    }
    return static_cast<uint64_t>(size) * 1024UL * 1024UL;
}

static inline float GetBatchSizeFactor()
{
    float factor = DEFAULT_BATCH_SIZE_FACTOR;
    auto env = std::getenv(BATCH_SIZE_FACTOR);
    if (env == nullptr) {
        return factor;
    }
    try {
        factor = std::stof(std::string(env));
    } catch (...) {
        fprintf(stderr, "Unknown exception parsing BATCH_SIZE_FACTOR\n");
    }
    return factor;
}

}  // namespace optiling
#endif // OPS_LOG_H