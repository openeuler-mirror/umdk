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
#endif // OPS_LOG_H