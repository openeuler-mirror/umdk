/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * ubs-hcom is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *      http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* Stubs for umq_qbuf_pool.c external dependencies.
 * umq_qbuf_pool.c (compiled into the tool target via CMakeLists.txt) is C
 * code whose deps (urpc_id_generator, urpc_util, umq_vlog, util_vlog) live
 * in .c files that are NOT compiled into this tool. We provide minimal
 * C-linkage stubs here so the link resolves cleanly. This TU does NOT
 * include umq_qbuf_pool.c. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "umq_qbuf_pool.h" /* pulls in util_vlog_ctx_t, urpc_id_generator_t, etc. */
#include "umq_tiny_qbuf_pool.h"

extern "C" {

/* --- vlog / util_vlog stubs --- */
static umq_vlog_config_t g_stub_log_cfg = {
    0,
    { UTIL_VLOG_LEVEL_DEBUG, {0}, NULL, NULL, {0, 0} }
};
umq_vlog_config_t *umq_get_log_config(void)
{
    return &g_stub_log_cfg;
}
util_vlog_ctx_t *umq_get_log_ctx(void)
{
    return &g_stub_log_cfg.ctx;
}

static const char *stub_level_str(util_vlog_level_t level)
{
    switch (level) {
        case UTIL_VLOG_LEVEL_EMERG:  return "EMERG";
        case UTIL_VLOG_LEVEL_ALERT:  return "ALERT";
        case UTIL_VLOG_LEVEL_CRIT:   return "CRIT";
        case UTIL_VLOG_LEVEL_ERR:    return "ERR";
        case UTIL_VLOG_LEVEL_WARN:   return "WARN";
        case UTIL_VLOG_LEVEL_NOTICE: return "NOTICE";
        case UTIL_VLOG_LEVEL_INFO:   return "INF";
        case UTIL_VLOG_LEVEL_DEBUG:  return "DBG";
        default:                     return "???";
    }
}

void util_vlog_output(util_vlog_ctx_t *ctx, util_vlog_level_t level, const char *file,
    util_vlog_type_t type, const char *function, int line, const char *format, ...)
{
    (void)ctx;
    (void)type;
    (void)function;
    char buf[1024];
    va_list ap;
    va_start(ap, format);
    int n = snprintf(buf, sizeof(buf), "[%s][%s:%d] ", stub_level_str(level), file, line);
    vsnprintf(buf + n, sizeof(buf) - n, format, ap);
    va_end(ap);
    fprintf(stderr, "%s", buf);
}

bool util_vlog_limit(util_vlog_ctx_t *ctx, uint32_t *print_count, uint64_t *last_time)
{
    (void)ctx;
    (void)print_count;
    (void)last_time;
    return false;
}

/* --- urpc_util stub --- */
uint64_t urpc_get_cpu_hz(void)
{
    return 1000000000ULL;
}

/* urpc_id_generator: linked from production code (urpc_id_generator.c +
 * urpc_bitmap.c + urpc_dbuf_stat.c) via CMakeLists. The previous stub
 * implementation lacked spinlock protection, causing duplicate slot_id
 * allocation under multi-threaded stress. */

/* Stub for urpc_thread_closure_register (C linkage).
 * umq_qbuf_pool.c calls this during init/uninit/TLS-register paths to register
 * cleanup callbacks for thread-local state. We don't exercise thread exit in
 * this tool, so a no-op stub is sufficient. */
__attribute__((weak)) void urpc_thread_closure_register(urpc_thread_closure_type_t type, uint64_t id,
                                                        void (*closure)(uint64_t id))
{
    (void)type;
    (void)id;
    (void)closure;
}

/* --- rx_io_buf stubs removed: umq_rx_qbuf_pool.c now compiled into the tool --- */

} /* extern "C" */

/* umq_qbuf_alloc is defined in umq_qbuf_pool_helper.c which depends on
 * umq_tiny_qbuf_pool and umq_huge_qbuf_pool. Rather than pulling in that
 * entire dependency chain, we provide a simplified version here that covers
 * the test scenarios: option==NULL -> AUTO -> NORMAL, fallback to ESCAPE.
 * umq_normal_qbuf_alloc / umq_qbuf_escape_alloc are public declarations in
 * umq_qbuf_pool.h; their definitions live in core.cpp (which includes the .c). */
extern "C" int umq_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    umq_alloc_pool_type_t pool_type = UMQ_ALLOC_POOL_AUTO;
    if (option != NULL && (option->flag & UMQ_ALLOC_FLAG_POOL_TYPE) != 0) {
        if (option->pool_type >= UMQ_ALLOC_POOL_MAX) {
            return -UMQ_ERR_EINVAL;
        }
        pool_type = option->pool_type;
    }

    if (pool_type == UMQ_ALLOC_POOL_AUTO || pool_type == UMQ_ALLOC_POOL_NORMAL) {
        int ret = umq_normal_qbuf_alloc(request_size, num, option, list);
        if (ret != UMQ_SUCCESS && pool_type == UMQ_ALLOC_POOL_AUTO) {
            ret = umq_qbuf_escape_alloc(request_size, num, option, list);
        }
        return ret;
    }
    if (pool_type == UMQ_ALLOC_POOL_ESCAPE) {
        return umq_qbuf_escape_alloc(request_size, num, option, list);
    }
    return -UMQ_ERR_EINVAL;
}

/* Stubs for umq_huge_qbuf_pool_info_get.
 * umq_dfx_api.c (now compiled into the tool target) calls these via the
 * umq_stats_qbuf_pool_get(UMQ_INVALID_HANDLE, ...) path. The tool only
 * initialises the normal + RX + tiny pools, so huge pool is not exercised.
 * Returning 0 without modifying stats->num leaves the normal/RX/tiny pools'
 * info entries populated in the stats struct. */
extern "C" int umq_huge_qbuf_pool_info_get(umq_qbuf_pool_stats_t *qbuf_pool_stats)
{
    (void)qbuf_pool_stats;
    return 0;
}

/* Tool-local umq_stats_qbuf_pool_get wrapper.
 * The real umq_dfx_api.c implementation calls umq_qbuf_pool_info_get() +
 * umq_huge_qbuf_pool_info_get() + umq_tiny_qbuf_pool_info_get() when umqh is
 * UMQ_INVALID_HANDLE. The tool initialises normal + RX + tiny pools, so
 * the huge call is a no-op (the stub above). This wrapper forwards
 * directly to umq_qbuf_pool_info_get + umq_tiny_qbuf_pool_info_get (both
 * compiled into the tool target) — skipping the huge dispatch — and lets the tool
 * avoid linking umq_dfx_api.c (which would drag in umq_inner.h / perf.h and
 * the transport-layer dependency chain). */
extern "C" int umq_stats_qbuf_pool_get(uint64_t umqh, umq_qbuf_pool_stats_t *qbuf_pool_stats)
{
    if (qbuf_pool_stats == NULL) {
        return -UMQ_ERR_EINVAL;
    }
    if (umqh != UMQ_INVALID_HANDLE) {
        /* The tool never holds a real umq handle; reject to surface misuse. */
        return -UMQ_ERR_EINVAL;
    }
    qbuf_pool_stats->num = 0;
    (void)umq_qbuf_pool_info_get(qbuf_pool_stats);
    (void)umq_tiny_qbuf_pool_info_get(qbuf_pool_stats);
    return 0;
}
