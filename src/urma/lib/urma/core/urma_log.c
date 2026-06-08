/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.
 * Description: urma log implementation
 * Author: Yan Fangfang
 * Create: 2020-9-28
 * Note:
 * History: 2020-9-28 inital implementation of urma log
 */

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "urma_opcode.h"
#include "urma_types.h"

#include "urma_log.h"

pthread_mutex_t g_urma_log_lock = PTHREAD_MUTEX_INITIALIZER;
urma_vlog_level_t g_urma_log_level = URMA_VLOG_LEVEL_INFO;
#define MAX_LOG_LEN                    512
#define MAX_THREAD_TAG_LEN             64
#define URMA_LOG_TAG                   "URMA"
#define LIBURMA_LOG                    "liburma"
#define URMA_LOG_ENV_STR               "URMA_LOG_LEVEL"
#define URMA_LOG_LEVEL_ENV_MAX_BUF_LEN 32
#define URMA_LOG_SEPARATOR_ENV_STR     "URMA_LOG_SEPARATOR"
#define URMA_LOG_SEPARATOR_MAX_LEN     8
#define URMA_LOG_SEPARATOR_VALID_CHARS "|,;:-/.~#"
#define URMA_LOG_SEPARATOR_DEFAULT     "|"

__thread char g_thread_tag[MAX_THREAD_TAG_LEN] = "-";
static char g_urma_log_separator[URMA_LOG_SEPARATOR_MAX_LEN] = URMA_LOG_SEPARATOR_DEFAULT;

static void urma_default_log_func(int level, char *message)
{
    syslog(level, "%s", message);
}

static urma_log_cb_t g_urma_log_func = urma_default_log_func;
static urma_loc_log_cb g_urma_loc_log_func = NULL;
static bool g_use_loc_log = false;

urma_status_t urma_register_log_func(urma_log_cb_t func)
{
    if (func == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    URMA_LOG_INFO("registered log successfully.\n");
    g_urma_log_func = func;
    g_urma_loc_log_func = NULL;
    g_use_loc_log = false;
    return URMA_SUCCESS;
}

urma_status_t urma_register_loc_log_func(urma_loc_log_cb func)
{
    if (func == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    g_urma_loc_log_func = func;
    g_use_loc_log = true;
    URMA_LOG_INFO("registered extended log successfully.\n");
    return URMA_SUCCESS;
}

urma_status_t urma_unregister_log_func(void)
{
    char logmsg[MAX_LOG_LEN + 1] = {0};
    (void)snprintf(logmsg, MAX_LOG_LEN, "%s%s%s%s%ld%s%s%s%s[%d]%sunregister log successfully.\n",
        URMA_LOG_TAG, g_urma_log_separator, LIBURMA_LOG, g_urma_log_separator,
        (long)syscall(__NR_gettid), g_urma_log_separator, g_thread_tag, g_urma_log_separator,
        __func__, __LINE__, g_urma_log_separator);
    (*g_urma_log_func)((int)URMA_VLOG_LEVEL_INFO, logmsg);
    g_urma_log_func = urma_default_log_func;
    g_urma_loc_log_func = NULL;
    g_use_loc_log = false;
    return URMA_SUCCESS;
}

int urma_log_init(void)
{
    openlog(NULL, LOG_PID | LOG_CONS | LOG_NDELAY, LOG_USER);
    return setlogmask(LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ERR) | LOG_MASK(LOG_WARNING) | LOG_MASK(LOG_INFO) |
                      LOG_MASK(LOG_DEBUG));
}

urma_vlog_level_t urma_log_get_level(void)
{
    urma_vlog_level_t level;

    pthread_mutex_lock(&g_urma_log_lock);
    level = g_urma_log_level;
    pthread_mutex_unlock(&g_urma_log_lock);
    return level;
}

void urma_log_set_level(urma_vlog_level_t level)
{
    if (level >= URMA_VLOG_LEVEL_MAX) {
        return;
    }
    pthread_mutex_lock(&g_urma_log_lock);
    g_urma_log_level = level;
    pthread_mutex_unlock(&g_urma_log_lock);
    return;
}

const char *urma_log_get_thread_tag(void)
{
    return g_thread_tag;
}

void urma_log_set_thread_tag(const char *tag)
{
    if (tag == NULL || strnlen(tag, URMA_MAX_NAME) >= URMA_MAX_NAME) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return;
    }
    (void)snprintf(g_thread_tag, sizeof(g_thread_tag), "%s", tag);
}

inline bool urma_log_drop(urma_vlog_level_t level)
{
    return ((level > g_urma_log_level) ? true : false);
}

const char *urma_get_level_print(urma_vlog_level_t level)
{
    switch (level) {
        case URMA_VLOG_LEVEL_CRIT:
            return "fatal";
        case URMA_VLOG_LEVEL_ERR:
            return "error";
        case URMA_VLOG_LEVEL_WARNING:
            return "warning";
        case URMA_VLOG_LEVEL_DEBUG:
            return "debug";
        case URMA_VLOG_LEVEL_INFO:
            return "info";
        case URMA_VLOG_LEVEL_EMERG:
        case URMA_VLOG_LEVEL_ALERT:
        case URMA_VLOG_LEVEL_NOTICE:
        case URMA_VLOG_LEVEL_MAX:
        default:
            return "Unknown";
    }
}

urma_vlog_level_t urma_log_get_level_from_string(const char *level_string)
{
    if (level_string == NULL) {
        return URMA_VLOG_LEVEL_MAX;
    }
    if (strcasecmp(level_string, "fatal") == 0) {
        return URMA_VLOG_LEVEL_CRIT;
    }
    if (strcasecmp(level_string, "error") == 0) {
        return URMA_VLOG_LEVEL_ERR;
    }
    if (strcasecmp(level_string, "warning") == 0) {
        return URMA_VLOG_LEVEL_WARNING;
    }
    if (strcasecmp(level_string, "info") == 0) {
        return URMA_VLOG_LEVEL_INFO;
    }
    if (strcasecmp(level_string, "debug") == 0) {
        return URMA_VLOG_LEVEL_DEBUG;
    }
    return URMA_VLOG_LEVEL_MAX;
}

void urma_getenv_log_level(void)
{
    char *level_str = getenv(URMA_LOG_ENV_STR);
    if (level_str == NULL) {
        return;
    }

    if (strnlen(level_str, URMA_LOG_LEVEL_ENV_MAX_BUF_LEN) >= URMA_LOG_LEVEL_ENV_MAX_BUF_LEN) {
        URMA_LOG_ERR("Invalid parameter: log level str.\n");
        return;
    }

    urma_vlog_level_t log_level = urma_log_get_level_from_string(level_str);
    if (log_level != URMA_VLOG_LEVEL_MAX) {
        pthread_mutex_lock(&g_urma_log_lock);
        g_urma_log_level = log_level;
        pthread_mutex_unlock(&g_urma_log_lock);
    }
}

static bool urma_is_valid_separator_char(char c)
{
    return strchr(URMA_LOG_SEPARATOR_VALID_CHARS, c) != NULL;
}

void urma_getenv_log_separator(void)
{
    char *sep_str = getenv(URMA_LOG_SEPARATOR_ENV_STR);
    if (sep_str == NULL || sep_str[0] == '\0') {
        return;
    }

    size_t len = strnlen(sep_str, URMA_LOG_SEPARATOR_MAX_LEN);
    if (len >= URMA_LOG_SEPARATOR_MAX_LEN) {
        return;
    }

    for (size_t i = 0; i < len; i++) {
        if (!urma_is_valid_separator_char(sep_str[i])) {
            return;
        }
    }

    pthread_mutex_lock(&g_urma_log_lock);
    (void)snprintf(g_urma_log_separator, URMA_LOG_SEPARATOR_MAX_LEN, "%s", sep_str);
    pthread_mutex_unlock(&g_urma_log_lock);
}

static int urma_vlog(const char *function, int line, urma_vlog_level_t level, const char *format, va_list va)
{
    int ret;
    char newformat[MAX_LOG_LEN + 1] = {0};
    char logmsg[MAX_LOG_LEN + 1] = {0};

    /* add log head info, "[URMA][liburma][thread_id=tid][thread_tag][function[Line=line]]format" */
    ret = snprintf(newformat, MAX_LOG_LEN, "[%s][%s][thread_id=%ld][%s][%s[Line=%d]]%s",
                   URMA_LOG_TAG, LIBURMA_LOG, (long)syscall(__NR_gettid), g_thread_tag, function,
                   line, format);
    if (ret <= 0 || ret >= sizeof(newformat)) {
        return ret;
    }
    ret = vsnprintf(logmsg, MAX_LOG_LEN, newformat, va);
    if (ret == -1) {
        (void)printf("logmsg size exceeds MAX_LOG_LEN size :%d.\n", MAX_LOG_LEN);
        return ret;
    }

    /* urma_vlog has no file parameter, only use original callback */
    (*g_urma_log_func)((int)level, logmsg);

    return ret;
}

void urma_log(const char *function, int line, urma_vlog_level_t level, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    (void)urma_vlog(function, line, level, format, va);
    va_end(va);
}

static int urma_vlog_loc(const char *file, const char *function, int line, urma_vlog_level_t level,
                         const char *format, va_list va)
{
    int ret;
    char newformat[MAX_LOG_LEN + 1] = {0};
    char logmsg[MAX_LOG_LEN + 1] = {0};

    /* add log head info, "[URMA][liburma][thread_id=tid][thread_tag][file:function:line]format" */
    ret = snprintf(newformat, MAX_LOG_LEN, "[%s][%s][thread_id=%ld][%s][%s:%s:%d]%s",
                   URMA_LOG_TAG, LIBURMA_LOG, (long)syscall(__NR_gettid), g_thread_tag, file,
                   function, line, format);
    if (ret <= 0 || ret >= sizeof(newformat)) {
        return ret;
    }
    ret = vsnprintf(logmsg, MAX_LOG_LEN, newformat, va);
    if (ret == -1) {
        (void)printf("logmsg size exceeds MAX_LOG_LEN size :%d.\n", MAX_LOG_LEN);
        return ret;
    }

    if (g_use_loc_log && g_urma_loc_log_func != NULL) {
        (*g_urma_loc_log_func)((int)level, file, function, line, logmsg);
    } else {
        (*g_urma_log_func)((int)level, logmsg);
    }

    return ret;
}

void urma_log_loc(const char *file, const char *function, int line, urma_vlog_level_t level, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    (void)urma_vlog_loc(file, function, line, level, format, va);
    va_end(va);
}

/* Time acquisition optimization function */
static inline time_t urma_log_rl_get_time(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return ts.tv_sec;
}

bool urma_log_rl_check(urma_log_rl_state_t *rs, const char *file,
                       const char *function, int line)
{
    time_t now = urma_log_rl_get_time();
    bool ret = false;

    /* Check if initialized first (without lock) */
    if ((rs->flags & URMA_LOG_RL_INITIALIZED) == 0) {
        /* Not initialized yet, need to initialize spinlock first */
        if (pthread_spin_init(&rs->lock, PTHREAD_PROCESS_PRIVATE) != 0) {
            /* Spinlock initialization failed, allow log output (safe fallback) */
            return true;
        }

        /* Mark as initialized (atomic operation to ensure visibility) */
        rs->begin = now;
        atomic_store(&rs->n_left, URMA_LOG_RL_LIMIT);
        atomic_store(&rs->missed, 0);
        /* Record log point location on first call */
        rs->file = file;
        rs->function = function;
        rs->line = line;
        /* Set INITIALIZED flag last (acts as memory barrier) */
        rs->flags |= URMA_LOG_RL_INITIALIZED;

        return true;  /* First call always allows log output */
    }

    /* Already initialized, proceed with normal flow */

    /* Check if window has expired (before trylock for performance) */
    bool window_expired = (now - rs->begin >= URMA_LOG_RL_WINDOW_SEC);

    /* Fast path: use atomic operations when trylock fails */
    if (pthread_spin_trylock(&rs->lock) != 0) {
        /* Lock contention: atomic check of remaining quota */
        long left = atomic_fetch_sub(&rs->n_left, 1);
        if (left > 0) {
            /* Has quota, allow log output */
            ret = true;
        }
        /* Note: window check will be done by the thread holding the lock */
        /* else: no quota (left <= 0), will be suppressed */
        goto out;
    }

    /* Full processing after acquiring lock */

    /* Check if window has expired */
    if (window_expired) {
        /* Output summary for previous window if there were suppressed logs */
        unsigned long m = atomic_exchange(&rs->missed, 0);
        if (m > 0) {
            /* Use recorded log point location for summary output */
            urma_log_loc(rs->file, rs->function, rs->line, URMA_VLOG_LEVEL_INFO,
                    "rate limit: %lu logs suppressed in last %ds",
                    m, URMA_LOG_RL_WINDOW_SEC);
        }

        /* Reset for new window */
        atomic_store(&rs->n_left, URMA_LOG_RL_LIMIT);
        rs->begin = now;
    }

    /* Atomic check of quota */
    long left = atomic_fetch_sub(&rs->n_left, 1);
    if (left > 0) {
        ret = true;  /* Has quota, allow log output */
    }
    /* else: no quota (left <= 0), log suppressed, will be counted in missed */

    pthread_spin_unlock(&rs->lock);

out:
    if (!ret) {
        atomic_fetch_add(&rs->missed, 1);
    }
    return ret;
}
