/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definition of generic commands of uvs_admin
 * Author: Huangbin
 * Create: 2020-03-09
 * Note:
 * History: 2020-03-09 huangbin Initial operation cmd trace
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "ub_dstring.h"
#include "uvs_admin_log.h"
#include "uvs_admin_cmd_trace.h"

#define THOUSANDTH 1000

static const char *g_cmd_uvs_admin_key_list[] = {
    "add", "del", "set", "reset", "flush", "start",
    "stop", "enable", "disable", "exit", "clear",
    "load", "unload", "reopen", "delete", "exit",
    "on", "off", "save", "restore", "show",
    "mod", "active", "deactive", "remove", "close",
    "run", "run2active", "settime", "escape",
    "remake", "reconn", "create", "destroy",
    "flowtrace", "switch", "preload",
    "A", "D", "I", "F", "Z", "N", "X", "s", NULL
};

static bool key_find_in_list(const char *str)
{
    const char **key = NULL;
    char *str_cpy = NULL;
    char *next_token = NULL;
    char *token = NULL;
    char seps[] = "-_/";
    size_t str_length;

    if (str == NULL) {
        return false;
    }
    str_length = strlen(str);
    if (str_length >= PATH_MAX) {
        return false;
    }
    str_cpy = strdup(str);
    if (str_cpy == NULL) {
        return false;
    }
    token = strtok_r(str_cpy, seps, &next_token);
    while (token != NULL) {
        key = g_cmd_uvs_admin_key_list;
        while (*key != NULL) {
            if (!strcmp(token, *key)) {
                free(str_cpy);
                return true;
            }
            key++;
        }
        token = strtok_r(NULL, seps, &next_token);
    }
    free(str_cpy);
    return false;
}

bool cmd_is_operation(int argc, char *argv[])
{
    int i;

    /* set i = i to ignore program_name */
    for (i = 1; i < argc; i++) {
        if (key_find_in_list(argv[i])) {
            return true;
        }
    }

    return false;
}

static char *process_escape_args(char **argv)
{
    struct dstring ds = DSTRING_INITIALIZER;
    char **argp = NULL;

    for (argp = argv; *argp; argp++) {
        const char *arg = *argp;
        const char *p = NULL;
        if (argp != argv) {
            dstring_put_char(&ds, ' ');
        }
        if (!arg[strcspn(arg, " \t\r\n\v\\\'\"")]) {
            (void)dstring_put_cstring(&ds, arg);
            continue;
        }
        dstring_put_char(&ds, '"');
        for (p = arg; *p; p++) {
            if (*p == '\\' || *p == '\"') {
                dstring_put_char(&ds, '\\');
            }
            dstring_put_char(&ds, *p);
        }
        dstring_put_char(&ds, '"');
    }
    return dstring_to_cstring(&ds);
}

static int time_format_helper(struct timeval tv, char *time_str, int str_len)
{
    struct tm now_time;
    char timeformat[MAX_LENGTH_LOG + 1] = {0};
    unsigned long millisecs;
    int ret;

    tzset();
    if (localtime_r(&tv.tv_sec, &now_time) == NULL) {
        return -1;
    }
    (void)strftime(timeformat, sizeof(timeformat), "%Y-%m-%d %H:%M:%S", &now_time);
    millisecs = tv.tv_usec / THOUSANDTH;
    ret = snprintf(time_str, MAX_LENGTH_LOG, "%s.%03ld", timeformat, millisecs);
    if (ret <= 0 || ret >= str_len) {
        return -1;
    }

    return 0;
}

uvs_admin_trace_t *trace_create(char *argv[])
{
    uvs_admin_trace_t *trace = NULL;
    trace = calloc(1, sizeof(*trace));
    if (trace == NULL) {
        return NULL;
    }
    trace->g_cmd = process_escape_args(argv);
    trace->isOperation = false;
    (void)gettimeofday(&trace->start_time, NULL);
    return trace;
}

void trace_destroy(uvs_admin_trace_t *trace)
{
    if (trace == NULL) {
        return;
    }
    if (trace->g_cmd != NULL) {
        free(trace->g_cmd);
    }
    free(trace);
}

void trace_log(const uvs_admin_trace_t *trace, int err)
{
    struct timeval end_time;
    struct dstring log_ds = DSTRING_INITIALIZER;
    char log_start_time[MAX_LENGTH_LOG + 1] = {0};
    char log_end_time[MAX_LENGTH_LOG + 1] = {0};

    if (!trace->isOperation) {
        return;
    }
    (void)gettimeofday(&end_time, NULL);
    if (time_format_helper(trace->start_time, log_start_time, MAX_LENGTH_LOG)) {
        return;
    }
    dstring_printf(&log_ds, "%s (start %s ", trace->g_cmd, log_start_time);
    if (time_format_helper(end_time, log_end_time, MAX_LENGTH_LOG)) {
        return;
    }
    dstring_printf(&log_ds, "exit %s)", log_end_time);
    if (err) {
        dstring_printf(&log_ds, ", status(%d).\n", err);
    }

    if (err) {
        UVS_ADMIN_LOG_ERR("uvs|%s|%s", trace->mod_name, dstring_to_cstring(&log_ds));
    } else {
        UVS_ADMIN_LOG_INFO("uvs|%s|%s", trace->mod_name, dstring_to_cstring(&log_ds));
    }

    dstring_destroy(&log_ds);
}
