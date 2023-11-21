/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: Definition of generic commands of uvs_admin
 * Author: Jilei
 * Create: 2023-07-20
 * Note:
 * History: 2023-07-20 Jilei Initial operation cmd trace
 */

#ifndef UVS_ADMIN_CMD_CTRACE_H
#define UVS_ADMIN_CMD_CTRACE_H

#include <sys/time.h>
#include <stdbool.h>
#include "urma_types.h"

#define MAX_LENGTH_LOG 1024
#define UVS_OPERATION_IDENT "UVS-OPERATION"

typedef struct uvs_admin_trace {
    char *g_cmd;
    const char *mod_name;
    bool isOperation;
    struct timeval start_time;
} uvs_admin_trace_t;

bool cmd_is_operation(int argc, char *argv[]);

/* first use the function:trace_create to create the Trace. */
uvs_admin_trace_t *trace_create(char *argv[]);

/* this function must be called at last . */
void trace_destroy(uvs_admin_trace_t *trace);

void trace_log(const uvs_admin_trace_t *trace, int err);

#endif /* UVS_ADMIN_CMD_CTRACE_H */
