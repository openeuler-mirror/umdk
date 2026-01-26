/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: reference count for queue resource
 */

#ifndef QUEUE_RESOURCE_REF_H
#define QUEUE_RESOURCE_REF_H

#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
using namespace std;
#endif
#include "urpc_framework_types.h"
#include "pthread.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct q_res_ref {
    atomic_uint ref_cnt;
} q_res_ref_t;

void q_res_ref_init(q_res_ref_t *ref);
int q_res_ref_get(q_res_ref_t *ref);
/* Do not count on the ref from remaining in memory when this function returns 0.
 * Return 1 if the object was removed, otherwise return 0. */
int q_res_ref_put(q_res_ref_t *ref, void (*release)(q_res_ref_t *ref, void *args), void *args);

#ifdef __cplusplus
}
#endif

#endif

