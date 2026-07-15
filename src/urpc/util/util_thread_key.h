/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: util thread key module
 * Create: 2026-07-15
 */

#ifndef UTIL_THREAD_KEY_H
#define UTIL_THREAD_KEY_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void* util_thread_key_t;

typedef struct util_thread_key_ops {
    util_thread_key_t *(*key_create)(void (*destr_function)(void *data));
    int (*key_delete)(util_thread_key_t *key);
    int (*setspecific)(util_thread_key_t *key, const void *data);
    void *(*getspecific)(util_thread_key_t *key);
} util_thread_key_ops_t;

void util_thread_key_ops_register(const util_thread_key_ops_t *ops);

util_thread_key_t *util_thread_key_create(void (*destr_function)(void *data));
int util_thread_key_delete(util_thread_key_t *key);
int util_thread_setspecific(util_thread_key_t *key, const void *data);
void *util_thread_getspecific(util_thread_key_t *key);

#ifdef __cplusplus
}
#endif

#endif
