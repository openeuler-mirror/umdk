/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: util thread key module
 * Create: 2026-07-15
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include "util_thread_key.h"

static util_thread_key_t *util_thread_key_create_impl(void (*destr_function)(void *data))
{
    pthread_key_t *p_key = (pthread_key_t *)calloc(1, sizeof(pthread_key_t));
    if (p_key == NULL) {
        return NULL;
    }

    int ret = pthread_key_create(p_key, destr_function);
    if (ret != 0) {
        free(p_key);
        errno = ret;
        return NULL;
    }

    return (util_thread_key_t *)p_key;
}

static int util_thread_key_delete_impl(util_thread_key_t *key)
{
    pthread_key_t *p_key = (pthread_key_t *)key;
    if (p_key == NULL) {
        return EINVAL;
    }

    int ret = pthread_key_delete(*p_key);
    if (ret == 0) {
        free(key);
    }
    return ret;
}

static int util_thread_setspecific_impl(util_thread_key_t *key, const void *data)
{
    pthread_key_t *p_key = (pthread_key_t *)key;
    if (p_key == NULL) {
        return EINVAL;
    }

    return pthread_setspecific(*p_key, data);
}

static void *util_thread_getspecific_impl(util_thread_key_t *key)
{
    pthread_key_t *p_key = (pthread_key_t *)key;
    if (p_key == NULL) {
        return NULL;
    }

    return pthread_getspecific(*p_key);
}

static util_thread_key_ops_t g_util_thread_key_ops = {
    .key_create = util_thread_key_create_impl,
    .key_delete = util_thread_key_delete_impl,
    .setspecific = util_thread_setspecific_impl,
    .getspecific = util_thread_getspecific_impl,
};

void util_thread_key_ops_register(const util_thread_key_ops_t *ops)
{
    if (ops == NULL) {
        g_util_thread_key_ops.key_create = util_thread_key_create_impl;
        g_util_thread_key_ops.key_delete = util_thread_key_delete_impl;
        g_util_thread_key_ops.setspecific = util_thread_setspecific_impl;
        g_util_thread_key_ops.getspecific = util_thread_getspecific_impl;
        return;
    }

    g_util_thread_key_ops = *ops;
}

util_thread_key_t *util_thread_key_create(void (*destr_function)(void *data))
{
    return g_util_thread_key_ops.key_create(destr_function);
}

int util_thread_key_delete(util_thread_key_t *key)
{
    return g_util_thread_key_ops.key_delete(key);
}

int util_thread_setspecific(util_thread_key_t *key, const void *data)
{
    return g_util_thread_key_ops.setspecific(key, data);
}

void *util_thread_getspecific(util_thread_key_t *key)
{
    return g_util_thread_key_ops.getspecific(key);
}
