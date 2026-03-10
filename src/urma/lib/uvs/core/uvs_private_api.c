/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * Description: uvs private api
 * Author: Li Hai
 * Create: 2024-2-18
 * Note:
 * History:
 */

#include <pthread.h>

#include "tpsa_log.h"

static pthread_rwlock_t g_uvs_api_rwlock = PTHREAD_RWLOCK_INITIALIZER;

void uvs_get_api_rdlock(void)
{
    pthread_rwlock_rdlock(&g_uvs_api_rwlock);
}

void uvs_get_api_wrlock(void)
{
    pthread_rwlock_wrlock(&g_uvs_api_rwlock);
}

void put_uvs_lock(void)
{
    pthread_rwlock_unlock(&g_uvs_api_rwlock);
}