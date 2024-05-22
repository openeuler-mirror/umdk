/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uvs private api
 * Author: Li Hai
 * Create: 2024-2-18
 * Note:
 * History:
 */

#include <pthread.h>

#include "uvs_private_api.h"

static pthread_mutex_t g_uvs_ops_lock;
static uvs_user_ops_t g_uvs_gaea_ops = {0};

uvs_user_ops_t* get_uvs_user_ops(user_ops_t user_ops)
{
    switch (user_ops) {
        case USER_OPS_GAEA:
            return &g_uvs_gaea_ops;
        case USER_OPS_MAX:
        default:
            return NULL;
    }
}

int uvs_ops_lock_init(void)
{
    if (pthread_mutex_init(&g_uvs_ops_lock, NULL) != 0) {
        return -1;
    }
    return 0;
}

void uvs_ops_lock_uninit(void)
{
    (void)pthread_mutex_destroy(&g_uvs_ops_lock);
}

void uvs_ops_mutex_lock(void)
{
    (void)pthread_mutex_lock(&g_uvs_ops_lock);
}

void uvs_ops_mutex_unlock(void)
{
    (void)pthread_mutex_unlock(&g_uvs_ops_lock);
}
