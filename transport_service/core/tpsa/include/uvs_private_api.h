/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uvs private api
 * Author: Li Hai
 * Create: 2024-2-18
 * Note:
 * History:
 */

#ifndef UVS_PRIVATE_API_H
#define UVS_PRIVATE_API_H

#include "uvs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

uvs_user_ops_t* get_uvs_user_ops(user_ops_t user_ops);
int uvs_ops_lock_init(void);
void uvs_ops_lock_uninit(void);
void uvs_ops_mutex_lock(void);
void uvs_ops_mutex_unlock(void);

#ifdef __cplusplus
}
#endif

#endif