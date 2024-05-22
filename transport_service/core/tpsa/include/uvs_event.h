/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: set and execute uvs event cb
 * Author: Liwenhao
 * Create: 2024-2-20
 * Note:
 * History:
 */
#ifndef UVS_EVENT_H
#define UVS_EVENT_H

#include "uvs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int uvs_event_set_cb(uvs_event_cb_t cb_func, void *cb_arg);
int uvs_event_execute_cb(struct uvs_event *event);

#ifdef __cplusplus
}
#endif

#endif /* UVS_EVENT_H */