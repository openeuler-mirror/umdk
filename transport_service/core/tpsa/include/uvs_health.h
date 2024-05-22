/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: check Whether the uvs thread is processing events
 * Author: Liwenhao
 * Create: 2024-2-20
 * Note:
 * History:
 */

#ifndef UVS_HEALTH_H
#define UVS_HEALTH_H

#ifdef __cplusplus
extern "C" {
#endif

void uvs_health_update_event_time(void);
int uvs_health_check_service_init(void);
void uvs_health_check_service_uninit(void);
#ifdef __cplusplus
}

#endif

#endif /* UVS_HEALTH_H */
