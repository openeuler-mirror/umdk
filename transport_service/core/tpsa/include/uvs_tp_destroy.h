/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uvs tp resource destroy header file
 * Author: Xu Zhicong
 * Create: 2024-1-18
 * Note:
 * History:
 */

#ifndef UVS_TP_DESTROY_H
#define UVS_TP_DESTROY_H

#include "uvs_tp_manage.h"

/*
* Clean TP res, for deleting vport cfg
*/
void uvs_clean_deleted_vport(uvs_ctx_t *ctx);

/*
* Clean TP res, for VF reboot
*/
void uvs_clean_rebooted_fe(uvs_ctx_t *ctx);

#endif