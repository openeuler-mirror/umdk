/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa config header file
 * Author: Chen Wen
 * Create: 2022-08-22
 * Note:
 * History:
 */

#ifndef TPSA_CONFIG_H
#define TPSA_CONFIG_H

#include "uvs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpsa_config {
    uvs_net_addr_type_t tpsa_ip_type;
    uvs_net_addr_t tpsa_server_ip;
    uint16_t tpsa_server_port;
} tpsa_config_t;

int tpsa_parse_config_file(tpsa_config_t *cfg);
tpsa_config_t uvs_get_config(void);

#ifdef __cplusplus
}
#endif

#endif