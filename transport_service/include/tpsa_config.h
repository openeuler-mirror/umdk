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

#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

int tpsa_config_init(void);
void tpsa_config_uninit(void);
int tpsa_get_server_ip(struct in_addr *ip);
int tpsa_get_server_port(uint16_t *port);

#ifdef __cplusplus
}
#endif

#endif