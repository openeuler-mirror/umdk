/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: UVS security header file
 * Author: Zhao Yusu
 * Create: 2024-02-28
 * Note:
 * History: 2024-02-28 Zhao Yusu         Introduce UVS socket security
 */

#ifndef UVS_SECURITY_H
#define UVS_SECURITY_H

#include <unistd.h>
#include <openssl/ssl.h>

#include "uvs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

SSL *uvs_create_secure_socket(int sockfd, uvs_ssl_cfg_t *cfg, bool server);
void uvs_destroy_secure_socket(SSL *ssl);
int uvs_ssl_init(uvs_ssl_cfg_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* UVS_SECURITY_H */
