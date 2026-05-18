/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: TLS CTX module interface for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-09
 * Note:
 * History: 2026-05-09  Create File
 */

#ifndef UMS_AGENT_TLS_CTX_H
#define UMS_AGENT_TLS_CTX_H

#include <stdbool.h>
#include <stddef.h>

#include <openssl/ssl.h>

#include "ums_agent_config.h"

int ums_agent_tls_ctx_init(const struct ums_agent_config *config);
void ums_agent_tls_ctx_deinit(void);

SSL_CTX *ums_agent_tls_get_server_ssl_ctx(void);
SSL_CTX *ums_agent_tls_get_client_ssl_ctx(void);

int ums_agent_tls_check_certs_expiry(const char *server_cert_path,
    const char *client_cert_path, bool force);

#endif /* UMS_AGENT_TLS_CTX_H */
