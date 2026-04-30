/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Configuration data structures and API for the UMS agent
 * Author: Hu Ying
 * Create: 2026-04-20
 * Note:
 * History: 2026-04-20  Create File
 */

#ifndef UMS_AGENT_CONFIG_H
#define UMS_AGENT_CONFIG_H

#include <stdint.h>
#include <limits.h>

#include "ums_agent_log.h"

#define UMS_AGENT_MAX_ADDR_LEN     64
#define UMS_AGENT_MAX_CIPHER_LEN   64
#define UMS_AGENT_MAX_PWD_DESC_LEN 128

struct ums_agent_x509_config {
    char truststore[PATH_MAX];
    char crl[PATH_MAX];
    char certificate[PATH_MAX];
    char private_key[PATH_MAX];
    char prkey_pwd_desc[UMS_AGENT_MAX_PWD_DESC_LEN];
};

struct ums_agent_config {
    enum ums_agent_log_level log_level;

    struct ums_agent_x509_config client;
    struct ums_agent_x509_config server;

    char listen_addr[UMS_AGENT_MAX_ADDR_LEN];
    int  listen_port;

    char cipher_suite[UMS_AGENT_MAX_CIPHER_LEN];
};

int  ums_agent_config_init(const char *path, struct ums_agent_config **config);
void ums_agent_config_deinit(struct ums_agent_config *config);
int ums_agent_resolve_path(const char *path, const char *config_name, char *resolved_path);

#endif /* UMS_AGENT_CONFIG_H */
