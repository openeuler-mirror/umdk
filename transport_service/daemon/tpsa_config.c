/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa config file
 * Author: Chen Wen
 * Create: 2022-08-24
 * Note:
 * History:
 */

#include <stdint.h>
#include <stdlib.h>

#include "ub_list.h"

#include "tpsa_ini.h"
#include "tpsa_log.h"
#include "tpsa_config.h"

#define TPSA_IP_LEN  32

static tpsa_config_t g_tpsa_config = {0};

int tpsa_parse_config_file(tpsa_config_t *cfg)
{
    struct in_addr addr;
    char server_ip[TPSA_IP_LEN] = {0};
    char tcp_port[TPSA_IP_LEN] = {0};
    unsigned int server_port;
    file_info_t *file = NULL;

    file = calloc(1, sizeof(file_info_t));
    if (file == NULL) {
        TPSA_LOG_ERR("Failed to malloc memory.\n");
        return -1;
    }

    (void)memcpy(&file->path[0], "/etc/tpsa/tpsa.ini", sizeof("/etc/tpsa/tpsa.ini"));
    (void)memcpy(&file->section[0], "TPSA", sizeof("TPSA"));

    /* read server_ip */
    (void)memcpy(&file->key[0], "tpsa_server_ip", sizeof("tpsa_server_ip"));
    int ret = tpsa_read_value_by_etc_file(file, server_ip, TPSA_IP_LEN);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to read tpsa_server_ip by etc file, ret: %d.\n", ret);
        goto free_file;
    }
    if (inet_pton(AF_INET, server_ip, &addr) <= 0) {
        TPSA_LOG_ERR("read ETC file: server_ip is illegal. server_ip:%s", server_ip);
        goto free_file;
    }
    g_tpsa_config.tpsa_server_ip = addr;
    cfg->tpsa_server_ip = addr;
    TPSA_LOG_INFO("read ETC file: get server_ip: %s.", server_ip);

    /* read server_port */
    (void)memcpy(file->key, "tpsa_server_port", sizeof("tpsa_server_port"));
    ret = tpsa_read_value_by_etc_file(file, tcp_port, TPSA_IP_LEN);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to read tpsa_server_port by etc file, ret: %d.\n", ret);
        goto free_file;
    }
    ret = ub_str_to_u32(tcp_port, &server_port);
    if (ret != 0) {
        TPSA_LOG_ERR("read ETC file: server_port is illegal. server_port:%s, ret:%d", tcp_port, ret);
        goto free_file;
    }
    g_tpsa_config.tpsa_server_port = htons((uint16_t)server_port);
    cfg->tpsa_server_port = g_tpsa_config.tpsa_server_port;
    TPSA_LOG_INFO("read ETC file: get server_port: %d.", server_port);

free_file:
    free(file);
    return ret;
}

tpsa_config_t uvs_get_config(void)
{
    return g_tpsa_config;
}