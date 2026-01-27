/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : client_test_object.cpp
 * Description   : test dlock client's object operations
 * History       : create file & add functions
 * 1.Date        : 2024-10-28
 * Author        : wujie
 * Modification  : Created file
 */

#include <cstddef>
#include <sys/time.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <mutex>

#include "dlock_types.h"
#include "dlock_client_api.h"
#include "example_common.h"

using namespace dlock;

#define CLIENT_INIT(a, b) client_init(a, b)

#define BASE_CLIENT_ID 1
#define CLIENT_NUM 32
#define LOOP_NUM 10000
#define BATCH_SIZE 2

pthread_t g_client_tid[CLIENT_NUM];
int g_client_id[CLIENT_NUM];
static char *g_server_ip = nullptr;
static char *g_dev_name = nullptr;
static char *g_eid_str = nullptr;
static int g_server_port = 0;
static int g_loglevel = LOG_WARNING;
static int g_client_num = CLIENT_NUM;
static trans_mode_t g_tp_mode = SEPERATE_CONN;

static int g_loop_num = LOOP_NUM;
static std::mutex g_client_mgr_lock;

void* client_launch(void *p_object)
{
    int client_id = *(int *)p_object;
    int object_id = 0;
    struct umo_atomic64_desc desc;
    int ret;
    char desc_str[256] = "dlock_desc";
    uint64_t v = 1;

    {
        std::unique_lock<std::mutex> locker(g_client_mgr_lock);
        ret = CLIENT_INIT(&client_id, g_server_ip);
    }
    if (ret != 0) {
        printf("client_init failed! ret: %d\n", ret);
        return 0;
    }
    printf("client init succeed\n");

    desc.lease_time = 600000;
    desc.p_desc = desc_str;
    desc.len = strlen(desc_str);

    ret = umo_atomic64_create(client_id, &desc, v, &object_id);
    if (ret != 0) {
        printf("client create object failed: %d\n", ret);
        return NULL;
    }
    printf("client create object id %d\n", object_id);

    ret = umo_atomic64_get(client_id, &desc, &object_id);
    if (ret != 0) {
        printf("client get object failed %d\n", ret);
        return NULL;
    }
    printf("client get object id %d\n", object_id);

    for (int k = 0; k < g_loop_num; k++) {
        uint64_t t = 1;
        ret = umo_atomic64_get_snapshot(client_id, object_id, &v);
        if (ret != 0) {
            printf("client get snapshot failed: %d\n", ret);
            break;
        }

        ret = umo_atomic64_faa(client_id, object_id, t, &v);
        if (ret != 0) {
            printf("client perform FAA failed: %d\n", ret);
            break;
        }

        ret = umo_atomic64_cas(client_id, object_id, v + t, v);
        if (ret != 0) {
            printf("client perform CAS failed: %d\n", ret);
            break;
        }
    }

    ret = umo_atomic64_release(client_id, object_id);
    if (ret != 0) {
        printf("client release object failed: %d\n", ret);
        return NULL;
    }
    printf("client release object id %d\n", object_id);

    ret = umo_atomic64_destroy(client_id, object_id);
    if (ret != 0) {
        printf("client destroy object failed: %d\n", ret);
        return NULL;
    }
    printf("client destroy object id %d\n", object_id);

    {
        std::unique_lock<std::mutex> locker(g_client_mgr_lock);
        ret = client_deinit(client_id);
    }
    if (ret != 0) {
        printf("client_deinit failed! ret: %d\n", ret);
        return 0;
    }
    printf("test done\n");
    return NULL;
}

int main(int argc, char *argv[])
{
    printf("this is client\n");
    int ret;
    struct client_cfg s_client_cfg;
    int opt;

    while ((opt = getopt(argc, argv, "i:e:d:p:c:l:m:g:")) != -1) {
        switch (opt) {
            case 'i': // server IP
                g_server_ip = strdup(optarg);
                break;
            case 'e': // eid string
                g_eid_str = strdup(optarg);
                break;
            case 'd': // device name
                g_dev_name = strdup(optarg);
                break;
            case 'p': // server port
                g_server_port = atoi(optarg);
                break;
            case 'c': // client number
                g_client_num = atoi(optarg);
                break;
            case 'l': // loop number
                g_loop_num = atoi(optarg);
                break;
            case 'm': // transport mode
                g_tp_mode = (trans_mode_t)atoi(optarg);
                break;
            case 'g': // log level
                g_loglevel = atoi(optarg);
                break;
            default:
                printf("Usage: %s [-i server_ip] [-e eid] [-d dev_name] [-p server_port] [-c client_num] \
                    [-l loop_num] [-m transport_mode] [-g log_level]\n", argv[0]);
                printf("Options: "
                    "-i IP     Server IP address \n"
                    "-e EID    EID string \n"
                    "-d DEV    Device name \n"
                    "-p PORT   Server port \n"
                    "-c NUM    Client number \n"
                    "-l NUM    Loop number \n"
                    "-m MODE   Transport mode \n"
                    "-g NUM    Log level\n");
                return -1;
        }
    }

    if (g_server_ip == nullptr) {
        printf("Error: Server IP must be provided\n");
        return -1;
    }

    if (g_eid_str == nullptr && g_dev_name == nullptr) {
        printf("Error: At least one of eid or dev_name must be provided\n");
        return -1;
    }

    if (g_server_port <= 0) {
        printf("Error: Server port is either not provided or provided with invalid value\n");
        return -1;
    }

    if (g_client_num <= 0 || g_client_num > CLIENT_NUM) {
        printf("Error: Invalid client number\n");
        return -1;
    }

    if (g_loglevel < 0 || g_loglevel > 7) {
        printf("Error: Invalid log level\n");
        return -1;
    }

    s_client_cfg.dev_name = g_dev_name;
    s_client_cfg.primary_port = g_server_port;
    s_client_cfg.log_level = g_loglevel;
    s_client_cfg.tp_mode = g_tp_mode;

    s_client_cfg.ssl.ssl_enable = false;
    s_client_cfg.ssl.ca_path = nullptr;
    s_client_cfg.ssl.crl_path = nullptr;
    s_client_cfg.ssl.cert_path = nullptr;
    s_client_cfg.ssl.prkey_path = nullptr;
    s_client_cfg.ssl.cert_verify_cb = nullptr;
    s_client_cfg.ssl.prkey_pwd_cb = nullptr;
    s_client_cfg.ssl.erase_prkey_cb = nullptr;

    if (g_eid_str != nullptr) {
        ret = str_to_urma_eid(g_eid_str, &s_client_cfg.eid);
        if (ret != 0) {
            printf("invalid eid: %s\n", g_eid_str);
            return -1;
        }
    } else {
        s_client_cfg.eid = {0};
    }

    ret = dclient_lib_init(&s_client_cfg);
    if (ret != 0) {
        printf("dlock client lib init failed! ret: %d\n", ret);
        return -1;
    }

    for (int i = 0; i < g_client_num; i++) {
        g_client_id[i] = BASE_CLIENT_ID + i;
        ret = pthread_create(&g_client_tid[i], NULL, client_launch, &g_client_id[i]);
        if (ret != 0) {
            printf("error to create thread for client\n");
            return -1;
        }
    }

    for (int i = 0; i < g_client_num; i++) {
        pthread_join(g_client_tid[i], NULL);
    }

    dclient_lib_deinit();

    if (g_server_ip != nullptr) {
        free(g_server_ip);
    }

    if (g_eid_str != nullptr) {
        free(g_eid_str);
    }

    if (g_dev_name != nullptr) {
        free(g_dev_name);
    }

    pthread_exit(NULL);
    return 0;
}
