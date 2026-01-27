/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : client_test.cpp
 * Description   : test dlock client's lock operations
 * History       : create file & add functions
 * 1.Date        : 2021-06-16
 * Author        : wangyue
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
    int lock_id_1 = client_id * 2;
    int lock_id_2 = client_id * 2 + 1;
    struct timeval tv_start, tv_end;
    long time, time_total, time_min, time_max;
    struct lock_desc lock_1 = {0};
    struct lock_desc lock_2 = {0};
    struct lock_request lock_req1 = {0};
    struct lock_request lock_req2 = {0};
    struct lock_request lock_req2_ext = {0};
    atomic_state lock_state1 = {0};
    atomic_state lock_state2 = {0};
    atomic_state lock_state2_ext = {0};
    int ret;

    time_total = time_max = 0;
    time_min = 1000000;

    {
        std::unique_lock<std::mutex> locker(g_client_mgr_lock);
        ret = CLIENT_INIT(&client_id, g_server_ip);
    }
    if (ret != 0) {
        printf("client_init failed! ret: %d\n", ret);
        return 0;
    }
    printf("client init succeed\n");

    gettimeofday(&tv_start, NULL);

    lock_1.lock_type = DLOCK_ATOMIC;
    lock_1.lease_time = tv_start.tv_sec + 60000;
    lock_1.p_desc = (char *)(&lock_id_1);
    lock_1.len = 4;
    ret = get_lock(client_id, &lock_1, &lock_id_1);
    if (ret != 0) {
        printf("getlock failed! ret: %d\n", ret);
        return 0;
    }
    lock_req1.lock_id = lock_id_1;
    lock_req1.expire_time = 6000;

    lock_2.lock_type = DLOCK_ATOMIC;
    lock_2.lease_time = tv_start.tv_sec + 60000;
    lock_2.p_desc = (char *)(&lock_id_2);
    lock_2.len = 4;
    ret = get_lock(client_id, &lock_2, &lock_id_2);
    if (ret != 0) {
        printf("getlock failed! ret: %d\n", ret);
        return 0;
    }
    lock_req2.lock_id = lock_id_2;
    lock_req2.expire_time = 6000;

    lock_req2_ext.lock_id = lock_id_2;
    lock_req2_ext.expire_time = 7000;

    for (int i = 0; i < g_loop_num; i++) {
        lock_req1.lock_op = LOCK_EXCLUSIVE;
        lock_req2.lock_op = LOCK_EXCLUSIVE;
        lock_req2_ext.lock_op = EXTEND_LOCK_EXCLUSIVE;
        ret = trylock(client_id, &lock_req2, &lock_state2);
        if (ret != 0) {
            printf("trylock failed! ret: %d\n", ret);
            return 0;
        }

        ret = lock_extend(client_id, &lock_req2_ext, &lock_state2_ext);
        if (ret != 0) {
            printf("lock_extend failed! ret: %d\n", ret);
            return 0;
        }

        gettimeofday(&tv_start, NULL);

        ret = trylock(client_id, &lock_req1, &lock_state1);
        if (ret != 0) {
            printf("trylock failed! ret: %d\n", ret);
            return 0;
        }

        gettimeofday(&tv_end, NULL);
        time = (long)tv_end.tv_usec - tv_start.tv_usec + (tv_end.tv_sec - tv_start.tv_sec)* 1000000;
        time_total += time;
        time_min = (time_min > time) ? time : time_min;
        time_max = (time_max < time) ? time : time_max;

        ret = unlock(client_id, lock_id_1, &lock_state1);
        if (ret != 0) {
            printf("unlock failed! ret: %d\n", ret);
            return 0;
        }

        ret = unlock(client_id, lock_id_2, &lock_state2);
        if (ret != 0) {
            printf("unlock failed! ret: %d\n", ret);
            return 0;
        }
    }
    ret = release_lock(client_id, lock_id_1);
    if (ret != 0) {
        printf("release_lock failed! ret: %d\n", ret);
        return 0;
    }
    ret = release_lock(client_id, lock_id_2);
    if (ret != 0) {
        printf("release_lock failed! ret: %d\n", ret);
        return 0;
    }

    {
        std::unique_lock<std::mutex> locker(g_client_mgr_lock);
        ret = client_deinit(client_id);
    }
    if (ret != 0) {
        printf("client_deinit failed! ret: %d\n", ret);
        return 0;
    }
    printf("thread[%d] total trylock time: %ld us, average %lf us\n",*(int *)p_object, time_total, 1.0*time_total/g_loop_num);
    printf("thread[%d] trylock max time: %ld us, min time: %ld\n", *(int *)p_object, time_max, time_min);
    return 0;
}

void* client_heartbeat_test(void *p_object)
{
    int client_id = *(int *)p_object;
    struct timeval tv_start, tv_end;
    long time, time_total, time_min, time_max;
    int ret;

    time_total = time_max = 0;
    time_min = 1000000;

    {
        std::unique_lock<std::mutex> locker(g_client_mgr_lock);
        ret = CLIENT_INIT(&client_id, g_server_ip);
    }
    if (ret != 0) {
        printf("client_init failed! ret: %d\n", ret);
        return 0;
    }
    printf("client init succeed\n");

    gettimeofday(&tv_start, NULL);

    for (int i = 0; i < g_loop_num; i++) {
        gettimeofday(&tv_start, NULL);
        ret = client_heartbeat(client_id, 10);
        if (ret != 0) {
            printf("client_heartbeat failed! ret: %d\n", ret);
            return 0;
        }
        gettimeofday(&tv_end, NULL);
        time = (long)tv_end.tv_usec - tv_start.tv_usec + (tv_end.tv_sec - tv_start.tv_sec)* 1000000;
        time_total += time;
        time_min = (time_min > time) ? time : time_min;
        time_max = (time_max < time) ? time : time_max;
    }

    {
        std::unique_lock<std::mutex> locker(g_client_mgr_lock);
        ret = client_deinit(client_id);
    }
    if (ret != 0) {
        printf("client_deinit failed! ret: %d\n", ret);
        return 0;
    }
    printf("thread[%d] total heartbeat time: %ld us, average %lf us\n",
        *(int *)p_object, time_total, 1.0*time_total/g_loop_num);
    printf("thread[%d] heartbeat max time: %ld us, min time: %ld\n", *(int *)p_object, time_max, time_min);
    return 0;
}

void* client_getlock_test(void *p_object)
{
    int client_id = *(int *)p_object;
    int lock_ids[BATCH_SIZE];
    struct timeval tv_start, tv_end;
    long time, time_total, time_min, time_max;
    struct lock_desc lock_descs[BATCH_SIZE];
    int i;
    int ret;

    time_total = time_max = 0;
    time_min = 1000000;
    {
        std::unique_lock<std::mutex> locker(g_client_mgr_lock);
        ret = CLIENT_INIT(&client_id, g_server_ip);
    }
    if (ret != 0) {
        printf("client_init failed! ret: %d\n", ret);
        return 0;
    }
    printf("client init succeed\n");

    for (i = 0; i < BATCH_SIZE; i++) {
        lock_ids[i] = client_id * BATCH_SIZE + i;
        lock_descs[i].lock_type = DLOCK_ATOMIC;
        lock_descs[i].lease_time = 60000;
        lock_descs[i].p_desc = (char *)(lock_ids + i);
        lock_descs[i].len = 4;
    }

    for (int k = 0; k < g_loop_num; k++) {
        gettimeofday(&tv_start, NULL);
        ret = batch_get_lock(client_id, BATCH_SIZE, lock_descs, lock_ids);
        gettimeofday(&tv_end, NULL);
        if (ret != 0) {
            printf("batch get lock ret %d\n", ret);
            return 0;
        }
        time = (long)tv_end.tv_usec - tv_start.tv_usec + (tv_end.tv_sec - tv_start.tv_sec)* 1000000;
        time_total += time;
        time_min = (time_min > time) ? time : time_min;
        time_max = (time_max < time) ? time : time_max;

        ret = batch_release_lock(client_id, BATCH_SIZE, lock_ids);
        if (ret != 0) {
            printf("batch release ret %d\n", ret);
            return 0;
        }
    }

    {
        std::unique_lock<std::mutex> locker(g_client_mgr_lock);
        ret = client_deinit(client_id);
    }
    if (ret != 0) {
        printf("client_deinit failed! ret: %d\n", ret);
        return 0;
    }
    printf("thread[%d] total get lock time: %ld us, average %lf us\n",*(int *)p_object, time_total,
                   1.0*time_total/g_loop_num);
    printf("thread[%d] getlock max time: %ld us, min time: %ld us\n", *(int *)p_object, time_max, time_min);
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
    for (int i = 0; i < g_client_num; i++) {
        g_client_id[i] = BASE_CLIENT_ID + i;
        ret = pthread_create(&g_client_tid[i], NULL, client_heartbeat_test, &g_client_id[i]);
        if (ret != 0) {
            printf("error to create thread for client\n");
            return -1;
        }
    }
    for (int i = 0; i < g_client_num; i++) {
        pthread_join(g_client_tid[i], NULL);
    }

    for (int i = 0; i < g_client_num; i++) {
        ret = pthread_create(&g_client_tid[i], NULL, client_getlock_test, &g_client_id[i]);
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
