/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : test_dlock_comm.h
 * Description   : dlock unit test common header file
 * History       : create file & add functions
 * 1.Date        : 2022-08-01
 * Author        : wangyue
 * Modification  : Created file
 */

#ifndef __TEST_DLOCK_COMM_H__
#define __TEST_DLOCK_COMM_H__

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <string>

#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include "dlock_types.h"
#include "dlock_common.h"
#include "dlock_client_api.h"
#include "dlock_server_api.h"
#include "dlock_log.h"

#define INVALID_IP_STR "1.1.1.1"

#define PRIMARY1_CONTROL_PORT_CLIENT 22000
#define PRIMARY2_CONTROL_PORT_CLIENT 22001
#define PRIMARY3_CONTROL_PORT_CLIENT 22002

#define PRIMARY1_CONTROL_PORT_REPLICA 21615

#define BASE_CLIENT_ID 1
#define CLIENT_NUM 8
#define BATCH_SIZE 31
#define LOCK_NUM_LIMIT 51200

#define DLOCK_SSL_FILE_PATH "/home/dlock_test/"

#define CA_PATH "/home/dlock_test/ca.crt"
#define CA_PRKEY_PWD "123456"
#define CA_2_PATH "/home/dlock_test/ca_2.crt"
#define CA_2_PRKEY_PWD "123456"

#define SERVER_CERT_PATH "/home/dlock_test/server.crt"
#define SERVER_PRKEY_PATH "/home/dlock_test/server_rsa_private.pem"
#define SERVER_PRKEY_PWD "server"
#define SERVER_PRKEY_PWD_LEN 6

#define CLIENT_CERT_PATH "/home/dlock_test/client.crt"
#define CLIENT_PRKEY_PATH "/home/dlock_test/client_rsa_private.pem"
#define CLIENT_PRKEY_PWD "client"
#define CLIENT_PRKEY_PWD_LEN 6

#define MAX_BUF 1024

extern int g_primary_server1_id;
extern int g_client_id[CLIENT_NUM];

using namespace dlock;

struct test_dlock_cfg {
    char *server_ip;
    dlock_eid_t eid;
    char *dev_name;
    int log_level;
};

struct dlock_ssl_ca_info {
    std::string ca_path;
    std::string ca_prkey_path;
    std::string ca_prkey_pwd;
};

struct dlock_primary_cfg {
    char *server_ip;
    unsigned int recovery_client_num;
    unsigned int num_of_replica;
    bool replica_enable;
    bool ssl_enable;
    trans_mode_t tp_mode;
    char *ctrl_cpuset;
    char *cmd_cpuset;
};

extern struct test_dlock_cfg g_test_dlock_cfg;

int generate_ssl_ca(std::string &pwd, std::string &path, std::string &file_suffix, int days);
int generate_ssl_crt(struct dlock_ssl_ca_info &ca_info, std::string &pwd, std::string &path, std::string &file_suffix, int days);
int generate_ssl_file(void);
int delete_ssl_file(void);
void server_get_prkey_pwd(char **prkey_pwd, int *prkey_pwd_len);
void client_get_prkey_pwd(char **prkey_pwd, int *prkey_pwd_len);
void erase_prkey(void *prkey_pwd, int prkey_pwd_len);

void default_server_ssl_cfg(struct ssl_cfg &ssl);
void default_client_ssl_cfg(struct ssl_cfg &ssl);

int get_listenfd_port(int *listen_fd, uint16_t *port);
int sock_connect(bool is_server, int listen_fd, uint16_t port);

void construct_primary_cfg(struct server_cfg &cfg_s, struct dlock_primary_cfg param_cfg);
void startup_primary_server1(unsigned int recovery_client_num, unsigned int num_of_replica, bool replica_enable,
    bool ssl_enable, trans_mode_t tp_mode);
void stop_primary_server1(void);

void init_dclient_lib_with_server1(bool ssl_enable, trans_mode_t tp_mode);
void startup_clients_of_server1(bool ssl_enable, trans_mode_t tp_mode);
void stop_clients_of_server1(void);
void reinit_clients_of_server1(void);
int update_client_locks(int client_id);
void recovery_clients_of_server1(void);

void prepare_default_primary_server_cfg(struct server_cfg &cfg_s);
void destroy_default_primary_server_cfg(struct server_cfg &cfg_s);

void default_server_ssl_init_attr(ssl_init_attr_t &init_attr);

#endif  //__TEST_DLOCK_COMM_H__
