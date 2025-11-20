/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: dlock unit test common file
 * Author: wangyue
 * Create: 2022-7-18
 * Note:
 * History:
 */
#include <cstddef>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <climits>

#include "gtest/gtest.h"
#include "dlock_common.h"
#include "dlock_client_api.h"
#include "dlock_server_api.h"
#include "test_dlock_comm.h"



#include <fstream>
#include <iostream> 



#define CONNECT_COUNT 5
#define SLEEP_TIME (100 * 1000) /* sleep for 100 ms */
#define MAX_CONNECTIONS 10

int g_primary_server1_id = 0;
int g_client_id[CLIENT_NUM];

static inline int create_directory(std::string &path)
{
    std::string _cmd = "mkdir -p ";
    _cmd += path;
    return system(_cmd.c_str());
}

static inline int delete_directory(std::string &path)
{
    std::string _cmd = "rm -rf ";
    _cmd += path;
    return system(_cmd.c_str());
}

int generate_ssl_ca(std::string &pwd, std::string &path, std::string &file_suffix, int days)
{
    std::string ca_path = path + file_suffix + ".crt";
    std::string prkey_path = path + file_suffix + "_rsa_private.pem";
    std::string _cmd = "openssl req -newkey rsa:2048 -passout pass:" + pwd + " -keyout " + prkey_path + \
        " -x509 -days " + std::to_string(days) + " -out " + ca_path + \
        " -subj \"/C=CN/ST=GD/L=SZ/O=COM/OU=NSP/CN=DLOCKTEST_CA/emailAddress=dlocktest@huawei.com\"";

    return system(_cmd.c_str());
}

int generate_ssl_crt(struct dlock_ssl_ca_info &ca_info, std::string &pwd, std::string &path,
    std::string &file_suffix, int days)
{
    int ret;

    std::string csr_path = path + file_suffix + ".csr";
    std::string crt_path = path + file_suffix + ".crt";
    std::string prkey_path = path + file_suffix + "_rsa_private.pem";

    std::string _cmd1 = "openssl req -newkey rsa:2048 -passout pass:" + pwd + " -keyout " + prkey_path + \
        " -out " + csr_path + \
        " -subj \"/C=CN/ST=GD/L=SZ/O=COM/OU=NSP/CN=DLOCKTEST/emailAddress=dlocktest@huawei.com\"";
    ret = system(_cmd1.c_str());
    if (ret != 0) {
        return ret;
    }

    std::string _cmd2 = "openssl x509 -req -days " + std::to_string(days) + " -in " + csr_path + \
        " -CA " + ca_info.ca_path + " -CAkey " + ca_info.ca_prkey_path + " -passin pass:" + ca_info.ca_prkey_pwd + \
        " -CAcreateserial -out " + crt_path;
    return system(_cmd2.c_str());
}

int generate_ssl_file(void)
{
    int ret;
    int days = 365;
    std::string path = DLOCK_SSL_FILE_PATH;
    std::string ca_prkey_pwd = CA_PRKEY_PWD;
    std::string server_prkey_pwd = SERVER_PRKEY_PWD;
    std::string client_prkey_pwd = CLIENT_PRKEY_PWD;
    std::string ca_suffix = "ca";
    std::string server_suffix = "server";
    std::string client_suffix = "client";

    (void)create_directory(path);

    ret = generate_ssl_ca(ca_prkey_pwd, path, ca_suffix, days);
    if (ret != 0) {
        return ret;
    }

    ca_suffix = "ca_2";
    ret = generate_ssl_ca(ca_prkey_pwd, path, ca_suffix, days);
    if (ret != 0) {
        return ret;
    }

    struct dlock_ssl_ca_info ca_info;
    ca_info.ca_path = path + "ca.crt";
    ca_info.ca_prkey_path = path + "ca_rsa_private.pem";
    ca_info.ca_prkey_pwd = ca_prkey_pwd;

    ret = generate_ssl_crt(ca_info, server_prkey_pwd, path, server_suffix, days);
    if (ret != 0) {
        return ret;
    }

    ret = generate_ssl_crt(ca_info, client_prkey_pwd, path, client_suffix, days);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int delete_ssl_file(void)
{
    std::string path = DLOCK_SSL_FILE_PATH;

    return delete_directory(path);
}

static inline int sock_sync_data(int sock, int len, char *local_data, char *remote_data)
{
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;

    rc = write(sock, local_data, len);
    if (rc < len) {
        printf("Failed writing data during sock_sync_data\n");
    } else {
        rc = 0;
    }

    while (!rc && total_read_bytes < len) {
        read_bytes = read(sock, remote_data, len);
        if (read_bytes > 0) {
            total_read_bytes += read_bytes;
        } else {
            rc = read_bytes;
        }
    }

    return rc;
}

static inline int sync_time(int sock_fd, char *a)
{
    int len = strlen(a);
    char *b = (char *)malloc(len + 1);
    if (sock_sync_data(sock_fd, len, a, b) != 0) {
        printf("sync time error, %s.\n", a);
        free(b);
        free(a);
        return -1;
    }
    if (memcmp(a, b, len)) {
        printf("sync time error, %s != %s.\n", a, b);
        free(b);
        free(a);
        return -1;
    }
    free(b);
    free(a);
    return 0;
}

int get_listenfd_port(int *listen_fd, uint16_t *port)
{
    int ret;
    struct sockaddr_in addr;
    struct sockaddr_in get_addr;
    socklen_t len = sizeof(get_addr);

    *listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*listen_fd < 0) {
        printf("Failed to create socket, (errno=%d %m)\n", errno);
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ret = bind(*listen_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    if (ret != 0) {
        printf("Failed to bind port, (errno=%d %m)\n", errno);
        close(*listen_fd);
        return -1;
    }
    ret = getsockname(*listen_fd, (struct sockaddr *)&get_addr, &len);
    if (ret != 0) {
        printf("Failed to get sock name, (errno=%d %m)\n", errno);
        close(*listen_fd);
        return -1;
    }
    *port = ntohs(get_addr.sin_port);
    return 0;
}

static int connect_retry(int sockfd, struct sockaddr *addr, uint32_t size)
{
    uint32_t times = 0;
    for (int i = 1; i <= CONNECT_COUNT; i++) {
        if (connect(sockfd, addr, size) != 0) {
            times += i * SLEEP_TIME;
            usleep(times);
            continue;
        }
        return 0;
    }
    return -1;
}

int sock_connect(bool is_server, int listen_fd, uint16_t port)
{
    int ret;
    struct sockaddr_in addr;
    int sockfd = -1;

    if (is_server) {
        /* server side */
        ret = listen(listen_fd, MAX_CONNECTIONS);
        if (ret < 0) {
            printf("socket listen failed, listen_fd:%d, (errno=%d %m)\n", listen_fd, errno);
            return -1;
        }
        sockfd = accept(listen_fd, nullptr, 0);
        if (sockfd < 0) {
            printf("socket accept failed, ret: %d, (errno=%d %m)\n", sockfd, errno);
            return -1;
        }
    } else {
        /* client side */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            printf("Failed to create socket: %d\n", errno);
            return -1;
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (connect_retry(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != 0) {
            printf("socket connect failed, (errno=%d %m)\n", errno);
            close(sockfd);
            return -1;
        }
    }
    URMA_LOG_INFO("socket connet success, sockfd: %d.\n", sockfd);
    return sockfd;
}

void server_get_prkey_pwd(char **prkey_pwd, int *prkey_pwd_len)
{
    *prkey_pwd = strdup(SERVER_PRKEY_PWD);
    *prkey_pwd_len = SERVER_PRKEY_PWD_LEN;
}

void client_get_prkey_pwd(char **prkey_pwd, int *prkey_pwd_len)
{
    *prkey_pwd = strdup(CLIENT_PRKEY_PWD);
    *prkey_pwd_len = CLIENT_PRKEY_PWD_LEN;
}

void erase_prkey(void *prkey_pwd, int prkey_pwd_len)
{
    memset_s(prkey_pwd, prkey_pwd_len, 0, prkey_pwd_len);
    free(prkey_pwd);
    return;
}

void default_server_ssl_cfg(struct ssl_cfg &ssl)
{
    ssl.ssl_enable = true;
    ssl.ca_path = strdup(CA_PATH);
    ssl.crl_path = nullptr;
    ssl.cert_path = strdup(SERVER_CERT_PATH);
    ssl.prkey_path = strdup(SERVER_PRKEY_PATH);
    ssl.cert_verify_cb = nullptr;
    ssl.prkey_pwd_cb = &server_get_prkey_pwd;
    ssl.erase_prkey_cb = &erase_prkey;
}

void default_client_ssl_cfg(struct ssl_cfg &ssl)
{
    ssl.ssl_enable = true;
    ssl.ca_path = strdup(CA_PATH);
    ssl.crl_path = nullptr;
    ssl.cert_path = strdup(CLIENT_CERT_PATH);
    ssl.prkey_path = strdup(CLIENT_PRKEY_PATH);
    ssl.cert_verify_cb = nullptr;
    ssl.prkey_pwd_cb = &client_get_prkey_pwd;
    ssl.erase_prkey_cb = &erase_prkey;
}

void construct_primary_cfg(struct server_cfg &cfg_s, struct dlock_primary_cfg param_cfg)
{
    cfg_s.type = SERVER_PRIMARY;
    cfg_s.dev_name = nullptr;
    memset_s(&cfg_s.eid, sizeof(dlock_eid_t), 0, sizeof(dlock_eid_t));
    cfg_s.log_level = LOG_WARNING;
    cfg_s.tp_mode = param_cfg.tp_mode;
    cfg_s.ub_token_disable = false;
    cfg_s.sleep_mode_enable = true;
    cfg_s.primary.num_of_replica = param_cfg.num_of_replica;
    cfg_s.primary.recovery_client_num = param_cfg.recovery_client_num;
    cfg_s.primary.ctrl_cpuset = param_cfg.ctrl_cpuset;
    cfg_s.primary.cmd_cpuset = param_cfg.cmd_cpuset;
    cfg_s.primary.server_ip_str = param_cfg.server_ip;
    cfg_s.primary.server_port = PRIMARY1_CONTROL_PORT_CLIENT;
    cfg_s.ssl.ssl_enable = param_cfg.ssl_enable;
    cfg_s.primary.replica_enable = param_cfg.replica_enable;
    cfg_s.primary.replica_port = 0;
    if (param_cfg.ssl_enable) {
        default_server_ssl_cfg(cfg_s.ssl);
    }
}

void startup_primary_server1(unsigned int recovery_client_num, unsigned int num_of_replica, bool replica_enable,
    bool ssl_enable, trans_mode_t tp_mode)
{
    int ret;
    unsigned int max_server_num = 10;
    char *server_ip = strdup(PRIMARY_ADDRESS);
    struct server_cfg cfg_s;
    struct dlock_primary_cfg param_cfg;
    char ctrl_cpuset[] = "15-20";
    char cmd_cpuset[] = "15-20";

    ret = dserver_lib_init(max_server_num);
    ASSERT_TRUE(ret == 0) << "dlock server lib init failed, ret: " << ret;

    param_cfg.server_ip = server_ip;
    param_cfg.tp_mode = tp_mode;
    param_cfg.ssl_enable = ssl_enable;
    param_cfg.recovery_client_num = recovery_client_num;
    param_cfg.num_of_replica = num_of_replica;
    param_cfg.replica_enable = replica_enable;
    param_cfg.ctrl_cpuset = ctrl_cpuset;
    param_cfg.cmd_cpuset = cmd_cpuset;
    construct_primary_cfg(cfg_s, param_cfg);
    ret = server_start(cfg_s, g_primary_server1_id);
    ASSERT_TRUE(ret == 0) << "server start failed, ret: " << ret;
    sleep(1);

    free(server_ip);
    if (ssl_enable) {
        free(cfg_s.ssl.ca_path);
        free(cfg_s.ssl.cert_path);
        free(cfg_s.ssl.prkey_path);
    }

    DLOCK_LOG_WARN("primary server %d started!", g_primary_server1_id);
}

void stop_primary_server1(void)
{
    int ret = server_stop(g_primary_server1_id);
    ASSERT_TRUE(ret == 0) << "server stop failed, ret: " << ret;

    DLOCK_LOG_WARN("primary server %d stopped!", g_primary_server1_id);
    g_primary_server1_id = 0;
    dserver_lib_deinit();
}

void init_dclient_lib_with_server1(bool ssl_enable, trans_mode_t tp_mode)
{
    int ret;
    struct client_cfg cfg_c;

    cfg_c.dev_name = nullptr;
    memset_s(&cfg_c.eid, sizeof(dlock_eid_t), 0, sizeof(dlock_eid_t));
    cfg_c.log_level = LOG_WARNING;
    cfg_c.tp_mode = tp_mode;
    cfg_c.ub_token_disable = false;
    cfg_c.primary_port = PRIMARY1_CONTROL_PORT_CLIENT;
    cfg_c.ssl.ssl_enable = ssl_enable;
    if (ssl_enable) {
        default_client_ssl_cfg(cfg_c.ssl);
    }

    ret = dclient_lib_init(&cfg_c);
    ASSERT_TRUE(ret == 0) << "dlock client lib init failed, ret: " << ret;

    if (ssl_enable) {
        free(cfg_c.ssl.ca_path);
        free(cfg_c.ssl.cert_path);
        free(cfg_c.ssl.prkey_path);
    }
}

void startup_clients_of_server1(bool ssl_enable, trans_mode_t tp_mode)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);

    init_dclient_lib_with_server1(ssl_enable, tp_mode);

    for (int i = 0; i < CLIENT_NUM; i++) {
        g_client_id[i] = BASE_CLIENT_ID + i;
        ret = client_init(&g_client_id[i], server_ip);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client init failed, ret: " << ret;
    }

    free(server_ip);
}

void stop_clients_of_server1(void)
{
    int ret;

    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = client_deinit(g_client_id[i]);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client deinit failed, ret: " << ret;
    }

    dclient_lib_deinit();
}

void reinit_clients_of_server1(void)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);

    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = client_reinit(g_client_id[i], server_ip);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client reinit failed, ret: " << ret;
    }
    free(server_ip);
}

int update_client_locks(int client_id)
{
    int ret;
    struct timeval tv_start, tv_end;
    long time;
    gettimeofday(&tv_start, nullptr);
    do {
        ret = update_all_locks(client_id);
        gettimeofday(&tv_end, nullptr);
        time = (long)tv_end.tv_usec - tv_start.tv_usec + (tv_end.tv_sec - tv_start.tv_sec)* 1000000;
        if (time > 6000000) {
            printf("update client locks time out, client_id: %d\n", client_id);
            break;
        }
        if (ret) {
            (void)usleep(SLEEP_INTERVAL);
        }
    } while (ret == DLOCK_EAGAIN);
    return ret;
}

void recovery_clients_of_server1(void)
{
    int ret;
    char *server_ip = strdup(PRIMARY_ADDRESS);

    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = client_reinit(g_client_id[i], server_ip);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client reinit failed, ret: " << ret;
    }

    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = update_client_locks(g_client_id[i]);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "update_client_locks failed, ret: " << ret;
    }

    for (int i = 0; i < CLIENT_NUM; i++) {
        ret = client_reinit_done(g_client_id[i]);
        ASSERT_TRUE(ret == DLOCK_SUCCESS) << "client_reinit_done failed, ret: " << ret;
    }

    free(server_ip);
}

void prepare_default_primary_server_cfg(struct server_cfg &cfg_s)
{
    struct dlock_primary_cfg param_cfg = {
        .server_ip = strdup(PRIMARY_ADDRESS),
        .recovery_client_num = 0,
        .num_of_replica = 0,
        .replica_enable = false,
        .ssl_enable = false,
        .tp_mode = SEPERATE_CONN,
        .ctrl_cpuset = strdup("10-12"),
        .cmd_cpuset = strdup("13-15"),
    };
    construct_primary_cfg(cfg_s, param_cfg);
}

void destroy_default_primary_server_cfg(struct server_cfg &cfg_s)
{
    free(cfg_s.primary.server_ip_str);
    free(cfg_s.primary.ctrl_cpuset);
    free(cfg_s.primary.cmd_cpuset);
}

void default_server_ssl_init_attr(ssl_init_attr_t &init_attr)
{
    init_attr.ca_path = CA_PATH;
    init_attr.crl_path = "";
    init_attr.cert_path = SERVER_CERT_PATH;
    init_attr.prkey_path = SERVER_PRKEY_PATH;
    init_attr.cert_verify_cb = nullptr;
    init_attr.prkey_pwd_cb = &server_get_prkey_pwd;
    init_attr.erase_prkey_cb = &erase_prkey;
}