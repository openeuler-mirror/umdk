/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: common function
*/

#include "common.h"

#define MAX_RETRY_CNT 60  // Linux default WAIT_TIME is 60s
#define MAX_CONNECTIONS 100
#define PARSE_CFG_MAX_LEN 100
#define MAX_RECV_TIMEOUT 10800
#define SLEEP_TIME_1000 1000
#define CONNECT_GET_APP_ID_TIMEOUT 3
#define APPID_TO_INDEX 2
#define SYNC_TIME_INFO_LEN 128

test_context_t g_test_ctx = {0};

test_context_t *get_test_ctx()
{
    return &g_test_ctx;
}

static void usage(const char *argv)
{
}

static uint32_t parse_eid_htobe32(char *eid)
{
    uint32_t num;
    char num1[PARSE_CFG_MAX_LEN];
    char num2[PARSE_CFG_MAX_LEN];
    char num3[PARSE_CFG_MAX_LEN];
    char num4[PARSE_CFG_MAX_LEN];
    char result[PARSE_CFG_MAX_LEN];
    (void)sscanf(eid, "%[^:]:%[^::]::%[^:]:%[^:]", num1, num2, num3, num4);
    (void)sprintf(result, "0x%s%s", num3, num4);
    num = htobe32(strtoul(result, NULL, 0));
    return num;
}

int parse_config(int argc, char *argv[])
{
    const char *const short_options = "a:d:D:e:s:p:i:u:x:m:k:I:t:M:T:";
    struct option long_options[] = {{"app_info", required_argument, NULL, 'a'},
                                    {"device_name", required_argument, NULL, 'd'},
                                    {"device_name2", required_argument, NULL, 'D'},
                                    {"eid", required_argument, NULL, 'e'},
                                    {"seed", required_argument, NULL, 's'},
                                    {"test_port", required_argument, NULL, 'p'},
                                    {"test_ip", required_argument, NULL, 'i'},
                                    {"test_mac", required_argument, NULL, 'M'},
                                    {"ubsc_ip", required_argument, NULL, 'u'},
                                    {"xargs", required_argument, NULL, 'x'},
                                    {"mode", required_argument, NULL, 'm'},
                                    {"tp_kind", required_argument, NULL, 'k'},
                                    {"tp_mode", required_argument, NULL, 'T'},
                                    {"test_ipv6", required_argument, NULL, 'I'},
                                    // NIC supports multiple IP address configurations
                                    {"ip_num", required_argument, NULL, 1},
                                    {"ip_addrs", required_argument, NULL, 2},
                                    {NULL, no_argument, NULL, '\0'}};

    char app_num[PARSE_CFG_MAX_LEN] = {0};
    char app_id[PARSE_CFG_MAX_LEN] = {0};
    char server_ip[PARSE_CFG_MAX_LEN] = {0};
    char tcp_port[PARSE_CFG_MAX_LEN] = {0};
    char test_ip[MAX_HOST_NUM][PARSE_CFG_MAX_LEN] = {0};
    char test_mac[PARSE_CFG_MAX_LEN] = {0};
    char test_ipv6[MAX_HOST_NUM][PARSE_CFG_MAX_LEN * 2] = {0};
    char ipaddrs[MAX_LINE_LENGTH] = {0};
    char *ipargs;
    size_t len = 0;
    int idx = 0;
    char *eid;

    (void)memset(app_num, 0, sizeof(app_num));
    (void)memset(app_id, 0, sizeof(app_id));
    (void)memset(server_ip, 0, sizeof(server_ip));
    (void)memset(tcp_port, 0, sizeof(tcp_port));
    (void)memset(test_ip, 0, sizeof(test_ip));
    (void)memset(test_mac, 0, sizeof(test_mac));
    (void)memset(test_ipv6, 0, sizeof(test_ipv6));

    TEST_LOG_INFO("### my pid = %u\n", getpid());

    while (1) {
        int c;
        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'a':
                (void)sscanf(optarg, "%[^:]:%[^:]:%[^:]:%[^:]", app_num, app_id, tcp_port,  server_ip);
                g_test_ctx.app_num = strtoul(app_num, NULL, 0);
                g_test_ctx.app_id = strtoul(app_id, NULL, 0);
                g_test_ctx.tcp_port = strtoul(tcp_port, NULL, 0);
                if (g_test_ctx.app_id != 1) {
                    if (g_test_ctx.server_ip != NULL) {
                        free(g_test_ctx.server_ip);
                        g_test_ctx.server_ip = NULL;
                    }
                    g_test_ctx.server_ip = strdup(server_ip);
                }
                break;
            case 'd':
                if (g_test_ctx.device_name != NULL) {
                    free(g_test_ctx.device_name);
                    g_test_ctx.device_name = NULL;
                }
                g_test_ctx.device_name = strdup(optarg);
                break;
            case 'D':
                if (g_test_ctx.device_name2 != NULL) {
                    free(g_test_ctx.device_name2);
                    g_test_ctx.device_name2 = NULL;
                }
                g_test_ctx.device_name2 = strdup(optarg);
                break;
            case 'e':
                eid = strdup(optarg);
                g_test_ctx.device_eid = parse_eid_htobe32(eid);
                g_test_ctx.eid = strdup(optarg);
                free(eid);
                break;
            case 's':
                g_test_ctx.seed = atoi(optarg);
                TEST_LOG_INFO("### g_test_ctx.seed = %u\n", g_test_ctx.seed);
                break;
            case 'p':
                g_test_ctx.test_port = atoi(optarg);
                break;
            case 'i':
                (void)sscanf(optarg, "%[^,],%[^,]", test_ip[0], test_ip[1]);
                for (int i = 0; i < MAX_HOST_NUM; i++) {
                    if (g_test_ctx.test_ip[i] != NULL) {
                        free(g_test_ctx.test_ip[i]);
                        g_test_ctx.test_ip[i] = NULL;
                    }
                    g_test_ctx.test_ip[i] = strdup(test_ip[i]);
                    TEST_LOG_INFO("### g_test_ctx.test_ip[%d] = %s\n", i, g_test_ctx.test_ip[i]);
                }
                break;
            case 'M':
                if (g_test_ctx.test_mac != NULL) {
                    free(g_test_ctx.test_mac);
                    g_test_ctx.test_mac = NULL;
                }
                g_test_ctx.test_mac = strdup(optarg);
                TEST_LOG_INFO("### g_test_ctx.test_mac = %s\n", g_test_ctx.test_mac);
                break;
            case 'u':
                if (g_test_ctx.ubsc_ip != NULL) {
                    free(g_test_ctx.ubsc_ip);
                    g_test_ctx.ubsc_ip = NULL;
                }
                g_test_ctx.ubsc_ip = strdup(optarg);
                break;
            case 'x':
                g_test_ctx.xargs = (void *)strdup(optarg);
                if (g_test_ctx.xargs == NULL) {
                    TEST_LOG_ERROR("### failed to allocate memory.\n");
                }
                break;
            case 'm':
                g_test_ctx.mode = atoi(optarg);
                TEST_LOG_INFO("### g_test_ctx.mode = %u\n", g_test_ctx.mode);
                break;
            case 'T':
                g_test_ctx.tp_mode = atoi(optarg);
                TEST_LOG_INFO("### g_test_ctx.tp_mode = %u\n", g_test_ctx.tp_mode);
                break;
            case 'k':
                g_test_ctx.tp_kind = atoi(optarg);
                if (g_test_ctx.tp_kind == 0) {
                    TEST_LOG_INFO("### g_test_ctx.tp_kind = TP\n");
                } else if (g_test_ctx.tp_kind == 1) {
                    TEST_LOG_INFO("### g_test_ctx.tp_kind = CTP\n");
                } else {
                    TEST_LOG_ERROR("### ERROR: g_test_ctx.tp_kind= %u\n", g_test_ctx.tp_kind);
                }
                break;
            case 'I':
                (void)sscanf(optarg, "%[^,],%[^,]", test_ipv6[0],  test_ipv6[1]);
                for (int i = 0; i < MAX_HOST_NUM; i++) {
                    if (g_test_ctx.test_ipv6[i] != NULL) {
                        free(g_test_ctx.test_ipv6[i]);
                        g_test_ctx.test_ipv6[i] = NULL;
                    }
                    g_test_ctx.test_ipv6[i] = strdup(test_ipv6[i]);
                    TEST_LOG_INFO("### g_test_ctx.test_ipv6[%d] = %s\n", i, g_test_ctx.test_ipv6[i]);
                }
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }
    return 0;
}

void free_config()
{
    if (g_test_ctx.server_ip != NULL) {
        free(g_test_ctx.server_ip);
        g_test_ctx.server_ip = NULL;
    }

    if (g_test_ctx.sock != NULL) {
        free(g_test_ctx.sock);
        g_test_ctx.sock = NULL;
    }

    if (g_test_ctx.not_sync != NULL) {
        free(g_test_ctx.not_sync);
        g_test_ctx.not_sync = NULL;
    }

    if (g_test_ctx.device_name != NULL) {
        free(g_test_ctx.device_name);
        g_test_ctx.device_name = NULL;
    }

    if (g_test_ctx.eid != NULL) {
        free(g_test_ctx.eid);
        g_test_ctx.eid = NULL;
    }

    if (g_test_ctx.ubsc_ip != NULL) {
        free(g_test_ctx.ubsc_ip);
        g_test_ctx.ubsc_ip = NULL;
    }

    if (g_test_ctx.xargs != NULL) {
        free(g_test_ctx.xargs);
        g_test_ctx.xargs = NULL;
    }

    if (g_test_ctx.test_mac != NULL) {
        free(g_test_ctx.test_mac);
        g_test_ctx.test_mac = NULL;
    }
}

static int server_listen()
{
    struct sockaddr_in addr;
    struct sockaddr_in src_addr;
    int optval = 1;
    int retval;
    socklen_t addr_len = sizeof(src_addr);
    uint16_t port = g_test_ctx.tcp_port;
    uint16_t src_port = 0;
    int index;
    int *sock;
    char buf[MAX_EXEC_CMD_RET_LEN];
    g_test_ctx.listen_sock = -1;

    g_test_ctx.sock = (int *)calloc(1, (g_test_ctx.app_num - 1) * sizeof(int));
    CHECK_JUMP(g_test_ctx.sock == NULL, EXIT, "Failed to calloc!\n");

    g_test_ctx.not_sync = (bool *)calloc(1, (g_test_ctx.app_num - 1) * sizeof(bool));
    CHECK_JUMP(g_test_ctx.not_sync == NULL, EXIT, "Failed to calloc!\n");

    sock = (int *)calloc(1, (g_test_ctx.app_num - 1) * sizeof(int));
    CHECK_JUMP(sock == NULL, EXIT, "Failed to calloc!\n");

    g_test_ctx.listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    CHECK_JUMP(g_test_ctx.listen_sock < 0, EXIT, "Failed to listen sock!, errno=%d\n", errno);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    retval = setsockopt(g_test_ctx.listen_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    CHECK_JUMP(retval < 0, EXIT, "Failed to setsockopt!, errno=%d\n", errno);

    for (int i = 0; i < MAX_RETRY_CNT; i++) {
        retval = bind(g_test_ctx.listen_sock, (struct sockaddr *)&addr, sizeof(struct sockaddr));
        if (retval == 0) {
            break;
        }
        TEST_LOG_ERROR("Failed to bind: %d, port=%d, retry=%d|%d\n", errno, port, i, MAX_RETRY_CNT);
        exec_cmd(buf, MAX_EXEC_CMD_RET_LEN, "netstat -anp | grep  %d", port);

        CHECK_JUMP(i == MAX_RETRY_CNT - 1, EXIT, "Failed to bind!, errno=%d\n", errno);
        sleep(1);
    }

    retval = listen(g_test_ctx.listen_sock, MAX_CONNECTIONS);
    CHECK_JUMP(retval != 0, EXIT, "Failed to listen! errno=%d\n", errno);

    for (int i = 0; i < g_test_ctx.app_num - 1; i++) {
        sock[i] = accept(g_test_ctx.listen_sock, (struct sockaddr *)&src_addr, &addr_len);
        src_port = ntohs(src_addr.sin_port);
        index = src_port - g_test_ctx.tcp_port - 1;
        g_test_ctx.sock[index] = sock[i];
        TEST_LOG_INFO("[ %d|%d ] server app%d connect success! \n", i + 1, g_test_ctx.app_num - 1, index);
    }

    CHECK_FREE(sock);
    return 0;
EXIT:
    if (g_test_ctx.listen_sock > 0) {
        close(g_test_ctx.listen_sock);
    }
    CHECK_FREE(sock);
    free_config();
    return -1;
}

static int client_sock_init()
{
    g_test_ctx.sock = (int *)malloc(sizeof(int));
    if (g_test_ctx.sock == NULL) {
        TEST_LOG_ERROR("memory alloc failed!\n");
        return -1;
    }
    (void)memset(g_test_ctx.sock, 0, sizeof(int));

    g_test_ctx.not_sync = (bool *)malloc(sizeof(int));
    if (g_test_ctx.not_sync == NULL) {
        TEST_LOG_ERROR("memory alloc failed!\n");
        free(g_test_ctx.sock);
        g_test_ctx.sock = NULL;
        return -1;
    }

    *g_test_ctx.not_sync = false;

    return 0;
}

static int client_connect()
{
    struct sockaddr_in addr;
    struct sockaddr_in cli_addr;
    int sockfd = -1;
    uint16_t port = g_test_ctx.tcp_port;
    int retval;
    int optval = 1;
    uint32_t app_id;
    uint16_t client_port = g_test_ctx.tcp_port + g_test_ctx.app_id - 1;

    retval = client_sock_init();
    if (retval != 0) {
        TEST_LOG_ERROR("client_sock_init failed!\n");
        return -1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        TEST_LOG_ERROR("Failed to create socket, errno=%d, err=%s\n", errno, strerror(errno));
        free_config();
        return -1;
    }
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons(client_port);
    cli_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    for (int i = 0; i < MAX_RETRY_CNT; i++) {
        retval = bind(sockfd, (struct sockaddr *)&cli_addr, sizeof(struct sockaddr));
        if (retval == 0) {
            break;
        }
        if (i == MAX_RETRY_CNT - 1) {
            close(sockfd);
            TEST_LOG_ERROR("Failed to bind port %d, errno=%d, err=%s retry=%d|%d\n", client_port, errno,
                           strerror(errno), i, MAX_RETRY_CNT);
            return -1;
        }
        sleep(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(g_test_ctx.server_ip);

    for (int i = 0; i < MAX_RETRY_CNT; i++) {
        retval = connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
        if (retval == 0) {
            g_test_ctx.sock[0] = sockfd;
            return 0;
        }
        TEST_LOG_ERROR("connect failed! ret=%d\n", retval);
        sleep(1);
    }
    close(sockfd);
    return -1;
}

int sock_connect()
{
    if (g_test_ctx.server_ip != NULL) {
        return client_connect();
    } else {
        return server_listen();
    }
}

void sock_disconnect()
{
    if (g_test_ctx.server_ip != NULL) {
        if (g_test_ctx.sock != NULL) {
            close(g_test_ctx.sock[0]);
        }
    } else {
        for (int i = 0; i < g_test_ctx.app_num - 1; i++) {
            if (g_test_ctx.sock != NULL) {
                close(g_test_ctx.sock[i]);
            }
        }
        close(g_test_ctx.listen_sock);
    }
}

typedef struct stRecvDataInfo {
    char *recv_buff;
    int data_len;
    int sock;
    volatile int finish;
} RecvDataInfo;

static void *thread_recv_data(void *arg)
{
    RecvDataInfo *precv_data_info = (RecvDataInfo *)arg;
    int retval = 0;
    int pos = 0;
    int len = precv_data_info->data_len;
    int retry_cnt = 0;
    while ((retry_cnt < MAX_RETRY_CNT) && (precv_data_info->finish == 0)) {
        retval = recv(precv_data_info->sock, precv_data_info->recv_buff + pos, len - pos, 0);
        if (retval < 0) {
            break;
        }
        pos = pos + retval;
        if (pos == len) {
            break;
        }
        retry_cnt++;
    }
    precv_data_info->data_len = pos;
    precv_data_info->finish = 1;
    return NULL;
}

int test_recv_data(int sock, char *buf, int len, int timeout)
{
    int timeout_count = timeout * SLEEP_TIME_1000;
    int pos = 0;
    int retval = 0;
    RecvDataInfo recv_data_info = {0};

    recv_data_info.recv_buff = buf;
    recv_data_info.data_len = len;
    recv_data_info.sock = sock;
    recv_data_info.finish = 0;

    retval = TestPoolAddWorker(thread_recv_data, (void *)&recv_data_info);

    while (timeout_count > 0) {
        if (recv_data_info.finish == 1) {
            return recv_data_info.data_len;
        }
        timeout_count--;
        usleep(SLEEP_TIME_1000);
    }

    close(sock);

    return recv_data_info.data_len;
}

int sync_data(int src_app_id, char *buf, int len)
{
    int ret;
    if (len == 0) {
        return 0;
    }
    if (g_test_ctx.server_ip == NULL) {
        if ((src_app_id != g_test_ctx.app_id) && (!g_test_ctx.not_sync[src_app_id - PROC_2])) {
            ret = test_recv_data(g_test_ctx.sock[src_app_id - PROC_2], buf, len, MAX_RECV_TIMEOUT);
            if (ret < len) {
                TEST_LOG_ERROR("sync_data recv Fail,ret = %d\n", ret);
            }
        }

        for (int i = 0; i < g_test_ctx.app_num - 1; i++) {
            if (i == src_app_id - PROC_2) {
                continue;
            }
            if (g_test_ctx.not_sync[i]) {
                continue;
            }

            ret = send(g_test_ctx.sock[i], buf, len, 0);
            if (ret < len) {
                TEST_LOG_INFO("sync_data send Fail,ret = %d\n", ret);
            }
        }
    } else {
        if (g_test_ctx.not_sync[0]) {
            return 0;
        }
        if (src_app_id != g_test_ctx.app_id) {
            ret = test_recv_data(g_test_ctx.sock[0], buf, len, MAX_RECV_TIMEOUT);
            if (ret < len) {
                TEST_LOG_INFO("sync_data recv Fail,ret = %d\n", ret);
            }
        } else {
            ret = send(g_test_ctx.sock[0], buf, len, 0);
            if (ret < len) {
                TEST_LOG_INFO("sync_data send Fail,ret = %d\n", ret);
            }
        }
    }
    return 0;
}

int sync_time(char const *info)
{
    int ret, rc = 0;
    int len = strlen(info);

    char lbuf[len + 1];
    char rbuf[len + 1];

    memset(lbuf, 0, len);
    memset(rbuf, 0, len);
    strncpy(lbuf, info, len);

    // 本质上是server和所有client之间做一次send、recv
    // 有client未执行到sync_time时server阻塞在recv等该client send，其他client阻塞在recv等server send
    // server未执行到sync_time时，所有client均阻塞在recv等server send
    if (g_test_ctx.server_ip == NULL) {
        for (int i = 0; i < g_test_ctx.app_num - 1; i++) {
            if (g_test_ctx.not_sync[i]) {
                continue;
            }
            ret = test_recv_data(g_test_ctx.sock[i], rbuf, len, MAX_RECV_TIMEOUT);
            CHECK_JUMP(ret < len, EXIT_ERR, "[ sync_time recv ] app_id=%d, ret=%d\n", i + PROC_2, ret);
            CHECK_JUMP(memcmp(lbuf, rbuf, len), EXIT_ERR, "[ sync_time recv ] app_id=%d, %s != %s\n", i + PROC_2, lbuf,
                       rbuf);
        }
        for (int i = 0; i < g_test_ctx.app_num - 1; i++) {
            if (g_test_ctx.not_sync[i]) {
                continue;
            }
            ret = send(g_test_ctx.sock[i], lbuf, len, 0);
            CHECK_JUMP(ret < len, EXIT_ERR, "[ sync_time send ] app_id=%d, ret=%d\n", i + PROC_2, ret);
        }
    } else {
        if (g_test_ctx.not_sync[0]) {
            return 0;
        }
        ret = send(g_test_ctx.sock[0], lbuf, len, 0);
        CHECK_JUMP(ret < len, EXIT_ERR, "[ sync_time send ] ret=%d\n", ret);
        ret = test_recv_data(g_test_ctx.sock[0], rbuf, len, MAX_RECV_TIMEOUT);
        CHECK_JUMP(ret < len, EXIT_ERR, "[ sync_time recv ] ret=%d\n", ret);
        CHECK_JUMP(memcmp(lbuf, rbuf, len), EXIT_ERR, "[ sync_time recv ] %s != %s\n", lbuf, rbuf);
    }
    TEST_LOG_INFO("[ sync_time success ] msg = %s\n", lbuf);
    return rc;
EXIT_ERR:
    TEST_LOG_ERROR("[ sync_time error ] msg = %s\n", lbuf);
    rc = -1;
    sock_disconnect();
    exit(-1);
}

void get_random_string(char *s, int size, uint32_t *seed)
{
    for (int i = 0; i < (size - 1); i++) {
        *(s + i) = 'a' + rand_r(seed) % LETTERS_NUM;
    }
    *(s + size - 1) = '\0';
}

uint32_t get_random_u32(uint32_t *seed)
{
    return rand_r(seed);
}

int test_common_init(int max_thread_num)
{
    int retval;

    // Initialize log module
    test_log_init();

    // Initialize thread pool
    retval = TestThreadPoolInit(max_thread_num);
    if (retval != TEST_SUCCESS) {
        TEST_LOG_ERROR("test_common_init:create thread pool failed!\n");
        return retval;
    }

    return retval;
}

int test_common_deinit()
{
    int retval;
    retval = TestThreadPoolDestroy();
    if (retval != TEST_SUCCESS) {
        TEST_LOG_ERROR("test_common_deinit:deinit thread pool failed!\n");
        return retval;
    }

    return retval;
}

void destroy_test_ctx(test_context_t *ctx)
{
    sock_disconnect();
    free_config();
    test_common_deinit();
}

test_context_t *create_test_ctx(int argc, char *argv[], int thread_num)
{
    test_context_t *ctx;

    ctx = get_test_ctx();
    memset(ctx, 0, sizeof(test_context_t));
    test_common_init(thread_num);
    if (parse_config(argc, argv) != 0) {
        destroy_test_ctx(ctx);
        return NULL;
    }
    if (sock_connect() != 0) {
        destroy_test_ctx(ctx);
        return NULL;
    }

    return ctx;
}

int exec_cmd(char *rbuf, uint32_t rbuf_size, const char *format, ...)
{
    char cmd[MAX_EXEC_CMD_RET_LEN] = {0};
    char buf[MAX_EXEC_CMD_RET_LEN] = {0};
    FILE *process;
    va_list va;
    size_t offset = 0;
    int ret = 0;
    va_start(va, format);

    ret = vsnprintf(cmd, sizeof(cmd), format, va);
    TEST_LOG_INFO("### cmd = %s ret = %d\n", cmd, ret);

    process = popen(cmd, "r");
    if (rbuf != NULL) {
        memset(rbuf, 0, rbuf_size);
        while (!feof(process)) {
            size_t readn = fread(buf, sizeof(char), sizeof(buf), process);
            if (readn == 0 && errno != EINTR) {
                break;
            }
            memcpy(rbuf + offset, buf, readn);
            offset += readn;
        }
        TEST_LOG_INFO("### rbuf = %s\n", rbuf);
    }
    pclose(process);

    va_end(va);
    return 0;
}