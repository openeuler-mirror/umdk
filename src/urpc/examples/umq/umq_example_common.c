/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: umq example common functions
 * Create: 2025-8-16
 * Note:
 * History: 2025-8-16
 */


#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "umq_example_common.h"

static const uint32_t EXAMPLE_MAX_POLL_BATCH = 64;
static const uint32_t EXAMPLE_REQUEST_SIZE = 8192;
static const uint32_t SOCKET_SEND_RECV_TIMEOUT = 5;
static const uint32_t EXAMPLE_BUFFER_SIZE = 8192;
static const uint32_t EXAMPLE_DEPTH = 128;

typedef struct exchange_info {
    uint32_t msg_len;
    uint8_t data[0];
} exchange_info_t;

#define GREETER_CASE_NUM 8

static struct option g_long_options[] = {
    {"dev",                required_argument, NULL, 'd'},
    {"event-mode",         required_argument, NULL, 'e'},
    {"port",               required_argument, NULL, 'p'},
    {"server-ip",          required_argument, NULL, 'i'},
    {"case",               required_argument, NULL, 'c'},
    {"ipv6-addr",          required_argument, NULL, 'I'},
    {"feature",            required_argument, NULL, 'f'},
    {"trans-mode",         required_argument, NULL, 'T'},
    {"eid-idx",            required_argument, NULL, 'E'},
    /* Long options only */
    {"server",             no_argument,       NULL, 'r'},
    {"client",             no_argument,       NULL, 'l'},
    {"cna",                required_argument, NULL, 'C'},
    {"deid",               required_argument, NULL, 'D'},
    {"tp-mode",            required_argument, NULL, 'M'},
    {"tp-type",            required_argument, NULL, 'P'},
    {"queue_cnt",          required_argument, NULL, 'q'},
    {"threadpool_size",    required_argument, NULL, 's'},
    {"m_dev_name",         required_argument, NULL, 'n'},
    {"m_eid_idx",          required_argument, NULL, 'x'},
    {NULL,                 0,                 NULL,  0 }
};

uint64_t init_and_create_umq(struct urpc_example_config *cfg, uint8_t *local_bind_info, uint32_t *bind_info_size)
{
    umq_init_cfg_t *init_cfg = (umq_init_cfg_t *)calloc(1, sizeof(*init_cfg));
    if (init_cfg == NULL) {
        LOG_PRINT_ERR("calloc init_cfg failed\n");
        return UMQ_INVALID_HANDLE;
    }
    init_cfg->feature = cfg->feature;
    init_cfg->cna = cfg->cna;
    init_cfg->ubmm_eid = cfg->deid;

    if (parse_trans_info(cfg, init_cfg) != 0) {
        goto FREE_CFG;
    }

    if (umq_init(init_cfg) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("umq_init failed\n");
        goto FREE_CFG;
    }

    umq_create_option_t option = {
        .trans_mode = init_cfg->trans_info[0].trans_mode,
        .create_flag = UMQ_CREATE_FLAG_RX_BUF_SIZE | UMQ_CREATE_FLAG_TX_BUF_SIZE | UMQ_CREATE_FLAG_RX_DEPTH |
                       UMQ_CREATE_FLAG_TX_DEPTH | UMQ_CREATE_FLAG_QUEUE_MODE | UMQ_CREATE_FLAG_TP_MODE |
                       UMQ_CREATE_FLAG_TP_TYPE,
        .rx_buf_size = EXAMPLE_BUFFER_SIZE,
        .tx_buf_size = EXAMPLE_BUFFER_SIZE,
        .rx_depth = EXAMPLE_DEPTH,
        .tx_depth = EXAMPLE_DEPTH,
        .mode = cfg->poll_mode,
        .tp_mode = cfg->tp_mode,
        .tp_type = cfg->tp_type,
    };
    if (cfg->instance_mode == SERVER) {
        if (sprintf(option.name, "%s", "server") <= 0) {
            LOG_PRINT_ERR("set name failed\n");
            goto UNINIT;
        }
    } else {
        if (sprintf(option.name, "%s", "client") <= 0) {
            LOG_PRINT_ERR("set name failed\n");
            goto UNINIT;
        }
    }
    (void)memcpy(&option.dev_info, &init_cfg->trans_info[0].dev_info, sizeof(umq_dev_assign_t));
    uint64_t umqh = umq_create(&option);
    if (umqh == UMQ_INVALID_HANDLE) {
        LOG_PRINT_ERR("umq_create failed\n");
        goto UNINIT;
    }

    *bind_info_size = umq_bind_info_get(umqh, local_bind_info, *bind_info_size);
    if (*bind_info_size == 0) {
        LOG_PRINT_ERR("umq_bind_info_get failed\n");
        goto DESTROY;
    }
    free(init_cfg);
    return umqh;

DESTROY:
    umq_destroy(umqh);

UNINIT:
    umq_uninit();

FREE_CFG:
    free(init_cfg);
    return UMQ_INVALID_HANDLE;
}

int send_exchange_data(int sock, uint8_t *send_data, uint32_t send_len)
{
    char buf[UMQ_MAX_BIND_INFO_SIZE] = {0};
    uint32_t buf_len = send_len + (uint32_t)sizeof(exchange_info_t);
    if (buf_len > UMQ_MAX_BIND_INFO_SIZE) {
        LOG_PRINT_ERR("exchange data too large\n");
        return -1;
    }

    exchange_info_t *exchange_info = (exchange_info_t *)buf;
    exchange_info->msg_len = send_len;
    (void)memcpy(exchange_info->data, send_data, send_len);
    if (send(sock, buf, buf_len, 0) < 0) {
        LOG_PRINT_ERR("send exchange data failed\n");
        return -1;
    }
    LOG_PRINT("send exchange data done, len: %u\n", buf_len);

    return 0;
}

int recv_exchange_data(int sock, uint8_t *recv_data, uint32_t *recv_len)
{
    int offset = 0;
    int exchange_data_size = 0;
    exchange_info_t recv_info = {0};
    void *recv_buf = &recv_info;
    uint32_t recv_size = (uint32_t)sizeof(exchange_info_t);
    while (1) {
        int len = recv(sock, recv_buf + offset, recv_size - offset, 0);
        if (len <= 0) {
            LOG_PRINT_ERR("receive exchange data failed\n");
            return -1;
        }

        offset += len;
        // receive exchange_info_t first, then recv data according to msg_len
        if (exchange_data_size == 0 && offset == sizeof(exchange_info_t)) {
            exchange_data_size = (int)recv_info.msg_len;
            offset = 0;
            recv_buf = recv_data;
            recv_size = (uint32_t)exchange_data_size;
            if (exchange_data_size > (int)*recv_len) {
                LOG_PRINT_ERR("recv_len[%u] too short, require: %d\n", *recv_len, exchange_data_size);
                return -1;
            }
        }

        if (exchange_data_size > 0 && offset >= exchange_data_size) {
            *recv_len = exchange_data_size;
            break;
        }
    }
    LOG_PRINT("recv exchange data done, len: %u\n", *recv_len);

    return 0;
}

int client_exchange_bind_info(const char *ip, uint16_t port, uint8_t *send_data, uint32_t send_len,
    uint8_t *recv_data, uint32_t *recv_len)
{
    int ret = -1;
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        LOG_PRINT_ERR("create socket failed\n");
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = SOCKET_SEND_RECV_TIMEOUT;
    timeout.tv_usec = 0;
    ret = setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket recv timeout failed\n");
        goto CLOSE_SOC;
    }

    ret = setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket send timeout failed\n");
        goto CLOSE_SOC;
    }

    int reuse = 1;
    ret = setsockopt(client_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket port reuse failed\n");
        goto CLOSE_SOC;
    }

    struct sockaddr_in server = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    if (inet_pton(AF_INET, ip, &server.sin_addr) != 1) {
        LOG_PRINT_ERR("ip[%s] not valid\n", ip);
        goto CLOSE_SOC;
    }
    if (connect(client_fd, (struct sockaddr*)&server, sizeof(server)) != 0) {
        LOG_PRINT_ERR("ip[%s] port[%u] connect failed\n", ip, port);
        goto CLOSE_SOC;
    }
    LOG_PRINT("server connected, ip: %s, port: %u\n", ip, port);

    if (send_exchange_data(client_fd, send_data, send_len) != 0) {
        goto CLOSE_SOC;
    }

    if (recv_exchange_data(client_fd, recv_data, recv_len) != 0) {
        goto CLOSE_SOC;
    }
    ret = 0;

CLOSE_SOC:
    close(client_fd);
    return ret;
}

int server_exchange_bind_info(const char *ip, uint16_t port, uint8_t *send_data, uint32_t send_len,
    uint8_t *recv_data, uint32_t *recv_len)
{
    int ret = -1;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        LOG_PRINT_ERR("create socket failed\n");
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = SOCKET_SEND_RECV_TIMEOUT;
    timeout.tv_usec = 0;

    ret = setsockopt(server_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket send timeout failed\n");
        goto CLOSE_SVR;
    }

    int reuse = 1;
    ret = setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket port reuse failed\n");
        goto CLOSE_SVR;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        LOG_PRINT_ERR("ip[%s] not valid\n", ip);
        goto CLOSE_SVR;
    }

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        LOG_PRINT_ERR("ip[%s] port[%u] bind failed\n", ip, port);
        goto CLOSE_SVR;
    }

    if (listen(server_fd, 1) != 0) {
        LOG_PRINT_ERR("ip[%s] port[%u] listen failed\n", ip, port);
        goto CLOSE_SVR;
    }
    LOG_PRINT("Server listening on ip[%s] port[%u]...\n", ip, port);

    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        LOG_PRINT_ERR("ip[%s] port[%u] accept failed\n", ip, port);
        goto CLOSE_SVR;
    }
    LOG_PRINT("client accepted\n");

    ret = setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (ret < 0) {
        LOG_PRINT_ERR("set socket recv timeout failed\n");
        goto CLOSE_CLI;
    }

    if (recv_exchange_data(client_fd, recv_data, recv_len) != 0) {
        goto CLOSE_CLI;
    }

    // 发送回应数据
    if (send_exchange_data(client_fd, send_data, send_len) != 0) {
        goto CLOSE_CLI;
    }

    usleep(EXAMPLE_SLEEP_TIME_US);
    ret = 0;

CLOSE_CLI:
    close(client_fd);

CLOSE_SVR:
    close(server_fd);
    return ret;
}

int parse_trans_info(struct urpc_example_config *cfg, umq_init_cfg_t *init_cfg)
{
    init_cfg->trans_info_num = 1;
    init_cfg->trans_info[0].trans_mode = cfg->trans_mode;

    if (cfg->dev_name != NULL) {
        init_cfg->trans_info[0].dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_DEV;
        strcpy(init_cfg->trans_info[0].dev_info.dev.dev_name, cfg->dev_name);
        init_cfg->trans_info[0].dev_info.dev.eid_idx = cfg->eid_idx;
    } else if (cfg->server_ip != NULL) {
        init_cfg->trans_info[0].dev_info.assign_mode = UMQ_DEV_ASSIGN_MODE_IPV4;
        strcpy(init_cfg->trans_info[0].dev_info.ipv4.ip_addr, cfg->server_ip);
    } else {
        LOG_PRINT_ERR("trans info not valid\n");
        return -1;
    }

    return 0;
}

int example_post_rx(uint64_t umqh, uint32_t depth)
{
    uint32_t request_size = EXAMPLE_REQUEST_SIZE;
    umq_buf_t *buf = umq_buf_alloc(request_size, depth, umqh, NULL);
    if (buf == NULL) {
        LOG_PRINT_ERR("alloc buf failed\n");
        return -1;
    }

    umq_buf_t *bad_buf = NULL;
    if (umq_post(umqh, buf, UMQ_IO_RX, &bad_buf) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("post rx failed\n");
        umq_buf_free(bad_buf);
        return -1;
    }

    return 0;
}

int example_poll_rx(uint64_t umqh, const char *check_data, uint32_t data_size, bool with_imm_data)
{
    umq_buf_t **buf = (umq_buf_t **)calloc(EXAMPLE_MAX_POLL_BATCH, sizeof(umq_buf_t *));
    if (buf == NULL) {
        return -1;
    }
    int ret = 0;

    uint64_t start = get_timestamp_ms();
    while (ret == 0 && get_timestamp_ms() - start < EXAMPLE_MAX_WAIT_TIME_MS) {
        ret = umq_poll(umqh, UMQ_IO_RX, buf, EXAMPLE_MAX_POLL_BATCH);
        usleep(EXAMPLE_SLEEP_TIME_US);
    }

    if (ret == 0 || buf[0] == NULL) {
        LOG_PRINT_ERR("umq_poll return nothing after timeout\n");
        free(buf);
        return -1;
    }

    umq_buf_pro_t *pro = (umq_buf_pro_t *)buf[0]->qbuf_ext;
    if (memcmp((char *)buf[0]->buf_data, check_data, data_size) != 0) {
        LOG_PRINT_ERR("polled data[%s] doesn't match check data[%s]\n", (char *)buf[0]->buf_data, check_data);
        ret = -1;
        goto FREE;
    }

    if (with_imm_data && pro->imm.user_data != EXAMPLE_TEST_IMM_DATA) {
        LOG_PRINT_ERR("polled imm.user_data[%u] doesn't match imm data[%u]\n",
                      (uint32_t)pro->imm.user_data, EXAMPLE_TEST_IMM_DATA);
        ret = -1;
        goto FREE;
    }

    LOG_PRINT("polled data: %s, imm.user_data: %u\n", (char *)buf[0]->buf_data, (uint32_t)pro->imm.user_data);
    ret = 0;

FREE:
    for (int i = 0; i < ret; i++) {
        umq_buf_free(buf[i]);
    }
    free(buf);
    return ret;
}

int example_post_tx(uint64_t umqh, const char *data, uint32_t data_size)
{
    umq_buf_t *buf = umq_buf_alloc(data_size, 1, umqh, NULL);
    if (buf == NULL) {
        LOG_PRINT_ERR("alloc buf failed\n");
        return -1;
    }

    buf->io_direction = UMQ_IO_TX;
    (void)memcpy(buf->buf_data, data, data_size);
    buf->data_size = data_size;
    buf->total_data_size = data_size;
    umq_buf_pro_t *pro = (umq_buf_pro_t *)buf->qbuf_ext;
    pro->imm.user_data = EXAMPLE_TEST_IMM_DATA;
    pro->flag.bs.solicited_enable = 1;
    pro->flag.bs.complete_enable = 1;
    pro->opcode = UMQ_OPC_SEND_IMM;
    umq_buf_t *bad_buf = NULL;
    if (umq_post(umqh, buf, UMQ_IO_TX, &bad_buf) != UMQ_SUCCESS) {
        umq_buf_free(bad_buf);
        LOG_PRINT_ERR("post tx failed\n");
        return -1;
    }

    return 0;
}

int example_poll_tx(uint64_t umqh)
{
    umq_buf_t **buf = (umq_buf_t **)calloc(EXAMPLE_MAX_POLL_BATCH, sizeof(umq_buf_t *));
    if (buf == NULL) {
        return -1;
    }
    int ret = umq_poll(umqh, UMQ_IO_TX, buf, EXAMPLE_MAX_POLL_BATCH);
    if (ret <= 0) {
        free(buf);
        return -1;
    }

    LOG_PRINT("tx polled\n");
    for (int i = 0; i < ret; ++i) {
        umq_buf_t *tmp_buf = buf[i];
        int32_t rest_data_size = (int32_t)tmp_buf->total_data_size;
        while (tmp_buf && rest_data_size > 0) {
            rest_data_size -= (int32_t)tmp_buf->data_size;
            if (rest_data_size <= 0) {
                tmp_buf->qbuf_next = NULL;
                break;
            }
            tmp_buf = tmp_buf->qbuf_next;
        }

        umq_buf_free(buf[i]);
    }
    free(buf);
    return 0;
}

int example_enqueue_data(uint64_t umqh, const char *data, uint32_t data_size)
{
    umq_buf_t *buf = umq_buf_alloc(data_size, 1, umqh, NULL);
    if (buf == NULL) {
        LOG_PRINT_ERR("alloc buf failed\n");
        return -1;
    }

    buf->io_direction = UMQ_IO_TX;
    (void)memcpy(buf->buf_data, data, data_size);
    buf->data_size = data_size;
    buf->total_data_size = data_size;
    umq_buf_t *bad_buf = NULL;
    if (umq_enqueue(umqh, buf, &bad_buf) != UMQ_SUCCESS) {
        LOG_PRINT_ERR("enqueue failed\n");
        umq_buf_free(bad_buf);
        return -1;
    }

    return 0;
}

int example_dequeue_data(uint64_t umqh, const char *check_data, uint32_t data_size)
{
    umq_buf_t *buf = NULL;
    uint64_t start = get_timestamp_ms();
    while (buf == NULL && get_timestamp_ms() - start < EXAMPLE_MAX_WAIT_TIME_MS) {
        buf = umq_dequeue(umqh);
        usleep(EXAMPLE_SLEEP_TIME_US);
    }

    if (buf == NULL) {
        LOG_PRINT_ERR("umq_dequeue return nothing after timeout\n");
        return -1;
    }

    if (buf->buf_data == NULL || memcmp((char *)buf->buf_data, check_data, data_size) != 0) {
        LOG_PRINT_ERR("dequeue data[%s] doesn't match check data[%s]\n", (char *)buf->buf_data, check_data);
        umq_buf_free(buf);
        return -1;
    }
    LOG_PRINT("dequeue data: %s\n", (char *)buf->buf_data);
    umq_buf_free(buf);
    return 0;
}

void example_flush(uint64_t umqh)
{
    umq_buf_t *buf[EXAMPLE_MAX_POLL_BATCH];
    int ret = 0;

    uint64_t start = get_timestamp_ms();
    while (get_timestamp_ms() - start < EXAMPLE_FLUSH_TIME_MS) {
        ret = umq_poll(umqh, UMQ_IO_ALL, buf, EXAMPLE_MAX_POLL_BATCH);
        if (ret > 0) {
            LOG_PRINT("example flush rx count: %d\n", ret);
            for (int i = 0; i < ret; i++) {
                umq_buf_free(buf[i]);
            }
            continue;
        }
        usleep(EXAMPLE_SLEEP_TIME_US);
    }
}

static int cfg_get_dev_name(struct urpc_example_config *cfg, char *data)
{
    char *save;
    char *new_data = strtok_r(data, ",", &save);
    uint32_t i = 0;
    while (i < EXAMPLE_MAX_DEV_NUM && (new_data != NULL)) {
        (void)strcpy(cfg->m_dev_name[i], new_data);
        new_data = strtok_r(NULL, ",", &save);
        i++;
    }
    
    if (cfg->m_dev_num != 0 && cfg->m_dev_num != i) {
        return -1;
    }
    cfg->m_dev_num = i;
    return 0;
}

static int cfg_get_eid_idx(struct urpc_example_config *cfg, char *data)
{
    char *save;
    char *new_data = strtok_r(data, ",", &save);
    uint32_t i = 0;
    while (i < EXAMPLE_MAX_DEV_NUM && (new_data != NULL)) {
        cfg->m_eid_idx[i] = (uint16_t)strtoul(new_data, NULL, 0);
        new_data = strtok_r(NULL, ",", &save);
        i++;
    }

    if (cfg->m_dev_num != 0 && cfg->m_dev_num != i) {
        return -1;
    }
    cfg->m_dev_num = i;
    return 0;
}

/* Parse the command line parameters for client and server */
int parse_arguments(int argc, char **argv, struct urpc_example_config *cfg)
{
    if (argc == 1) {
        return -1;
    }

    cfg->tcp_port = DEFAULT_PORT;

    while (1) {
        int c;
        unsigned long param;

        c = getopt_long(argc, argv, "d:e:p:i:c:I:f:T:E:D:M:P:", g_long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'd':
                /* need to free when exiting */
                cfg->dev_name = strdup(optarg);
                break;
            case 'e':
                param = (uint32_t)strtoul(optarg, NULL, 0);
                if (param >= (uint32_t)UMQ_MODE_MAX) {
                    return -1;
                }
                cfg->poll_mode = (umq_queue_mode_t)param;
                break;
            case 'p':
                param = strtoul(optarg, NULL, 0);
                if (param > PORT_MAX) {
                    return -1;
                }
                cfg->tcp_port = (uint16_t)param;
                break;
            case 'i':
                /* need to free when exiting */
                cfg->server_ip = strdup(optarg);
                break;
            case 'c':
                param = (uint32_t)strtoul(optarg, NULL, 0);
                if (param >= (uint32_t)GREETER_CASE_NUM) {
                    return -1;
                }
                cfg->case_type = (int)param;
                break;
            case 'r':
                cfg->instance_mode = cfg->instance_mode == NONE ? SERVER : cfg->instance_mode;
                break;
            case 'l':
                cfg->instance_mode = cfg->instance_mode == NONE ? CLIENT : cfg->instance_mode;
                break;
            case 'I':
                cfg->is_ipv6 = true;
                /* need to free when exiting */
                cfg->server_ip = strdup(optarg);
                break;
            case 'f':
                param = strtoul(optarg, NULL, 0);
                cfg->feature = (uint32_t)param;
                break;
            case 'T':
                param = (uint32_t)strtoul(optarg, NULL, 0);
                if (param >= (uint32_t)UMQ_TRANS_MODE_MAX) {
                    return -1;
                }
                cfg->trans_mode = (umq_trans_mode_t)param;
                break;
            case 'E':
                param = strtoul(optarg, NULL, 0);
                cfg->eid_idx = (uint16_t)param;
                break;
            case 'C':
                cfg->cna = (uint16_t)strtoul(optarg, NULL, 0);
                break;
            case 'D':
                cfg->deid = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'M':
                param = (uint32_t)strtoul(optarg, NULL, 0);
                if (param >= (uint32_t)UMQ_TM_MAX) {
                    return -1;
                }
                cfg->tp_mode = (umq_tp_mode_t)param;
                break;
            case 'P':
                param = (uint32_t)strtoul(optarg, NULL, 0);
                if (param >= (uint32_t)UMQ_TP_TYPE_MAX) {
                    return -1;
                }
                cfg->tp_type = (umq_tp_type_t)param;
                break;
            case 'q':
                cfg->queue_num = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 's':
                cfg->thread_poll_size = (int)strtol(optarg, NULL, 0);
                break;
            case 'n':
                if (cfg_get_dev_name(cfg, optarg) != 0) {
                    return -1;
                }
                break;
            case 'x':
                if (cfg_get_eid_idx(cfg, optarg) != 0) {
                    return -1;
                }
                break;
            default:
                return -1;
        }
    }

    return 0;
}

void print_config(struct urpc_example_config *cfg)
{
    (void)printf(" ------------------------------------------------\n");
    if (cfg->dev_name) {
        (void)printf(" Device name : \"%s\"\n", cfg->dev_name);
    }
    if (cfg->server_ip) {
        (void)printf(" IP : %s\n", cfg->server_ip);
    }
    (void)printf(" TCP port : %hu\n", cfg->tcp_port);
    (void)printf(" Mode: %s\n", cfg->poll_mode == UMQ_MODE_INTERRUPT ? "Interrupt" : "Polling");
    (void)printf(" ------------------------------------------------\n\n");
}

void log_get_current_time(char *buffer, uint32_t len)
{
    if (buffer == NULL || len < 1) {
        return;
    }

    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    if (localtime_r(&tv.tv_sec, &tm) == NULL) {
        buffer[0] = '\0';
        return;
    }

    int ret = snprintf(
        buffer, len - 1, "%02d%02d %02d:%02d:%02d", tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (ret < 0 || ret >= (int)(len - 1)) {
        buffer[0] = '\0';
    }
}

