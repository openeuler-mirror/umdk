/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : utils.cpp
 * Description   : utility function
 * History       : create file & add functions
 * 1.Date        : 2021-06-16
 * Author        : zhangjun
 * Modification  : Created file
 */

#include "utils.h"

#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <linux/limits.h>

#include "dlock_log.h"
#include "dlock_connection.h"
#include "tcp_connection.h"
#include "ssl_connection.h"
#include "jetty_mgr_sepconn.h"
#include "jetty_mgr_uniconn.h"

namespace dlock {
const unsigned int IP_CHAR_MAX_LEN = 16;
const unsigned int IP_LEN = 4;
const unsigned int FIRST_32BIT = 0;
const unsigned int SECOND_32BIT = 1;
const unsigned int THIRD_32BIT = 2;
const unsigned int FOURTH_32BIT = 3;
const unsigned int MULTICAST_MASK = 0xff0e0000;
const unsigned int LOWER_16BIT_MASK = 0x0000ffff;
const unsigned int MAX_RES_LEN = 512;
const int CPUSET_RANGE_NUM = 2;
const unsigned int URMA_EID_STR_MIN_LEN = 3;
const unsigned int DEFAULT_TCP_RMEM = 87380;

int check_ip_format(const char *ip_str, unsigned long len)
{
    unsigned int ip[IP_LEN] = {0};
    int pos = 0;

    if ((len == 0u) ||
        (sscanf(ip_str, "%u.%u.%u.%u%n",
                  &ip[0], &ip[1], &ip[2], &ip[3], &pos) != IP_LEN)) { // 0/1/2/3 : index of ip
        DLOCK_LOG_ERR("ip format error.");
        return -1;
    }

    return 0;
}

int convert_ip_addr(const char *ip_str,  struct in_addr *addr)
{
    if ((ip_str == nullptr) || (check_ip_format(ip_str, strnlen(ip_str, IP_CHAR_MAX_LEN)) != 0)) {
        DLOCK_LOG_ERR("ip is illegal.");
        return -1;
    }

    if (inet_aton(ip_str, addr) == 0) {
        DLOCK_LOG_ERR("ip is illegal.");
        return -1;
    }

    return 0;
}

int set_send_recv_timeout(int sockfd)
{
    return set_send_recv_timeout(sockfd, static_cast<int>(CONTROL_SOCKET_TIMEOUT));
}

int set_send_recv_timeout(int sockfd, int timeout_second)
{
    struct timeval timeout;
    int ret;

    timeout.tv_sec = timeout_second;
    timeout.tv_usec = 0;

    ret = setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    if (ret < 0) {
        DLOCK_LOG_ERR("setsockopt error (errno=%d %m)", errno);
        return -1;
    }

    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    if (ret < 0) {
        DLOCK_LOG_ERR("setsockopt error (errno=%d %m)", errno);
        return -1;
    }

    return 0;
}

int set_primary_keepalive(int sockfd)
{
    int ret;
    int keep_alive = 1;
    int keep_idle = 60;
    int keep_cnt = 9;
    int keep_intvl = 6;

    ret = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const void*>(&keep_alive), sizeof(keep_alive));
    if (ret < 0) {
        DLOCK_LOG_ERR("setsockopt error (errno=%d %m)", errno);
        return -1;
    }

    ret = setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, reinterpret_cast<const void*>(&keep_idle), sizeof(keep_idle));
    if (ret < 0) {
        DLOCK_LOG_ERR("setsockopt error (errno=%d %m)", errno);
        return -1;
    }

    ret = setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, reinterpret_cast<const void*>(&keep_intvl), sizeof(keep_intvl));
    if (ret < 0) {
        DLOCK_LOG_ERR("setsockopt error (errno=%d %m)", errno);
        return -1;
    }

    ret = setsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, reinterpret_cast<const void*>(&keep_cnt), sizeof(keep_cnt));
    if (ret < 0) {
        DLOCK_LOG_ERR("setsockopt error (errno=%d %m)", errno);
        return -1;
    }

    return 0;
}

uint8_t *construct_control_msg(enum dlock_control_msg type, uint8_t version,
    size_t hdr_len, size_t total_len, uint16_t message_id, int32_t value)
{
    if (total_len > DLOCK_MAX_CTRL_MSG_SIZE) {
        DLOCK_LOG_ERR("message length %zu is longer than %u", total_len, DLOCK_MAX_CTRL_MSG_SIZE);
        return nullptr;
    }

    uint8_t *buff = (uint8_t *)malloc(total_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("malloc error (errno=%d %m)", errno);
        return nullptr;
    }

    struct dlock_control_hdr *msg_hdr = reinterpret_cast<struct dlock_control_hdr*>(buff);
    msg_hdr->magic_no = DLOCK_CP_MAGIC_NO;
    msg_hdr->version = version;
    msg_hdr->hdr_len = static_cast<uint8_t>(hdr_len);
    msg_hdr->total_len = static_cast<uint16_t>(total_len);
    msg_hdr->type = static_cast<uint8_t>(type);
    msg_hdr->rsvd = 0;
    msg_hdr->message_id = message_id;
    msg_hdr->value = value;
    return buff;
}

uint8_t* xchg_control_msg(dlock_connection *p_conn, uint8_t* buf, size_t send_len, size_t recv_len)
{
    long ret;
    struct dlock_control_hdr *p_msg_hdr;

    ret = p_conn->send(buf, send_len, 0);
    if (ret < 0) {
        DLOCK_LOG_ERR("xchg_control_msg, send error (errno=%d %m)", errno);
        goto err;
    }

    if (recv_len > send_len) {
        free(buf);
        buf = (uint8_t*)malloc(recv_len);
        if (buf == nullptr) {
            DLOCK_LOG_ERR("xchg_control_msg, realloc error (errno=%d %m)", errno);
            return nullptr;
        }
    }

    ret = p_conn->recv(buf, DLOCK_FIXED_CTRL_MSG_HDR_LEN, static_cast<int>(MSG_WAITALL));
    if (ret == 0) {
        DLOCK_LOG_ERR("error occurred and socket closed at primary");
        goto err;
    }
    if (ret < 0) {
        DLOCK_LOG_ERR("xchg_control_msg, recv hdr error (errno=%d %m)", errno);
        goto err;
    }
    if (ret != static_cast<long>(DLOCK_FIXED_CTRL_MSG_HDR_LEN)) {
        DLOCK_LOG_ERR("xchg_control_msg, recv hdr length error, ret: %ld", ret);
        goto err;
    }
    recv_len -= static_cast<size_t>(ret);
    p_msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buf);
    if (p_msg_hdr->total_len > DLOCK_FIXED_CTRL_MSG_HDR_LEN) {
        if ((p_msg_hdr->total_len - DLOCK_FIXED_CTRL_MSG_HDR_LEN) != static_cast<uint16_t>(recv_len)) {
            DLOCK_LOG_ERR("xchg_control_msg, recv message header total_len field error, unexpected total_len: %u",
                p_msg_hdr->total_len);
            goto err;
        }
        ret = p_conn->recv(buf + DLOCK_FIXED_CTRL_MSG_HDR_LEN, recv_len, static_cast<int>(MSG_WAITALL));
        if (ret < 0) {
            DLOCK_LOG_ERR("xchg_control_msg, recv message extend header and body error (errno=%d %m)", errno);
            goto err;
        }
        if (ret != static_cast<long>(recv_len)) {
            DLOCK_LOG_ERR("xchg_control_msg, recv message extend header and body length error, ret: %ld", ret);
            goto err;
        }
    }
    return buf;

err:
    free(buf);
    return nullptr;
}

uint8_t* xchg_control_msg_by_time(dlock_connection *p_conn, uint8_t* buf,
    size_t send_len, size_t recv_len, unsigned int timeout)
{
    long ret;
    long recv_bytes = 0;
    time_t time_usec = timeout * ONE_MILLION;
    
    ret = p_conn->send(buf, send_len, 0);
    if (ret < 0) {
        DLOCK_LOG_ERR("xchg_control_msg_by_time, send error (errno=%d %m)", errno);
        goto err;
    }

    if (recv_len > send_len) {
        free(buf);
        buf = (uint8_t*)malloc(recv_len);
        if (buf == nullptr) {
            DLOCK_LOG_ERR("xchg_control_msg_by_time, realloc error (errno=%d %m)", errno);
            return nullptr;
        }
    }

    struct timeval tv_start;
    struct timeval tv_end;
    static_cast<void>(gettimeofday(&tv_start, nullptr));
    do {
        ret = p_conn->recv(buf + recv_bytes, recv_len, static_cast<int>(MSG_DONTWAIT));
        static_cast<void>(gettimeofday(&tv_end, nullptr));
        if (ret > 0) {
            recv_bytes += ret;
            recv_len -= static_cast<size_t>(ret);
        }
    } while (((errno == EAGAIN) || (errno == EWOULDBLOCK)) && (recv_len > 0u) &&
             ((tv_end.tv_sec - tv_start.tv_sec) * ONE_MILLION + (tv_end.tv_usec - tv_start.tv_usec)  < time_usec));
    if (recv_len > 0u) {
        DLOCK_LOG_ERR("xchg_control_msg_by_time, recv error (errno=%d %m)", errno);
        goto err;
    }

    return buf;
err:
    free(buf);
    return nullptr;
}

static const unsigned int HASH_SEED = 5381;
static const unsigned int HASH_SHIFT = 5;

unsigned int get_hash(unsigned int len, unsigned char *buf)
{
    unsigned hash_val = HASH_SEED;
    unsigned int i;

    for (i = 0; i < len; i++) {
        hash_val = ((hash_val << HASH_SHIFT) + hash_val) + buf[i];
    }
    return hash_val;
}

void flush_recv_buffer(dlock_connection *p_conn)
{
    ssize_t ret;
    char buf[MAX_RES_LEN];
    unsigned int recv_len = 0;

    do {
        ret = p_conn->recv(buf, MAX_RES_LEN, static_cast<int>(MSG_DONTWAIT));
        /* The length of the actually received data does not need to be accurately calculated.
         * Only the flush operation time needs to be limited to prevent blocking. */
        recv_len += MAX_RES_LEN;
    } while ((ret > 0) && (recv_len < DEFAULT_TCP_RMEM));
}

void flush_recv_buffer(dlock_connection *p_conn, unsigned int len)
{
    int ret;
    char buf[MAX_RES_LEN];
    unsigned int temp_len;

    if (len == 0u) {
        DLOCK_LOG_ERR("invalid flush length");
        return;
    }

    do {
        temp_len = (len > MAX_RES_LEN) ? MAX_RES_LEN : len;
        len -= temp_len;
        ret = static_cast<int>(p_conn->recv(buf, static_cast<size_t>(temp_len), static_cast<int>(MSG_DONTWAIT)));
    } while ((ret > 0) && (len > 0u));
}

bool check_cpuset_valid(char *token, int *cpu_id)
{
    uint32_t i = 0;
    int num_cpus = sysconf(_SC_NPROCESSORS_CONF);
    uint32_t token_len = strlen(token);
    uint32_t num_non_space = 0;

    for (; i < token_len; i++) {
        if (token[i] == ' ') {
            continue;
        }
        if (isdigit(token[i]) == false) {
            return false;
        }
        num_non_space++;
    }
    // cpuset like " - 30" or "  " is ilegal
    if (num_non_space == 0u) {
        return false;
    }
    *cpu_id = static_cast<int>(strtol(token, nullptr, 10)); // 10:base10
    return ((*cpu_id < num_cpus) ? true : false);
}

bool get_cpuset(char *cpuset_token, int *range_start_id, int *range_end_id)
{
    char delims[] = "-";
    char *token = nullptr;
    char *next_token = nullptr;
    int cpu_id;
    int token_num = 0;

    // cpuset like "-30" is ilegal
    if (cpuset_token[0] == '-') {
        return false;
    }
    token = strtok_r(cpuset_token, delims, &next_token);
    while (token != nullptr) {
        token_num++;
        // in case of cpuset that looks like: 8-9-10
        if ((token_num > CPUSET_RANGE_NUM) || (!check_cpuset_valid(token, &cpu_id))) {
            return false;
        }
        if (token_num == 1) {
            *range_start_id = cpu_id;
        } else {
            *range_end_id = cpu_id;
        }
        token = strtok_r(nullptr, delims, &next_token);
    }
    if (token_num == 1) {
        *range_end_id = *range_start_id;
    }
    return true;
}

bool check_server_id_invalid(int server_id)
{
    return ((server_id <= 0) || (server_id > MAX_SERVER_ID));
}

bool check_primary_cfg_valid(const struct primary_cfg &primary)
{
    if (check_port_range_invalid(primary.server_port)) {
        DLOCK_LOG_ERR("invalid server port: %d", primary.server_port);
        return false;
    }

    if (check_port_range_invalid(primary.replica_port)) {
        DLOCK_LOG_ERR("invalid replica port: %d", primary.replica_port);
        return false;
    }

    if (primary.replica_enable) {
        DLOCK_LOG_ERR("The replica server function cannot be enabled!");
        return false;
    }

    if (primary.recovery_client_num > MAX_NUM_CLIENT) {
        DLOCK_LOG_ERR("invalid recovery_client_num: %u", primary.recovery_client_num);
        return false;
    }

    if (primary.num_of_replica != 0u) {
        DLOCK_LOG_ERR("replica is not enabled, invalid num_of_replica: %u", primary.num_of_replica);
        return false;
    }

    return true;
}

bool check_ssl_cfg_valid(const struct ssl_cfg &cfg)
{
    if (!cfg.ssl_enable) {
        return true;
    }

    if ((cfg.ca_path == nullptr) ||
        (cfg.cert_path == nullptr) ||
        (cfg.prkey_path == nullptr) ||
        (cfg.prkey_pwd_cb == nullptr) ||
        (cfg.erase_prkey_cb == nullptr)) {
        return false;
    }

    return true;
}

int set_ssl_init_attr(const struct ssl_cfg &cfg, bool &ssl_enable, ssl_init_attr_t &ssl_init_attr)
{
    ssl_enable = cfg.ssl_enable;
    if (!ssl_enable) {
        return 0;
    }

    ssl_init_attr.ca_path = cfg.ca_path;
    if (!get_canonical_path(ssl_init_attr.ca_path)) {
        DLOCK_LOG_ERR("invalid CA path");
        return -1;
    }

    ssl_init_attr.crl_path = ((cfg.crl_path != nullptr) ? cfg.crl_path : "");
    if ((cfg.crl_path != nullptr) && (!get_canonical_path(ssl_init_attr.crl_path))) {
        DLOCK_LOG_ERR("invalid CRL path");
        return -1;
    }

    ssl_init_attr.cert_path = cfg.cert_path;
    if (!get_canonical_path(ssl_init_attr.cert_path)) {
        DLOCK_LOG_ERR("invalid cert path");
        return -1;
    }

    ssl_init_attr.prkey_path = cfg.prkey_path;
    if (!get_canonical_path(ssl_init_attr.prkey_path)) {
        DLOCK_LOG_ERR("invalid private-key path");
        return -1;
    }

    ssl_init_attr.cert_verify_cb = cfg.cert_verify_cb;
    ssl_init_attr.prkey_pwd_cb = cfg.prkey_pwd_cb;
    ssl_init_attr.erase_prkey_cb = cfg.erase_prkey_cb;
    return 0;
}

dlock_connection *create_connection(int sockfd, bool is_primary, bool ssl_enable, const ssl_init_attr_t &ssl_init_attr)
{
    if (!ssl_enable) {
        dlock_connection *p_conn = new(std::nothrow) tcp_connection(sockfd);
        if (p_conn == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for c++ object!");
        }
        return p_conn;
    }

    dlock_connection *p_conn = new(std::nothrow) ssl_connection(sockfd);
    if (p_conn == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for c++ object!");
        return p_conn;
    }
    int ret = (dynamic_cast<ssl_connection *>(p_conn))->ssl_init(is_primary, ssl_init_attr);
    if (ret != 0) {
        DLOCK_LOG_ERR("SSL init error");
        p_conn->set_fd(-1);
        delete p_conn;
        return nullptr;
    }
    return p_conn;
}

/* Check whether the path is canonical, and canonical it. */
bool get_canonical_path(std::string &path)
{
    if ((path.size() == 0u) || (path.size() > PATH_MAX)) {
        DLOCK_LOG_ERR("invalid parameter, path length: %zu", path.size());
        return false;
    }

    /* It will allocate memory to store path */
    char *realPath = realpath(path.c_str(), nullptr);
    if (realPath == nullptr) {
        DLOCK_LOG_ERR("realpath error (errno=%d %m)", errno);
        return false;
    }

    path = realPath;
    free(realPath);

    return true;
}

void u32_to_eid(uint32_t ipv4, dlock_eid_t *eid)
{
    eid->in4.reserved = 0;
    eid->in4.prefix = htobe32(URMA_IPV4_MAP_IPV6_PREFIX);
    eid->in4.addr = htobe32(ipv4);
}

int str_to_urma_eid(const char *buf, dlock_eid_t *eid)
{
    unsigned long ret;
    uint32_t ipv4;

    if (buf == nullptr || strnlen(buf, IP_CHAR_MAX_LEN) <= URMA_EID_STR_MIN_LEN || eid == nullptr) {
        DLOCK_LOG_ERR("Invalid argument.\n");
        return -1;
    }

    // ipv6 addr
    if (inet_pton(AF_INET6, buf, eid) > 0) {
        return 0;
    }

    // ipv4 addr: xx.xx.xx.xx
    if (inet_pton(AF_INET, buf, &ipv4) > 0) {
        u32_to_eid(be32toh(ipv4), eid);
        return 0;
    }

    // ipv4 value: 0x12345  or abcdef or 12345
    ret = strtoul(buf, nullptr, 0);
    if (ret > 0u && ret != ULONG_MAX) {
        u32_to_eid(static_cast<uint32_t>(ret), eid);
        return 0;
    }

    DLOCK_LOG_ERR("format error: %s", buf);
    return -1;
}

bool check_if_eid_match(const urma_eid_t &eid1, const urma_eid_t &eid2)
{
    for (uint8_t i = 0; i < URMA_EID_SIZE; i++) {
        if (eid1.raw[i] != eid2.raw[i]) {
            return false;
        }
    }

    return true;
}

jetty_mgr *create_jetty_mgr(urma_ctx *p_urma_ctx, urma_jfc_t *exe_jfc, new_jetty_t type, trans_mode_t tp_mode,
    dlock_server *p_server)
{
    jetty_mgr *p_jetty_mgr;
    uint32_t num_buf;

    switch (type) {
        case CLIENT:
            num_buf = CMD_RQ_SIZE;
            break;
        case CLIENT_PRIMARY:
            num_buf = CMD_RQ_SIZE + CMD_SQ_SIZE;
            break;
        case REPLICA_PRIMARY:
            num_buf = EXE_SQ_SIZE + EXE_RQ_SIZE;
            break;
        default:
            DLOCK_LOG_ERR("Incorrect new jetty type");
            return nullptr;
    }

    if (tp_mode == UNI_CONN) {
        jetty_mgr_uniconn *p_mgr_uniconn;
        p_jetty_mgr = new(std::nothrow) jetty_mgr_uniconn(p_urma_ctx, p_server);
        if (p_jetty_mgr == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for c++ object!");
            return nullptr;
        }

        p_mgr_uniconn = dynamic_cast<jetty_mgr_uniconn *>(p_jetty_mgr);
        if (p_mgr_uniconn->jetty_mgr_uniconn_init(p_urma_ctx, exe_jfc, num_buf) != DLOCK_SUCCESS) {
            p_mgr_uniconn->jetty_mgr_deinit();
            delete p_mgr_uniconn;
            DLOCK_LOG_ERR("Fail to init jetty mgr uniconn!");
            return nullptr;
        }
        if (!p_mgr_uniconn->check_construct_succeed(p_mgr_uniconn, true)) {
            return nullptr;
        }
    } else {
        jetty_mgr_sepconn *p_mgr_sepconn;
        p_jetty_mgr = new(std::nothrow) jetty_mgr_sepconn(p_urma_ctx, p_server);
        if (p_jetty_mgr == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for c++ object!");
            return nullptr;
        }

        p_mgr_sepconn = dynamic_cast<jetty_mgr_sepconn *>(p_jetty_mgr);
        if (p_mgr_sepconn->jetty_mgr_sepconn_init(p_urma_ctx, exe_jfc, num_buf) != DLOCK_SUCCESS) {
            p_mgr_sepconn->jetty_mgr_deinit();
            delete p_mgr_sepconn;
            DLOCK_LOG_ERR("Fail to init jetty mgr sepconn!");
            return nullptr;
        }
        if (!p_mgr_sepconn->check_construct_succeed(p_mgr_sepconn, true)) {
            return nullptr;
        }
    }
    return p_jetty_mgr;
}

dlock_status_t set_jetty_connection(jetty_mgr *p_jetty_mgr, struct urma_init_body *jetty_info, trans_mode_t tp_mode)
{
    dlock_status_t ret;

    if (tp_mode == SEPERATE_CONN) {
        jetty_mgr_sepconn *p_mgr_sepconn = dynamic_cast<jetty_mgr_sepconn *>(p_jetty_mgr);

#ifdef UB_AGG
        if (jetty_info->is_bond &&
            (p_mgr_sepconn->add_urma_bond_rjfr_id_info(&jetty_info->bond_id_info) != DLOCK_SUCCESS)) {
            DLOCK_LOG_ERR("add urma bond rjfr id info error");
            return DLOCK_FAIL;
        }
#endif /* UB_AGG */

        ret = p_mgr_sepconn->import_jfr(jetty_info->jfr_id, jetty_info->flag.bs.token_policy, jetty_info->token);
        if (ret != DLOCK_SUCCESS) {
            DLOCK_LOG_ERR("import jfr error");
            return DLOCK_FAIL;
        }
    } else {
        jetty_mgr_uniconn *p_mgr_uniconn = dynamic_cast<jetty_mgr_uniconn *>(p_jetty_mgr);

#ifdef UB_AGG
        if (jetty_info->is_bond &&
            (p_mgr_uniconn->add_urma_bond_rjetty_id_info(&jetty_info->bond_id_info) != DLOCK_SUCCESS)) {
            DLOCK_LOG_ERR("add urma bond rjetty id info error");
            return DLOCK_FAIL;
        }
#endif /* UB_AGG */

        ret = p_mgr_uniconn->import_jetty(jetty_info->jetty_id, jetty_info->flag.bs.token_policy, jetty_info->token);
        if (ret != DLOCK_SUCCESS) {
            DLOCK_LOG_ERR("import jetty error");
            return DLOCK_FAIL;
        }
        ret = p_mgr_uniconn->bind_jetty();
        if (ret != DLOCK_SUCCESS) {
            DLOCK_LOG_ERR("bind jetty error");
            return DLOCK_FAIL;
        }
    }
    return DLOCK_SUCCESS;
}
};
