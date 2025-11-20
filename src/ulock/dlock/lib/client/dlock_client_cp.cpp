/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : dlock_client_cp.cpp
 * Description   : dlock client control plane process
 * History       : create file & add functions
 * 1.Date        : 2021-06-16
 * Author        : zhangjun
 * Modification  : Created file
 */

#include "dlock_types.h"
#include "dlock_client.h"

#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <csignal>
#include <chrono>

#include "dlock_common.h"
#include "dlock_log.h"
#include "utils.h"
#include "urma_ctx.h"
#include "dlock_descriptor.h"
#include "dlock_connection.h"
#include "jetty_mgr_sepconn.h"

namespace dlock {
constexpr uint32_t STATS_API_INVOKING_FREQ_UPDATE_INTERVAL = 1000000;    /* The unit is microsecond. total: 1s */
constexpr uint32_t MAX_STATS_API_INVOKING_FREQ_PER_SEC = 10000;
constexpr unsigned int MAX_HEARTBEAT_TIMEOUT = 300;
constexpr long MAX_CONTINUOUS_EAGAIN = 120000000; /* 120 second */

dlock_client::dlock_client() noexcept : m_is_inited(false), m_p_urma_ctx(nullptr), m_primary_port(CONTROL_PORT_CLIENT),
    m_ssl_enable(false), m_tp_mode(SEPERATE_CONN), m_stats_access_cnt(0)
{
    DLOCK_LOG_DEBUG("dlock clientMgr construct");
    m_stats_access_tp_prev = std::chrono::steady_clock::now();
}

dlock_client::~dlock_client()
{
    if (m_p_urma_ctx != nullptr) {
        delete m_p_urma_ctx;
        m_p_urma_ctx = nullptr;
    }
    DLOCK_LOG_DEBUG("client deconstruct");
}

dlock_client dlock_client::_instance;

dlock_client &dlock_client::instance()
{
    return _instance;
}

int dlock_client::init(const struct client_cfg *p_client_cfg)
{
    if (m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has been inited");
        return -1;
    }

    if ((p_client_cfg->tp_mode != SEPERATE_CONN) && (p_client_cfg->tp_mode != UNI_CONN)) {
        DLOCK_LOG_ERR("invalid transport mode set");
        return -1;
    }
    m_tp_mode = p_client_cfg->tp_mode;

    dlock_set_log_level(p_client_cfg->log_level);

    struct urma_ctx_cfg urma_cfg = {
        .num_buf = CLIENT_PER_HOST * (CMD_SQ_SIZE + CMD_RQ_SIZE),
        .num_cqe = 0,
        .dev_name = p_client_cfg->dev_name,
        .eid = p_client_cfg->eid,
        .tp_mode = p_client_cfg->tp_mode,
        .ub_token_disable = p_client_cfg->ub_token_disable,
    };
    m_p_urma_ctx = new(std::nothrow) urma_ctx(urma_cfg);
    if (m_p_urma_ctx == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for urma_ctx");
        return -1;
    }
    if ((m_p_urma_ctx->m_urma_ctx == nullptr) || (m_p_urma_ctx->m_local_tseg == nullptr)) {
        DLOCK_LOG_ERR("failed to init urma context");
        delete m_p_urma_ctx;
        m_p_urma_ctx = nullptr;
        return -1;
    }

    int ret = set_ssl_init_attr(p_client_cfg->ssl, m_ssl_enable, m_ssl_init_attr);
    if (ret != 0) {
        DLOCK_LOG_ERR("failed to set SSL initialization attributes");
        delete m_p_urma_ctx;
        m_p_urma_ctx = nullptr;
        return -1;
    }

    m_is_inited = true;
    m_primary_port = (p_client_cfg->primary_port > 0) ? p_client_cfg->primary_port : m_primary_port;

    return 0;
}

void dlock_client::clear_m_client_map(void)
{
    std::unique_lock<std::shared_mutex> locker(m_client_map_rwlock);
    if (!m_client_map.empty()) {
        auto iter = m_client_map.begin();
        while (iter != m_client_map.end()) {
            delete iter->second;
            static_cast<void>(iter++);
        }
        m_client_map.clear();
    }
}

void dlock_client::deinit()
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return;
    }

    clear_m_client_map();

    if (m_p_urma_ctx != nullptr) {
        delete m_p_urma_ctx;
        m_p_urma_ctx = nullptr;
    }
    m_is_inited = false;
}

int dlock_client::connect_to_server(const char *ip_str) const
{
    struct in_addr ip_addr;

    if (convert_ip_addr(ip_str, &ip_addr) < 0) {
        DLOCK_LOG_ERR("invalid server addr");
        return -1;
    }

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        DLOCK_LOG_ERR("create socket error (errno=%d %m)", errno);
        return -1;
    }

    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(m_primary_port);
    servaddr.sin_addr = ip_addr;
    int ret = connect(sock_fd, reinterpret_cast<struct sockaddr *>(&servaddr), sizeof(servaddr));
    if (ret != 0) {
        DLOCK_LOG_ERR("connect to server error (errno=%d %m)", errno);
        static_cast<void>(close(sock_fd));
        return ((errno == ECONNREFUSED) ? -(static_cast<int>(DLOCK_NOT_READY)) : -1);
    }
    int flag = 1;
    static_cast<void>(setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&flag), sizeof(int)));
    static_cast<void>(set_send_recv_timeout(sock_fd));
    return sock_fd;
}

int dlock_client::add_client(uint8_t *buff, dlock_connection *p_conn, jetty_mgr &p_jetty_mgr, int *p_client_id,
    bool reinit_flag)
{
    struct client_init_resp_body *resp_body =
        reinterpret_cast<struct client_init_resp_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);

    if (reinit_flag && (*p_client_id != resp_body->client_id)) {
        DLOCK_LOG_ERR("client reinit response msg error, client_id does not match");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    dlock_status_t ret = p_jetty_mgr.import_seg(&resp_body->obj_mem_seg, resp_body->obj_mem_seg_token);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("import seg failed");
        return -1;
    }

    dlock_status_t status_ret = set_jetty_connection(&p_jetty_mgr, &resp_body->jetty_info, m_tp_mode);
    if (status_ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("failed to set jetty connection");
        return -1;
    }

    if (m_ssl_enable) {
        struct dlock_key *key = reinterpret_cast<struct dlock_key *>(reinterpret_cast<unsigned char *>(resp_body) +
            DLOCK_CLIENT_INIT_RESP_BODY_LEN);
        if (key->key_len > p_jetty_mgr.m_dlock_cipher->m_key->key_len) {
            DLOCK_LOG_ERR("response message key len exceeds the limit.");
            return -1;
        }
        static_cast<void>(memcpy(p_jetty_mgr.m_dlock_cipher->m_key->key,
            reinterpret_cast<unsigned char *>(key + 1), key->key_len));
        if (reinit_flag) {
            DLOCK_LOG_INFO("data plane key of client updated from server");
        } else {
            DLOCK_LOG_INFO("data plane key of client got from server");
        }
    }

    *p_client_id = resp_body->client_id;
    std::unique_lock<std::shared_mutex> locker(m_client_map_rwlock);
    client_entry_c *p_client_new = new(std::nothrow) client_entry_c(resp_body->client_id, p_conn, &p_jetty_mgr);
    if (p_client_new == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for client_entry_c");
        return -1;
    }

    /* After the primary server is faulty, and replica server is not supported,
     * a new primary server can be started. The client reconnects to the new server
     * and synchronizes lock information to the server. In this case, the atomic64
     * object information is invalid and needs to be created and get again.
     */
    if (reinit_flag && resp_body->server_state == SERVER_WAIT_CLIENT_REINIT) {
        p_client_new->set_m_obj_invalid_flag();
    }

    m_client_map[resp_body->client_id] = p_client_new;
    p_conn->set_peer_info(DLOCK_CONN_PEER_PRIMARY_SERVER, 0);
    return 0;
}

int dlock_client::init_client_do(int *p_client_id, const char *ip_str, bool reinit_flag)
{
    uint8_t *buff = nullptr;
    struct client_init_req_body *req_body = nullptr;
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_CLIENT_INIT_REQ_BODY_LEN;
    size_t recv_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_CLIENT_INIT_RESP_BODY_LEN;
    if (m_ssl_enable) {
        recv_len += sizeof(struct dlock_key) + sizeof(unsigned char) * AES_KEY_BYTES;
    }

    static_cast<void>(signal(SIGPIPE, SIG_IGN));
    int sock_fd = connect_to_server(ip_str);
    if (sock_fd < 0) {
        DLOCK_LOG_ERR("connect_to_server error");
        return ((sock_fd == -(static_cast<int>(DLOCK_NOT_READY))) ? static_cast<int>(DLOCK_NOT_READY) : -1);
    }

    dlock_connection *p_conn = create_connection(sock_fd, false, m_ssl_enable, m_ssl_init_attr);
    if (p_conn == nullptr) {
        DLOCK_LOG_ERR("failed to init dlock connection");
        static_cast<void>(close(sock_fd));
        return -1;
    }

    int ret = -1;
    uint16_t message_id;
    jetty_mgr *p_jetty_mgr = nullptr;
    struct dlock_control_hdr *msg_hdr = nullptr;

    if (p_conn->rand_init_next_message_id() != 0) {
        DLOCK_LOG_ERR("failed to randomly initialize next message id");
        goto err_del_p_conn;
    }

    p_jetty_mgr = create_jetty_mgr(m_p_urma_ctx, nullptr, CLIENT, m_tp_mode, nullptr);
    if (p_jetty_mgr == nullptr) {
        DLOCK_LOG_ERR("failed to create jetty mgr");
        goto err_del_p_conn;
    }

    if (p_jetty_mgr->rand_init_next_message_id() != 0) {
        DLOCK_LOG_ERR("failed to randomly initialize next message id");
        goto err_del_p_jetty_mgr;
    }

    message_id = p_conn->generate_message_id();
    buff = construct_control_msg(((reinit_flag) ? CLIENT_REINIT_REQUEST : CLIENT_INIT_REQUEST),
        DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, *p_client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        goto err_del_p_jetty_mgr;
    }

    req_body = reinterpret_cast<struct client_init_req_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    if (p_jetty_mgr->construct_jetty_xchg_info(&req_body->jetty_info, p_jetty_mgr) != DLOCK_SUCCESS) {
        goto err_free_buff;
    }
    req_body->min_version = DLOCK_MIN_PROTO_VERSION;

    buff = xchg_control_msg(p_conn, buff, msg_len, recv_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        goto err_del_p_jetty_mgr;
    }

    msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    ret = check_resp_control_msg_hdr(*msg_hdr, ((reinit_flag) ? CLIENT_REINIT_RESPONSE : CLIENT_INIT_RESPONSE),
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
        goto err_free_buff;
    }

    ret = add_client(buff, p_conn, *p_jetty_mgr, p_client_id, reinit_flag);
    if (ret != 0) {
        DLOCK_LOG_ERR("add_client error");
        goto err_free_buff;
    }
    free(buff);
    return ret;

err_free_buff:
    free(buff);
err_del_p_jetty_mgr:
    p_jetty_mgr->jetty_mgr_deinit();
    delete p_jetty_mgr;
    p_jetty_mgr = nullptr;
err_del_p_conn:
    delete p_conn;
    p_conn = nullptr;
    return ret;
}

int dlock_client::init_client(int *p_client_id, const char *ip_str)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }

    return init_client_do(p_client_id, ip_str, false);
}

int dlock_client::reinit_client(int client_id, const char *ip_str)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }
    client_entry_c *p_client_old;
    client_entry_c *p_client_new;

    std::shared_lock<std::shared_mutex> shared_locker(m_client_map_rwlock);
    auto it = m_client_map.find(client_id);
    if (it != m_client_map.end()) {
        // current entry should be removed only if init_client_do succeeds.
        // m_client_map[client_id] will be covered by new entry in add_client
        // when succeeds, so there is no need to call m_client_map erase
        p_client_old = it->second;
    } else {
        DLOCK_LOG_ERR("client has not been inited");
        return static_cast<int>(DLOCK_EINVAL);
    }
    shared_locker.unlock();

    std::unique_lock<std::mutex> locker(m_mutex_lock);
    int ret = init_client_do(&client_id, ip_str, true);
    if (ret != 0) {
        return ret;
    }
    shared_locker.lock();
    p_client_new = m_client_map[client_id];
    shared_locker.unlock();

    if (p_client_new->get_m_obj_invalid_flag()) {
        p_client_new->clear_m_obj_invalid_flag();
    } else {
        p_client_new->m_object_map.insert(p_client_old->m_object_map.begin(), p_client_old->m_object_map.end());
        p_client_new->m_obj_desc_map.insert(p_client_old->m_obj_desc_map.begin(), p_client_old->m_obj_desc_map.end());
        p_client_old->m_object_map.clear();
        p_client_old->m_obj_desc_map.clear();
    }

    p_client_new->m_lock_map.insert(p_client_old->m_lock_map.begin(), p_client_old->m_lock_map.end());
    p_client_new->m_lock_map.insert(p_client_old->m_update_map.begin(), p_client_old->m_update_map.end());
    p_client_new->update_associated_client_pointer();
    p_client_old->m_lock_map.clear();
    p_client_old->m_update_map.clear();
    delete p_client_old;
    return ret;
}

int dlock_client::delete_client(int client_id)
{
    std::unique_lock<std::shared_mutex> locker(m_client_map_rwlock);
    client_map_t::iterator iter = m_client_map.find(client_id);
    if (iter == m_client_map.end()) {
        DLOCK_LOG_ERR("client has not been inited");
        return -1;
    }
    delete iter->second;
    if (m_ssl_enable) {
        DLOCK_LOG_INFO("data plane key deleted at client");
    }
    static_cast<void>(m_client_map.erase(iter));
    return 0;
}

int dlock_client::deinit_client(int client_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return -1;
    }

    int ret = -1;
    uint8_t *buff = nullptr;
    struct dlock_control_hdr *msg_hdr = nullptr;
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;

    if (m_tp_mode == SEPERATE_CONN) {
        jetty_mgr_sepconn *p_jetty_mgr_sepconn = dynamic_cast<jetty_mgr_sepconn *>(p_client->m_p_jetty_mgr);
        p_jetty_mgr_sepconn->unimport_tjfr();
    }

    uint16_t message_id = p_client->m_p_conn->generate_message_id();
    buff = construct_control_msg(CLIENT_DEINIT_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        ret = -1;
        goto err2;
    }

    buff = xchg_control_msg(p_client->m_p_conn, buff, msg_len, msg_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        ret = static_cast<int>(DLOCK_BAD_RESPONSE);
        goto err2;
    }

    msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    ret = check_resp_control_msg_hdr(*msg_hdr, CLIENT_DEINIT_RESPONSE,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
        goto err1;
    }

    free(buff);
    return delete_client(client_id);

err1:
    free(buff);
err2:
    static_cast<void>(delete_client(client_id));
    return ret;
}

int dlock_client::heartbeat(int client_id, unsigned int timeout)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }
    /* Set high limit of MAX_HEARTBEAT_TIMEOUT to prevent stuck if user set an extremely big timeout */
    if ((timeout == 0u) || (timeout > MAX_HEARTBEAT_TIMEOUT)) {
        DLOCK_LOG_ERR("invalid timeout %d", timeout);
        return static_cast<int>(DLOCK_EINVAL);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return static_cast<int>(DLOCK_EINVAL);
    }

    uint8_t *buff = nullptr;
    struct dlock_control_hdr *msg_hdr = nullptr;
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
    uint16_t message_id = p_client->m_p_conn->generate_message_id();

    buff = construct_control_msg(CLIENT_HEARTBEAT_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return -1;
    }

    buff = xchg_control_msg_by_time(p_client->m_p_conn, buff, msg_len, msg_len, timeout);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg_by_time error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }
    msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*msg_hdr, CLIENT_HEARTBEAT_RESPONSE,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
        free(buff);
        return ret;
    }

    free(buff);
    return 0;
}

int dlock_client::get_lock(int client_id, const struct lock_desc *p_desc, int *p_lock_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("get_lock, client has not been inited");
        return -1;
    }

    uint8_t *buff = nullptr;
    struct dlock_control_hdr *msg_hdr = nullptr;
    struct get_lock_body *msg_get_lock_body = nullptr;
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_GET_LOCK_BODY_LEN + p_desc->len;
    size_t recv_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_GET_LOCK_BODY_LEN;
    uint16_t message_id = p_client->m_p_conn->generate_message_id();
    lock_map_t::iterator lock_iter;
    lock_entry_c *p_lock_entry = nullptr;

    buff = construct_control_msg(GET_LOCK_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return -1;
    }

    int lock_id = *p_lock_id;
    msg_get_lock_body = reinterpret_cast<struct get_lock_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    msg_get_lock_body->lock_id = lock_id;
    msg_get_lock_body->lock_type = p_desc->lock_type;
    msg_get_lock_body->lease_time = p_desc->lease_time;
    msg_get_lock_body->desc_len = p_desc->len;
    /* since buffer allocated for msg_get_lock_body->desc is p_desc->len in msg_len calculation,
    *  destMax equals to p_desc->len
    */
    static_cast<void>(memcpy(msg_get_lock_body->desc, p_desc->p_desc, p_desc->len));

    buff = xchg_control_msg(p_client->m_p_conn, buff, msg_len, recv_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    std::unique_lock<std::shared_mutex> locker(m_map_rwlock, std::defer_lock);

    msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*msg_hdr, GET_LOCK_RESPONSE, DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
        free(buff);
        return ret;
    }

    msg_get_lock_body = reinterpret_cast<struct get_lock_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    *p_lock_id = lock_id = msg_get_lock_body->lock_id;
    if (lock_id <= 0) {
        DLOCK_LOG_ERR("invalid lock_id: %d", lock_id);
        goto err1;
    }
    shared_locker.lock();
    lock_iter = p_client->m_lock_map.find(lock_id);
    if (lock_iter != p_client->m_lock_map.end()) {
        shared_locker.unlock();
        DLOCK_LOG_ERR("lock %d has already been got", lock_id);
        goto err1;
    }
    shared_locker.unlock();

    p_lock_entry = new(std::nothrow) lock_entry_c(lock_id, static_cast<enum dlock_type>(msg_get_lock_body->lock_type),
                   msg_get_lock_body->offset, msg_get_lock_body->lease_time, p_client);
    if (p_lock_entry == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for lock_entry_c");
        goto err1;
    }

    p_lock_entry->m_lock_desc = new(std::nothrow) dlock_descriptor();
    if (p_lock_entry->m_lock_desc == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
        delete p_lock_entry;
        goto err1;
    }
    if (p_lock_entry->m_lock_desc->descriptor_init(p_desc->len,
        reinterpret_cast<unsigned char*>(p_desc->p_desc))) {
        DLOCK_LOG_ERR("dlock descriptor init failed");
        delete p_lock_entry->m_lock_desc;
        p_lock_entry->m_lock_desc = nullptr;
        delete p_lock_entry;
        goto err1;
    }

    locker.lock();
    p_client->m_lock_map[lock_id] = p_lock_entry;
    locker.unlock();
    free(buff);
    return 0;

err1:
    if (msg_hdr->value == -(static_cast<int>(DLOCK_NOT_READY))) {
        free(buff);
        return static_cast<int>(DLOCK_NOT_READY);
    }
    free(buff);
    return -1;
}

int dlock_client::release_lock(int client_id, int lock_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return -1;
    }
    if (p_client->check_lock_async_state(lock_id)) {
        DLOCK_LOG_WARN("an async op is ongoing on lock %x", lock_id);
        return static_cast<int>(DLOCK_EASYNC);
    }

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock);
    lock_map_t::iterator lock_iter = p_client->m_lock_map.find(lock_id);
    if (lock_iter == p_client->m_lock_map.end()) {
        DLOCK_LOG_ERR("lock %d has not been got", lock_id);
        return -1;
    }
    shared_locker.unlock();
    enum dlock_state release_lock_state = lock_iter->second->m_lock_state;
    if ((release_lock_state != UNLOCKED) && (release_lock_state != LOCK_INITIALIZED)) {
        DLOCK_LOG_ERR("should unlock first");
        return (((release_lock_state == EXCLUSIVE_TICKETED) || (release_lock_state == SHARED_TICKETED)) ?
            static_cast<int>(DLOCK_TICKET_TO_UNLOCK) : -1);
    }

    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_RELEASE_LOCK_BODY_LEN;
    uint16_t message_id = p_client->m_p_conn->generate_message_id();
    uint8_t *buff = construct_control_msg(RELEASE_LOCK_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return -1;
    }

    struct release_lock_body *msg_release_lock_body = reinterpret_cast<struct release_lock_body *>(
        buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    msg_release_lock_body->lock_id = lock_id;

    buff = xchg_control_msg(p_client->m_p_conn, buff, msg_len, DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    struct dlock_control_hdr *msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*msg_hdr, RELEASE_LOCK_RESPONSE, DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
        if ((ret != static_cast<int>(DLOCK_NOT_READY)) && (ret != static_cast<int>(DLOCK_BAD_RESPONSE))) {
            p_client->delete_local_lock_entry(m_map_rwlock, lock_iter);
        }
        free(buff);
        return ret;
    }

    p_client->delete_local_lock_entry(m_map_rwlock, lock_iter);
    free(buff);
    return 0;
}

int dlock_client::check_stats_api_invoking_freq(void)
{
    std::chrono::steady_clock::time_point m_tp_now = std::chrono::steady_clock::now();
    std::chrono::microseconds interval =
        std::chrono::duration_cast<std::chrono::microseconds>(m_tp_now - m_stats_access_tp_prev);

    if (interval.count() > STATS_API_INVOKING_FREQ_UPDATE_INTERVAL) {
        m_stats_access_tp_prev = m_tp_now;
        m_stats_access_cnt = 0;
    }

    if (m_stats_access_cnt >= MAX_STATS_API_INVOKING_FREQ_PER_SEC) {
        return -1;
    }

    ++m_stats_access_cnt;
    return 0;
}

int dlock_client::get_client_debug_stats(int client_id, struct debug_stats *stats)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    std::unique_lock<std::mutex> locker(m_stats_access_lock);
    if (check_stats_api_invoking_freq() != 0) {
        DLOCK_LOG_ERR("The frequency of invoking the statistics API is too high. "
            "Please wait for a while and try again.");
        return static_cast<int>(DLOCK_EAGAIN);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    static_cast<void>(memcpy(stats, &p_client->m_stats, sizeof(p_client->m_stats)));

    return static_cast<int>(DLOCK_SUCCESS);
}

int dlock_client::clear_client_debug_stats(int client_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    std::unique_lock<std::mutex> locker(m_stats_access_lock);
    if (check_stats_api_invoking_freq() != 0) {
        DLOCK_LOG_ERR("The frequency of invoking the statistics API is too high. "
            "Please wait for a while and try again.");
        return static_cast<int>(DLOCK_EAGAIN);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    static_cast<void>(memset(&p_client->m_stats, 0, sizeof(p_client->m_stats)));
    return static_cast<int>(DLOCK_SUCCESS);
}

uint8_t *dlock_client::construct_batch_get_lock_req(int client_id, unsigned int lock_num,
    uint16_t message_id, const struct lock_desc *p_descs, int *p_lock_ids, size_t &msg_len) const
{
    struct batch_get_lock_body *msg_batch_get_lock_body = nullptr;
    struct get_lock_body *msg_get_lock_body = nullptr;
    size_t initial_msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_BATCH_GET_LOCK_BODY_LEN;
    size_t temp_msg_len = initial_msg_len;
    uint32_t i;

    msg_len = 0;

    for (i = 0; i < lock_num; i++) {
        temp_msg_len += DLOCK_GET_LOCK_BODY_LEN + p_descs[i].len;
    }

    uint8_t *buff = construct_control_msg(BATCH_GET_LOCK_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, temp_msg_len, message_id, client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return nullptr;
    }

    msg_batch_get_lock_body = reinterpret_cast<struct batch_get_lock_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    msg_batch_get_lock_body->lock_num = lock_num;

    temp_msg_len = initial_msg_len;
    for (i = 0; i < lock_num; i++) {
        msg_get_lock_body = reinterpret_cast<struct get_lock_body *>(buff + temp_msg_len);
        msg_get_lock_body->lock_id = p_lock_ids[i];
        msg_get_lock_body->lock_type = p_descs[i].lock_type;
        msg_get_lock_body->lease_time = p_descs[i].lease_time;
        msg_get_lock_body->desc_len = p_descs[i].len;
        /* since buffer allocated for msg_get_lock_body->desc is p_desc->len[i] in temp_msg_len calculation,
        *  destMax equals to p_desc->len[i]
        */
        static_cast<void>(memcpy(msg_get_lock_body->desc, p_descs[i].p_desc, p_descs[i].len));
        temp_msg_len += DLOCK_GET_LOCK_BODY_LEN + p_descs[i].len;
    }

    msg_len = temp_msg_len;
    return buff;
}

int dlock_client::batch_add_local_lock_entry(client_entry_c &p_client_entry, uint8_t *buff,
    unsigned int lock_num, const struct lock_desc *p_descs, int *p_lock_ids)
{
    lock_map_t::iterator lock_iter;
    struct batch_get_lock_body *msg_batch_get_lock_body =
        reinterpret_cast<struct batch_get_lock_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    struct get_lock_body *msg_get_lock_body = msg_batch_get_lock_body->get_lock_entry;

    if (msg_batch_get_lock_body->lock_num != lock_num) {
        DLOCK_LOG_ERR("response message lock_num %u error, expected lock_num: %u",
            msg_batch_get_lock_body->lock_num, lock_num);
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    uint32_t i;
    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    std::unique_lock<std::shared_mutex> locker(m_map_rwlock, std::defer_lock);
    for (i = 0; i < lock_num; i++) {
        p_lock_ids[i] = msg_get_lock_body[i].lock_id;
        if (p_lock_ids[i] <= 0) {
            DLOCK_LOG_ERR("invalid lock_id[%d]: %d", i, p_lock_ids[i]);
            continue;
        }
        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_lock_ids[i]);
        if (lock_iter != p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            DLOCK_LOG_WARN("lock %d has already been got", p_lock_ids[i]);
            continue;
        }
        shared_locker.unlock();
        lock_entry_c *p_lock_entry = new(std::nothrow) lock_entry_c(p_lock_ids[i],
            static_cast<enum dlock_type>(msg_get_lock_body[i].lock_type),
            msg_get_lock_body[i].offset, msg_get_lock_body[i].lease_time, &p_client_entry);
        if (p_lock_entry == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for lock_entry_c");
            return -1;
        }

        p_lock_entry->m_lock_desc = new(std::nothrow) dlock_descriptor();
        if (p_lock_entry->m_lock_desc == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
            delete p_lock_entry;
            return -1;
        }
        if (p_lock_entry->m_lock_desc->descriptor_init(p_descs[i].len,
            reinterpret_cast<unsigned char*>(p_descs[i].p_desc))) {
            DLOCK_LOG_ERR("dlock descriptor init failed");
            delete p_lock_entry->m_lock_desc;
            p_lock_entry->m_lock_desc = nullptr;
            delete p_lock_entry;
            return -1;
        }

        locker.lock();
        p_client_entry.m_lock_map[p_lock_ids[i]] = p_lock_entry;
        locker.unlock();
    }
    return 0;
}

int dlock_client::batch_get_lock(int client_id, unsigned int lock_num, const struct lock_desc *p_descs, int *p_lock_ids)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("batch_get_lock, client has not been inited");
        return -1;
    }

    uint8_t *buff = nullptr;
    size_t msg_len = 0;
    uint16_t message_id = p_client->m_p_conn->generate_message_id();
    buff = construct_batch_get_lock_req(client_id, lock_num, message_id, p_descs, p_lock_ids, msg_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct batch get lock request failed");
        return -1;
    }

    size_t recv_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_BATCH_GET_LOCK_BODY_LEN +
        (lock_num * DLOCK_GET_LOCK_BODY_LEN);
    buff = xchg_control_msg(p_client->m_p_conn, buff, msg_len, recv_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    struct dlock_control_hdr *msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*msg_hdr, BATCH_GET_LOCK_RESPONSE, DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
        goto err1;
    }

    ret = batch_add_local_lock_entry(*p_client, buff, lock_num, p_descs, p_lock_ids);
    if (ret != 0) {
        goto err1;
    }
    free(buff);
    return 0;
err1:
    free(buff);
    return ret;
}

uint8_t *dlock_client::construct_batch_release_lock_req(client_entry_c &p_client_entry,
    unsigned int lock_num, uint16_t message_id, int *p_lock_ids, size_t &msg_len)
{
    uint32_t i;
    uint32_t j;
    uint32_t temp_req_num = 0;
    size_t temp_msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_BATCH_RELEASE_LOCK_BODY_LEN;
    lock_map_t::iterator lock_iter;

    msg_len = 0;

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    for (i = 0; i < lock_num; i++) {
        if (p_client_entry.check_lock_async_state(p_lock_ids[i])) {
            DLOCK_LOG_ERR("an async op is ongoing on lock %x", p_lock_ids[i]);
            p_lock_ids[i] = 0;
            continue;
        }

        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_lock_ids[i]);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            DLOCK_LOG_ERR("lock %d has not been got", p_lock_ids[i]);
            p_lock_ids[i] = 0;
            continue;
        }
        shared_locker.unlock();
        if (lock_iter->second->m_ref_count > 0u) {
            DLOCK_LOG_ERR("should unlock %d first", p_lock_ids[i]);
            p_lock_ids[i] = 0;
            continue;
        }
        temp_msg_len += DLOCK_RELEASE_LOCK_BODY_LEN;
        temp_req_num++;
    }
    if (temp_req_num == 0u) {
        DLOCK_LOG_ERR("no valid lock_id for release");
        return nullptr;
    }

    uint8_t *buff = construct_control_msg(BATCH_RELEASE_LOCK_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, temp_msg_len, message_id, p_client_entry.m_client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return nullptr;
    }

    struct batch_release_lock_body *msg_batch_release_lock_body =
        reinterpret_cast<struct batch_release_lock_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    msg_batch_release_lock_body->lock_num = temp_req_num;

    struct release_lock_body *msg_release_lock_body = msg_batch_release_lock_body->release_lock_entry;
    for (i = 0, j = 0; i < lock_num; i++) {
        if (p_lock_ids[i] == 0) {
            continue;
        }
        // lock_num actually sent is temp_req_num, which is no bigger than lock_num
        msg_release_lock_body[j++].lock_id = p_lock_ids[i];
    }

    msg_len = temp_msg_len;
    return buff;
}

void dlock_client::batch_delete_local_lock_entry(client_entry_c &p_client_entry,
    unsigned int lock_num, int *p_lock_ids)
{
    uint32_t i;
    lock_map_t::iterator lock_iter;

    std::unique_lock<std::shared_mutex> locker(m_map_rwlock, std::defer_lock);
    for (i = 0; i < lock_num; i++) {
        if (p_lock_ids[i] == 0) {
            continue;
        }
        locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_lock_ids[i]);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            locker.unlock();
            DLOCK_LOG_ERR("lock %d has not been got", p_lock_ids[i]);
            p_lock_ids[i] = 0;
            continue;
        }
        delete lock_iter->second;
        static_cast<void>(p_client_entry.m_lock_map.erase(lock_iter));
        locker.unlock();
    }
}

int dlock_client::batch_release_lock(int client_id, unsigned int lock_num, int *p_lock_ids)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return -1;
    }

    uint8_t *buff = nullptr;
    struct dlock_control_hdr *msg_hdr = nullptr;
    size_t msg_len = 0;
    uint16_t message_id = p_client->m_p_conn->generate_message_id();

    buff = construct_batch_release_lock_req(*p_client, lock_num, message_id, p_lock_ids, msg_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct batch release lock request failed");
        return -1;
    }

    buff = xchg_control_msg(p_client->m_p_conn, buff, msg_len, DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*msg_hdr, BATCH_RELEASE_LOCK_RESPONSE,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
        if ((ret != static_cast<int>(DLOCK_NOT_READY)) && (ret != static_cast<int>(DLOCK_BAD_RESPONSE))) {
            batch_delete_local_lock_entry(*p_client, lock_num, p_lock_ids);
        }
        free(buff);
        return ret;
    }
    batch_delete_local_lock_entry(*p_client, lock_num, p_lock_ids);
    free(buff);
    return 0;
}

static void *update_locks_requester(void *p_object)
{
    client_entry_c *p_client_entry = reinterpret_cast<client_entry_c *>(p_object);
    p_client_entry->update_locks_requester();
    return nullptr;
}

int dlock_client::update_all_locks(int client_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }

    client_entry_c *p_client_entry = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client_entry == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    if ((p_client_entry->m_update_map.empty()) && (p_client_entry->m_lock_map.empty())) {
        DLOCK_LOG_DEBUG("no locks to be updated");
        return static_cast<int>(DLOCK_SUCCESS);
    }

    uint8_t *buf = (uint8_t *)malloc(DLOCK_MAX_CTRL_MSG_SIZE * sizeof(char));
    if (buf == nullptr) {
        DLOCK_LOG_ERR("malloc error (errno=%d %m)", errno);
        return static_cast<int>(DLOCK_ENOMEM);
    }

    /* next_resp_message_id must be obtained before the update_locks_requester thread is created. */
    uint16_t next_resp_message_id = p_client_entry->m_p_conn->get_next_message_id();

    pthread_t update_locks_tid;
    p_client_entry->m_update_lock_state = 1;
    int ret = pthread_create(&update_locks_tid, nullptr, update_locks_requester, p_client_entry);
    if (ret != 0) {
        DLOCK_LOG_ERR("failed to create new thread for client update locks");
        free(buf);
        return -1;
    }

    return update_locks_response_handler(*p_client_entry, buf, DLOCK_MAX_CTRL_MSG_SIZE,
        update_locks_tid, next_resp_message_id);
}

int dlock_client::update_locks_response_handler(client_entry_c &p_client_entry, uint8_t *buf, uint32_t buf_len,
    pthread_t update_locks_requester_tid, uint16_t next_resp_message_id)
{
    int ret = 0;
    int recv_locks_num = 0;
    bool last_is_eagain = false;
    struct timeval tv_start;
    struct timeval tv_end;

    uint16_t expected_message_id = next_resp_message_id;
    while ((p_client_entry.m_update_lock_state == 1) || (recv_locks_num < p_client_entry.m_update_lock_num)) {
        ret = recv_update_locks_response(p_client_entry, buf, buf_len, expected_message_id);
        if (ret != static_cast<int>(DLOCK_SUCCESS)) {
            if (ret != static_cast<int>(DLOCK_EAGAIN)) {
                break;
            }

            if (!last_is_eagain) {
                static_cast<void>(gettimeofday(&tv_start, nullptr));
                last_is_eagain = true;
                continue;
            }
            /* To avoid the case that no message is received at client side for quite long time which
             * causes the client to continue waiting and a stuck happens.
             */
            static_cast<void>(gettimeofday(&tv_end, nullptr));
            if (((tv_end.tv_usec - tv_start.tv_usec) + (tv_end.tv_sec - tv_start.tv_sec) * ONE_MILLION) >=
                MAX_CONTINUOUS_EAGAIN) {
                break;
            }
            continue;
        }

        last_is_eagain = false;
        ret = process_update_locks_response(p_client_entry, buf, buf_len);
        if (ret != 0) {
            break;
        }
        recv_locks_num++;
        expected_message_id++;
    }

    p_client_entry.m_update_lock_state = 0;
    free(buf);
    static_cast<void>(pthread_join(update_locks_requester_tid, nullptr));
    lock_map_t::iterator lock_iter = p_client_entry.m_update_map.begin();
    while (lock_iter != p_client_entry.m_update_map.end()) {
        if (lock_iter->second->m_lock_updated) {
            lock_iter->second->m_lock_updated = false;
            lock_iter = p_client_entry.m_update_map.erase(lock_iter);
        } else {
            ++lock_iter;
        }
    }
    p_client_entry.m_update_lock_num = 0;
    return (ret != 0) ? ret
        : static_cast<int>((p_client_entry.m_update_map.empty()) ? DLOCK_SUCCESS : DLOCK_EAGAIN);
}

int dlock_client::recv_update_locks_response(client_entry_c &p_client_entry,
    uint8_t *buf, uint32_t buf_len, uint16_t expected_message_id)
{
    int ret;

    ret = static_cast<int>(p_client_entry.m_p_conn->recv(buf,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, static_cast<int>(MSG_DONTWAIT)));
    if (ret <= 0) {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            return static_cast<int>(DLOCK_EAGAIN);
        }
        DLOCK_LOG_ERR("recv message header error (errno=%d %m)", errno);
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }
    if (ret != static_cast<int>(DLOCK_FIXED_CTRL_MSG_HDR_LEN)) {
        DLOCK_LOG_ERR("recv message header length error, ret: %d", ret);
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    struct dlock_control_hdr *msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buf);

    if (msg_hdr->total_len > DLOCK_FIXED_CTRL_MSG_HDR_LEN) {
        // buf_len == DLOCK_MAX_CTRL_MSG_SIZE
        if (msg_hdr->total_len > buf_len) {
            DLOCK_LOG_ERR("invalid message total_len");
            return static_cast<int>(DLOCK_BAD_RESPONSE);
        }

        size_t recv_len = static_cast<size_t>(msg_hdr->total_len) - DLOCK_FIXED_CTRL_MSG_HDR_LEN;
        ret = static_cast<int>(p_client_entry.m_p_conn->recv(buf + DLOCK_FIXED_CTRL_MSG_HDR_LEN,
            recv_len, static_cast<int>(MSG_WAITALL)));
        if (ret <= 0) {
            DLOCK_LOG_ERR("recv message extend header and body error (errno=%d %m)", errno);
            return static_cast<int>(DLOCK_BAD_RESPONSE);
        }
        if (ret != static_cast<int>(recv_len)) {
            DLOCK_LOG_ERR("recv message extend header and body length error, ret: %d, message total_len: %u",
                ret, msg_hdr->total_len);
            return static_cast<int>(DLOCK_BAD_RESPONSE);
        }
    }

    ret = check_resp_control_msg_hdr(*msg_hdr, BATCH_UPDATE_LOCKS_RESPONSE,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, expected_message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
        return ret;
    }

    return static_cast<int>(DLOCK_SUCCESS);
}

int dlock_client::process_update_locks_response(client_entry_c &p_client_entry,
    uint8_t *buf, uint32_t buf_len)
{
    struct batch_update_lock_body *msg_batch_update_lock_body =
        reinterpret_cast<struct batch_update_lock_body *>(buf + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    struct update_lock_body *p_msg_update = nullptr;
    uint32_t offset = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_BATCH_UPDATE_LOCK_BODY_LEN;

    uint32_t lock_num = msg_batch_update_lock_body->lock_num;
    if (lock_num > MAX_LOCK_BATCH_SIZE) {
        DLOCK_LOG_ERR("invalid message lock_num");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    uint32_t i;
    for (i = 0; i < lock_num; i++) {
        if ((offset + DLOCK_UPDATE_LOCK_BODY_LEN) > buf_len) {
            DLOCK_LOG_ERR("update locks error, the buf access boundary will be exceeded");
            return -1;
        }
        p_msg_update = reinterpret_cast<struct update_lock_body *>(buf + offset);
        if (p_msg_update->lock_id <= 0) {
            DLOCK_LOG_WARN("invalid lock id %d", p_msg_update->lock_id);
            continue;  // invalid lock_id
        }

        offset += static_cast<uint32_t>(DLOCK_UPDATE_LOCK_BODY_LEN) + p_msg_update->desc_len;
        if (offset > buf_len) {
            DLOCK_LOG_ERR("update locks error, the buf access boundary will be exceeded");
            return -1;
        }
        if (update_lock_entry(p_client_entry, p_msg_update) != 0) {
            return -1;
        }
    }
    return 0;
}

int dlock_client::update_lock_entry(client_entry_c &p_client_entry, struct update_lock_body *p_msg_update)
{
    lock_entry_c *p_lock_entry = nullptr;
    lock_map_t::iterator lock_iter = p_client_entry.m_update_map.find(p_msg_update->lock_id);
    if (lock_iter == p_client_entry.m_update_map.end()) {
        lock_iter = p_client_entry.m_update_map.begin();

        dlock_descriptor *desc_temp = new(std::nothrow) dlock_descriptor();
        if (desc_temp == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
            return -1;
        }
        if (desc_temp->descriptor_init(p_msg_update->desc_len, p_msg_update->desc)) {
            DLOCK_LOG_ERR("dlock descriptor init failed");
            delete desc_temp;
            return -1;
        }
       
        while (lock_iter != p_client_entry.m_update_map.end()) {
            if (desc_temp->is_desc_equal(desc_temp, lock_iter->second->m_lock_desc)) {
                break;
            }
            ++lock_iter;
        }
        delete desc_temp;
    }

    if (lock_iter != p_client_entry.m_update_map.end()) {
        p_lock_entry = lock_iter->second;
        p_lock_entry->lock_update(p_msg_update);
        p_client_entry.m_lock_map[p_msg_update->lock_id] = p_lock_entry;
    }
    return 0;
}

int dlock_client::reinit_done(int client_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("clientMgr has not been inited");
        return -1;
    }

    client_entry_c *p_client_entry = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client_entry == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    uint8_t *buff = nullptr;
    struct dlock_control_hdr *msg_hdr = nullptr;
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;

    uint16_t message_id = p_client_entry->m_p_conn->generate_message_id();
    buff = construct_control_msg(CLIENT_REINIT_DONE_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return static_cast<int>(DLOCK_ENOMEM);
    }
    buff = xchg_control_msg(p_client_entry->m_p_conn, buff, msg_len, msg_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }
    msg_hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*msg_hdr, CLIENT_REINIT_DONE_RESPONSE,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
    }

    free(buff);
    return ret;
}

int dlock_client::check_resp_control_msg_hdr_status(int32_t status) const
{
    if (status == static_cast<int32_t>(DLOCK_SUCCESS)) {
        return 0;
    }

    if ((status == -1) ||
        ((status >= static_cast<int32_t>(DLOCK_CLIENT_NOT_INIT)) &&
         (status <= static_cast<int32_t>(DLOCK_SERVER_NO_RESOURCE))) ||
        ((status >= static_cast<int32_t>(DLOCK_EAGAIN)) && (status <= static_cast<int32_t>(DLOCK_EASYNC))) ||
        ((status >= static_cast<int32_t>(DLOCK_OBJECT_ALREADY_EXISTED)) &&
         (status <= static_cast<int32_t>(DLOCK_OBJECT_TOO_MANY)))) {
        DLOCK_LOG_ERR("message status %d error", status);
        return status;
    }

    return static_cast<int>(DLOCK_BAD_RESPONSE);
}

int dlock_client::check_resp_control_msg_hdr(const struct dlock_control_hdr &msg_hdr,
    enum dlock_control_msg type, size_t expected_hdr_len, uint16_t expected_message_id) const
{
    if (msg_hdr.magic_no != DLOCK_CP_MAGIC_NO) {
        DLOCK_LOG_ERR("message magic_no %u error", msg_hdr.magic_no);
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    /*
     * The current DLOCK_PROTO_VERSION is set to 1, no previous version needs to be compatible.
     * If the peer uses a later dlock protocol version, the peer downgrades the protocol
     * version to 1 after version negotiation.
     */
    if (msg_hdr.version != DLOCK_PROTO_VERSION) {
        DLOCK_LOG_ERR("message version %u error, expected version: %u", msg_hdr.version, DLOCK_PROTO_VERSION);
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    /* msg_hdr.total_len has been verified in the previous process. */
    if (msg_hdr.hdr_len != expected_hdr_len) {
        DLOCK_LOG_ERR("message hdr_len %u error, expected hdr_len: %zu", msg_hdr.hdr_len, expected_hdr_len);
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    if (msg_hdr.type != static_cast<uint8_t>(type)) {
        DLOCK_LOG_ERR("message type %u error, expected type: %u", msg_hdr.type, static_cast<uint32_t>(type));
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    if (msg_hdr.message_id != expected_message_id) {
        DLOCK_LOG_ERR("message message_id %u error, expected message_id: %u",
            msg_hdr.message_id, expected_message_id);
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    return check_resp_control_msg_hdr_status(msg_hdr.status);
}

int dlock_client::atomic64_create(int client_id, const struct umo_atomic64_desc *p_desc, uint64_t init_val,
    int *p_obj_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("the clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }
    
    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("atomic64_create, client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    dlock_descriptor *desc = new(std::nothrow) dlock_descriptor();
    if (desc == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
        return static_cast<int>(DLOCK_ENOMEM);
    }
    dlock_status_t dlock_ret = desc->descriptor_init(p_desc->len, reinterpret_cast<unsigned char*>(p_desc->p_desc));
    if (dlock_ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("dlock descriptor init failed");
        delete desc;
        return static_cast<int>(dlock_ret);
    }
    
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_OBJECT_CREATE_BODY_LEN + p_desc->len;
    size_t recv_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_OBJECT_CREATE_BODY_LEN;
    uint16_t message_id = p_client->m_p_conn->generate_message_id();
    auto buff = construct_control_msg(OBJECT_CREATE_REQUEST,  DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, client_id);
    if (buff == nullptr) {
        delete desc;
        DLOCK_LOG_ERR("construct_control_msg error");
        return static_cast<int>(DLOCK_ENOMEM);
    }

    auto body = reinterpret_cast<struct object_create_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    body->obj_id = static_cast<int>(get_hash(p_desc->len, reinterpret_cast<unsigned char *>(p_desc->p_desc)));
    body->lease_time = p_desc->lease_time;
    body->init_value = init_val;
    body->desc_len = p_desc->len;
    /* since buffer allocated for body->desc is p_desc->len in msg_len calculation, destMax equals to p_desc->len */
    static_cast<void>(memcpy(body->desc, p_desc->p_desc, p_desc->len));

    buff = xchg_control_msg(p_client->m_p_conn, buff, msg_len, recv_len);
    if (buff == nullptr) {
        delete desc;
        DLOCK_LOG_ERR("xchg_control_msg error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    auto hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*hdr, OBJECT_CREATE_RESPONSE, DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        delete desc;
        DLOCK_LOG_ERR("response msg error");
        free(buff);
        return ret;
    }

    body = reinterpret_cast<struct object_create_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    {
        std::lock_guard<std::mutex> lg(p_client->m_obj_desc_lock);
        p_client->m_obj_desc_map[desc] = body->obj_id;
    }

    // p_obj_id only modified if create object succeeds
    *p_obj_id = body->obj_id;
    free(buff);
    DLOCK_LOG_DEBUG("object id %d has been created", *p_obj_id);
    return 0;
}

void dlock_client::erase_obj_desc_map_by_id(client_entry_c &p_client_entry, int obj_id)
{
    std::lock_guard<std::mutex> lg(p_client_entry.m_obj_desc_lock);
    for (auto it = p_client_entry.m_obj_desc_map.begin(); it != p_client_entry.m_obj_desc_map.end(); ++it) {
        if (it->second == obj_id) {
            delete it->first;
            p_client_entry.m_obj_desc_map.erase(it);
            return;
        }
    }
}

int dlock_client::atomic64_destroy(int client_id, int obj_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("the clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_OBJECT_DESTROY_BODY_LEN;
    uint16_t message_id = p_client->m_p_conn->generate_message_id();
    auto buff = construct_control_msg(OBJECT_DESTROY_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return static_cast<int>(DLOCK_ENOMEM);
    }

    auto body = reinterpret_cast<struct object_destroy_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    body->obj_id = obj_id;

    buff = xchg_control_msg(p_client->m_p_conn, buff, msg_len, msg_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    auto hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*hdr, OBJECT_DESTROY_RESPONSE, DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error");
        if ((ret != static_cast<int>(DLOCK_NOT_READY)) && (ret != static_cast<int>(DLOCK_BAD_RESPONSE))) {
            erase_obj_desc_map_by_id(*p_client, obj_id);
        }
        free(buff);
        return ret;
    }

    erase_obj_desc_map_by_id(*p_client, obj_id);
    free(buff);
    return 0;
}

bool dlock_client::add_object_entry(unsigned int len, unsigned char *buf, client_entry_c &p_client_entry,
    const struct object_get_body *body)
{
    object_entry_c *p_obj_entry = new(std::nothrow) object_entry_c(body->obj_id, body->offset);
    if (p_obj_entry == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for c++ object!");
        return false;
    }

    p_obj_entry->m_object_desc = new(std::nothrow) dlock_descriptor();
    if (p_obj_entry->m_object_desc == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
        delete p_obj_entry;
        return false;
    }
    dlock_status_t dlock_ret = p_obj_entry->m_object_desc->descriptor_init(len, buf);
    if (dlock_ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("dlock descriptor init failed");
        delete p_obj_entry->m_object_desc;
        delete p_obj_entry;
        return false;
    }

    {
        std::unique_lock<std::shared_mutex> lock(p_client_entry.m_omap_rwlock);
        auto it = p_client_entry.m_object_map.find(body->obj_id);
        if (it != p_client_entry.m_object_map.end()) {
            delete it->second->m_object_desc;
            delete it->second;
        }
        p_client_entry.m_object_map[body->obj_id] = p_obj_entry;
    }

    return true;
}

int dlock_client::check_resp_object_get_body(const struct object_get_body *body) const
{
    if (body->obj_id <= 0) {
        DLOCK_LOG_ERR("response message body obj_id %d error", body->obj_id);
        return -1;
    }

    if (body->offset > (OBJECT_MEMORY_SIZE - sizeof(uint64_t))) {
        DLOCK_LOG_ERR("response message body offset %lu error", body->offset);
        return -1;
    }

    return 0;
}

int dlock_client::atomic64_get(int client_id, const struct umo_atomic64_desc *p_desc, int *p_obj_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("the clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("atomic64_get, client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_OBJECT_GET_BODY_LEN + p_desc->len;
    size_t recv_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_OBJECT_GET_BODY_LEN;
    uint16_t message_id = p_client->m_p_conn->generate_message_id();
    auto buff = construct_control_msg(OBJECT_GET_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return static_cast<int>(DLOCK_ENOMEM);
    }

    auto body = reinterpret_cast<struct object_get_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    body->obj_id = 0;
    body->lease_time = p_desc->lease_time;
    body->desc_len = p_desc->len;
    static_cast<void>(memcpy(body->desc, p_desc->p_desc, p_desc->len));

    buff = xchg_control_msg(p_client->m_p_conn, buff, msg_len, recv_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    auto hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*hdr, OBJECT_GET_RESPONSE, DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error hdr");
        free(buff);
        return ret;
    }

    body = reinterpret_cast<struct object_get_body *>(hdr + 1);
    if (check_resp_object_get_body(body) != 0) {
        DLOCK_LOG_ERR("response msg body error");
        free(buff);
        return DLOCK_BAD_RESPONSE;
    }

    if (!add_object_entry(p_desc->len, reinterpret_cast<unsigned char *>(p_desc->p_desc), *p_client, body)) {
        free(buff);
        return static_cast<int>(DLOCK_ENOMEM);
    }

    *p_obj_id = body->obj_id;
    free(buff);
    DLOCK_LOG_DEBUG("object id %d has been got", *p_obj_id);
    return 0;
}

void dlock_client::release_local_cache(client_entry_c &p_client_entry, int obj_id)
{
    std::unique_lock<std::shared_mutex> lock(p_client_entry.m_omap_rwlock);
    auto it = p_client_entry.m_object_map.find(obj_id);
    if (it == p_client_entry.m_object_map.end()) {
        DLOCK_LOG_DEBUG("object id %d has not been got by client", obj_id);
        return;
    }
    delete it->second->m_object_desc;
    delete it->second;
    p_client_entry.m_object_map.erase(it);
}

int dlock_client::atomic64_release(int client_id, int obj_id)
{
    if (!m_is_inited) {
        DLOCK_LOG_ERR("the clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_ERR("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_OBJECT_RELEASE_BODY_LEN;
    uint16_t message_id = p_client->m_p_conn->generate_message_id();
    auto buff = construct_control_msg(OBJECT_RELEASE_REQUEST, DLOCK_PROTO_VERSION,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, message_id, client_id);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return static_cast<int>(DLOCK_ENOMEM);
    }

    auto body = reinterpret_cast<struct object_release_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    body->obj_id = obj_id;

    buff = xchg_control_msg(p_client->m_p_conn, buff, msg_len, msg_len);
    if (buff == nullptr) {
        DLOCK_LOG_ERR("xchg_control_msg error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }

    auto hdr = reinterpret_cast<struct dlock_control_hdr *>(buff);
    int ret = check_resp_control_msg_hdr(*hdr, OBJECT_RELEASE_RESPONSE, DLOCK_FIXED_CTRL_MSG_HDR_LEN, message_id);
    if (ret != 0) {
        DLOCK_LOG_ERR("response msg error hdr");
        if ((ret != static_cast<int>(DLOCK_NOT_READY)) && (ret != static_cast<int>(DLOCK_BAD_RESPONSE))) {
            release_local_cache(*p_client, obj_id);
        }
        free(buff);
        return ret;
    }

    release_local_cache(*p_client, obj_id);
    free(buff);
    return 0;
}
};
