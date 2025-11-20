/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : dlock_server.cpp
 * Description   : dlock server
 * History       : create file & add functions
 * 1.Date        : 2021-06-15
 * Author        : zhangjun
 * Modification  : Created file
 */

#include <unistd.h>
#include <climits>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <csignal>
#include <vector>
#include <sys/time.h>
#include <fcntl.h>
#include <chrono>

#include "ub_barrier.h"
#include "dlock_log.h"
#include "utils.h"
#include "urma_ctx.h"
#include "lock_memory.h"
#include "dlock_descriptor.h"
#include "dlock_connection.h"
#include "jetty_mgr_uniconn.h"
#include "dlock_server.h"

namespace dlock {
#if defined(MEASURE_ENABLE) && (MEASURE_ENABLE != 0)
#include <sys/time.h>
static const uint32_t MEASURE_INTERVAL = 1048576;
static const uint32_t MILLION = 1000000;
#endif
static const uint32_t MICRO_PER_SEC = 1000000;
static const double MODE_UPDATE_INTERVAL = 0.1;
static const double MODE_SLEEP_TH = 100;
static const uint32_t USLEEP_INTERVAL = 1000;
static const uint32_t RETRY_INTERVAL = 10; // us
static const uint32_t MAX_RETRY_TIME = 100;
static const uint32_t JETTY_MGR_INVALID_QUEUE_WARNING_SIZE = 1024;
static const uint32_t JETTY_MGR_INVALID_TIMEOUT = 10000000; // us
static const int MAX_TRY_ALLOC_CLIENT_ID_TIME = 6;
static const int CLIENT_ID_MASK = 0x7FFFFFFF;
static const int RANDOM_SEED_LEN = 48;

int (dlock_server::*g_control_do[DLOCK_CONTROL_MAX])(dlock_connection *, struct dlock_control_hdr *, uint8_t *) = {
    [REPLICA_INIT_REQUEST] = nullptr,
    [REPLICA_INIT_RESPONSE] = nullptr,
    [REPLICA_CTRL_CATCHUP_REQUEST] = nullptr,
    [REPLICA_CTRL_CATCHUP_RESPONSE] = nullptr,
    [REPLICA_ADD_CLIENTS_REQUEST] = nullptr,
    [REPLICA_ADD_CLIENTS_RESPONSE] = nullptr,
    [REPLICA_ADD_LOCKS_REQUEST] = nullptr,
    [REPLICA_ADD_LOCKS_RESPONSE] = nullptr,
    [REPLICA_ADD_LOCK_CLIENT_RELS_REQUEST] = nullptr,
    [REPLICA_ADD_LOCK_CLIENT_RELS_RESPONSE] = nullptr,
    [REPLICA_DEINIT_REQUEST] = nullptr,
    [REPLICA_DEINIT_RESPONSE] = nullptr,
    [CLIENT_INIT_REQUEST] = &dlock_server::init_client_do,
    [CLIENT_INIT_RESPONSE] = nullptr,
    [CLIENT_DEINIT_REQUEST] = &dlock_server::deinit_client_do,
    [CLIENT_DEINIT_RESPONSE] = nullptr,
    [CLIENT_HEARTBEAT_REQUEST] = &dlock_server::client_heartbeat_do,
    [CLIENT_HEARTBEAT_RESPONSE] = nullptr,
    [GET_LOCK_REQUEST] = &dlock_server::get_lock_do,
    [GET_LOCK_RESPONSE] = nullptr,
    [RELEASE_LOCK_REQUEST] = &dlock_server::release_lock_do,
    [RELEASE_LOCK_RESPONSE] = nullptr,
    [BATCH_GET_LOCK_REQUEST] = &dlock_server::batch_get_lock_do,
    [BATCH_GET_LOCK_RESPONSE] = nullptr,
    [BATCH_RELEASE_LOCK_REQUEST] = &dlock_server::batch_release_lock_do,
    [BATCH_RELEASE_LOCK_RESPONSE] = nullptr,
    [OBJECT_CREATE_REQUEST] = &dlock_server::create_object_do,
    [OBJECT_CREATE_RESPONSE] = nullptr,
    [OBJECT_GET_REQUEST] = &dlock_server::get_object_do,
    [OBJECT_GET_RESPONSE] = nullptr,
    [OBJECT_RELEASE_REQUEST] = &dlock_server::release_object_do,
    [OBJECT_RELEASE_RESPONSE] = nullptr,
    [OBJECT_DESTROY_REQUEST] = &dlock_server::destroy_object_do,
    [OBJECT_DESTROY_RESPONSE] = nullptr,
    [CLIENT_REINIT_REQUEST] = &dlock_server::reinit_client_do,
    [CLIENT_REINIT_RESPONSE] = nullptr,
    [CLIENT_REINIT_DONE_REQUEST] = &dlock_server::reinit_client_done,
    [CLIENT_REINIT_DONE_RESPONSE] = nullptr,
    [BATCH_UPDATE_LOCKS_REQUEST] = &dlock_server::batch_update_locks_do,
    [BATCH_UPDATE_LOCKS_RESPONSE] = nullptr,
};

dlock_server::dlock_server(int server_id) noexcept
    : m_control_tid(0), m_cmd_tid(0), m_is_primary(false), m_p_urma_ctx(nullptr), m_exe_jfc(nullptr),
      m_primary(nullptr), m_next_client_id(1), m_curr_lock_id(1), m_recv_buf_size(DLOCK_MAX_CTRL_MSG_SIZE),
      m_recv_buff(nullptr), m_server_id(server_id), m_stop(false), m_lock_memory(nullptr), m_lock_mem_dma_tseg(nullptr),
      m_recovery_client_num(0), m_listen_fd(-1), m_ssl_enable(false), m_is_cpu_ctrl_affnty_set(false),
      m_is_cpu_cmd_affnty_set(false), m_time_current({0}), m_num_reqs(0), m_sleep_cfg_enable(true),
      m_sleep_mode(false), m_client_num(0), m_tp_mode(SEPERATE_CONN), m_server_state(SERVER_INIT),
      m_control_epfd(-1), m_lock_num(0), m_object_memory(nullptr), m_obj_mem_dma_tseg(nullptr),
      m_curr_object_id(1), m_curr_object_num(0)
{
    DLOCK_LOG_DEBUG("server %d construct", server_id);
    static_cast<void>(gettimeofday(&m_time_previous, nullptr));
    static_cast<void>(memset(&m_stats, 0, sizeof(struct debug_stats)));

    m_lock_mem_tseg_token.token = 0;
    m_obj_mem_tseg_token.token = 0;
}

void dlock_server::unregister_lock_mem_dma_tseg(void)
{
    if (m_lock_mem_dma_tseg == nullptr) {
        return;
    }

    urma_status_t ret = urma_unregister_seg(m_lock_mem_dma_tseg);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to unregister seg, ret: %d", static_cast<int>(ret));
    }
    m_lock_mem_dma_tseg = nullptr;
}

void dlock_server::unregister_obj_mem_dma_tseg(void)
{
    if (m_obj_mem_dma_tseg == nullptr) {
        return;
    }

    urma_status_t ret = urma_unregister_seg(m_obj_mem_dma_tseg);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to unregister seg, ret: %d", static_cast<int>(ret));
    }
    m_obj_mem_dma_tseg = nullptr;
}

void dlock_server::delete_exe_jfc(void)
{
    if (m_exe_jfc == nullptr) {
        return;
    }

    urma_status_t ret = urma_delete_jfc(m_exe_jfc);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to delete jfc, ret: %d", static_cast<int>(ret));
    }
    m_exe_jfc = nullptr;
}

void dlock_server::clear_m_client_map(void)
{
    if (!m_client_map.empty()) {
        auto iter = m_client_map.begin();
        while (iter != m_client_map.end()) {
            delete iter->second;
            static_cast<void>(iter++);
        }
        m_client_map.clear();
    }
}

void dlock_server::clear_m_jetty_mgr_map(void)
{
    std::unique_lock<std::shared_mutex> locker(m_jetty_mgr_map_rwlock);
    m_jetty_mgr_map.clear();
}

void dlock_server::clear_m_lock_map(void)
{
    if (!m_lock_map.empty()) {
        auto iter = m_lock_map.begin();
        while (iter != m_lock_map.end()) {
            delete iter->second;
            static_cast<void>(iter++);
        }
        m_lock_map.clear();
        m_lock_desc_map.clear();
    }
}

void dlock_server::clear_m_object_map(void)
{
    if (m_object_map.size() != 0) {
        auto iter = m_object_map.begin();
        while (iter != m_object_map.end()) {
            m_object_memory->free_object_memory(iter->second->m_offset);
            delete iter->second->m_object_desc;
            delete iter->second;
            (void)iter++;
        }
        m_object_map.clear();
        m_object_desc_map.clear();
    }
}

void dlock_server::clear_m_fd2conn_map(void)
{
    if (!m_fd2conn_map.empty()) {
        auto iter = m_fd2conn_map.begin();
        while (iter != m_fd2conn_map.end()) {
            delete iter->second;
            static_cast<void>(iter++);
        }
        m_fd2conn_map.clear();
    }
}

void dlock_server::clear_m_jetty_mgr_invalid_queue(void)
{
    struct jetty_mgr_invalid_info invalid_info;

    while (!m_jetty_mgr_invalid_queue.empty()) {
        invalid_info = m_jetty_mgr_invalid_queue.front();
        invalid_info.p_jetty_mgr->jetty_mgr_deinit();
        delete invalid_info.p_jetty_mgr;
        m_jetty_mgr_invalid_queue.pop();
    }
}

void dlock_server::delete_sockfd(int sockfd) const
{
    static_cast<void>(epoll_ctl(m_control_epfd, EPOLL_CTL_DEL, sockfd, nullptr));
    static_cast<void>(close(sockfd));
}

void dlock_server::delete_dlock_connection(dlock_connection *p_conn)
{
    static_cast<void>(m_fd2conn_map.erase(p_conn->get_fd()));
    static_cast<void>(epoll_ctl(m_control_epfd, EPOLL_CTL_DEL, p_conn->get_fd(), nullptr));
    delete p_conn;
}

void dlock_server::deinit_server_proc(void)
{
    clear_m_jetty_mgr_invalid_queue();

    if (m_primary != nullptr) {
        delete m_primary;
        m_primary = nullptr;
    }

    unregister_lock_mem_dma_tseg();
    unregister_obj_mem_dma_tseg();
    delete_exe_jfc();

    clear_m_client_map();
    clear_m_jetty_mgr_map();
    clear_m_lock_map();
    clear_m_object_map();
    m_except_client_set.clear();

    if (m_p_urma_ctx != nullptr) {
        delete m_p_urma_ctx;
        m_p_urma_ctx = nullptr;
    }
    if (m_recv_buff != nullptr) {
        free(m_recv_buff);
        m_recv_buff = nullptr;
    }
    if (m_object_memory != nullptr) {
        delete m_object_memory;
        m_object_memory = nullptr;
    }
    if (m_lock_memory != nullptr) {
        delete m_lock_memory;
        m_lock_memory = nullptr;
    }

    if (m_listen_fd > 0) {
        static_cast<void>(close(m_listen_fd));
        m_listen_fd = -1;
    }

    clear_m_fd2conn_map();
}

dlock_server::~dlock_server()
{
    DLOCK_LOG_DEBUG("server deconstruct");
    deinit_server_proc();
}

int dlock_server::init(const struct server_cfg &cfg)
{
    if (m_is_primary) {
        DLOCK_LOG_ERR("server has been inited");
        return -1;
    }

    dlock_set_log_level(cfg.log_level);
    m_sleep_cfg_enable = cfg.sleep_mode_enable;

    int ret = set_ssl_init_attr(cfg.ssl, m_ssl_enable, m_ssl_init_attr);
    if (ret != 0) {
        DLOCK_LOG_ERR("failed to set SSL initialization attributes");
        return -1;
    }

    m_tp_mode = cfg.tp_mode;

    switch (cfg.type) {
        case SERVER_PRIMARY:
            DLOCK_LOG_DEBUG("init as primary");
            return init_as_primary(cfg);
        case SERVER_REPLICA:
        case SERVER_MAX:
        default:
            DLOCK_LOG_ERR("invalid server type");
            return -1;
    }
}

void dlock_server::deinit()
{
    if (!m_is_primary) {
        DLOCK_LOG_ERR("server has not been inited");
        return;
    }

    deinit_server_proc();

    m_is_primary = false;
}

int dlock_server::init_server(bool is_primary, const struct server_cfg &cfg)
{
    struct urma_ctx_cfg urma_cfg = {0};
    int ret = -1;

    if (m_is_primary) {
        DLOCK_LOG_ERR("server has been inited");
        return -1;
    }
    m_object_memory = new(std::nothrow) object_memory(OBJECT_MAX_NUMBER, is_primary, this);
    if (m_object_memory == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for object_memory!");
        return static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
    }
    if (!m_object_memory->init()) {
        DLOCK_LOG_ERR("failed to init object memory");
        ret = static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        goto DEL_OBJ_MEMORY;
    }

    m_lock_memory = new(std::nothrow) lock_memory(LOCK_MEMORY_SIZE, is_primary, this);
    if (m_lock_memory == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for lock_memory");
        ret = static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        goto DEL_OBJ_MEMORY;
    }
    if (m_lock_memory->m_p_lock_memory == nullptr) {
        DLOCK_LOG_ERR("failed to init lock memory");
        ret = static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        goto DEL_LOCK_MEMORY;
    }

    urma_cfg.num_buf = SERVER_URMA_CTX_REG_BUF_NUM;
    urma_cfg.num_cqe = MAX_NUM_CLIENT * CQ_SIZE_PER_CLIENT;
    urma_cfg.dev_name = cfg.dev_name;
    urma_cfg.eid = cfg.eid;
    urma_cfg.tp_mode = cfg.tp_mode;
    urma_cfg.ub_token_disable = cfg.ub_token_disable;

    m_p_urma_ctx = new(std::nothrow) urma_ctx(urma_cfg);
    if (m_p_urma_ctx == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for urma_ctx");
        ret = static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        goto DEL_LOCK_MEMORY;
    }
    if ((m_p_urma_ctx->m_urma_ctx == nullptr) || m_p_urma_ctx->m_local_tseg == nullptr) {
        DLOCK_LOG_ERR("failed to init urma context");
        goto DEL_URMA_CTX;
    }
    m_recv_buff = (uint8_t*)calloc(1, m_recv_buf_size);
    if (m_recv_buff == nullptr) {
        DLOCK_LOG_ERR("failed to allocate recv buffer");
        ret = static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        goto DEL_URMA_CTX;
    }
    m_exe_jfc = m_p_urma_ctx->new_jfc(static_cast<int>(MAX_NUM_REPLICA * (EXE_SQ_SIZE + EXE_RQ_SIZE)));
    if (m_exe_jfc == nullptr) {
        DLOCK_LOG_ERR("failed to create exe jfc");
        goto FREE_BUFF;
    }
    m_lock_mem_dma_tseg = m_p_urma_ctx->register_new_seg(m_lock_memory->m_p_lock_memory,
        LOCK_MEMORY_SIZE, m_lock_mem_tseg_token);
    if (m_lock_mem_dma_tseg == nullptr) {
        DLOCK_LOG_ERR("error to register new seg");
        goto DEL_JFC;
    }
    m_obj_mem_dma_tseg = m_p_urma_ctx->register_new_seg(reinterpret_cast<uint8_t *>(m_object_memory->m_addr),
        OBJECT_MEMORY_SIZE, m_obj_mem_tseg_token);
    if (m_obj_mem_dma_tseg == nullptr) {
        DLOCK_LOG_ERR("error to register new seg");
        goto UNREG_LOCK_MEM_DMA_TSEG;
    }
    return 0;

UNREG_LOCK_MEM_DMA_TSEG:
    unregister_lock_mem_dma_tseg();
    m_lock_mem_dma_tseg = nullptr;
DEL_JFC:
    delete_exe_jfc();
FREE_BUFF:
    free(m_recv_buff);
    m_recv_buff = nullptr;
DEL_URMA_CTX:
    delete m_p_urma_ctx;
    m_p_urma_ctx = nullptr;
DEL_LOCK_MEMORY:
    delete m_lock_memory;
    m_lock_memory = nullptr;
DEL_OBJ_MEMORY:
    delete m_object_memory;
    m_object_memory = nullptr;
    return ret;
}

int dlock_server::primary_get_addr_and_ports(const struct server_cfg &cfg,
    struct in_addr &ip_addr, uint16_t &server_port) const
{
    if (convert_ip_addr(cfg.primary.server_ip_str, &ip_addr) < 0) {
        DLOCK_LOG_ERR("invalid server ip addr in primary cfg");
        return -1;
    }

    server_port = (cfg.primary.server_port > 0) ?
        static_cast<uint16_t>(cfg.primary.server_port) : static_cast<uint16_t>(CONTROL_PORT_CLIENT);
    return 0;
}

int dlock_server::create_listen_fd(const struct in_addr &ip_addr, uint16_t port, int &listen_fd)
{
    int sock_fd;
    int ret;
    int32_t enabled = 1;
    struct sockaddr_in servaddr;

    sock_fd = socket(AF_INET, static_cast<int>(SOCK_STREAM), 0);
    if (sock_fd < 0) {
        DLOCK_LOG_ERR("create socket error (errno=%d %m)", errno);
        return -1;
    }
    ret = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    if (ret < 0) {
        DLOCK_LOG_ERR("setsockopt error (errno=%d %m)", errno);
        static_cast<void>(close(sock_fd));
        return -1;
    }
    static_cast<void>(memset(&servaddr, 0, sizeof(servaddr)));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr = ip_addr;
    servaddr.sin_port = htons(port);
    ret = bind(sock_fd, reinterpret_cast<struct sockaddr *>(&servaddr), sizeof(servaddr));
    if (ret < 0) {
        DLOCK_LOG_ERR("bind error (errno=%d %m)", errno);
        static_cast<void>(close(sock_fd));
        return -1;
    }
    ret = listen(sock_fd, LISTEN_QUEUE);
    if (ret < 0) {
        DLOCK_LOG_ERR("listen error (errno=%d %m)", errno);
        static_cast<void>(close(sock_fd));
        return -1;
    }

    listen_fd = sock_fd;
    return 0;
}

void dlock_server::init_primary_server_state(void)
{
    if (m_recovery_client_num != 0u) {
        m_server_state = SERVER_WAIT_CLIENT_REINIT;
        DLOCK_LOG_DEBUG("server wait clients reinit! server_id: %d", m_server_id);
        return;
    }
    m_server_state = SERVER_READY;
    DLOCK_LOG_DEBUG("server ready! server_id: %d", m_server_id);
}

dlock_status_t dlock_server::read_entropy_pool(int fd, uint8_t *seed, int seed_len) const
{
    ssize_t read_bytes;
    while (seed_len > 0) {
        read_bytes = read(fd, seed, static_cast<size_t>(seed_len));
        if ((read_bytes > 0) && (read_bytes <= seed_len)) {
            seed_len -= read_bytes;
            seed += read_bytes;
        } else if ((read_bytes != EINTR) || ((read_bytes == 0) && (seed_len != 0))) {
            return DLOCK_FAIL;
        }
    }
    return DLOCK_SUCCESS;
}

dlock_status_t dlock_server::set_random_seed() const
{
    uint8_t seed[RANDOM_SEED_LEN];
    dlock_status_t status;
    int seed_len = RANDOM_SEED_LEN;

    int fd = open("/dev/random", O_RDONLY);
    if (fd < 0) {
        DLOCK_LOG_ERR("open /dev/random error, (errno=%d %m)", errno);
        return DLOCK_FAIL;
    }
    status = read_entropy_pool(fd, seed, seed_len);
    static_cast<void>(close(fd));
    if (status != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("read seed from entropy pool failed");
        return DLOCK_FAIL;
    }
    RAND_seed(seed, seed_len);
    if (RAND_status() != 1) {
        DLOCK_LOG_ERR("not get long enough seed");
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}

int dlock_server::init_as_primary(const struct server_cfg &cfg)
{
    int ret;
    struct in_addr ip_addr;
    uint16_t server_port;

    /* set random seed for ssl key_gen case and client_id randomly produced case */
    if (set_random_seed() != DLOCK_SUCCESS) {
        return -1;
    }

    ret = primary_set_affinity(cfg.primary.ctrl_cpuset, CTRL_THREAD);
    if (ret < 0) {
        DLOCK_LOG_ERR("set ctrl thread cpu affinity fail");
        return -1;
    }

    ret = primary_set_affinity(cfg.primary.cmd_cpuset, CMD_THREAD);
    if (ret < 0) {
        DLOCK_LOG_ERR("set ctrl thread cmd affinity fail");
        return -1;
    }

    ret = init_server(true, cfg);
    if (ret != 0) {
        DLOCK_LOG_ERR("failed to init server");
        return ret;
    }

    ret = primary_get_addr_and_ports(cfg, ip_addr, server_port);
    if (ret < 0) {
        DLOCK_LOG_ERR("failed to get primary addr and ports");
        return -1;
    }

    ret = create_listen_fd(ip_addr, server_port, m_listen_fd);
    if (ret < 0) {
        DLOCK_LOG_ERR("failed to init primary bind sock");
        return -1;
    }

    m_recovery_client_num = cfg.primary.recovery_client_num;
    m_is_primary = true;

#if defined(MEASURE_ENABLE) && (MEASURE_ENABLE != 0)
    m_measure_count = 0;
#endif

    init_primary_server_state();
    return 0;
}

void dlock_server::get_process_control_msg_range(uint8_t &min_type, uint8_t &max_type) const
{
    if (m_server_state == SERVER_WAIT_CLIENT_REINIT) {
        min_type = static_cast<uint8_t>(CLIENT_REINIT_REQUEST);
        max_type = static_cast<uint8_t>(BATCH_UPDATE_LOCKS_RESPONSE);
        return;
    }

    /* m_server_state == SERVER_READY */
    min_type = static_cast<uint8_t>(CLIENT_INIT_REQUEST);
    max_type = static_cast<uint8_t>(CLIENT_REINIT_DONE_RESPONSE);
}

void dlock_server::mark_client_exception(int32_t client_id, dlock_connection *p_conn)
{
    client_map_t::iterator iter = m_client_map.find(client_id);
    if (iter != m_client_map.end()) {
        iter->second->set_m_p_conn(nullptr);
        static_cast<void>(m_except_client_set.insert(client_id));
    }

    delete_dlock_connection(p_conn);
}

void dlock_server::clear_lock_client_relation(int client_id, client_entry_s *client_entry)
{
    lock_entry_s *lock_entry = nullptr;
    int32_t lock_id;

    auto lock_iter = client_entry->m_lock_map.begin();
    while (lock_iter != client_entry->m_lock_map.end()) {
        lock_entry = lock_iter->second;
        static_cast<void>(lock_entry->m_lease_time_map.erase(client_id));
        if (lock_entry->m_lease_time_map.empty()) {
            lock_id = lock_entry->m_lock_id;
            static_cast<void>(m_lock_desc_map.erase(lock_entry->m_lock_dec));
            delete lock_entry->m_lock_dec;
            lock_entry->m_lock_dec = nullptr;
            delete lock_entry;
            // m_lock_map in dlock_server exists dependently from m_lock_map in client_entry_s.
            // The former consists of all locks in server, while the later only consists locks related to it
            static_cast<void>(m_lock_map.erase(lock_id));
            static_cast<void>(client_entry->m_lock_map.erase(lock_iter++));
            if (m_lock_num <= 0) {
                DLOCK_LOG_ERR("improper state lock num counter");
                continue;
            }
            m_lock_num--;
            continue;
        }
        static_cast<void>(lock_iter++);
    }
}

void dlock_server::clear_object_client_relation(int client_id, client_entry_s *client_entry)
{
    object_entry_s *object_entry = nullptr;
    int32_t obj_id;

    auto object_iter = client_entry->m_object_map.begin();
    while (object_iter != client_entry->m_object_map.end()) {
        object_entry = object_iter->second;
        obj_id = object_entry->m_id;
        // reduce reference count and remove client from this object's lease time map
        object_entry->m_refcnt--;
        static_cast<void>(object_entry->m_lease_tp_map.erase(client_id));

        // object was not created by this client, but has been got by him
        if (object_entry->m_owner_id != client_entry->m_client_id) {
            client_entry->m_object_map.erase(object_iter++);
            if (object_entry->m_destroyed && (object_entry->m_refcnt == 0 || object_entry->check_lease_expired())) {
                DLOCK_LOG_DEBUG("clear_object_client_relation: destroying object id:%d", obj_id);
                destroy_object_entry(object_entry);
            }
            continue;
        }
        // object was created and got by this client, and the reference count != 0 and lease time doesn't expire
        if ((object_entry->m_refcnt != 0) && (!object_entry->check_lease_expired())) {
            object_entry->m_owner_id = 0;
            client_entry->m_object_map.erase(object_iter++);
            continue;
        }
        // object was created and got by this client, but the reference count = 0 or lease time expires
        // destroy the object
        static_cast<void>(client_entry->m_object_map.erase(object_iter++));
        DLOCK_LOG_DEBUG("clear_object_client_relation: destroying object id:%d", obj_id);
        destroy_object_entry(object_entry);
    }
}

int dlock_server::delete_except_client_entry()
{
    int client_id;

    // No client entry to release
    if (m_except_client_set.empty()) {
        return static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
    }

    exception_client_set_t::iterator except_iter = m_except_client_set.begin();
    while (except_iter != m_except_client_set.end()) {
        client_id = *except_iter;
        // delete client_entry_s and locks related to this client which aren't ocuppied by other clients
        client_map_t::iterator client_iter = m_client_map.find(client_id);
        if (client_iter != m_client_map.end()) {
            // failed to modify jetty mgr state to invalid;
            if (modify_jetty_mgr_to_invalid(client_iter->second->m_p_jetty_mgr)) {
                DLOCK_LOG_DEBUG("failed to invalidate jetty_mgr owned by the client, the client entry"
                    "cannot be deleted at this time");
                static_cast<void>(++except_iter);
                continue;
            }
            client_iter->second->m_p_jetty_mgr = nullptr;
            if (!client_iter->second->m_lock_map.empty()) {
                clear_lock_client_relation(client_id, client_iter->second);
            }
            if (!client_iter->second->m_object_map.empty()) {
                clear_object_client_relation(client_id, client_iter->second);
            }
            delete client_iter->second;
            static_cast<void>(m_client_map.erase(client_iter));
            m_client_num--;
            static_cast<void>(m_except_client_set.erase(except_iter));
            DLOCK_LOG_INFO("client marked exception deleted");
            return 0;
        } else {
            DLOCK_LOG_ERR("client marked exception does not exist in client_map");
            return -1;
        }
    }

    return -1;
}

void dlock_server::conn_exception_process(dlock_connection *p_conn)
{
    dlock_conn_peer_info_t peer_info;

    p_conn->get_peer_info(peer_info);
    switch (peer_info.peer_type) {
        case DLOCK_CONN_PEER_CLIENT:
            m_stats.stats[DEBUG_STATS_CLIENT_DISCONNECT]++;
            DLOCK_LOG_WARN("dlock connection closed by client");
            mark_client_exception(peer_info.peer_id, p_conn);
            return;
        case DLOCK_CONN_PEER_REPLICA_SERVER:
            DLOCK_LOG_WARN("invalid peer type, replica server is not supported");
            break;
        case DLOCK_CONN_PEER_PRIMARY_SERVER:
            DLOCK_LOG_WARN("dlock connection closed by primary server");
            m_primary->m_p_conn = nullptr;
            break;
        case DLOCK_CONN_PEER_DEFAULT:
        default:
            break;
    }

    delete_dlock_connection(p_conn);
}

int dlock_server::recv_msg_hdr(dlock_connection *p_conn, struct dlock_control_hdr *msg_hdr)
{
    long ret;
    int retry_cnt = 5; // 5:retry cnt

    do {
        ret = p_conn->recv(msg_hdr, DLOCK_FIXED_CTRL_MSG_HDR_LEN, static_cast<int>(MSG_WAITALL));
        retry_cnt--;
    } while (ret < 0 && errno == EINTR && retry_cnt > 0);
    if (ret < 0) {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            return -1;
        }
        DLOCK_LOG_ERR("recv message header error (errno=%d %m)", errno);
        return -1;
    } else if (ret == 0) {
        conn_exception_process(p_conn);
        return -1;
    }
    if (ret != static_cast<int>(DLOCK_FIXED_CTRL_MSG_HDR_LEN)) {
        DLOCK_LOG_ERR("recv message header length error, ret: %ld", ret);
        return -1;
    }
    DLOCK_LOG_DEBUG("recv %ld", ret);
    return 0;
}

int dlock_server::recv_msg_ext_hdr_and_body(dlock_connection *p_conn,
    uint8_t ext_hdr_len, uint16_t body_len, uint8_t **msg_ext_hdr, uint8_t **msg_body)
{
    long ret;
    uint16_t expected_recv_len = ext_hdr_len + body_len;

    uint8_t *buf = (uint8_t *)malloc(expected_recv_len);
    if (buf == nullptr) {
        DLOCK_LOG_ERR("malloc error (errno=%d %m)", errno);
        return -1;
    }
    ret = p_conn->recv(buf, expected_recv_len, static_cast<int>(MSG_WAITALL));
    if (ret < 0) {
        DLOCK_LOG_ERR("recv message extend header and body error (errno=%d %m)", errno);
        free(buf);
        return -1;
    }
    if (ret != expected_recv_len) {
        DLOCK_LOG_ERR("recv message extend header and body length error, ret: %ld", ret);
        free(buf);
        return -1;
    }

    *msg_ext_hdr = (ext_hdr_len == 0) ? nullptr : buf;
    *msg_body = buf + ext_hdr_len;
    return 0;
}

int dlock_server::check_control_msg_client_id(const struct dlock_control_hdr msg_hdr,
    dlock_connection *p_conn) const
{
    dlock_conn_peer_info_t peer_info;

    p_conn->get_peer_info(peer_info);
    // for client_reinit in recovery case, no peer_info set now
    if (peer_info.peer_type == DLOCK_CONN_PEER_DEFAULT) {
        return 0;
    }
    if (msg_hdr.client_id != peer_info.peer_id) {
        DLOCK_LOG_ERR("fake client attack, occupy the connection of a client");
        return -1;
    }

    return 0;
}

void dlock_server::fake_client_msg_process(dlock_connection *p_conn)
{
    dlock_conn_peer_info_t peer_info;

    flush_recv_buffer(p_conn);

    p_conn->get_peer_info(peer_info);
    mark_client_exception(peer_info.peer_id, p_conn);
}

int dlock_server::check_msg_type_range(const struct dlock_control_hdr msg_hdr, const uint8_t min_type,
    const uint8_t max_type, int32_t *ret_status) const
{
    if ((msg_hdr.type < min_type) || (msg_hdr.type > max_type)) {
        if (m_server_state != SERVER_READY) {
            DLOCK_LOG_ERR("primary server is not ready, server_state: %u, recovery_client_num: %u",
                static_cast<uint32_t>(m_server_state), m_recovery_client_num);
            *ret_status = static_cast<int32_t>(DLOCK_NOT_READY);
            return -1;
        }
        DLOCK_LOG_ERR("message type error, type: %d, min_type: %d, max_type: %d", msg_hdr.type, min_type, max_type);
        *ret_status = -1;
        return -1;
    }
    return 0;
}

int dlock_server::check_control_msg_hdr(const struct dlock_control_hdr &msg_hdr) const
{
    if (msg_hdr.magic_no != DLOCK_CP_MAGIC_NO) {
        DLOCK_LOG_ERR("message magic_no %u error", msg_hdr.magic_no);
        return -1;
    }

    if ((msg_hdr.type == static_cast<uint8_t>(CLIENT_INIT_REQUEST)) ||
        (msg_hdr.type == static_cast<uint8_t>(CLIENT_REINIT_REQUEST))) {
        if (msg_hdr.version < DLOCK_MIN_PROTO_VERSION) {
            DLOCK_LOG_ERR("message version %u error, the minimum supported dlock protocol version is %u",
                msg_hdr.version, DLOCK_MIN_PROTO_VERSION);
            return -1;
        }

        if (msg_hdr.hdr_len < DLOCK_FIXED_CTRL_MSG_HDR_LEN) {
            DLOCK_LOG_ERR("message hdr_len %u error, less than the fixed message header length",
                msg_hdr.hdr_len);
            return -1;
        }
    } else {
        if (msg_hdr.version != DLOCK_PROTO_VERSION) {
            DLOCK_LOG_ERR("message version %u error, expected version: %u",
                msg_hdr.version, DLOCK_PROTO_VERSION);
            return -1;
        }

        if (msg_hdr.hdr_len != DLOCK_FIXED_CTRL_MSG_HDR_LEN) {
            DLOCK_LOG_ERR("message hdr_len %u error, expected hdr_len: %u",
                msg_hdr.hdr_len, DLOCK_FIXED_CTRL_MSG_HDR_LEN);
            return -1;
        }
    }

    if ((msg_hdr.total_len < msg_hdr.hdr_len) || (msg_hdr.total_len > DLOCK_MAX_CTRL_MSG_SIZE)) {
        DLOCK_LOG_ERR("message total_len %u error", msg_hdr.total_len);
        return -1;
    }

    return 0;
}

void dlock_server::free_msg_ext_hdr_and_body_recv_buf(uint8_t *msg_ext_hdr, uint8_t *msg_body) const
{
    if (msg_ext_hdr != nullptr) {
        free(msg_ext_hdr);
        return;
    }

    if (msg_body != nullptr) {
        free(msg_body);
    }
}

int dlock_server::process_control_msg(dlock_connection *p_conn, uint8_t min_type, uint8_t max_type)
{
    struct dlock_control_hdr msg_hdr = {0};
    uint8_t *msg_ext_hdr = nullptr;
    uint8_t *msg_body = nullptr;
    long ret;
    int32_t ret_status = -1;

    ret = recv_msg_hdr(p_conn, &msg_hdr);
    if (ret == -1) {
        return -1;
    }

    if (check_control_msg_hdr(msg_hdr) != 0) {
        flush_recv_buffer(p_conn);
        return -1;
    }

    if (check_msg_type_range(msg_hdr, min_type, max_type, &ret_status) < 0) {
        goto err;
    }

    if (check_control_msg_client_id(msg_hdr, p_conn) < 0) {
        goto err_fake_client;
    }

    if (msg_hdr.total_len > DLOCK_FIXED_CTRL_MSG_HDR_LEN) {
        ret = recv_msg_ext_hdr_and_body(p_conn, static_cast<uint8_t>(msg_hdr.hdr_len - DLOCK_FIXED_CTRL_MSG_HDR_LEN),
            static_cast<uint16_t>(msg_hdr.total_len - msg_hdr.hdr_len), &msg_ext_hdr, &msg_body);
        if (ret != 0) {
            goto err;
        }
    }

    if (g_control_do[msg_hdr.type] == nullptr) {
        DLOCK_LOG_ERR("unsupported type of control message, %d", msg_hdr.type);
        ret_status = -1;
        goto err;
    }

    p_conn->set_next_message_id(msg_hdr.message_id);
    ret_status = (this->*g_control_do[msg_hdr.type])(p_conn, &msg_hdr, msg_body);
    if (ret_status != 0) {
        goto err;
    }

    free_msg_ext_hdr_and_body_recv_buf(msg_ext_hdr, msg_body);
    return 0;
err_fake_client:
    fake_client_msg_process(p_conn);
    free_msg_ext_hdr_and_body_recv_buf(msg_ext_hdr, msg_body);
    return -1;
err:
    process_control_msg_err(msg_hdr, p_conn, ret_status);
    free_msg_ext_hdr_and_body_recv_buf(msg_ext_hdr, msg_body);
    return -1;
}

void dlock_server::process_control_msg_err(struct dlock_control_hdr &msg_hdr,
    dlock_connection *p_conn, int32_t ret_status)
{
    flush_recv_buffer(p_conn);

    if (msg_hdr.type % 2u == 1u) {    // For received response message, no error response need to send.
        return;
    }

    msg_hdr.hdr_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
    msg_hdr.total_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
    msg_hdr.type++;
    msg_hdr.status = ret_status;

    static_cast<void>(p_conn->send(&msg_hdr, DLOCK_FIXED_CTRL_MSG_HDR_LEN, 0));
    if (m_is_primary &&
        ((msg_hdr.type == static_cast<uint8_t>(CLIENT_INIT_REQUEST)) ||
        (msg_hdr.type == static_cast<uint8_t>(CLIENT_DEINIT_REQUEST)) ||
        (msg_hdr.type == static_cast<uint8_t>(REPLICA_INIT_REQUEST)) ||
        (msg_hdr.type == static_cast<uint8_t>(REPLICA_DEINIT_REQUEST)))) {
        delete_dlock_connection(p_conn);
        p_conn = nullptr;
    }
}

int dlock_server::primary_control_func(int control_epfd, int ev_fd)
{
    int ret;

    if (ev_fd != m_listen_fd) {
        DLOCK_LOG_DEBUG("process control msg");
        uint8_t min_type;
        uint8_t max_type;
        connection_map_t::iterator conn_iter = m_fd2conn_map.find(ev_fd);
        if (conn_iter == m_fd2conn_map.end()) {
            DLOCK_LOG_ERR("Failed to find dlock_connection corresponding to the sockfd %d", ev_fd);
            return -1;
        }
        get_process_control_msg_range(min_type, max_type);
        static_cast<void>(process_control_msg(conn_iter->second, min_type, max_type));
        return 0;
    }

    struct sockaddr_in client_addr;
    socklen_t cliaddr_len = sizeof(client_addr);
    int new_sock = accept(ev_fd, reinterpret_cast<struct sockaddr *>(&client_addr), &cliaddr_len);
    if (new_sock < 0) {
        DLOCK_LOG_ERR("accept error (errno=%d %m)", errno);
        return -1;
    }

    connection_map_t::iterator conn_iter = m_fd2conn_map.find(new_sock);
    if (conn_iter != m_fd2conn_map.end()) {
        DLOCK_LOG_ERR("The dlock_connection corresponding to the sockfd %d already exists.", new_sock);
        (void)close(new_sock);
        return -1;
    }

    epoll_event new_ev = {0, {.ptr = nullptr}};
    new_ev.events = static_cast<uint32_t>(EPOLLIN);
    new_ev.data.fd = new_sock;
    ret = epoll_ctl(control_epfd, EPOLL_CTL_ADD, new_ev.data.fd, &new_ev);
    if (ret < 0) {
        DLOCK_LOG_ERR("epoll_ctl add error (errno=%d %m)", errno);
        static_cast<void>(close(new_sock));
        return -1;
    }

    int flag = 1;
    static_cast<void>(setsockopt(new_sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&flag), sizeof(int)));
    static_cast<void>(set_send_recv_timeout(new_sock, static_cast<int>(PRIMARY_SERVER_CONTROL_SOCKET_TIMEOUT)));
    static_cast<void>(set_primary_keepalive(new_sock));
    DLOCK_LOG_DEBUG("accept success");

    dlock_connection *p_conn = create_connection(new_sock, m_is_primary, m_ssl_enable, m_ssl_init_attr);
    if (p_conn == nullptr) {
        DLOCK_LOG_ERR("failed to init dlock connection");
        delete_sockfd(new_sock);
        return -1;
    }
    m_fd2conn_map[new_sock] = p_conn;
    return 0;
}

int dlock_server::primary_control_loop()
{
    int control_epfd = epoll_create(MAX_NUM_CLIENT);
    if (control_epfd == -1) {
        DLOCK_LOG_ERR("epoll_create error (errno=%d %m)", errno);
        return -1;
    }

    epoll_event *control_events =
        reinterpret_cast<struct epoll_event *>(calloc(MAX_NUM_CLIENT + MAX_NUM_REPLICA, sizeof(struct epoll_event)));
    if (control_events == nullptr) {
        DLOCK_LOG_ERR("calloc error (errno=%d %m)", errno);
        static_cast<void>(close(control_epfd));
        return -1;
    }

    epoll_event control_ev = {0, {.ptr = nullptr}};
    int ret;
    control_ev.events = static_cast<uint32_t>(EPOLLIN);
    control_ev.data.fd = m_listen_fd;
    ret = epoll_ctl(control_epfd, EPOLL_CTL_ADD, control_ev.data.fd, &control_ev);
    if (ret < 0) {
        DLOCK_LOG_ERR("epoll_ctl add error (errno=%d %m)", errno);
        goto err;
    }
    m_control_epfd = control_epfd;

    while (!m_stop) {
        ret = epoll_wait(control_epfd, control_events, MAX_NUM_CLIENT + MAX_NUM_REPLICA, EPOLL_TIMEOUT);
        if ((ret < 0) || (ret > static_cast<int>(MAX_NUM_CLIENT + MAX_NUM_REPLICA))) {
            DLOCK_LOG_ERR("epoll_wait error (errno=%d %m)", errno);
            goto err;
        }
        if (ret == 0) {
            DLOCK_LOG_DEBUG("epoll_wait timeout");
            continue;
        }
        for (int event_idx = 0; event_idx < ret; event_idx++) {
            static_cast<void>(primary_control_func(control_epfd, control_events[event_idx].data.fd));
        }
    }

    free(control_events);
    static_cast<void>(close(control_epfd));
    return 0;
err:
    free(control_events);
    static_cast<void>(close(control_epfd));
    return -1;
}

void dlock_server::preprocess_lock_cmd_msg(struct lock_cmd_msg *msg, uint32_t cmd_num)
{
    struct timeval tv_cur;

    static_cast<void>(gettimeofday(&tv_cur, nullptr));
    for (int i = 0; i < static_cast<int>(cmd_num); i++) {
        if ((msg[i].op_code != static_cast<uint8_t>(EXCLUSIVE_LOCK_EXTEND)) &&
            (msg[i].op_code != static_cast<uint8_t>(SHARED_LOCK_EXTEND))) {
            continue;
        }

        switch (msg[i].lock_type) {
            case DLOCK_ATOMIC:
                msg[i].ls.atomic.time_out +=
                    (msg[i].ls.atomic.time_out == 0u) ? 0 : static_cast<uint32_t>(tv_cur.tv_sec);
                break;

            case DLOCK_FAIR:
                msg[i].ls.fl.time_out += (msg[i].ls.fl.time_out == 0u) ? 0 : static_cast<uint32_t>(tv_cur.tv_sec);
                break;

            default:
                m_stats.stats[DEBUG_STATS_EINVAL_LOCK_TYPE]++;
                DLOCK_LOG_DEBUG("lock type %x, extend not supported", msg[i].lock_type);
                return;
        }
    }
}

void dlock_server::modify_response_with_fairlock_ticket(struct lock_cmd_msg *msg, uint32_t cmd_num,
    uint32_t ticket_obtain_time) const
{
    /* If replica is not enabled, the server needs to synchronize the lock state of the clients
     * to rectify the fault. In this scenario, the lock state needs to be determined based on
     * the time_out value. Therefore, for a fair lock, when the client holds a ticket in the queue
     * state, the returned timeout in lock_state is the current time when the ticket is obtained. */
    for (uint32_t i = 0; i < cmd_num; i++) {
        if (msg[i].op_ret == static_cast<uint16_t>(DLOCK_EAGAIN)) {
            if (msg[i].op_code == static_cast<uint8_t>(SHARED_TRYLOCK)) {
                --msg[i].ls.fl.m_shared;    /* ticket */
                msg[i].ls.fl.time_out = ticket_obtain_time;
                continue;
            }

            if (msg[i].op_code == static_cast<uint8_t>(EXCLUSIVE_TRYLOCK)) {
                --msg[i].ls.fl.m_exclusive;    /* ticket */
                msg[i].ls.fl.time_out = ticket_obtain_time;
            }
        }
    }
}

void dlock_server::modify_response_with_fairlock_ticket(struct lock_cmd_msg *msg, uint32_t cmd_num) const
{
    struct timeval tv_cur;

    static_cast<void>(gettimeofday(&tv_cur, nullptr));
    modify_response_with_fairlock_ticket(msg, cmd_num, static_cast<uint32_t>(tv_cur.tv_sec));
}

int dlock_server::check_cmd_msg_common_field(const struct lock_cmd_msg &msg) const
{
    if (msg.magic_no != DLOCK_DP_MAGIC_NO) {
        DLOCK_LOG_DEBUG("message magic_no %u error", msg.magic_no);
        return -1;
    }

    if (msg.version != DLOCK_PROTO_VERSION) {
        DLOCK_LOG_DEBUG("message version %u error", msg.version);
        return -1;
    }

    return 0;
}

int dlock_server::do_lock(struct urma_buf *p_rx_buf, uint32_t msg_len)
{
    dlock_status_t ret;
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    struct lock_cmd_msg *msg = reinterpret_cast<struct lock_cmd_msg *>(p_rx_buf->buf + rx_data_offset);
    uint32_t cmd_num = (msg_len - rx_data_offset) / sizeof(struct lock_cmd_msg);
    int i;
    dlock_status_t cipher_ret;

    p_rx_buf->p_jetty_mgr->m_dlock_cipher->m_data_offset = AES_IV_LEN;
    cipher_ret = p_rx_buf->p_jetty_mgr->cmd_msg_cipher(static_cast<int>(DECRYPTION),
        p_rx_buf->buf, msg_len, m_ssl_enable);
    if (cipher_ret != DLOCK_SUCCESS) {
        m_stats.stats[DEBUG_STATS_DECRYPT_FAIL]++;
        DLOCK_LOG_DEBUG("rx data decryption failed");
        p_rx_buf->p_jetty_mgr->recycle_rx_buf(p_rx_buf);
        return -1;
    }

    if (check_cmd_msg_common_field(*msg) != 0) {
        m_stats.stats[DEBUG_STATS_BAD_REQUEST]++;
        DLOCK_LOG_DEBUG("failed to verify cmd msg");
        p_rx_buf->p_jetty_mgr->recycle_rx_buf(p_rx_buf);
        return -1;
    }
    p_rx_buf->p_jetty_mgr->set_next_message_id(msg->message_id);
    preprocess_lock_cmd_msg(msg, cmd_num);

    for (i = 0; i < static_cast<int>(cmd_num); i++) {
        static_cast<void>(m_lock_memory->do_lock_cmd(p_rx_buf->p_jetty_mgr->m_peer_info.peer_id, &msg[i], msg[i].ls));
    }

    modify_response_with_fairlock_ticket(msg, cmd_num);

    cipher_ret = p_rx_buf->p_jetty_mgr->cmd_msg_cipher(static_cast<int>(ENCRYPTION),
        p_rx_buf->buf, msg_len, m_ssl_enable);
    if (cipher_ret != DLOCK_SUCCESS) {
        m_stats.stats[DEBUG_STATS_ENCRYPT_FAIL]++;
        DLOCK_LOG_DEBUG("tx data encryption failed");
        p_rx_buf->p_jetty_mgr->recycle_rx_buf(p_rx_buf);
        return -1;
    }

    std::unique_lock<std::mutex> locker(p_rx_buf->b_mutex);
    ret = p_rx_buf->p_jetty_mgr->post_send(reinterpret_cast<uint8_t *>(msg) - rx_data_offset, msg_len,
        reinterpret_cast<uint64_t>(p_rx_buf));
    if (ret != DLOCK_SUCCESS) {
        m_stats.stats[DEBUG_STATS_SEND_FAIL]++;
        DLOCK_LOG_DEBUG("post_send error");
        p_rx_buf->p_jetty_mgr->recycle_rx_buf(p_rx_buf);
        return static_cast<int>(ret);
    }
    p_rx_buf->jfs_ref_count++;
    locker.unlock();

#if defined(MEASURE_ENABLE) && (MEASURE_ENABLE != 0)
    measure_throughput();
#endif
    return static_cast<int>(ret);
}

#if defined(MEASURE_ENABLE) && (MEASURE_ENABLE != 0)
void dlock_server::measure_throughput(void)
{
    if ((++m_measure_count) % MEASURE_INTERVAL != 0) {
        return;
    }

    struct timeval tv_end;
    static_cast<void>(gettimeofday(&tv_end, nullptr));
    double time_dif = (static_cast<double>(tv_end.tv_usec) - m_tv_start.tv_usec) / MICRO_PER_SEC +
        (tv_end.tv_sec - m_tv_start.tv_sec);
    DLOCK_LOG_DEBUG("throughput is %.2f Mops", (MEASURE_INTERVAL / time_dif) / MILLION);
    m_tv_start = tv_end;
}
#endif

void dlock_server::process_urma_cr_local_jfs(const urma_cr_t &cr) const
{
    struct urma_buf *p_rx_buf = reinterpret_cast<struct urma_buf *>(cr.user_ctx);

    std::unique_lock<std::mutex> locker(p_rx_buf->b_mutex);
    p_rx_buf->jfs_ref_count--;
    if (p_rx_buf->jfs_ref_count == 0u) {
        p_rx_buf->p_jetty_mgr->recycle_rx_buf(p_rx_buf);
    }
}

int dlock_server::modify_jetty_mgr_to_busy(jetty_mgr *p_jetty_mgr) const
{
    jetty_mgr_state_t expected_state = JETTY_MGR_ACTIVE;
    jetty_mgr_state_t new_state = JETTY_MGR_BUSY;

    if (p_jetty_mgr->m_state.compare_exchange_strong(expected_state, new_state)) {
        return 0;
    }

    /*
     * If the jetty_mgr state is JETTY_MGR_INVALID, indicate The data plane communication channel has been destroyed,
     * and the corresponding jetty_mgr is expired and is to be deleted.
     * If the jetty_mgr state is JETTY_MGR_BUSY, indicate jetty_mgr state is abnormal, the jetty_mgr cannot be in
     * JETTY_MGR_BUSY state.
     * Therefore, if the jetty_mgr is in either of the two states, cr should be ignored.
     */
    return -1;
}

int dlock_server::modify_jetty_mgr_to_active(jetty_mgr *p_jetty_mgr) const
{
    jetty_mgr_state_t expected_state = JETTY_MGR_BUSY;
    jetty_mgr_state_t new_state = JETTY_MGR_ACTIVE;

    if (p_jetty_mgr->m_state.compare_exchange_strong(expected_state, new_state)) {
        return 0;
    }

    return -1;
}

int dlock_server::modify_jetty_mgr_to_invalid(jetty_mgr *p_jetty_mgr)
{
    struct jetty_mgr_invalid_info invalid_info;
    jetty_mgr_state_t expected_state = JETTY_MGR_ACTIVE;
    jetty_mgr_state_t new_state = JETTY_MGR_INVALID;
    uint32_t cnt = 0;

    while (!p_jetty_mgr->m_state.compare_exchange_strong(expected_state, new_state) && cnt < MAX_RETRY_TIME) {
        static_cast<void>(usleep(RETRY_INTERVAL));
        ++cnt;
    }

    if (p_jetty_mgr->m_state != JETTY_MGR_INVALID) {
        DLOCK_LOG_WARN("failed to modify jetty_mgr to invalid state, retry times exceeds the limit");
        return -1;
    }

    p_jetty_mgr->delete_urma_channel_resource();

    /*
     * Add jetty_mgr to jetty_mgr_invalid_queue and delay the deletion of jetty_mgr to prevent jetty
     * concurrent access conflicts caused by data plane thread
     */
    invalid_info.p_jetty_mgr = p_jetty_mgr;
    invalid_info.invalid_time_point = std::chrono::steady_clock::now();
    m_jetty_mgr_invalid_queue.push(invalid_info);
    return 0;
}

int dlock_server::check_recv_cr_status(urma_cr_t *cr, int idx, bool ssl_enable)
{
    struct urma_buf *p_rx_buf = nullptr;
    int ret = 0;
    uint32_t iv_len = ssl_enable ? AES_IV_LEN : 0;

    /*
     * If cr->status is URMA_CR_WR_SUSPEND_DONE or URMA_CR_WR_FLUSH_ERR_DONE,
     * it indicates that the cr is a fake CQE generated by the hardware, and cr->user_ctx is invalid.
     */
    if (cr[idx].status == URMA_CR_WR_FLUSH_ERR_DONE) {
        jetty_mgr *p_jetty_mgr = nullptr;

        /* cr local_id is jetty/jfs id. */
        std::shared_lock<std::shared_mutex> shared_locker(m_jetty_mgr_map_rwlock);
        jetty_mgr_map_t::iterator jetty_mgr_iter = m_jetty_mgr_map.find(cr[idx].local_id);
        if (jetty_mgr_iter == m_jetty_mgr_map.end()) {
            DLOCK_LOG_WARN("The jetty_mgr associated with cr does not exist, cr local_id: %u, status: 0x%x.",
                cr[idx].local_id, cr[idx].status);
            ret = -1;
            goto out;
        }
        p_jetty_mgr = jetty_mgr_iter->second;

        p_jetty_mgr->set_m_flush_err_done();
        if (!p_jetty_mgr->get_m_modify_jetty2err()) {
            /* unexpected flush err done cr */
            DLOCK_LOG_ERR("cr failed, local_id: %u, status: 0x%x", cr[idx].local_id, cr[idx].status);
        }

        ret = -1;
        goto out;
    }

    if (cr[idx].status == URMA_CR_WR_SUSPEND_DONE) {
        DLOCK_LOG_ERR("cr failed, local_id: %u, status: 0x%x", cr[idx].local_id, cr[idx].status);
        ret = -1;
        goto out;
    }

    if (cr[idx].status != URMA_CR_SUCCESS) {
        DLOCK_LOG_ERR("cr failed, local_id: %u, status: 0x%x, s_r: %u",
            cr[idx].local_id, static_cast<int>(cr[idx].status), cr[idx].flag.bs.s_r);
        ret = -1;
        goto out;
    }
    if (cr[idx].flag.bs.s_r == 0u) {
        process_urma_cr_local_jfs(cr[idx]);
        ret = 1;
        goto out;
    }
    p_rx_buf = reinterpret_cast<struct urma_buf *>(cr[idx].user_ctx);
    if (p_rx_buf->p_jetty_mgr == nullptr) {
        DLOCK_LOG_DEBUG("jetty mgr has been deleted, rx buf has been released, ignore the cr");
        ret = -1;
        goto out;
    }
    if (modify_jetty_mgr_to_busy(p_rx_buf->p_jetty_mgr)) {
        DLOCK_LOG_DEBUG("failed to modify jetty_mgr to busy state, ignore the cr");
        ret = -1;
        goto out;
    }
    p_rx_buf->p_jetty_mgr->replenish_rx_buf();

    if ((cr[idx].completion_len == 0u) ||
        ((cr[idx].completion_len - iv_len) % sizeof(struct lock_cmd_msg) != 0u)) {
        DLOCK_LOG_ERR("invalid length %u", cr[idx].completion_len);
        p_rx_buf->p_jetty_mgr->recycle_rx_buf(p_rx_buf);
        ret = -1;
        goto modify_jetty_mgr;
    }

modify_jetty_mgr:
    static_cast<void>(modify_jetty_mgr_to_active(p_rx_buf->p_jetty_mgr));
out:
    return ret;
}

int dlock_server::primary_preinit_func(const urma_cr_t &cr) const
{
    struct urma_buf *p_rx_buf = reinterpret_cast<struct urma_buf *>(cr.user_ctx);
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    struct lock_cmd_msg *p_cmd_msg = reinterpret_cast<struct lock_cmd_msg *>(p_rx_buf->buf + rx_data_offset);
    uint32_t msg_len = cr.completion_len;
    uint32_t cmd_num = (msg_len - rx_data_offset) / sizeof(struct lock_cmd_msg);
    dlock_status_t cipher_ret;

    p_rx_buf->p_jetty_mgr->m_dlock_cipher->m_data_offset = AES_IV_LEN;
    cipher_ret = p_rx_buf->p_jetty_mgr->cmd_msg_cipher(static_cast<int>(DECRYPTION),
        p_rx_buf->buf, msg_len, m_ssl_enable);
    if (cipher_ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("rx data decryption failed");
        p_rx_buf->p_jetty_mgr->recycle_rx_buf(p_rx_buf);
        return -1;
    }

    for (int j = 0; j < static_cast<int>(cmd_num); j++) {
        p_cmd_msg[j].op_ret = static_cast<uint16_t>(DLOCK_NOT_READY);
    }

    cipher_ret = p_rx_buf->p_jetty_mgr->cmd_msg_cipher(static_cast<int>(ENCRYPTION),
        p_rx_buf->buf, msg_len, m_ssl_enable);
    if (cipher_ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("tx data encryption failed");
        p_rx_buf->p_jetty_mgr->recycle_rx_buf(p_rx_buf);
        return -1;
    }

    std::unique_lock<std::mutex> locker(p_rx_buf->b_mutex);
    dlock_status_t status = p_rx_buf->p_jetty_mgr->post_send(
        reinterpret_cast<uint8_t *>(p_cmd_msg) - rx_data_offset,
        msg_len, reinterpret_cast<uint64_t>(p_rx_buf));
    if (status != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("post_send error");
        p_rx_buf->p_jetty_mgr->recycle_rx_buf(p_rx_buf);
        return -1;
    }
    p_rx_buf->jfs_ref_count++;

    return 0;
}

void dlock_server::server_mode_handler()
{
    double time_dif;

    if (m_sleep_mode) {
        static_cast<void>(usleep(USLEEP_INTERVAL));
    }
    static_cast<void>(gettimeofday(&m_time_current, nullptr));
    time_dif = (static_cast<double>(m_time_current.tv_usec) - m_time_previous.tv_usec) / MICRO_PER_SEC +
        (m_time_current.tv_sec - m_time_previous.tv_sec);
    if (time_dif > MODE_UPDATE_INTERVAL) {
        m_sleep_mode = (m_num_reqs / time_dif) < MODE_SLEEP_TH;
        m_time_previous.tv_sec = m_time_current.tv_sec;
        m_time_previous.tv_usec = m_time_current.tv_usec;
        m_num_reqs = 0;
    }
}

int dlock_server::primary_cmd_handler()
{
    int n;
    int ret;
    urma_cr_t *cr = reinterpret_cast<urma_cr_t *>(calloc(MAX_NUM_CLIENT, sizeof(urma_cr_t)));
    struct urma_buf *p_rx_buf = nullptr;

    if (cr == nullptr) {
        DLOCK_LOG_ERR("calloc error (errno=%d %m)", errno);
        return -1;
    }

    m_p_urma_ctx->set_m_jfc_polling();
    while (!m_stop) {
        if (m_sleep_cfg_enable) {
            server_mode_handler();
        };
        n = urma_poll_jfc(m_p_urma_ctx->m_jfc, MAX_NUM_CLIENT, cr);
        if ((n < 0) || (n > MAX_NUM_CLIENT)) {
            DLOCK_LOG_ERR("urma_poll_jfc error, ret: %d", n);
            goto err;
        }
        if (n == 0) {
            continue;
        }

        for (int i = 0; i < n; i++) {
            ret = check_recv_cr_status(cr, i, m_ssl_enable);
            if (ret != 0) {
                continue;
            }
            p_rx_buf = reinterpret_cast<struct urma_buf *>(cr[i].user_ctx);

            if (m_server_state != SERVER_READY) {
                static_cast<void>(primary_preinit_func(cr[i]));
                static_cast<void>(modify_jetty_mgr_to_active(p_rx_buf->p_jetty_mgr));
                continue;
            }

            ret = do_lock(reinterpret_cast<struct urma_buf *>(cr[i].user_ctx),
                cr[i].completion_len);
            if (ret < 0) {
                DLOCK_LOG_ERR("do_lock error");
                static_cast<void>(modify_jetty_mgr_to_active(p_rx_buf->p_jetty_mgr));
                continue;
            }

            static_cast<void>(modify_jetty_mgr_to_active(p_rx_buf->p_jetty_mgr));
        }
        m_num_reqs += n;
    }

    m_p_urma_ctx->clear_m_jfc_polling();
    free(cr);
    return 0;
err:
    m_p_urma_ctx->clear_m_jfc_polling();
    free(cr);
    return -1;
}

static void *primary_control_launch(void *p_object)
{
    dlock_server *p_server = (dlock_server *)p_object;
    static_cast<void>(signal(SIGPIPE, SIG_IGN));
    int ret = p_server->primary_control_loop();
    if (ret != 0) {
        DLOCK_LOG_ERR("dlock server primary_control_launch thread exits abnormally.");
    }
    return nullptr;
}

static void *primary_cmd_launch(void *p_object)
{
    dlock_server *p_server = (dlock_server *)p_object;
    int ret = p_server->primary_cmd_handler();
    if (ret != 0) {
        DLOCK_LOG_ERR("dlock server primary_cmd_launch thread exits abnormally.");
    }
    return nullptr;
}

void dlock_server::get_primary_affinity(enum thread_type type) const
{
    int i = 0;
    cpu_set_t cpuset;
    int ret;

    CPU_ZERO(&cpuset);
    if (type == CTRL_THREAD) {
        ret = pthread_getaffinity_np(m_control_tid, sizeof(cpuset), &cpuset);
    } else {
        ret = pthread_getaffinity_np(m_cmd_tid, sizeof(cpuset), &cpuset);
    }
    if (ret != 0) {
        DLOCK_LOG_WARN("get affinity failed");
        return;
    }
    for (i = 0; i < sysconf(_SC_NPROCESSORS_CONF); i++) {
        if (CPU_ISSET(i, &cpuset)) {
            DLOCK_LOG_INFO("set thread of type %d to CPU %d", static_cast<int>(type), i);
        }
    }
}

int dlock_server::set_thread_affinity() const
{
    int ret;

    if (m_is_cpu_ctrl_affnty_set) {
        ret = pthread_setaffinity_np(m_control_tid, sizeof(m_ctrl_cpuset), &m_ctrl_cpuset);
        if (ret != 0) {
            DLOCK_LOG_ERR("cpuset control thread affinity set failed");
            return -1;
        }
        get_primary_affinity(CTRL_THREAD);
    }
    if (m_is_cpu_cmd_affnty_set) {
        ret = pthread_setaffinity_np(m_cmd_tid, sizeof(m_cmd_cpuset), &m_cmd_cpuset);
        if (ret != 0) {
            DLOCK_LOG_ERR("cpuset cmd thread affinity set failed");
            return -1;
        }
        get_primary_affinity(CMD_THREAD);
    }
    return 0;
}

int dlock_server::launch()
{
    int ret;

    if (!m_is_primary) {
        DLOCK_LOG_ERR("server has not been inited");
        return -1;
    }

    m_stop = false;

    ret = pthread_create(&m_control_tid, nullptr, primary_control_launch, reinterpret_cast<void *>(this));
    if (ret != 0) {
        DLOCK_LOG_ERR("failed to create new thread for main control loop of server");
        return -1;
    }

    ret = pthread_create(&m_cmd_tid, nullptr, primary_cmd_launch, reinterpret_cast<void *>(this));
    if (ret != 0) {
        DLOCK_LOG_ERR("failed to create new thread for main cmd loop of server");
        return -1;
    }

    ret = set_thread_affinity();
    return ret;
}

int dlock_server::primary_set_affinity(char *cpuset, enum thread_type type)
{
    char delims[] = ",";
    char *token = nullptr;
    char *next_token = nullptr;
    int range_start_id;
    int range_end_id;
    int iter;
    cpu_set_t *cpuset_ptr;
    bool *is_cpu_affnty_set;

    if (cpuset == nullptr) {
        DLOCK_LOG_INFO("no cpuset specified");
        return 0;
    }
    // cpuset "" is ilegal
    size_t num_cpus = static_cast<size_t>(sysconf(_SC_NPROCESSORS_CONF));
    size_t max_cpuset_str = (num_cpus > 1) ? 7 * num_cpus + (num_cpus - 1) : 7; // fmt:XXX-XXX,XXX-XXX...
    size_t cpuset_len = strnlen(cpuset, max_cpuset_str + 1);
    if (cpuset_len == 0u || cpuset_len > max_cpuset_str) {
        DLOCK_LOG_ERR("invalid cpuset");
        return -1;
    }
    cpuset_ptr = (type == CTRL_THREAD) ? (&m_ctrl_cpuset) : (&m_cmd_cpuset);
    CPU_ZERO(cpuset_ptr);
    is_cpu_affnty_set = (type == CTRL_THREAD) ? (&m_is_cpu_ctrl_affnty_set) : (&m_is_cpu_cmd_affnty_set);
    token = strtok_r(cpuset, delims, &next_token);
    while (token != nullptr) {
        if (!get_cpuset(token, &range_start_id, &range_end_id)) {
            DLOCK_LOG_ERR("invalid cpuset");
            return -1;
        }

        for (iter = range_start_id; iter <= range_end_id; iter++) {
            CPU_SET(iter, cpuset_ptr);
        }
        token = strtok_r(nullptr, delims, &next_token);
    }
    *is_cpu_affnty_set = true;
    return 0;
}

void dlock_server::quit()
{
    if (m_stop) {
        DLOCK_LOG_ERR("server has already quitted");
        return;
    }

    m_stop = true;

    static_cast<void>(pthread_join(m_control_tid, nullptr));
    static_cast<void>(pthread_join(m_cmd_tid, nullptr));
}

int dlock_server::get_client_id()
{
    int ret;
    int icount = MAX_TRY_ALLOC_CLIENT_ID_TIME;
    int client_id;

    if (m_client_map.size() > MAX_NUM_CLIENT) {
        DLOCK_LOG_WARN("reach max client limits");
        return -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
    }

    while ((icount--) > 0) {
        ret = RAND_priv_bytes(reinterpret_cast<unsigned char *>(&client_id), sizeof(int));
        if (ret != 1) {
            DLOCK_LOG_ERR("Random client id generation failed, return: %d", ret);
            return -1;
        }
        client_id = static_cast<int>(static_cast<unsigned int>(client_id) & CLIENT_ID_MASK);
        if (client_id == 0) {
            continue;
        }
        client_map_t::iterator iter = m_client_map.find(client_id);
        if (iter != m_client_map.end()) {
            continue;
        }
        return client_id;
    }
    DLOCK_LOG_ERR("alloc client id failed");
    return -1;
}

int dlock_server::update_client(int32_t client_id, dlock_connection *p_conn, jetty_mgr *p_jetty_mgr, bool reinit_flag)
{
    dlock_conn_peer_t peer_type = m_is_primary ? DLOCK_CONN_PEER_CLIENT : DLOCK_CONN_PEER_PRIMARY_SERVER;
    client_map_t::iterator iter = m_client_map.find(client_id);
    if (iter != m_client_map.end()) {
        DLOCK_LOG_DEBUG("client has been inited");
        if (iter->second->m_p_conn != p_conn) {
            p_conn->set_peer_info(peer_type, client_id);
            p_jetty_mgr->set_peer_info(peer_type, client_id);
            iter->second->m_p_conn = p_conn;
            iter->second->m_p_jetty_mgr = p_jetty_mgr;
            iter->second->m_reinit_flag = reinit_flag;
            DLOCK_LOG_INFO("client sockfd and dlock_connection has been changed");
        }
        // Clear client_id from exception client set when this client calls reinit
        if (m_except_client_set.find(client_id) != m_except_client_set.end()) {
            static_cast<void>(m_except_client_set.erase(client_id));
        }
    } else {
        // A reinit call but not at recovery phase which means the client entry has been deleted by server
        if ((reinit_flag) && (m_recovery_client_num == 0u)) {
            DLOCK_LOG_ERR("client entry has been cleared because it disconnected for long while");
            return static_cast<int>(DLOCK_CLIENT_REMOVED_BY_SERVER);
        }
        client_entry_s *p_client_entry = new(std::nothrow) client_entry_s(client_id, p_conn, p_jetty_mgr);
        if (p_client_entry == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for client_entry_s");
            return static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        }
        p_conn->set_peer_info(peer_type, p_client_entry->m_client_id);
        p_jetty_mgr->set_peer_info(peer_type, p_client_entry->m_client_id);
        p_client_entry->m_reinit_flag = reinit_flag;
        m_client_map[client_id] = p_client_entry;
    }

    static_cast<void>(p_jetty_mgr->post_recv_all());
    return 0;
}

void dlock_server::delete_invalid_jetty_mgr(void)
{
    struct jetty_mgr_invalid_info invalid_info;
    std::chrono::microseconds interval;
    std::chrono::steady_clock::time_point tp_now = std::chrono::steady_clock::now();

    while (!m_jetty_mgr_invalid_queue.empty()) {
        invalid_info = m_jetty_mgr_invalid_queue.front();
        interval = std::chrono::duration_cast<std::chrono::microseconds>(tp_now - invalid_info.invalid_time_point);
        if ((interval.count() < JETTY_MGR_INVALID_TIMEOUT) &&
            (m_jetty_mgr_invalid_queue.size() < JETTY_MGR_INVALID_QUEUE_WARNING_SIZE)) {
            break;
        }

        m_jetty_mgr_invalid_queue.pop();
        invalid_info.p_jetty_mgr->jetty_mgr_deinit();
        delete invalid_info.p_jetty_mgr;
    }
}

jetty_mgr *dlock_server::init_client_primary(struct urma_init_body *jetty_info, bool /* reinit_flag */)
{
    dlock_status_t ret;
    jetty_mgr *p_jetty_mgr = nullptr;

    /*
     * Before creating a jetty_mgr, check whether the jetty_mgr_invalid_queue contains jetty_mgr that
     * expires and needs to be deleted.
     */
    delete_invalid_jetty_mgr();
    p_jetty_mgr = create_jetty_mgr(m_p_urma_ctx, nullptr, CLIENT_PRIMARY, m_tp_mode, this);
    if (p_jetty_mgr == nullptr) {
        DLOCK_LOG_ERR("failed to init jetty");
        return nullptr;
    }

    if (p_jetty_mgr->m_tp_mode != jetty_info->tp_mode) {
        DLOCK_LOG_ERR("inconsistent transport mode on client and server, client mode:%d, server mode:%d",
            static_cast<int>(jetty_info->tp_mode), static_cast<int>(p_jetty_mgr->m_tp_mode));
        goto err1;
    }
    ret = set_jetty_connection(p_jetty_mgr, jetty_info, m_tp_mode);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("Failed to set jetty connection");
        goto err1;
    }

    return p_jetty_mgr;

err1:
    p_jetty_mgr->jetty_mgr_deinit();
    delete p_jetty_mgr;
    return nullptr;
}

int dlock_server::init_client_response(dlock_connection *p_conn, int32_t client_id,
    jetty_mgr *p_jetty_mgr, bool reinit_flag)
{
    struct client_init_resp_body *resp_body = nullptr;
    uint8_t *buff = nullptr;
    size_t body_len;
    size_t msg_len;
    size_t key_len;
    int ret;

    if (m_is_primary) {
        key_len = sizeof(struct dlock_key) + (sizeof(unsigned char) * p_jetty_mgr->m_dlock_cipher->m_key->key_len);
        key_len = (m_ssl_enable) ? key_len : 0;
        body_len = DLOCK_CLIENT_INIT_RESP_BODY_LEN + key_len;
        msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + body_len;
    } else {
        body_len = 0;
        msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
    }

    buff = construct_control_msg((reinit_flag) ? CLIENT_REINIT_RESPONSE : CLIENT_INIT_RESPONSE,
        DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN, msg_len, p_conn->get_next_message_id(),
        static_cast<int32_t>(DLOCK_SUCCESS));
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return -1;
    }

    if (m_is_primary) {
        resp_body = reinterpret_cast<struct client_init_resp_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
        if (p_jetty_mgr->construct_jetty_xchg_info(&resp_body->jetty_info, p_jetty_mgr) != DLOCK_SUCCESS) {
            goto err1;
        }
        resp_body->client_id = client_id;
        resp_body->server_state = m_server_state;
        resp_body->rsvd = 0;
        static_cast<void>(memcpy(&resp_body->obj_mem_seg, &(m_obj_mem_dma_tseg->seg), sizeof(urma_seg_t)));
        resp_body->obj_mem_seg_token = m_obj_mem_tseg_token.token;

        if (m_ssl_enable) {
            if (p_jetty_mgr->gen_key(reinterpret_cast<struct dlock_key *>(
                reinterpret_cast<uint8_t *>(resp_body) +
                DLOCK_CLIENT_INIT_RESP_BODY_LEN)) != DLOCK_SUCCESS) {
                goto err1;
            }
            if (reinit_flag) {
                DLOCK_LOG_INFO("data plane key of client updated at server");
            } else {
                DLOCK_LOG_INFO("data plane key of client generated at server");
            }
        }
    }

    ret = static_cast<int>(p_conn->send(buff, msg_len, 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("send error (errno=%d %m)", errno);
        goto err1;
    }

    free(buff);
    return 0;
err1:
    free(buff);
    return -1;
}

int dlock_server::client_num_count_down()
{
    if (m_client_num > 0) {
        m_client_num--;
        return 0;
    }

    DLOCK_LOG_ERR("incorrect client count m_client_num");
    return -1;
}

int dlock_server::negotiate_proto_version(const struct client_init_req_body &req_body) const
{
    /*
     * The current DLOCK_PROTO_VERSION is set to 2, no previous version needs to be compatible.
     * If the peer uses a later dlock protocol version, the peer downgrades the protocol
     * version to 2 after version negotiation.
     *
     * If the protocol version is upgraded, the code in the version negotiation part needs
     * to be rewritten to negotiate a protocol version supported by both sides as the message version.
     */

    if (req_body.min_version > DLOCK_PROTO_VERSION) {
        return -1;
    }

    return 0;
}

int dlock_server::init_client_do(dlock_connection *p_conn, struct dlock_control_hdr *msg_hdr, uint8_t *msg_body)
{
    struct client_init_req_body *req_body = reinterpret_cast<struct client_init_req_body *>(msg_body);
    jetty_mgr *p_jetty_mgr = nullptr;
    client_map_t::iterator iter;
    int32_t client_id = msg_hdr->client_id;
    int ret = -1;

    if (check_msg_body_len_invalid(msg_hdr, DLOCK_CLIENT_INIT_REQ_BODY_LEN)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, DLOCK_CLIENT_INIT_REQ_BODY_LEN);
        return -1;
    }

    if (negotiate_proto_version(*req_body) != 0) {
        DLOCK_LOG_ERR("failed to negotiate dlock protocol version");
        return static_cast<int>(DLOCK_PROTO_VERSION_NEGOTIATION_FAIL);
    }

    if (m_client_num == MAX_NUM_CLIENT) {
        ret = delete_except_client_entry();
        if (ret != 0) {
            DLOCK_LOG_ERR("clients inited exceeds MAX_NUM_CLIENT limit");
            goto init_err1;
        }
    }
    if (m_is_primary) {
        client_id = get_client_id();
        if (client_id < 0) {
            if (client_id == -static_cast<int>(DLOCK_SERVER_NO_RESOURCE)) {
                ret = static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
            }
            goto init_err1;  // fail to allocate a new client_id
        }

        p_jetty_mgr = init_client_primary(&req_body->jetty_info, false);
        if (p_jetty_mgr == nullptr) {
            DLOCK_LOG_ERR("failed to init_client_primary");
            goto init_err1;
        }
        /* For version with replica, update_client should be put outside of m_is_primary if branch */
        ret = update_client(client_id, p_conn, p_jetty_mgr, false);
        if (ret != 0) {
            goto init_err2;
        }
    }

    ret = init_client_response(p_conn, client_id, p_jetty_mgr, false);
    if (ret != 0) {
        DLOCK_LOG_ERR("failed to init_client_response");
        goto init_err3;
    }

    m_client_num++;
    DLOCK_LOG_INFO("succeed to init client");
    return 0;

init_err3:
    iter = m_client_map.find(client_id);
    if (iter != m_client_map.end()) {
        delete iter->second;
    }
    static_cast<void>(m_client_map.erase(client_id));
    return ret;

init_err2:
    if (p_jetty_mgr != nullptr) {
        p_jetty_mgr->jetty_mgr_deinit();
        delete p_jetty_mgr;
        p_jetty_mgr = nullptr;
    }

init_err1:
    return ret;
}

int dlock_server::reinit_client_do(dlock_connection *p_conn, struct dlock_control_hdr *msg_hdr, uint8_t *msg_body)
{
    if (!m_is_primary) {
        DLOCK_LOG_WARN("replica got client reinit msg");
        return -1;
    }

    if (check_msg_body_len_invalid(msg_hdr, DLOCK_CLIENT_INIT_REQ_BODY_LEN)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, DLOCK_CLIENT_INIT_REQ_BODY_LEN);
        return -1;
    }

    struct client_init_req_body *req_body = reinterpret_cast<struct client_init_req_body *>(msg_body);
    if (negotiate_proto_version(*req_body) != 0) {
        DLOCK_LOG_ERR("failed to negotiate dlock protocol version");
        return static_cast<int>(DLOCK_PROTO_VERSION_NEGOTIATION_FAIL);
    }

    int32_t client_id = msg_hdr->client_id;
    int ret = -1;
    jetty_mgr *p_jetty_mgr = nullptr;
    client_map_t::iterator iter;

    p_jetty_mgr = init_client_primary(&req_body->jetty_info, true);
    if (p_jetty_mgr == nullptr) {
        DLOCK_LOG_ERR("failed to init_client_primary");
        goto err1;
    }

    iter = m_client_map.find(client_id);
    if (iter != m_client_map.end()) {
        if ((m_recovery_client_num != 0u)  && iter->second->m_client_lock_updated) {
            DLOCK_LOG_ERR("Primary Server is in the fault recovery pre-initialization process, "
                "failed to reinit client repeatedly.");
            goto err2;
        }
        DLOCK_LOG_DEBUG("clear client jetty");
        if (client_num_count_down() < 0) {
            goto err2;
        }
        iter->second->m_p_jetty_mgr->jetty_mgr_deinit();
        delete iter->second->m_p_jetty_mgr;
        iter->second->m_p_jetty_mgr = nullptr;
        if ((iter->second->m_p_conn != nullptr) && (iter->second->m_p_conn != p_conn)) {
            delete_dlock_connection(iter->second->m_p_conn);
            iter->second->m_p_conn = nullptr;
        }
    }

    /* two cases:
     * case 1: reinit called after server recovery
     * m_client_num starts from 0
     * case 2: reinit called after network error(DLOCK_BAD_RESPONSE)
     * m_client_num may starts from MAX_NUM_CLIENT, in that m_client_num
     * compared with MAX_NUM_CLIENT should be done here instead of before
     * init_client_primary(MAX_NUM_CLIENT + 1 is valid there)
     */
    m_client_num++;
    if (m_client_num > MAX_NUM_CLIENT) {
        /* only case 1 gets here */
        m_client_num--;
        ret = static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        DLOCK_LOG_ERR("clients reinited exceeds MAX_NUM_CLIENT limit");
        goto err2;
    }

    ret = update_client(client_id, p_conn, p_jetty_mgr, true);
    if (ret != 0) {
        m_client_num--;
        goto err2;
    }

    ret = init_client_response(p_conn, client_id, p_jetty_mgr, true);
    if (ret != 0) {
        DLOCK_LOG_ERR("failed to reinit_client_response");
        /* to avoid client_entry_s leak in case 1 with m_client_num of
         * MAX_NUM_CLIENT + 1, m_client_num++ should be done before this
         * error check
         */
        m_client_num--;
        goto err2;
    }

    DLOCK_LOG_DEBUG("reinited client");
    return 0;

err2:
    p_jetty_mgr->jetty_mgr_deinit();
    delete p_jetty_mgr;
    p_jetty_mgr = nullptr;
err1:
    return ret;
}

int dlock_server::deinit_client_do(dlock_connection *p_conn,
    struct dlock_control_hdr *msg_hdr, uint8_t * /* msg_body */)
{
    uint8_t *buff = nullptr;
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
    int ret;

    if (check_msg_body_len_invalid(msg_hdr, 0)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, 0);
        return -1;
    }

    client_map_t::iterator iter = m_client_map.find(msg_hdr->client_id);
    if (iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client has not been inited");
        return -1;
    }

    if (modify_jetty_mgr_to_invalid(iter->second->m_p_jetty_mgr)) {
        DLOCK_LOG_WARN("failed to invalidate jetty_mgr owned by the client, the client entry"
            "cannot be deleted at this time");
        return -1;
    }
    iter->second->m_p_jetty_mgr = nullptr;
    delete iter->second;
    if (m_ssl_enable) {
        DLOCK_LOG_INFO("data plane key of client deleted at server");
    }
    static_cast<void>(m_client_map.erase(iter));
    if (client_num_count_down() < 0) {
        return -1;
    }

    buff = construct_control_msg(CLIENT_DEINIT_RESPONSE, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        msg_len, p_conn->get_next_message_id(), static_cast<int32_t>(DLOCK_SUCCESS));
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return -1;
    }

    ret = static_cast<int>(p_conn->send(buff, msg_len, 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("send error (errno=%d %m)", errno);
        goto err1;
    }

    free(buff);
    if (m_is_primary) {
        delete_dlock_connection(p_conn);
    }

    DLOCK_LOG_INFO("succeed to deinit client");
    return 0;
err1:
    free(buff);
    return -1;
}

int dlock_server::client_heartbeat_do(dlock_connection *p_conn, struct dlock_control_hdr *msg_hdr,
    uint8_t * /* msg_body */)
{
    if (!m_is_primary) {
        // replica should not response.
        DLOCK_LOG_WARN("replica got heartbeat message");
        return -1;
    }

    if (check_msg_body_len_invalid(msg_hdr, 0)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, 0);
        return -1;
    }

    client_map_t::iterator iter = m_client_map.find(msg_hdr->client_id);
    if (iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client has not been inited");
        return -1;
    }

    uint8_t *buff = nullptr;
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
    int ret;

    buff = construct_control_msg(CLIENT_HEARTBEAT_RESPONSE, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        msg_len, p_conn->get_next_message_id(), static_cast<int32_t>(DLOCK_SUCCESS));
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct client heartbeat response message error");
        return -1;
    }

    ret = static_cast<int>(p_conn->send(buff, msg_len, 0));
    free(buff);
    return (ret < 0) ? -1 : 0;
}

int dlock_server::get_lock_reply(dlock_connection *p_conn, struct get_lock_body *msg_body) const
{
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_GET_LOCK_BODY_LEN;
    uint8_t *buff = nullptr;
    int ret;

    buff = construct_control_msg(GET_LOCK_RESPONSE, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        msg_len, p_conn->get_next_message_id(), static_cast<int32_t>(DLOCK_SUCCESS));
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_get_lock_reply_msg error");
        return -1;
    }

    struct get_lock_body *get_msg = reinterpret_cast<struct get_lock_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    static_cast<void>(memcpy(get_msg, msg_body, DLOCK_GET_LOCK_BODY_LEN));
    ret = static_cast<int>(p_conn->send(buff, msg_len, 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("send error (errno=%d %m)", errno);
        free(buff);
        return -1;
    }

    free(buff);
    return 0;
}

int dlock_server::find_available_lock_id(int lock_id)
{
    lock_map_t::iterator lock_iter = m_lock_map.find(lock_id);
    if ((lock_id > 0) && (lock_iter == m_lock_map.end())) {
        return lock_id;
    }
    bool loop_flag = false;
    do {
        m_curr_lock_id++;
        if (m_curr_lock_id <= 0) {
            if (loop_flag) {
                DLOCK_LOG_ERR("no available lock id");
                return -1;
            }
            loop_flag = true;
            m_curr_lock_id = 1;
        }
        lock_iter = m_lock_map.find(m_curr_lock_id);
    } while (lock_iter != m_lock_map.end());
    return m_curr_lock_id;
}

int dlock_server::find_available_object_id(int object_id)
{
    auto iter = m_object_map.find(object_id);
    if ((object_id > 0) && (iter == m_object_map.end())) {
        return object_id;
    }
    bool loop_flag = false;
    do {
        m_curr_object_id++;
        if (m_curr_object_id <= 0) {
            if (loop_flag) {
                DLOCK_LOG_ERR("no available object id");
                return -1;
            }
            loop_flag = true;
            m_curr_object_id = 1;
        }
        iter = m_object_map.find(m_curr_object_id);
    } while (iter != m_object_map.end());
    return m_curr_object_id;
}

int dlock_server::get_lock_do(dlock_connection * /* p_conn */, struct dlock_control_hdr *msg_hdr, uint8_t *msg_body)
{
    struct get_lock_body *get_msg = reinterpret_cast<struct get_lock_body *>(msg_body);
    uint16_t expected_msg_body_len = DLOCK_GET_LOCK_BODY_LEN + static_cast<uint16_t>(get_msg->desc_len);

    if (check_msg_body_len_invalid(msg_hdr, expected_msg_body_len)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, desc_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, get_msg->desc_len, expected_msg_body_len);
        return -1;
    }

    client_map_t::iterator client_iter = m_client_map.find(msg_hdr->client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client has not been inited");
        return -1;
    }

    lock_entry_s *lock_entry = get_lock_by_msg(get_msg);
    if (lock_entry == nullptr) {
        return (get_msg->lock_id == -static_cast<int>(DLOCK_SERVER_NO_RESOURCE)) ?
            static_cast<int>(DLOCK_SERVER_NO_RESOURCE) : -1;
    }

    lock_map_t::iterator lock_iter = client_iter->second->m_lock_map.find(get_msg->lock_id);
    if (lock_iter != client_iter->second->m_lock_map.end()) {
        DLOCK_LOG_WARN("lock_id %d has been got", get_msg->lock_id);
        return get_lock_reply(client_iter->second->m_p_conn, get_msg);
    }

    client_iter->second->m_lock_map[get_msg->lock_id] = lock_entry;
    lock_entry->m_lease_time_map[msg_hdr->client_id] = get_msg->lease_time;  // 增加max_lease_time

    return get_lock_reply(client_iter->second->m_p_conn, get_msg);
}

void dlock_server::lock_entry_release(lock_entry_s *lock_entry, const struct release_lock_body *release_msg)
{
    if (lock_entry == nullptr || release_msg == nullptr) {
        DLOCK_LOG_ERR("lock_entry or release_msg is nullptr");
        return;
    }

    static_cast<void>(m_lock_desc_map.erase(lock_entry->m_lock_dec));

    delete lock_entry->m_lock_dec;
    lock_entry->m_lock_dec = nullptr;

    delete lock_entry;

    static_cast<void>(m_lock_map.erase(release_msg->lock_id));
    if (m_lock_num <= 0) {
        DLOCK_LOG_ERR("improper state lock num counter");
        return;
    }
    m_lock_num--;
}

int dlock_server::release_lock_do(dlock_connection *p_conn, struct dlock_control_hdr *msg_hdr,
    uint8_t *msg_body)
{
    uint8_t *buff = nullptr;
    struct release_lock_body *release_msg = reinterpret_cast<struct release_lock_body *>(msg_body);
    int ret;

    if (check_msg_body_len_invalid(msg_hdr, DLOCK_RELEASE_LOCK_BODY_LEN)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, DLOCK_RELEASE_LOCK_BODY_LEN);
        return -1;
    }

    client_map_t::iterator client_iter = m_client_map.find(msg_hdr->client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client has not been inited");
        return -1;
    }

    lock_map_t::iterator lock_iter = client_iter->second->m_lock_map.find(release_msg->lock_id);
    if (lock_iter == client_iter->second->m_lock_map.end()) {
        DLOCK_LOG_WARN("lock_id %d has not been got", release_msg->lock_id);
        return -1;
    }

    lock_entry_s *lock_entry = lock_iter->second;
    static_cast<void>(lock_entry->m_lease_time_map.erase(msg_hdr->client_id));
    if (lock_entry->m_lease_time_map.empty()) {
        lock_entry_release(lock_entry, release_msg);
    }
    static_cast<void>(client_iter->second->m_lock_map.erase(release_msg->lock_id));

    buff = construct_control_msg(RELEASE_LOCK_RESPONSE, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, p_conn->get_next_message_id(), static_cast<int32_t>(DLOCK_SUCCESS));
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return -1;
    }

    ret = static_cast<int>(client_iter->second->m_p_conn->send(buff, DLOCK_FIXED_CTRL_MSG_HDR_LEN, 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("send error (errno=%d %m)", errno);
        free(buff);
        return -1;
    }

    free(buff);
    return 0;
}

lock_entry_s *dlock_server::get_lock_by_msg(struct get_lock_body *get_msg)
{
    if (get_msg->lock_type >= static_cast<uint32_t>(DLOCK_MAX)) {
        DLOCK_LOG_ERR("unsupported lock type %d", get_msg->lock_type);
        return nullptr;
    }

    dlock_descriptor *desc = new(std::nothrow) dlock_descriptor();
    if (desc == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
        get_msg->lock_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        return nullptr;
    }
    dlock_status_t ret = desc->descriptor_init(get_msg->desc_len, get_msg->desc);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("dlock descriptor init failed");
        if (ret == DLOCK_ENOMEM) {
            get_msg->lock_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        }
        delete desc;
        return nullptr;
    }

    int32_t lock_id = get_msg->lock_id;
    lock_entry_s *lock_entry = nullptr;
    lock_desc_map_t::iterator lock_desc_iter = m_lock_desc_map.find(desc);
    if (lock_desc_iter == m_lock_desc_map.end()) {
        /* in this case, new lock will be allocated */
        if (m_lock_num >= MAX_NUM_LOCK) {
            DLOCK_LOG_ERR("the num of locks exceeds limit");
            get_msg->lock_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
            delete desc;
            return nullptr;
        }
        // check lock_id avalibility
        if (m_is_primary) {
            lock_id = find_available_lock_id(lock_id);
            if (lock_id <= 0) {
                DLOCK_LOG_ERR("cannot find avaliable lock_id");
                /* use -static_cast<int>(DLOCK_SERVER_NO_RESOURCE) not static_cast<int>(DLOCK_SERVER_NO_RESOURCE),
                   because there is lock_id with the value of static_cast<int>(DLOCK_SERVER_NO_RESOURCE) which
                   is valid */
                get_msg->lock_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
                delete desc;
                return nullptr;
            }
            lock_entry = new(std::nothrow) lock_entry_s(lock_id, static_cast<enum dlock_type>(get_msg->lock_type),
                m_lock_memory);
            if (lock_entry == nullptr) {
                DLOCK_LOG_ERR("c++ new failed, bad alloc for lock_entry_s");
                get_msg->lock_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
                delete desc;
                return nullptr;
            }
            if (lock_entry->m_lock_offset == UINT_MAX) {
                DLOCK_LOG_ERR("get_lock_memory error");
                get_msg->lock_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
                delete desc;
                delete lock_entry;
                return nullptr;
            }
            get_msg->lock_id = lock_id;
            get_msg->offset = lock_entry->m_lock_offset;
        } else {
            lock_entry = new(std::nothrow) lock_entry_s(get_msg->lock_id,
                static_cast<enum dlock_type>(get_msg->lock_type),
                get_msg->offset, m_lock_memory);
            if (lock_entry == nullptr) {
                DLOCK_LOG_ERR("c++ new failed, bad alloc for lock_entry_s");
                get_msg->lock_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
                delete desc;
                return nullptr;
            }
        }
        lock_entry->m_lock_dec = desc;
        m_lock_desc_map[desc] = lock_entry;
        m_lock_map[get_msg->lock_id] = lock_entry;
        m_lock_num++;
    } else {
        lock_entry = lock_desc_iter->second;
        if (get_msg->lock_type != static_cast<uint32_t>(lock_entry->m_lock_type)) {
            DLOCK_LOG_ERR("lock type is inconsistent, original lock_type: %u, request lock_type: %u",
                static_cast<uint32_t>(lock_entry->m_lock_type), get_msg->lock_type);
            get_msg->lock_id = -1;
            delete desc;
            return nullptr;
        }

        get_msg->lock_id = lock_entry->m_lock_id;
        get_msg->offset = lock_entry->m_lock_offset;
        delete desc;
    }

    return lock_entry;
}

int dlock_server::batch_get_lock_do(dlock_connection * /* p_conn */,
    struct dlock_control_hdr *msg_hdr, uint8_t *msg_body)
{
    struct batch_get_lock_body *msg_batch_get_lock_body =
        reinterpret_cast<struct batch_get_lock_body *>(msg_body);
    struct get_lock_body *msg_get_lock_body = msg_batch_get_lock_body->get_lock_entry;
    int client_id = msg_hdr->client_id;
    client_map_t::iterator client_iter = m_client_map.find(client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client has not been inited");
        return -1;
    }

    uint16_t msg_body_len = static_cast<uint16_t>(msg_hdr->total_len - msg_hdr->hdr_len);
    size_t offset = DLOCK_BATCH_GET_LOCK_BODY_LEN;
    uint32_t lock_num = msg_batch_get_lock_body->lock_num;
    lock_entry_s *lock_entry = nullptr;
    uint32_t i;
    for (i = 0; i < lock_num; i++) {
        msg_get_lock_body = reinterpret_cast<struct get_lock_body *>(msg_body + offset);
        offset += DLOCK_GET_LOCK_BODY_LEN + msg_get_lock_body->desc_len;
        if (offset > msg_body_len) {
            DLOCK_LOG_ERR("desc len %d error", msg_get_lock_body->desc_len);
            return -1;
        }
        lock_entry = get_lock_by_msg(msg_get_lock_body);
        if (lock_entry == nullptr) {
            continue;
        }
        lock_map_t::iterator lock_iter = client_iter->second->m_lock_map.find(msg_get_lock_body->lock_id);
        if (lock_iter != client_iter->second->m_lock_map.end()) {
            DLOCK_LOG_WARN("lock_id %d has been got", msg_get_lock_body->lock_id);
            continue;
        }
        client_iter->second->m_lock_map[msg_get_lock_body->lock_id] = lock_entry;
        lock_entry->m_lease_time_map[client_id] = msg_get_lock_body->lease_time;
    }

    return batch_get_lock_reply(client_iter->second->m_p_conn, lock_num, msg_body);
}

int dlock_server::batch_get_lock_reply(dlock_connection *p_conn, uint32_t lock_num, uint8_t *msg_body) const
{
    uint8_t *buff = nullptr;
    int ret;
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_BATCH_GET_LOCK_BODY_LEN +
        (lock_num * DLOCK_GET_LOCK_BODY_LEN);

    buff = construct_control_msg(BATCH_GET_LOCK_RESPONSE, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        msg_len, p_conn->get_next_message_id(), static_cast<int32_t>(DLOCK_SUCCESS));
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_get_lock_reply_msg error");
        return -1;
    }

    struct batch_get_lock_body *msg_batch_get_lock_body =
        reinterpret_cast<struct batch_get_lock_body *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    msg_batch_get_lock_body->lock_num = lock_num;

    size_t offset = DLOCK_BATCH_GET_LOCK_BODY_LEN;
    struct get_lock_body *src;
    struct get_lock_body *dest = msg_batch_get_lock_body->get_lock_entry;
    uint32_t i;
    for (i = 0; i < lock_num; i++) {
        src = reinterpret_cast<struct get_lock_body *>(msg_body + offset);
        static_cast<void>(memcpy(dest + i, src, DLOCK_GET_LOCK_BODY_LEN));
        offset += DLOCK_GET_LOCK_BODY_LEN + src->desc_len;
    }

    ret = static_cast<int>(
        p_conn->send(buff, msg_len, 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("send error (errno=%d %m)", errno);
        free(buff);
        return -1;
    }

    free(buff);
    return 0;
}

void dlock_server::release_lock_map_entry(const lock_map_t::iterator lock_iter,
    const struct release_lock_body release_msg, int32_t client_id)
{
    lock_entry_s *lock_entry = lock_iter->second;
    static_cast<void>(lock_entry->m_lease_time_map.erase(client_id));
    if (lock_entry->m_lease_time_map.empty()) {
        static_cast<void>(m_lock_desc_map.erase(lock_entry->m_lock_dec));
        delete lock_entry->m_lock_dec;
        lock_entry->m_lock_dec = nullptr;
        delete lock_entry;
        static_cast<void>(m_lock_map.erase(release_msg.lock_id));
        if (m_lock_num <= 0) {
            DLOCK_LOG_ERR("improper state lock num counter");
            return;
        }
        m_lock_num--;
    }
}

int dlock_server::batch_release_lock_do(dlock_connection *p_conn,
    struct dlock_control_hdr *msg_hdr, uint8_t *msg_body)
{
    uint8_t *buff = nullptr;
    struct batch_release_lock_body *batch_release_msg =
        reinterpret_cast<struct batch_release_lock_body *>(msg_body);
    struct release_lock_body *release_msg = batch_release_msg->release_lock_entry;
    int ret;

    if (msg_hdr->total_len - msg_hdr->hdr_len < DLOCK_BATCH_RELEASE_LOCK_BODY_LEN) {
        DLOCK_LOG_ERR("message body length error, less than DLOCK_BATCH_RELEASE_LOCK_BODY_LEN, "
            "hdr_len: %u, total_len: %u", msg_hdr->hdr_len, msg_hdr->total_len);
        return -1;
    }

    uint32_t lock_num = batch_release_msg->lock_num;
    uint16_t expected_msg_body_len = static_cast<uint16_t>(DLOCK_BATCH_RELEASE_LOCK_BODY_LEN +
        (lock_num * DLOCK_RELEASE_LOCK_BODY_LEN));
    if (check_msg_body_len_invalid(msg_hdr, expected_msg_body_len)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, expected_msg_body_len);
        return -1;
    }

    client_map_t::iterator client_iter = m_client_map.find(msg_hdr->client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client has not been inited");
        return -1;
    }

    uint32_t i;
    for (i = 0; i < lock_num; i++) {
        lock_map_t::iterator lock_iter = client_iter->second->m_lock_map.find(release_msg[i].lock_id);
        if (lock_iter == client_iter->second->m_lock_map.end()) {
            DLOCK_LOG_WARN("lock_id %d has not been got by client", release_msg[i].lock_id);
            continue;
        }

        release_lock_map_entry(lock_iter, release_msg[i], msg_hdr->client_id);
        static_cast<void>(client_iter->second->m_lock_map.erase(release_msg[i].lock_id));
    }

    buff = construct_control_msg(BATCH_RELEASE_LOCK_RESPONSE, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, p_conn->get_next_message_id(), static_cast<int32_t>(DLOCK_SUCCESS));
    if (buff == nullptr) {
        DLOCK_LOG_ERR("batch construct_control_msg error");
        return -1;
    }

    ret = static_cast<int>(client_iter->second->m_p_conn->send(buff, DLOCK_FIXED_CTRL_MSG_HDR_LEN, 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("batch send error (errno=%d %m)", errno);
        free(buff);
        return -1;
    }

    free(buff);
    return 0;
}

int dlock_server::reinit_client_done(dlock_connection * p_conn,
    struct dlock_control_hdr* msg_hdr, uint8_t* /* msg_body */)
{
    if (!m_is_primary) {
        DLOCK_LOG_WARN("replica got reinit done msg");
        return -1;
    }

    uint8_t *buff = nullptr;
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
    int ret;

    DLOCK_LOG_DEBUG("reinit_done");
    client_map_t::iterator iter = m_client_map.find(msg_hdr->client_id);
    if (iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client has not been inited");
        return -1;
    }
    if (!iter->second->m_reinit_flag) {
        DLOCK_LOG_ERR("client has not been reinited");
        return -1;
    }
    buff = construct_control_msg(CLIENT_REINIT_DONE_RESPONSE, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        msg_len, p_conn->get_next_message_id(), static_cast<int32_t>(DLOCK_SUCCESS));
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct_control_msg error");
        return -1;
    }

    ret = static_cast<int>(p_conn->send(buff, msg_len, 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("send error (errno=%d %m)", errno);
        free(buff);
        return -1;
    }

    iter->second->m_reinit_flag = false;
    if (m_recovery_client_num != 0) {
        if ((--m_recovery_client_num) == 0u) {
            m_server_state = SERVER_READY;
            DLOCK_LOG_DEBUG("server ready! server_id: %d", m_server_id);
        }
        DLOCK_LOG_DEBUG("update m_recovery_client_num: %u", m_recovery_client_num);
    }
    free(buff);
    return 0;
}

lock_entry_s *dlock_server::update_lock_by_msg(struct update_lock_body *update_msg)
{
    if (update_msg->lock_type >= static_cast<uint32_t>(DLOCK_MAX)) {
        DLOCK_LOG_ERR("unsupported lock type %d", update_msg->lock_type);
        update_msg->lock_id = -1;
        return nullptr;
    }

    dlock_descriptor *desc = new(std::nothrow) dlock_descriptor();
    if (desc == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
        update_msg->lock_id = -1;
        return nullptr;
    }
    if (desc->descriptor_init(update_msg->desc_len, update_msg->desc)) {
        DLOCK_LOG_ERR("dlock descriptor init failed");
        delete desc;
        update_msg->lock_id = -1;
        return nullptr;
    }
    
    int32_t lock_id = update_msg->lock_id;
    lock_entry_s *lock_entry = nullptr;
    lock_desc_map_t::iterator lock_desc_iter = m_lock_desc_map.find(desc);
    if (lock_desc_iter == m_lock_desc_map.end()) {
        if (m_lock_num >= MAX_NUM_LOCK) {
            /* update_msg would not be exploded to users, so return -1 is enough */
            DLOCK_LOG_ERR("the num of locks exceeds limit");
            update_msg->lock_id = -1;
            delete desc;
            return nullptr;
        }
        // check lock_id avalibility
        lock_id = find_available_lock_id(lock_id);
        if (lock_id <= 0) {
            DLOCK_LOG_ERR("cannot find avaliable lock_id");
            update_msg->lock_id = -1;
            delete desc;
            return nullptr;
        }
        lock_entry = new(std::nothrow) lock_entry_s(lock_id, static_cast<enum dlock_type>(update_msg->lock_type),
            m_lock_memory);
        if (lock_entry == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for lock_entry_s");
            update_msg->lock_id = -1;
            delete desc;
            return nullptr;
        }
        if (lock_entry->m_lock_offset == UINT_MAX) {
            DLOCK_LOG_ERR("get_lock_memory error");
            delete desc;
            delete lock_entry;
            update_msg->lock_id = -1;
            return nullptr;
        }
        update_msg->lock_id = lock_id;
        update_msg->offset = lock_entry->m_lock_offset;
        lock_entry->m_lock_dec = desc;
        m_lock_desc_map[desc] = lock_entry;
        m_lock_map[update_msg->lock_id] = lock_entry;
        m_lock_num++;
    } else {
        lock_entry = lock_desc_iter->second;
        update_msg->lock_id = lock_entry->m_lock_id;
        update_msg->offset = lock_entry->m_lock_offset;
        delete desc;
    }
    m_lock_memory->sync_lock_state(static_cast<uint32_t>(lock_entry->m_lock_type), lock_entry->m_lock_offset,
        update_msg->ls);
    return lock_entry;
}

int dlock_server::batch_update_locks_do(dlock_connection *p_conn, struct dlock_control_hdr* msg_hdr, uint8_t *msg_body)
{
    if (!m_is_primary) {
        DLOCK_LOG_WARN("replica got batch update locks msg");
        return -1;
    }
    struct batch_update_lock_body *msg_batch_update_lock_body =
        reinterpret_cast<struct batch_update_lock_body *>(msg_body);
    struct update_lock_body *p_msg_update = msg_batch_update_lock_body->update_lock_entry;
    int32_t client_id = msg_hdr->client_id;
    client_map_t::iterator client_iter = m_client_map.find(client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client has not been inited");
        return -1;
    }
    if (!client_iter->second->m_reinit_flag) {
        DLOCK_LOG_ERR("client has not been reinited");
        return -1;
    }

    uint16_t msg_body_len = static_cast<uint16_t>(msg_hdr->total_len - msg_hdr->hdr_len);
    size_t offset = DLOCK_BATCH_UPDATE_LOCK_BODY_LEN;
    uint32_t lock_num = msg_batch_update_lock_body->lock_num;
    lock_entry_s *lock_entry = nullptr;
    uint32_t i;
    for (i = 0; i < lock_num; i++) {
        p_msg_update = reinterpret_cast<struct update_lock_body *>(msg_body + offset);
        offset += DLOCK_UPDATE_LOCK_BODY_LEN + p_msg_update->desc_len;
        if (offset > msg_body_len) {
            DLOCK_LOG_WARN("Invalid msg_hdr length: %u when batch update locks do", msg_hdr->total_len);
            break;
        }
        lock_entry = update_lock_by_msg(p_msg_update);
        if (lock_entry == nullptr) {
            continue;
        }
        lock_map_t::iterator lock_iter = client_iter->second->m_lock_map.find(p_msg_update->lock_id);
        if (lock_iter != client_iter->second->m_lock_map.end()) {
            DLOCK_LOG_WARN("lock_id %d has been got", p_msg_update->lock_id);
            continue;
        }
        client_iter->second->m_lock_map[p_msg_update->lock_id] = lock_entry;
        lock_entry->m_lease_time_map[client_id] = p_msg_update->lease_time;
        client_iter->second->m_client_lock_updated = true;
    }

    int ret;
    msg_hdr->type = static_cast<uint8_t>(BATCH_UPDATE_LOCKS_RESPONSE); // send back same message with updates
    msg_hdr->status = static_cast<int32_t>(DLOCK_SUCCESS);
    ret = static_cast<int>(p_conn->send(msg_hdr, DLOCK_FIXED_CTRL_MSG_HDR_LEN, 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("send error (errno=%d %m)", errno);
        return -1;
    }

    ret = static_cast<int>(p_conn->send(msg_body,
        (static_cast<size_t>(msg_hdr->total_len) - DLOCK_FIXED_CTRL_MSG_HDR_LEN), 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("send error (errno=%d %m)", errno);
        return -1;
    }

    return 0;
}

object_entry_s *dlock_server::create_object_by_msg(struct object_create_body *body, int32_t client_id)
{
    dlock_descriptor *desc = new(std::nothrow) dlock_descriptor();
    if (desc == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
        body->obj_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        return nullptr;
    }
        
    dlock_status_t ret = desc->descriptor_init(body->desc_len, body->desc);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("dlock descriptor init failed");
        if (ret == DLOCK_ENOMEM) {
            body->obj_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
        }
        delete desc;
        return nullptr;
    }

    int32_t object_id = body->obj_id;
    object_entry_s *entry = nullptr;

    if (m_is_primary) {
        object_id = find_available_object_id(object_id);
        if (object_id <= 0) {
            DLOCK_LOG_ERR("cannot find avaliable object_id");
            body->obj_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
            delete desc;
            return nullptr;
        }
        entry = new(std::nothrow) object_entry_s(object_id, client_id);
        if (entry == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for c++ object!");
            body->obj_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
            delete desc;
            return nullptr;
        }
        entry->m_offset = m_object_memory->alloc_object_memory();
        if (entry->m_offset >= INVALID_OFFSET) {
            DLOCK_LOG_ERR("get_object_memory error");
            body->obj_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
            delete desc;
            delete entry;
            return nullptr;
        }
        body->obj_id = object_id;
        body->offset = entry->m_offset;
    } else {
        entry = new(std::nothrow) object_entry_s(object_id, client_id, body->offset);
        if (entry == nullptr) {
            DLOCK_LOG_ERR("c++ new failed, bad alloc for c++ object!");
            body->obj_id = -static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
            delete desc;
            return nullptr;
        }
    }
    m_object_memory->set(entry->m_offset, body->init_value);
    entry->m_object_desc = desc;
    m_object_desc_map[desc] = entry;
    m_object_map[object_id] = entry;
    return entry;
}

template <typename T>
int dlock_server::object_reply(dlock_connection *p_conn, T *body)
{
    size_t msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + sizeof(T);
    uint8_t *buff = nullptr;
    int ret;

    buff = construct_control_msg(T::get_response_type(), DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        msg_len, p_conn->get_next_message_id(), static_cast<int32_t>(DLOCK_SUCCESS));
    if (buff == nullptr) {
        DLOCK_LOG_ERR("construct object message error");
        return -1;
    }

    T *reply = reinterpret_cast<T *>(buff + DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    static_cast<void>(memcpy(reply, body, sizeof(T)));
    ret = static_cast<int>(p_conn->send(buff, msg_len, 0));
    if (ret < 0) {
        DLOCK_LOG_ERR("send error (errno=%d %m)", errno);
        free(buff);
        return -1;
    }

    free(buff);
    return 0;
}

void dlock_server::refresh_object_entry(object_entry_s *entry, struct dlock_control_hdr *msg_hdr,
    std::chrono::seconds lease_time)
{
    int obj_id = entry->m_id;
    DLOCK_LOG_DEBUG("destroyed object %d being reset when m_refcnt = 0 or lease_time expired", obj_id);

    entry->m_lease_tp_map.clear();
    entry->m_owner_id = msg_hdr->client_id;
    entry->m_refcnt = 0;
    entry->m_destroyed = false;
    entry->m_max_lease_tp = std::chrono::steady_clock::now() + lease_time;
    entry->m_lease_tp_map[msg_hdr->client_id] = entry->m_max_lease_tp;
    for (auto it = m_client_map.begin(); it != m_client_map.end(); ++it) {
        auto cs = it->second;
        auto it2 = cs->m_object_map.find(obj_id);
        if (it2 != cs->m_object_map.end()) {
            cs->m_object_map.erase(it2);
        }
    }
}

int dlock_server::create_object_do(dlock_connection * /* p_conn */, struct dlock_control_hdr *msg_hdr,
    uint8_t *msg_body)
{
    struct object_create_body *body = reinterpret_cast<struct object_create_body *>(msg_body);
    uint16_t expected_msg_body_len = DLOCK_OBJECT_CREATE_BODY_LEN + static_cast<uint16_t>(body->desc_len);

    if (check_msg_body_len_invalid(msg_hdr, expected_msg_body_len)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, desc_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, body->desc_len, expected_msg_body_len);
        return static_cast<int>(DLOCK_EINVAL);
    }
    auto client_iter = m_client_map.find(msg_hdr->client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client_id has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    std::chrono::seconds lease_time(body->lease_time);

    dlock_descriptor *desc = new(std::nothrow) dlock_descriptor();
    if (desc == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
        return static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
    }
    dlock_status_t ret = desc->descriptor_init(body->desc_len, body->desc);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("dlock descriptor init failed");
        delete desc;
        return static_cast<int>(ret);
    }
    object_desc_map_t::iterator it = m_object_desc_map.find(desc);
    delete desc;
    // if requested object has been created
    if (it != m_object_desc_map.end()) {
        object_entry_s *entry = it->second;
        if (entry->m_destroyed) {
            if (entry->m_refcnt != 0 && !entry->check_lease_expired()) {
                DLOCK_LOG_DEBUG("object has already been destroyed, but m_refcnt or lease_time has not been reset");
                return static_cast<int>(DLOCK_OBJECT_ALREADY_DESTROYED);
            }
            // refresh the object, in this case, only lease time expire could happen
            refresh_object_entry(entry, msg_hdr, lease_time);
            /* As find_available_object_id not called here, uniqueness of object_id can't be gauranteed.
             * In case obj_id in body passed by client is inconsistent with obj_id of entry, correct
             * obj_id should be returned to client
             */
            body->obj_id = entry->m_id;
            return object_reply(client_iter->second->m_p_conn, body);
        } else {
            // if the same client or owner_id = 0
            if ((msg_hdr->client_id == entry->m_owner_id) || (entry->m_owner_id == 0)) {
                // update lease timestamp
                auto tp2 = std::chrono::steady_clock::now() + lease_time;
                entry->m_max_lease_tp = std::max(entry->m_max_lease_tp, tp2);
                entry->m_lease_tp_map[msg_hdr->client_id] = std::max(entry->m_lease_tp_map[msg_hdr->client_id], tp2);
                body->obj_id = entry->m_id;
                body->offset = entry->m_offset;
                DLOCK_LOG_DEBUG("client_id creates object again");
                return static_cast<int>(DLOCK_OBJECT_ALREADY_CREATED);
            }
            // else return error
            DLOCK_LOG_ERR("another client_id creates the same object");
            return static_cast<int>(DLOCK_OBJECT_ALREADY_EXISTED);
        }
    }

    // check if exceeds the number of maximum objects the server can create
    if (m_curr_object_num == MAX_OBJECT_SIZE) {
        DLOCK_LOG_ERR("too many objects have been created");
        return static_cast<int>(DLOCK_OBJECT_TOO_MANY);
    }

    // create one
    object_entry_s *entry = create_object_by_msg(body, msg_hdr->client_id);
    if (entry == nullptr) {
        return (body->obj_id == -static_cast<int>(DLOCK_SERVER_NO_RESOURCE)) ?
            static_cast<int>(DLOCK_SERVER_NO_RESOURCE) : -1;
    }

    entry->m_max_lease_tp = std::chrono::steady_clock::now() + lease_time;
    entry->m_lease_tp_map[msg_hdr->client_id] = entry->m_max_lease_tp;
    m_curr_object_num++;

    DLOCK_LOG_DEBUG("object id %d has been created, cur_obj_num %d",
                    body->obj_id, m_curr_object_num);

    return object_reply(client_iter->second->m_p_conn, body);
}

void dlock_server::destroy_object_entry(object_entry_s *entry)
{
    if (m_curr_object_num <= 0) {
        DLOCK_LOG_ERR("improper state object num counter");
        return;
    }
    
    int obj_id = entry->m_id;
    DLOCK_LOG_DEBUG("object id:%d refcnt:%d", obj_id, entry->m_refcnt);

    m_object_memory->free_object_memory(entry->m_offset);

    auto desc = entry->m_object_desc;
    m_object_desc_map.erase(desc);
    delete desc;

    m_object_map.erase(entry->m_id);
    delete entry;

    m_curr_object_num--;

    for (auto it = m_client_map.begin(); it != m_client_map.end(); ++it) {
        auto cs = it->second;
        auto it2 = cs->m_object_map.find(obj_id);
        if (it2 != cs->m_object_map.end()) {
            cs->m_object_map.erase(it2);
        }
    }
}

int dlock_server::destroy_object_do(dlock_connection * /* p_conn */, struct dlock_control_hdr *msg_hdr,
    uint8_t *msg_body)
{
    struct object_destroy_body *body = reinterpret_cast<struct object_destroy_body *>(msg_body);
    if (check_msg_body_len_invalid(msg_hdr, DLOCK_OBJECT_DESTROY_BODY_LEN)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, DLOCK_OBJECT_DESTROY_BODY_LEN);
        return static_cast<int>(DLOCK_EINVAL);
    }
    auto client_iter = m_client_map.find(msg_hdr->client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client_id has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    auto object_it = m_object_map.find(body->obj_id);
    if (object_it == m_object_map.end()) {
        DLOCK_LOG_WARN("object %d has not been created", body->obj_id);
        return static_cast<int>(DLOCK_OBJECT_NOT_CREATE);
    }

    auto entry = object_it->second;
    if ((entry->m_owner_id != msg_hdr->client_id) && (entry->m_owner_id != 0)) {
        DLOCK_LOG_WARN("client id != owner id and owner_id != 0");
        return static_cast<int>(DLOCK_OBJECT_INVALID_OWNER);
    }

    // if client_id matches owner_id but the object was already destroyed
    if (entry->m_destroyed) {
        DLOCK_LOG_WARN("object %d has already been destroyed", body->obj_id);
        return static_cast<int>(DLOCK_OBJECT_ALREADY_DESTROYED);
    }

    entry->m_destroyed = true;
    if (entry->m_refcnt == 0 || entry->check_lease_expired()) {
        destroy_object_entry(entry);
    }

    DLOCK_LOG_DEBUG("client has destroyed object id %d cur_obj_num %d", body->obj_id, m_curr_object_num);

    return object_reply(client_iter->second->m_p_conn, body);
}

int dlock_server::get_object_do(dlock_connection * /* p_conn */, struct dlock_control_hdr *msg_hdr,
    uint8_t *msg_body)
{
    struct object_get_body *body = reinterpret_cast<struct object_get_body *>(msg_body);
    uint16_t expected_msg_body_len = DLOCK_OBJECT_GET_BODY_LEN + static_cast<uint16_t>(body->desc_len);

    if (check_msg_body_len_invalid(msg_hdr, expected_msg_body_len)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, desc_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, body->desc_len, expected_msg_body_len);
        return static_cast<int>(DLOCK_EINVAL);
    }
    auto client_iter = m_client_map.find(msg_hdr->client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client_id has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    client_entry_s *cs = client_iter->second;

    dlock_descriptor *desc = new(std::nothrow) dlock_descriptor();
    if (desc == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for dlock_descriptor");
        return static_cast<int>(DLOCK_SERVER_NO_RESOURCE);
    }
    dlock_status_t ret = desc->descriptor_init(body->desc_len, body->desc);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("dlock descriptor init failed");
        delete desc;
        return static_cast<int>(ret);
    }
    object_desc_map_t::iterator it = m_object_desc_map.find(desc);
    delete desc;
    if (it == m_object_desc_map.end()) {
        DLOCK_LOG_ERR("object has not been created");
        return static_cast<int>(DLOCK_OBJECT_NOT_CREATE);
    }

    object_entry_s *entry = it->second;
    if (entry->m_destroyed) {
        DLOCK_LOG_ERR("object id %d has been destroyed", entry->m_id);
        return static_cast<int>(DLOCK_OBJECT_ALREADY_DESTROYED);
    }

    if (cs->m_object_map.find(entry->m_id) == cs->m_object_map.end()) {
        // first time get
        cs->m_object_map[entry->m_id] = entry;
        entry->m_refcnt++;
    }

    std::chrono::seconds lease_time(body->lease_time);
    auto tp2 = std::chrono::steady_clock::now() + lease_time;
    entry->m_max_lease_tp = std::max(entry->m_max_lease_tp, tp2);
    entry->m_lease_tp_map[msg_hdr->client_id] = std::max(entry->m_lease_tp_map[msg_hdr->client_id], tp2);
    body->obj_id = entry->m_id;
    body->offset = entry->m_offset;

    DLOCK_LOG_DEBUG("client has got object id %d refcnt %d", body->obj_id, entry->m_refcnt);

    return object_reply(client_iter->second->m_p_conn, body);
}

int dlock_server::release_object_do(dlock_connection * /* p_conn */, struct dlock_control_hdr *msg_hdr,
    uint8_t *msg_body)
{
    struct object_release_body *body = reinterpret_cast<struct object_release_body *>(msg_body);
    if (check_msg_body_len_invalid(msg_hdr, DLOCK_OBJECT_RELEASE_BODY_LEN)) {
        DLOCK_LOG_ERR("message body length error, hdr_len: %u, total_len: %u, expected_msg_body_len: %u",
            msg_hdr->hdr_len, msg_hdr->total_len, DLOCK_OBJECT_RELEASE_BODY_LEN);
        return static_cast<int>(DLOCK_EINVAL);
    }
    auto client_iter = m_client_map.find(msg_hdr->client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_WARN("client_id has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    client_entry_s *cs = client_iter->second;
    auto object_it = cs->m_object_map.find(body->obj_id);
    if (object_it == cs->m_object_map.end()) {
        DLOCK_LOG_ERR("object id %d has not been got", body->obj_id);
        return static_cast<int>(DLOCK_OBJECT_NOT_GET);
    }

    object_entry_s *entry = object_it->second;

    entry->m_refcnt--;
    entry->m_lease_tp_map.erase(msg_hdr->client_id);
    int32_t refcnt = entry->m_refcnt;
    cs->m_object_map.erase(object_it);
    if (entry->m_destroyed && (entry->m_refcnt == 0 || entry->check_lease_expired())) {
        destroy_object_entry(entry);
    }

    DLOCK_LOG_DEBUG("client released object id %d refcnt %d", body->obj_id, refcnt);

    return object_reply(client_iter->second->m_p_conn, body);
}
};
