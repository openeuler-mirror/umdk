/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : jetty_mgr.cpp
 * Description   : jetty manager
 * History       : create file & add functions
 * 1.Date        : 2022-03-01
 * Author        : jiasiyuan
 * Modification  : Created file
 */
 
#include <cstring>
#include <unistd.h>

#include "dlock_types.h"
#include "jetty_mgr.h"

#include <netinet/in.h>
#include <sys/time.h>

#include "dlock_common.h"
#include "dlock_log.h"
#include "dlock_server.h"
#include "utils.h"

namespace dlock {
static const uint32_t JETTY_MGR_WAIT_FLUSH_ERR_DONE_TIMEOUT = 60000000; // us
static const uint32_t JETTY_MGR_SLEEP_INTERVAL = 1000; // us

void jetty_mgr::jfs_cfg_init(urma_jfs_cfg_t &jfs_cfg, urma_transport_mode_t tp_mode, uint32_t order_type) const
{
    jfs_cfg.flag.bs.order_type = order_type;
    jfs_cfg.flag.bs.multi_path = 0;
    jfs_cfg.trans_mode = tp_mode;
    jfs_cfg.priority = URMA_MAX_PRIORITY;
    jfs_cfg.max_sge = static_cast<uint8_t>(m_urma_ctx->m_dev_attr.dev_cap.max_jfs_sge);
    jfs_cfg.max_rsge = static_cast<uint8_t>(m_urma_ctx->m_dev_attr.dev_cap.max_jfs_rsge);
    jfs_cfg.max_inline_data = m_urma_ctx->m_dev_attr.dev_cap.max_jfs_inline_len;
    jfs_cfg.rnr_retry = URMA_TYPICAL_RNR_RETRY;
    jfs_cfg.err_timeout = URMA_TYPICAL_ERR_TIMEOUT;
    jfs_cfg.jfc = m_jfc;
    if (m_is_exe) {
        jfs_cfg.depth = EXE_SQ_SIZE;
    } else {
        jfs_cfg.depth = CMD_SQ_SIZE;
    }
}

void jetty_mgr::jfr_cfg_init(urma_jfr_cfg_t &jfr_cfg, urma_transport_mode_t tp_mode, uint32_t order_type) const
{
    jfr_cfg.flag.bs.token_policy = get_token_policy();
    jfr_cfg.flag.bs.tag_matching = URMA_NO_TAG_MATCHING;
    jfr_cfg.flag.bs.order_type = order_type;
    jfr_cfg.trans_mode = tp_mode;
    jfr_cfg.max_sge = static_cast<uint8_t>(m_urma_ctx->m_dev_attr.dev_cap.max_jfr_sge);
    jfr_cfg.min_rnr_timer = URMA_TYPICAL_MIN_RNR_TIMER;
    jfr_cfg.jfc = m_jfc;
    jfr_cfg.token_value = m_jfr_token;
    jfr_cfg.id = 0;
    if (m_is_exe) {
        jfr_cfg.depth = EXE_RQ_SIZE;
    } else {
        jfr_cfg.depth = CMD_RQ_SIZE;
    }
}

dlock_status_t jetty_mgr::get_jfc(void)
{
    urma_jfc_cfg_t jfc_cfg = {
        .depth = CQ_SIZE_PER_CLIENT,
        .flag = {.value = 0},
        .ceqn = 0,
        .jfce = nullptr,
        .user_ctx = 0,
    };

    if (m_urma_ctx == nullptr) {
        DLOCK_LOG_ERR("urma ctx not created");
        return DLOCK_EINVAL;
    }

    if (m_urma_ctx->m_jfc != nullptr) {
        m_jfc = m_urma_ctx->m_jfc;
    } else {
        m_jfc = urma_create_jfc(m_urma_ctx->m_urma_ctx, &jfc_cfg);
        if (m_jfc == nullptr) {
            DLOCK_LOG_ERR("Failed to create jfc");
            return DLOCK_FAIL;
        }
    }

    return DLOCK_SUCCESS;
}

jetty_mgr::jetty_mgr(urma_ctx *p_urma_ctx, dlock_server *p_server) noexcept
    : m_cr_data(0), m_gid_idx(GID_INDEX), m_urma_ctx(p_urma_ctx), m_jfc(nullptr),
    m_tp_mode(SEPERATE_CONN), m_is_exe(false), m_dlock_cipher(nullptr), m_p_rx_buf(nullptr),
    m_missing_rx_buf_num(0), m_ci(0), m_dst_tseg(nullptr), m_state(JETTY_MGR_ACTIVE), m_next_message_id(0),
    m_local_id(0), m_modify_jetty2err(false), m_flush_err_done(false), m_p_server(p_server)
{
    m_jfr_token.token = 0;
}

/* Before calling the jetty_mgr destructor, you must call jetty_mgr_deinit() */
jetty_mgr::~jetty_mgr() noexcept
{
    struct urma_buf *p_rx_buf = nullptr;

    if ((!m_is_exe) && (m_urma_ctx->m_jfc == nullptr)) {
        delete_jfc();
    }

    std::unique_lock<std::mutex> locker(m_idle_rx_buf_pool_lock, std::defer_lock);
    locker.lock();
    m_idle_rx_buf_pool.clear();
    locker.unlock();

    while (m_p_rx_buf != nullptr) {
        p_rx_buf = m_p_rx_buf->next;
        m_p_rx_buf->p_jetty_mgr = nullptr;
        m_urma_ctx->release_memory(m_p_rx_buf);
        m_p_rx_buf = p_rx_buf;
    }

    if (m_urma_ctx != nullptr) {
        m_urma_ctx = nullptr;
    }

    if (m_dlock_cipher != nullptr) {
        delete m_dlock_cipher;
    }
}

dlock_status_t jetty_mgr::jetty_mgr_init(urma_ctx *p_urma_ctx, urma_jfc_t *p_jfc, uint32_t num_buf)
{
    struct urma_buf *p_rx_buf = nullptr;
    dlock_status_t ret;

    if (p_jfc != nullptr) {
        m_jfc = p_jfc;
        m_is_exe = true;
    } else {
        ret = get_jfc();
        if (ret != DLOCK_SUCCESS) {
            DLOCK_LOG_ERR("Fail to get jfc when initiate jetty mgr");
            return ret;
        }
    }

    for (unsigned int i = 0; i < num_buf; i++) {
        p_rx_buf = m_p_rx_buf;
        m_p_rx_buf = p_urma_ctx->get_memory();
        if (m_p_rx_buf == nullptr) {
            DLOCK_LOG_ERR("the urma ctx has no registered urma buf");
            return DLOCK_ENOMEM;
        }
        m_p_rx_buf->next = p_rx_buf;
        m_p_rx_buf->p_jetty_mgr = this;
        m_p_rx_buf->jfs_ref_count = 0;
    }

    ret = m_urma_ctx->gen_token_value(m_jfr_token);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("Failed to generate token value");
        return DLOCK_FAIL;
    }

    m_dlock_cipher = new(std::nothrow) dlock_cipher();
    if (m_dlock_cipher == nullptr) {
        DLOCK_LOG_ERR("c++ new failed, bad alloc for c++ object!");
        return DLOCK_ENOMEM;
    }

    ret = m_dlock_cipher->cipher_init(AES_KEY_BYTES);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("Failed to init dlock cipher");
        delete m_dlock_cipher;
        m_dlock_cipher = nullptr;
        return ret;
    }

    return DLOCK_SUCCESS;
}

void jetty_mgr::jetty_mgr_deinit(void)
{
    delete_urma_channel_resource();
}

void jetty_mgr::unimport_dst_tseg(void)
{
    if (m_dst_tseg == nullptr) {
        return;
    }

    urma_status_t ret = urma_unimport_seg(m_dst_tseg);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to unimport seg, ret: %d", static_cast<int>(ret));
    }
    m_dst_tseg = nullptr;
}

void jetty_mgr::delete_jfc(void) noexcept
{
    if (m_jfc == nullptr) {
        return;
    }

    urma_status_t ret = urma_delete_jfc(m_jfc);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to delete jfc, ret: %d", static_cast<int>(ret));
    }
    m_jfc = nullptr;
}

void jetty_mgr::recycle_rx_buf(struct urma_buf *p_rx_buf)
{
    if (m_missing_rx_buf_num == 0u) {
        std::unique_lock<std::mutex> locker(m_idle_rx_buf_pool_lock, std::defer_lock);
        locker.lock();
        m_idle_rx_buf_pool.push_back(p_rx_buf);
        locker.unlock();
        return;
    }

    if (post_recv_buf(p_rx_buf) != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("fail to post recv buf when recycle");
        return;
    }

    m_missing_rx_buf_num--;
}

void jetty_mgr::replenish_rx_buf(void)
{
    struct urma_buf *p_idle_rx_buf;
    dlock_status_t ret;

    std::unique_lock<std::mutex> locker(m_idle_rx_buf_pool_lock);
    if (m_idle_rx_buf_pool.size() != 0u) {
        p_idle_rx_buf = m_idle_rx_buf_pool.back();
        m_idle_rx_buf_pool.pop_back();

        ret = post_recv_buf(p_idle_rx_buf);
        if (ret != DLOCK_SUCCESS) {
            m_idle_rx_buf_pool.push_back(p_idle_rx_buf);
            m_missing_rx_buf_num++;
            DLOCK_LOG_DEBUG("Fail to post receive when rx buffer pool is not ready");
        }
    } else {
        m_missing_rx_buf_num++;
    }
}

dlock_status_t jetty_mgr::post_send_after_recv(uint8_t *buf, uint32_t len, uint64_t wr_id) const
{
    dlock_status_t ret;

    ret = post_recv(URMA_MTU);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("Failed to post recv");
        return ret;
    }
    ret = post_send(buf, len, wr_id);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("Failed to post send");
        return ret;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr::poll_jfc(uint32_t &comp_len, int async_mode)
{
    int poll_res;
    urma_cr_t cr;
    struct timeval tv_start;
    struct timeval tv_end;

    if (async_mode == 0) { // in sync mode, timeout should be checked here
        static_cast<void>(gettimeofday(&tv_start, nullptr));
    }
    for (;;) {
        poll_res = urma_poll_jfc(m_jfc, 1, &cr);
        if (poll_res < 0 || poll_res > 1) {
            DLOCK_LOG_DEBUG("poll jfc error");
            return DLOCK_FAIL;
        } else if ((poll_res == 0) && (async_mode == 0)) {
            static_cast<void>(gettimeofday(&tv_end, nullptr));
            if ((tv_end.tv_sec - tv_start.tv_sec) * ONE_MILLION +  (tv_end.tv_usec - tv_start.tv_usec) <
                LOCK_TIMEOUT) {
                continue;
            }
            DLOCK_LOG_DEBUG("DLOCK_ETIMEOUT");
            return DLOCK_ETIMEOUT;
        } else if ((poll_res == 0) && (async_mode == 1)) { // async mode
            return DLOCK_ASYNC_AGAIN;
        }

        if (cr.status != URMA_CR_SUCCESS) {
            DLOCK_LOG_DEBUG("cr failed status: 0x%x, cr.flag.bs.s_r: %u", static_cast<int>(cr.status), cr.flag.bs.s_r);
            return DLOCK_FAIL;
        }
        if (cr.flag.bs.s_r == 1u) {
            comp_len = cr.completion_len;
            m_cr_data = cr.user_ctx;
            return DLOCK_SUCCESS;
        } else {
            continue;
        }
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr::send_and_get_res(uint8_t *buf, uint32_t len, uint64_t wr_id, uint32_t &comp_len)
{
    dlock_status_t ret;

    ret = post_recv(URMA_MTU);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("post recv error");
        return ret;
    }

    ret = post_send(buf, len, wr_id);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("post send error");
        return ret;
    }

    return poll_jfc(comp_len, 0);
}

dlock_status_t jetty_mgr::gen_key(struct dlock_key *key) const
{
    dlock_status_t ret;

    if ((key == nullptr) || (m_dlock_cipher->m_key->key_len != AES_KEY_BYTES)) {
        DLOCK_LOG_DEBUG("Invalid parameter for gen_key");
        return DLOCK_EINVAL;
    }
    key->key_len = m_dlock_cipher->m_key->key_len;
    key->key = reinterpret_cast<unsigned char *>(key) + sizeof(struct dlock_key);
    ret = m_dlock_cipher->secure_rand_gen(key->key, key->key_len);
    if (ret != DLOCK_SUCCESS) {
        return ret;
    }
    static_cast<void>(memcpy(m_dlock_cipher->m_key->key, key->key, key->key_len));
    return DLOCK_SUCCESS;
}

/* guarantee buf is long enough for extra iv */
dlock_status_t jetty_mgr::cmd_msg_cipher(int op_type, uint8_t *buf, uint32_t len, bool ssl_enable) const
{
    dlock_status_t ret;
    uint8_t *buf_out;
    uint32_t out_len;

    if (!ssl_enable) {
        return DLOCK_SUCCESS;
    }

    out_len = len + AES_IV_LEN - m_dlock_cipher->m_data_offset;
    buf_out = (uint8_t *)malloc(sizeof(uint8_t) * out_len);
    if (buf_out == nullptr) {
        DLOCK_LOG_ERR("cmd msg cipher buf: malloc error (errno=%d %m)", errno);
        return DLOCK_ENOMEM;
    }
    static_cast<void>(memset(buf_out, 0, out_len));
    ret = m_dlock_cipher->cipher_op(op_type, buf_out, reinterpret_cast<int *>(&out_len),
        buf, static_cast<int>(len));
    if (ret != DLOCK_SUCCESS) {
        free(buf_out);
        return ret;
    }
    if (out_len != len - m_dlock_cipher->m_data_offset) {
        DLOCK_LOG_ERR("incorrect cipher len: %d", out_len);
        free(buf_out);
        return DLOCK_FAIL;
    }
    out_len = len + AES_IV_LEN - m_dlock_cipher->m_data_offset;
    static_cast<void>(memcpy(buf, buf_out, out_len));
    free(buf_out);
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr::cmd_msg_cipher(int op_type, uint8_t *buf_in, uint32_t len, uint8_t *buf_out,
    bool ssl_enable) const
{
    dlock_status_t ret;
    uint32_t out_len = len + AES_IV_LEN - m_dlock_cipher->m_data_offset;

    if (!ssl_enable) {
        return DLOCK_SUCCESS;
    }

    /* As we already have 5 params for cmd_msg_cipher func, out_len we caculated in the func instead
     * of passing it as a param. But we ensure out_len is actually the size of buf_out to fulfill
     * secure fuction requirment.
     */
    static_cast<void>(memset(buf_out, 0, out_len));
    ret = m_dlock_cipher->cipher_op(op_type, buf_out, reinterpret_cast<int *>(&out_len),
        buf_in, static_cast<int>(len));
    if (ret != DLOCK_SUCCESS) {
        return ret;
    }
    if (out_len != len - m_dlock_cipher->m_data_offset) {
        DLOCK_LOG_ERR("incorrect cipher len: %d", out_len);
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr::check_recv(uint32_t &comp_len)
{
    return poll_jfc(comp_len, 1);
}

void jetty_mgr::import_seg_flag_init(urma_import_seg_flag_t &flag) const
{
    flag.bs.cacheable = URMA_NON_CACHEABLE;
    flag.bs.access = DLOCK_SEG_ACCESS_FLAGS;
    flag.bs.mapping = URMA_SEG_NOMAP;
    flag.bs.reserved = 0;
}

dlock_status_t jetty_mgr::import_seg(urma_seg_t *seg, uint32_t token)
{
    urma_import_seg_flag_t flag = {.value = 0};
    import_seg_flag_init(flag);
    urma_token_t token_value = {
        .token = token,
    };

    m_dst_tseg = urma_import_seg(m_urma_ctx->m_urma_ctx, seg, &token_value, 0, flag);
    if (m_dst_tseg == nullptr) {
        DLOCK_LOG_ERR("Failed to import seg\n");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

void jetty_mgr::set_peer_info(dlock_conn_peer_t peer_type, int peer_id)
{
    m_peer_info.peer_type = peer_type;
    m_peer_info.peer_id = peer_id;
}

void jetty_mgr::get_peer_info(dlock_conn_peer_info_t &peer_info) const
{
    peer_info.peer_type = m_peer_info.peer_type;
    peer_info.peer_id = m_peer_info.peer_id;
}

int jetty_mgr::rand_init_next_message_id(void)
{
    int ret = RAND_priv_bytes(reinterpret_cast<unsigned char *>(&m_next_message_id), sizeof(m_next_message_id));
    if (ret != 1) {
        DLOCK_LOG_ERR("failed to generate random next message id, ret: %d", ret);
        return -1;
    }
    return 0;
}

uint16_t jetty_mgr::generate_message_id(void)
{
    return (m_next_message_id++);
}

uint16_t jetty_mgr::get_next_message_id(void) const
{
    return m_next_message_id;
}

void jetty_mgr::set_next_message_id(uint16_t next_message_id)
{
    m_next_message_id = next_message_id;
}

void jetty_mgr::fill_read_sge(urma_sge_t *src_sge, urma_sge_t *dst_sge, uint32_t offset) const
{
    src_sge->addr = m_dst_tseg->seg.ubva.va + offset;
    src_sge->len = sizeof(uint64_t);
    src_sge->tseg = m_dst_tseg;

    dst_sge->addr = reinterpret_cast<uint64_t>(m_p_rx_buf->buf);
    dst_sge->len = sizeof(uint64_t);
    dst_sge->tseg = m_urma_ctx->m_local_tseg;
}

void jetty_mgr::fill_read_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge, urma_sge_t *dst_sge) const
{
    wr->opcode = URMA_OPC_READ;

    wr->rw.src.sge = src_sge;
    wr->rw.src.num_sge = 1;

    wr->rw.dst.sge = dst_sge;
    wr->rw.dst.num_sge = 1;
}

void jetty_mgr::fill_faa_cas_sge(urma_sge_t *src_sge, urma_sge_t *dst_sge, uint32_t offset) const
{
    src_sge->addr = reinterpret_cast<uint64_t>(m_p_rx_buf->buf);
    src_sge->len = sizeof(uint64_t);
    src_sge->tseg = m_urma_ctx->m_local_tseg;

    dst_sge->addr = m_dst_tseg->seg.ubva.va + offset;
    dst_sge->len = sizeof(uint64_t);
    dst_sge->tseg = m_dst_tseg;
}

void jetty_mgr::fill_faa_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge,
    urma_sge_t *dst_sge, uint64_t operand) const
{
    wr->opcode = URMA_OPC_FADD;
    wr->faa.src = src_sge;
    wr->faa.dst = dst_sge;
    wr->faa.operand = operand;
}

void jetty_mgr::fill_cas_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge,
    urma_sge_t *dst_sge, uint64_t cmp_data, uint64_t swap_data) const
{
    wr->opcode = URMA_OPC_CAS;
    wr->cas.src = src_sge;
    wr->cas.dst = dst_sge;
    wr->cas.cmp_data = cmp_data;
    wr->cas.swap_data = swap_data;
}

dlock_status_t jetty_mgr::poll_jfc_wait_after_post_send(uint64_t wr_id, urma_cr_t *cr) const
{
    int poll_res;
    struct timeval tv_start;
    struct timeval tv_end;

    (void)gettimeofday(&tv_start, nullptr);
    for (;;) {
        poll_res = urma_poll_jfc(m_jfc, 1, cr);
        if (poll_res < 0 || poll_res > 1) {
            DLOCK_LOG_DEBUG("poll jfc error");
            return DLOCK_FAIL;
        }

        if (poll_res == 0) {
            (void)gettimeofday(&tv_end, nullptr);
            if ((tv_end.tv_sec - tv_start.tv_sec) * ONE_MILLION +  (tv_end.tv_usec - tv_start.tv_usec) <
                LOCK_TIMEOUT) {
                continue;
            }
            DLOCK_LOG_DEBUG("DLOCK_ETIMEOUT");
            return DLOCK_ETIMEOUT;
        }

        if (cr->status != URMA_CR_SUCCESS) {
            DLOCK_LOG_DEBUG("cr failed status: 0x%x", static_cast<int>(cr->status));
            return DLOCK_FAIL;
        }

        if (cr->flag.bs.s_r != 0) {
            DLOCK_LOG_DEBUG("unexpected rx cr, opcode: 0x%x", static_cast<int>(cr->opcode));
            return DLOCK_FAIL;
        }

        if (cr->user_ctx != wr_id) {
            DLOCK_LOG_DEBUG("unexpected tx cr, wr_id: %lu", cr->user_ctx);
            return DLOCK_FAIL;
        }

        return DLOCK_SUCCESS;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr::post_read_and_get_res(uint64_t wr_id, uint32_t offset, uint64_t *res_val) const
{
    dlock_status_t ret;
    urma_cr_t cr;

    ret = post_read(offset, wr_id);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("post read error");
        return DLOCK_FAIL;
    }

    ret = poll_jfc_wait_after_post_send(wr_id, &cr);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("poll jfc after post read error");
        return DLOCK_BAD_RESPONSE;
    }

    *res_val = *(reinterpret_cast<uint64_t *>(m_p_rx_buf->buf));
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr::post_faa_and_get_res(uint64_t wr_id, uint32_t offset,
    uint64_t add_val, uint64_t *res_val) const
{
    dlock_status_t ret;
    urma_cr_t cr;

    ret = post_faa(offset, add_val, wr_id);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("post faa error");
        return DLOCK_FAIL;
    }

    ret = poll_jfc_wait_after_post_send(wr_id, &cr);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("poll jfc after post faa error");
        return DLOCK_BAD_RESPONSE;
    }

    *res_val = *(reinterpret_cast<uint64_t *>(m_p_rx_buf->buf));
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr::post_cas_and_get_res(uint64_t wr_id, uint32_t offset,
    uint64_t cmp_val, uint64_t swap_val) const
{
    dlock_status_t ret;
    urma_cr_t cr;

    ret = post_cas(offset, cmp_val, swap_val, wr_id);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("post cas error");
        return DLOCK_FAIL;
    }

    ret = poll_jfc_wait_after_post_send(wr_id, &cr);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_DEBUG("poll jfc after post cas error");
        return DLOCK_BAD_RESPONSE;
    }

    uint64_t original_val = *(reinterpret_cast<uint64_t *>(m_p_rx_buf->buf));
    if (original_val != cmp_val) {
        DLOCK_LOG_DEBUG("cas failed, unexpected original_val: %lx, cmp_val: %lx",
            original_val, cmp_val);
        return DLOCK_OBJECT_CAS_FAILED;
    }

    return DLOCK_SUCCESS;
}

#ifdef UB_AGG
dlock_status_t jetty_mgr::construct_urma_bond_id_xchg_info(struct urma_init_body *jetty_info) const
{
    if (m_urma_ctx->is_ub_bonding_dev()) {
        jetty_info->is_bond = true;
        if (get_urma_bond_id_info(&jetty_info->bond_id_info) != DLOCK_SUCCESS) {
            DLOCK_LOG_ERR("failed to get ub bond id info");
            return DLOCK_FAIL;
        }
        return DLOCK_SUCCESS;
    }

    jetty_info->is_bond = false;
    static_cast<void>(memset(&jetty_info->bond_id_info, 0, sizeof(urma_bond_id_info_out_t)));
    return DLOCK_SUCCESS;
}
#endif /* UB_AGG */

void jetty_mgr::wait_flush_err_done(void)
{
    if ((m_p_server == nullptr) || m_flush_err_done || (!m_urma_ctx->is_m_jfc_polling())) {
        return;
    }

    /*
     * For the dlock server instance, multiple Jetty/JFS instances share one JFC. Due to UB hardware
     * and driver constraints, before deleting a Jetty/JFS instance, must modify the Jetty to error
     * state and wait for the fake URMA_CR_WR_FLUSH_ERR_DONE CR, otherwise, unpredictable errors
     * may occur.
     *
     * For the dlock client instance, each Jetty/JFS exclusively occupies one JFC. If a Jetty/JFS
     * is deleted, it will no longer poll the JFC, and the JFC will also be removed. Therefore,
     * jetty/jfs can be directly deleted without waiting for the URMA_CR_WR_FLUSH_ERR_DONE CR.
     * UB driver will modify jetty/jfs to error before deleting jetty/jfs.
     */
    std::chrono::microseconds interval;
    std::chrono::steady_clock::time_point tp_start = std::chrono::steady_clock::now();

    while ((!m_flush_err_done) && m_urma_ctx->is_m_jfc_polling()) {
        std::chrono::steady_clock::time_point tp_now = std::chrono::steady_clock::now();
        interval = std::chrono::duration_cast<std::chrono::microseconds>(tp_now - tp_start);
        if (interval.count() > JETTY_MGR_WAIT_FLUSH_ERR_DONE_TIMEOUT) { // 60s timeout
            DLOCK_LOG_ERR("Waiting for fake URMA_CR_WR_FLUSH_ERR_DONE CR timeout! local_id: %u.", m_local_id);
            break;
        }

        static_cast<void>(usleep(JETTY_MGR_SLEEP_INTERVAL));
    }
}
};
