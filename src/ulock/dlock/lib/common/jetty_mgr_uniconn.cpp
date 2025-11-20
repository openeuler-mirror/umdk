/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : jetty_mgr_uniconn.cpp
 * Description   : jetty manager uni connection mode
 * History       : create file & add functions
 * 1.Date        : 2022-10-19
 * Author        : wujie
 * Modification  : Created file
 */

#include <cstring>

#include "dlock_types.h"
#include "jetty_mgr_uniconn.h"

#include <netinet/in.h>

#include "dlock_common.h"
#include "dlock_log.h"
#include "dlock_server.h"
#include "utils.h"

namespace dlock {
dlock_status_t jetty_mgr_uniconn::create_jetty(void)
{
    urma_jfs_cfg_t jfs_cfg;
    urma_jfr_cfg_t jfr_cfg;
    urma_jetty_cfg_t jetty_cfg;

    static_cast<void>(memset(&jfs_cfg, 0, sizeof(urma_jfs_cfg_t)));
    static_cast<void>(memset(&jfr_cfg, 0, sizeof(urma_jfr_cfg_t)));
    static_cast<void>(memset(&jetty_cfg, 0, sizeof(urma_jetty_cfg_t)));
    jfs_cfg_init(jfs_cfg, URMA_TM_RC, URMA_OL);
    jfr_cfg_init(jfr_cfg, URMA_TM_RC, URMA_OL);
    jetty_cfg.jfs_cfg = jfs_cfg;

    if (m_urma_ctx->get_urma_dev_type() == URMA_TRANSPORT_UB) {
        m_share_jfr = urma_create_jfr(m_urma_ctx->m_urma_ctx, &jfr_cfg);
        if (m_share_jfr == nullptr) {
            DLOCK_LOG_ERR("Failed to create share jfr");
            return DLOCK_FAIL;
        }

        jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR; /* UB dev should use share jfr */
        jetty_cfg.shared.jfr = m_share_jfr;
    } else {
        DLOCK_LOG_ERR("urma device type is not UB!");
        return DLOCK_FAIL;
    }

    m_jetty = urma_create_jetty(m_urma_ctx->m_urma_ctx, &jetty_cfg);
    if (m_jetty == nullptr) {
        DLOCK_LOG_ERR("Failed to create jetty");
        delete_share_jfr();
        return DLOCK_FAIL;
    }

    m_local_id = m_jetty->jetty_id.id;
    if (m_p_server != nullptr) {
        m_p_server->add_to_m_jetty_mgr_map(m_local_id, this);
    }

    return DLOCK_SUCCESS;
}

bool jetty_mgr_uniconn::check_construct_succeed(jetty_mgr_uniconn *p_mgr_uniconn, bool rx_buf_check) const
{
    if (p_mgr_uniconn->m_jetty == nullptr) {
        DLOCK_LOG_ERR("error to init qp");
        return false;
    }
    if ((rx_buf_check) && (p_mgr_uniconn->m_p_rx_buf == nullptr)) {
        DLOCK_LOG_ERR("error to get buf");
        return false;
    }
    if ((m_dlock_cipher->m_ctx == nullptr) || (m_dlock_cipher->m_key == nullptr)) {
        DLOCK_LOG_ERR("error to init dlock cipher");
        return false;
    }

    return true;
}

jetty_mgr_uniconn::jetty_mgr_uniconn(urma_ctx *p_urma_ctx, dlock_server *p_server) noexcept
    : jetty_mgr(p_urma_ctx, p_server), m_share_jfr(nullptr), m_jetty(nullptr), m_tjetty(nullptr)
{
    m_tp_mode = UNI_CONN;
}

jetty_mgr_uniconn::~jetty_mgr_uniconn() noexcept
{
}

dlock_status_t jetty_mgr_uniconn::jetty_mgr_uniconn_init(urma_ctx *p_urma_ctx, urma_jfc_t *p_jfc,
    uint32_t num_buf)
{
    dlock_status_t ret;

    ret = jetty_mgr_init(p_urma_ctx, p_jfc, num_buf);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("init jetty mgr failed");
        return ret;
    }

    ret = create_jetty();
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("create jetty failed");
        return ret;
    }

    return DLOCK_SUCCESS;
}

void jetty_mgr_uniconn::unbind_jetty(void)
{
    if (m_jetty == nullptr) {
        return;
    }

    urma_status_t ret = urma_unbind_jetty(m_jetty);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to unbind jetty, ret: %d", static_cast<int>(ret));
    }
}

void jetty_mgr_uniconn::unimport_tjetty(void)
{
    if (m_tjetty == nullptr) {
        return;
    }

    urma_status_t ret = urma_unimport_jetty(m_tjetty);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to unimport jetty, ret: %d", static_cast<int>(ret));
    }
    m_tjetty = nullptr;
}

void jetty_mgr_uniconn::delete_share_jfr(void)
{
    if (m_share_jfr == nullptr) {
        return;
    }
 
    urma_status_t ret = urma_delete_jfr(m_share_jfr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to delete share jfr, ret: %d", static_cast<int>(ret));
    }
    m_share_jfr = nullptr;
}

void jetty_mgr_uniconn::delete_jetty(void)
{
    if (m_jetty == nullptr) {
        return;
    }

    if (m_p_server != nullptr) {
        m_p_server->erase_from_m_jetty_mgr_map(m_jetty->jetty_id.id);
    }

    urma_status_t ret = urma_delete_jetty(m_jetty);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to delete jetty, ret: %d", static_cast<int>(ret));
    }
    m_jetty = nullptr;

    delete_share_jfr();
}

void jetty_mgr_uniconn::modify_share_jfr_err(void)
{
    if (m_share_jfr == nullptr) {
        return;
    }

    urma_jfr_attr_t attr = {0};
    attr.mask = JFR_STATE;
    attr.state = URMA_JFR_STATE_ERROR;

    urma_status_t ret = urma_modify_jfr(m_share_jfr, &attr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to modify jfr to URMA_JFR_STATE_ERROR, ret: %d", static_cast<int>(ret));
    }
}

void jetty_mgr_uniconn::modify_jetty_err(void)
{
    if (m_jetty == nullptr) {
        return;
    }

    urma_jetty_attr_t attr = {0};
    attr.mask = JETTY_STATE;
    attr.state = URMA_JETTY_STATE_ERROR;

    m_modify_jetty2err = true;
    urma_status_t ret = urma_modify_jetty(m_jetty, &attr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to modify jetty to URMA_JETTY_STATE_ERROR, ret: %d", static_cast<int>(ret));
        /* If modify jetty to error state failed, don't wait URMA_CR_WR_FLUSH_ERR_DONE CR */
        m_flush_err_done = true;
    }

    modify_share_jfr_err();
}

void jetty_mgr_uniconn::delete_urma_channel_resource(void) noexcept
{
    modify_jetty_err();

    unimport_dst_tseg();
    unbind_jetty();
    unimport_tjetty();

    wait_flush_err_done();
    delete_jetty();
}

dlock_status_t jetty_mgr_uniconn::construct_jetty_xchg_info(struct urma_init_body *jetty_info,
    jetty_mgr *p_jetty_mgr) const
{
    jetty_mgr_uniconn *p_mgr_uniconn = dynamic_cast<jetty_mgr_uniconn *>(p_jetty_mgr);
    if (jetty_info == nullptr || p_jetty_mgr == nullptr || p_jetty_mgr->m_urma_ctx == nullptr) {
        DLOCK_LOG_ERR("Invalid para");
        return DLOCK_FAIL;
    }
    jetty_info->tp_mode = p_jetty_mgr->m_tp_mode;
    static_cast<void>(memcpy(&(jetty_info->jetty_id), &(p_mgr_uniconn->m_jetty->jetty_id), sizeof(urma_jetty_id_t)));
    jetty_info->token = get_jfr_token();
    jetty_info->flag.bs.token_policy = get_token_policy();

#ifdef UB_AGG
    return construct_urma_bond_id_xchg_info(jetty_info);
#else
    return DLOCK_SUCCESS;
#endif /* UB_AGG */
}

dlock_status_t jetty_mgr_uniconn::import_jetty(const urma_jetty_id_t jetty_id, uint32_t token_policy, uint32_t token)
{
    urma_rjetty_t rjetty = {0};
    urma_token_t token_value = {
        .token = token,
    };

    rjetty.jetty_id = jetty_id;
    rjetty.trans_mode = URMA_TM_RC;
    rjetty.flag.bs.token_policy = token_policy;
    rjetty.flag.bs.order_type = URMA_OL;
    rjetty.tp_type = URMA_RTP;

    if (m_urma_ctx->get_urma_dev_type() == URMA_TRANSPORT_UB) {
        rjetty.type = URMA_JETTY;
    } else {
        DLOCK_LOG_ERR("urma device type is not UB!");
        return DLOCK_FAIL;
    }

    m_tjetty = urma_import_jetty(m_urma_ctx->m_urma_ctx, &rjetty, &token_value);
    if (m_tjetty == nullptr) {
        DLOCK_LOG_ERR("Failed to import jetty");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_uniconn::bind_jetty(void) const
{
    urma_status_t ret = urma_bind_jetty(m_jetty, m_tjetty);
    if ((ret != URMA_SUCCESS) && (ret != URMA_EEXIST)) {
        DLOCK_LOG_ERR("Failed to bind jetty");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

void jetty_mgr_uniconn::fill_send_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge, uint64_t wr_id, uint32_t len) const
{
    static_cast<void>(memset(wr, 0, sizeof(urma_jfs_wr_t)));
    wr->flag.bs.complete_enable = URMA_COMPLETE_ENABLE;
    wr->flag.bs.solicited_enable = URMA_SOLICITED_DISABLE;
    if (len <= m_jetty->jetty_cfg.jfs_cfg.max_inline_data) {
        wr->flag.bs.inline_flag = URMA_INLINE_ENABLE;
    }
    wr->next = nullptr;
    wr->opcode = URMA_OPC_SEND;
    wr->user_ctx = static_cast<uintptr_t>(wr_id);
    wr->tjetty = m_tjetty;

    wr->send.src.sge = src_sge;
    wr->send.src.num_sge = 1;
    wr->send.tseg = nullptr;
}

dlock_status_t jetty_mgr_uniconn::post_send(uint8_t *buf, uint32_t len, uint64_t wr_id) const
{
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr = nullptr;
    urma_sge_t src_sge;
    urma_status_t ret;

    src_sge.addr = reinterpret_cast<uint64_t>(buf);
    src_sge.len = len;
    src_sge.tseg = m_urma_ctx->m_local_tseg;

    fill_send_wr(&wr, &src_sge, wr_id, len);

    ret = urma_post_jetty_send_wr(m_jetty, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("jetty post send error");
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}

void jetty_mgr_uniconn::fill_recv_wr(urma_jfr_wr_t *wr, urma_sge_t *dst_sge, uint64_t wr_id) const
{
    static_cast<void>(memset(wr, 0, sizeof(urma_jfr_wr_t)));
    wr->next = nullptr;
    wr->src.sge = dst_sge;
    wr->src.num_sge = 1;
    wr->user_ctx = static_cast<uintptr_t>(wr_id);
}


dlock_status_t jetty_mgr_uniconn::post_recv(uint32_t len, uint64_t wr_id) const
{
    urma_jfr_wr_t wr;
    urma_jfr_wr_t *bad_wr = nullptr;
    urma_sge_t dst_sge;
    urma_status_t ret;

    dst_sge.addr = reinterpret_cast<uint64_t>(m_p_rx_buf->buf);
    dst_sge.len = len;
    dst_sge.tseg = m_urma_ctx->m_local_tseg;

    fill_recv_wr(&wr, &dst_sge, wr_id);

    ret = urma_post_jetty_recv_wr(m_jetty, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("jetty post recv error");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_uniconn::post_recv(uint32_t len) const
{
    return post_recv(len, reinterpret_cast<uint64_t>(m_p_rx_buf));
}

dlock_status_t jetty_mgr_uniconn::post_recv_buf(struct urma_buf *p_rx_buf) const
{
    urma_jfr_wr_t wr;
    urma_jfr_wr_t *bad_wr = nullptr;
    urma_sge_t dst_sge;
    urma_status_t ret;

    dst_sge.addr = reinterpret_cast<uint64_t>(p_rx_buf->buf);
    dst_sge.len = URMA_MTU;
    dst_sge.tseg = m_urma_ctx->m_local_tseg;

    fill_recv_wr(&wr, &dst_sge, reinterpret_cast<uint64_t>(p_rx_buf));

    ret = urma_post_jetty_recv_wr(m_jetty, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("jetty post recv error");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_uniconn::post_recv_all(void)
{
    struct urma_buf *p_rx_buf = m_p_rx_buf;
    uint32_t jfr_depth = get_jfr_depth();
    urma_jfr_wr_t wr;
    urma_jfr_wr_t *bad_wr = nullptr;
    urma_sge_t dst_sge;
    uint32_t count = 0;
    urma_status_t ret;

    dst_sge.len = URMA_MTU;
    dst_sge.tseg = m_urma_ctx->m_local_tseg;
    while ((p_rx_buf != nullptr) && (count < jfr_depth)) {
        dst_sge.addr = reinterpret_cast<uint64_t>(p_rx_buf->buf);

        fill_recv_wr(&wr, &dst_sge, reinterpret_cast<uint64_t>(p_rx_buf));

        ret = urma_post_jetty_recv_wr(m_jetty, &wr, &bad_wr);
        if (ret != URMA_SUCCESS) {
            DLOCK_LOG_ERR("jetty post recv error");
            return DLOCK_FAIL;
        }
        p_rx_buf = p_rx_buf->next;
        count++;
    }

    std::unique_lock<std::mutex> locker(m_idle_rx_buf_pool_lock, std::defer_lock);
    while (p_rx_buf != nullptr) {
        locker.lock();
        m_idle_rx_buf_pool.push_back(p_rx_buf);
        locker.unlock();
        p_rx_buf = p_rx_buf->next;
    }
    return DLOCK_SUCCESS;
}

void jetty_mgr_uniconn::fill_write_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge,
    urma_sge_t *dst_sge, uint64_t wr_id, uint32_t len) const
{
    static_cast<void>(memset(wr, 0, sizeof(urma_jfs_wr_t)));
    wr->flag.bs.complete_enable = URMA_COMPLETE_ENABLE;
    wr->flag.bs.solicited_enable = URMA_SOLICITED_DISABLE;
    if (len <= m_jetty->jetty_cfg.jfs_cfg.max_inline_data) {
        wr->flag.bs.inline_flag = URMA_INLINE_ENABLE;
    }
    wr->tjetty = m_tjetty;
    wr->next = nullptr;
    wr->opcode = URMA_OPC_WRITE;
    wr->user_ctx = static_cast<uintptr_t>(wr_id);

    wr->rw.src.sge = src_sge;
    wr->rw.src.num_sge = 1;

    wr->rw.dst.sge = dst_sge;
    wr->rw.dst.num_sge = 1;
}

dlock_status_t jetty_mgr_uniconn::post_write(urma_target_seg_t *src_tseg,
    uint8_t *buf, uint32_t len, uint64_t wr_id) const
{
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr = nullptr;
    urma_sge_t src_sge;
    urma_sge_t dst_sge;
    urma_status_t ret;

    src_sge.addr = reinterpret_cast<uint64_t>(buf);
    src_sge.len = len;
    src_sge.tseg = src_tseg;

    dst_sge.addr = m_dst_tseg->seg.ubva.va;
    dst_sge.len = static_cast<uint32_t>(m_dst_tseg->seg.len);
    dst_sge.tseg = m_dst_tseg;

    fill_write_wr(&wr, &src_sge, &dst_sge, wr_id, len);

    ret = urma_post_jetty_send_wr(m_jetty, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("jetty post send error");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

void jetty_mgr_uniconn::fill_base_wr(urma_jfs_wr_t *wr, uint64_t wr_id) const
{
    static_cast<void>(memset(wr, 0, sizeof(urma_jfs_wr_t)));
    wr->flag.bs.complete_enable = URMA_COMPLETE_ENABLE;
    wr->flag.bs.solicited_enable = URMA_SOLICITED_DISABLE;
    wr->flag.bs.inline_flag = URMA_INLINE_DISABLE;
    wr->tjetty = m_tjetty;
    wr->user_ctx = static_cast<uintptr_t>(wr_id);
    wr->next = nullptr;
}

dlock_status_t jetty_mgr_uniconn::post_read(uint32_t offset, uint64_t wr_id) const
{
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr = nullptr;
    urma_sge_t src_sge;
    urma_sge_t dst_sge;
    urma_status_t ret;

    fill_read_sge(&src_sge, &dst_sge, offset);
    fill_base_wr(&wr, wr_id);
    fill_read_wr(&wr, &src_sge, &dst_sge);

    ret = urma_post_jetty_send_wr(m_jetty, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("post jetty wr read error, ret: %u", ret);
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_uniconn::post_faa(uint32_t offset, uint64_t operand, uint64_t wr_id) const
{
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr = nullptr;
    urma_sge_t src_sge;
    urma_sge_t dst_sge;
    urma_status_t ret;

    fill_faa_cas_sge(&src_sge, &dst_sge, offset);
    fill_base_wr(&wr, wr_id);
    fill_faa_wr(&wr, &src_sge, &dst_sge, operand);

    ret = urma_post_jetty_send_wr(m_jetty, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("post jetty wr faa error, ret: %u", ret);
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_uniconn::post_cas(uint32_t offset, uint64_t cmp_data, uint64_t swap_data, uint64_t wr_id) const
{
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr = nullptr;
    urma_sge_t src_sge;
    urma_sge_t dst_sge;
    urma_status_t ret;

    fill_faa_cas_sge(&src_sge, &dst_sge, offset);
    fill_base_wr(&wr, wr_id);
    fill_cas_wr(&wr, &src_sge, &dst_sge, cmp_data, swap_data);

    ret = urma_post_jetty_send_wr(m_jetty, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("post jetty wr cas error, ret: %u", ret);
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}

#ifdef UB_AGG
dlock_status_t jetty_mgr_uniconn::get_urma_bond_id_info(urma_bond_id_info_out_t *bond_id_info) const
{
    urma_bond_id_info_in_t in = {
        .jetty = m_jetty,
        .type = URMA_JETTY,
    };
    urma_user_ctl_in_t user_ctl_in = {
        .addr = (uint64_t)&in,
        .len = sizeof(urma_bond_id_info_in_t),
        .opcode = URMA_USER_CTL_BOND_GET_ID_INFO,
    };

    urma_user_ctl_out_t user_ctl_out = {
        .addr = (uint64_t)bond_id_info,
        .len = sizeof(urma_bond_id_info_out_t),
    };

    if (urma_user_ctl(m_jetty->urma_ctx, &user_ctl_in, &user_ctl_out)) {
        DLOCK_LOG_ERR("failed to get ub bond jetty id info");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_uniconn::add_urma_bond_rjetty_id_info(urma_bond_add_rjetty_id_info_in_t *info) const
{
    urma_user_ctl_in_t user_ctl_in = {
        .addr = (uint64_t)info,
        .len = sizeof(urma_bond_add_rjetty_id_info_in_t),
        .opcode = URMA_USER_CTL_BOND_ADD_RJETTY_ID_INFO,
    };
    urma_user_ctl_out_t user_ctl_out = {
        .addr = 0,
        .len = 0,
    };

    if (urma_user_ctl(m_urma_ctx->m_urma_ctx, &user_ctl_in, &user_ctl_out)) {
        DLOCK_LOG_ERR("failed to add urma bond rjetty id info");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}
#endif /* UB_AGG */
};
