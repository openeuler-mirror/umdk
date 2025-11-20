/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : jetty_mgr_sepconn.cpp
 * Description   : jetty manager seperate connection mode
 * History       : create file & add functions
 * 1.Date        : 2022-10-19
 * Author        : wujie
 * Modification  : Created file
 */

#include <cstring>

#include "dlock_types.h"
#include "jetty_mgr_sepconn.h"

#include <netinet/in.h>

#include "dlock_common.h"
#include "dlock_log.h"
#include "dlock_server.h"
#include "utils.h"

namespace dlock {
dlock_status_t jetty_mgr_sepconn::create_jfs(void)
{
    urma_jfs_cfg_t jfs_cfg;

    static_cast<void>(memset(&jfs_cfg, 0, sizeof(urma_jfs_cfg_t)));
    jfs_cfg_init(jfs_cfg, URMA_TM_RM, URMA_OI);
    m_jfs = urma_create_jfs(m_urma_ctx->m_urma_ctx, &jfs_cfg);
    if (m_jfs == nullptr) {
        DLOCK_LOG_ERR("Failed to create jfs");
        return DLOCK_FAIL;
    }

    m_local_id = m_jfs->jfs_id.id;
    if (m_p_server != nullptr) {
        m_p_server->add_to_m_jetty_mgr_map(m_local_id, this);
    }

    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_sepconn::create_jfr(void)
{
    urma_jfr_cfg_t jfr_cfg;

    static_cast<void>(memset(&jfr_cfg, 0, sizeof(urma_jfr_cfg_t)));
    jfr_cfg_init(jfr_cfg, URMA_TM_RM, URMA_OI);
    m_jfr = urma_create_jfr(m_urma_ctx->m_urma_ctx, &jfr_cfg);
    if (m_jfr == nullptr) {
        DLOCK_LOG_ERR("Failed to create jfr");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

bool jetty_mgr_sepconn::check_construct_succeed(jetty_mgr_sepconn *p_mgr_sepconn, bool rx_buf_check) const
{
    if ((p_mgr_sepconn->m_jfs == nullptr) || (p_mgr_sepconn->m_jfr == nullptr)) {
        DLOCK_LOG_ERR("error to init qp");
        return false;
    }
    if ((rx_buf_check) && (p_mgr_sepconn->m_p_rx_buf == nullptr)) {
        DLOCK_LOG_ERR("error to get buf");
        return false;
    }
    if ((m_dlock_cipher->m_ctx == nullptr) || (m_dlock_cipher->m_key == nullptr)) {
        DLOCK_LOG_ERR("error to init dlock cipher");
        return false;
    }

    return true;
}

jetty_mgr_sepconn::jetty_mgr_sepconn(urma_ctx *p_urma_ctx, dlock_server *p_server) noexcept
    : jetty_mgr(p_urma_ctx, p_server), m_jfs(nullptr), m_jfr(nullptr), m_tjfr(nullptr)
{
    m_tp_mode = SEPERATE_CONN;
}

jetty_mgr_sepconn::~jetty_mgr_sepconn() noexcept
{
}

dlock_status_t jetty_mgr_sepconn::jetty_mgr_sepconn_init(urma_ctx *p_urma_ctx, urma_jfc_t *p_jfc,
    uint32_t num_buf)
{
    dlock_status_t ret;

    ret = jetty_mgr_init(p_urma_ctx, p_jfc, num_buf);
    if (ret != DLOCK_SUCCESS) {
        return ret;
    }

    ret = create_jfs();
    if (ret != DLOCK_SUCCESS) {
        return ret;
    }

    ret = create_jfr();
    if (ret != DLOCK_SUCCESS) {
        return ret;
    }

    return DLOCK_SUCCESS;
}

void jetty_mgr_sepconn::unimport_tjfr(void)
{
    if (m_tjfr == nullptr) {
        return;
    }

    urma_status_t ret = urma_unimport_jfr(m_tjfr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to unimport jfr, ret: %d", static_cast<int>(ret));
    }
    m_tjfr = nullptr;
}

void jetty_mgr_sepconn::delete_jfr(void)
{
    if (m_jfr == nullptr) {
        return;
    }

    urma_status_t ret = urma_delete_jfr(m_jfr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to delete jfr, ret: %d", static_cast<int>(ret));
    }
    m_jfr = nullptr;
}

void jetty_mgr_sepconn::delete_jfs(void)
{
    if (m_jfs == nullptr) {
        return;
    }

    if (m_p_server != nullptr) {
        m_p_server->erase_from_m_jetty_mgr_map(m_jfs->jfs_id.id);
    }

    urma_status_t ret = urma_delete_jfs(m_jfs);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to delete jfs, ret: %d", static_cast<int>(ret));
    }
    m_jfs = nullptr;
}

void jetty_mgr_sepconn::modify_jfr_err(void)
{
    if (m_jfr == nullptr) {
        return;
    }

    urma_jfr_attr_t attr = {0};
    attr.mask = JFR_STATE;
    attr.state = URMA_JFR_STATE_ERROR;

    urma_status_t ret = urma_modify_jfr(m_jfr, &attr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to modify jfr to URMA_JFR_STATE_ERROR, ret: %d", static_cast<int>(ret));
    }
}

void jetty_mgr_sepconn::modify_jfs_err(void)
{
    if (m_jfs == nullptr) {
        return;
    }

    urma_jfs_attr_t attr = {0};
    attr.mask = JFS_STATE;
    attr.state = URMA_JETTY_STATE_ERROR;

    m_modify_jetty2err = true;
    urma_status_t ret = urma_modify_jfs(m_jfs, &attr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to modify jfs to URMA_JETTY_STATE_ERROR, ret: %d", static_cast<int>(ret));
        /* If modify jfs to error state failed, don't wait URMA_CR_WR_FLUSH_ERR_DONE CR */
        m_flush_err_done = true;
    }
}

void jetty_mgr_sepconn::delete_urma_channel_resource(void) noexcept
{
    modify_jfr_err();
    modify_jfs_err();

    unimport_tjfr();
    unimport_dst_tseg();

    wait_flush_err_done();
    delete_jfr();
    delete_jfs();
}

dlock_status_t jetty_mgr_sepconn::construct_jetty_xchg_info(struct urma_init_body *jetty_info,
    jetty_mgr *p_jetty_mgr) const
{
    jetty_mgr_sepconn *p_sepconn_mgr = dynamic_cast<jetty_mgr_sepconn *>(p_jetty_mgr);
    if (jetty_info == nullptr || p_jetty_mgr == nullptr || p_jetty_mgr->m_urma_ctx == nullptr) {
        DLOCK_LOG_ERR("Invalid para");
        return DLOCK_FAIL;
    }
    jetty_info->tp_mode = p_jetty_mgr->m_tp_mode;
    static_cast<void>(memcpy(&(jetty_info->jfr_id), &(p_sepconn_mgr->m_jfr->jfr_id), sizeof(urma_jfr_id_t)));
    jetty_info->token = get_jfr_token();
    jetty_info->flag.bs.token_policy = get_token_policy();

#ifdef UB_AGG
    return construct_urma_bond_id_xchg_info(jetty_info);
#else
    return DLOCK_SUCCESS;
#endif /* UB_AGG */
}

dlock_status_t jetty_mgr_sepconn::import_jfr(const urma_jfr_id_t jfr_id, uint32_t token_policy, uint32_t token)
{
    urma_rjfr_t remote_jfr;
    urma_token_t token_value = {
        .token = token,
    };

    static_cast<void>(memset(&remote_jfr, 0, sizeof(urma_rjfr_t)));
    static_cast<void>(memcpy(&(remote_jfr.jfr_id), &jfr_id, sizeof(urma_jfr_id_t)));
    remote_jfr.trans_mode = URMA_TM_RM;
    remote_jfr.flag.bs.token_policy = token_policy;
    m_tjfr = urma_import_jfr(m_urma_ctx->m_urma_ctx, &remote_jfr, &token_value);
    if (m_tjfr == nullptr) {
        DLOCK_LOG_ERR("Failed to import jfr");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_sepconn::post_send(uint8_t *buf, uint32_t len, uint64_t wr_id) const
{
    urma_target_seg_t *src_tseg = nullptr;
    urma_jfs_wr_flag_t flag;

    flag.value = 0;
    flag.bs.complete_enable = 1;

    if (len <= m_jfs->jfs_cfg.max_inline_data) {
        flag.bs.inline_flag = 1;
    } else {
        src_tseg = m_urma_ctx->m_local_tseg;
    }

    if (urma_send(m_jfs, m_tjfr, src_tseg, reinterpret_cast<uint64_t>(buf), len,
        flag, static_cast<uintptr_t>(wr_id)) != URMA_SUCCESS) {
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}


dlock_status_t jetty_mgr_sepconn::post_recv(uint32_t len, uint64_t wr_id) const
{
    if (urma_recv(m_jfr, m_urma_ctx->m_local_tseg, reinterpret_cast<uint64_t>(m_p_rx_buf->buf), len,
        reinterpret_cast<uintptr_t>(wr_id)) != URMA_SUCCESS) {
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_sepconn::post_recv(uint32_t len) const
{
    if (urma_recv(m_jfr, m_urma_ctx->m_local_tseg, reinterpret_cast<uint64_t>(m_p_rx_buf->buf), len,
        reinterpret_cast<uintptr_t>(m_p_rx_buf)) != URMA_SUCCESS) {
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_sepconn::post_recv_buf(struct urma_buf *p_rx_buf) const
{
    if (urma_recv(m_jfr, m_urma_ctx->m_local_tseg, reinterpret_cast<uint64_t>(p_rx_buf->buf), URMA_MTU,
        reinterpret_cast<uintptr_t>(p_rx_buf)) != URMA_SUCCESS) {
        DLOCK_LOG_ERR("Failed to post recv");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_sepconn::post_recv_all(void)
{
    struct urma_buf *p_rx_buf = m_p_rx_buf;
    uint32_t count = 0;
    urma_status_t ret;

    while ((p_rx_buf != nullptr) && (count < m_jfr->jfr_cfg.depth)) {
        ret = urma_recv(m_jfr, m_urma_ctx->m_local_tseg, reinterpret_cast<uint64_t>(p_rx_buf->buf), URMA_MTU,
            reinterpret_cast<uintptr_t>(p_rx_buf));
        if (ret != URMA_SUCCESS) {
            DLOCK_LOG_DEBUG("Failed to post recv");
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

dlock_status_t jetty_mgr_sepconn::post_write(urma_target_seg_t *src_tseg,
    uint8_t *buf, uint32_t len, uint64_t wr_id) const
{
    urma_jfs_wr_flag_t flag;

    flag.value = 0;
    flag.bs.complete_enable = 1;

    if (urma_write(m_jfs, m_tjfr, m_dst_tseg, src_tseg, reinterpret_cast<uint64_t>(m_dst_tseg->seg.ubva.va),
        reinterpret_cast<uint64_t>(buf), len, flag, static_cast<uintptr_t>(wr_id)) != URMA_SUCCESS) {
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

void jetty_mgr_sepconn::fill_base_wr(urma_jfs_wr_t *wr, uint64_t wr_id) const
{
    static_cast<void>(memset(wr, 0, sizeof(urma_jfs_wr_t)));
    wr->flag.bs.complete_enable = URMA_COMPLETE_ENABLE;
    wr->flag.bs.solicited_enable = URMA_SOLICITED_DISABLE;
    wr->flag.bs.inline_flag = URMA_INLINE_DISABLE;
    wr->tjetty = m_tjfr;
    wr->user_ctx = static_cast<uintptr_t>(wr_id);
    wr->next = nullptr;
}

dlock_status_t jetty_mgr_sepconn::post_read(uint32_t offset, uint64_t wr_id) const
{
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr = nullptr;
    urma_sge_t src_sge;
    urma_sge_t dst_sge;
    urma_status_t ret;

    fill_read_sge(&src_sge, &dst_sge, offset);
    fill_base_wr(&wr, wr_id);
    fill_read_wr(&wr, &src_sge, &dst_sge);

    ret = urma_post_jfs_wr(m_jfs, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("post jetty wr read error, ret: %u", ret);
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_sepconn::post_faa(uint32_t offset, uint64_t operand, uint64_t wr_id) const
{
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr = nullptr;
    urma_sge_t src_sge;
    urma_sge_t dst_sge;
    urma_status_t ret;

    fill_faa_cas_sge(&src_sge, &dst_sge, offset);
    fill_base_wr(&wr, wr_id);
    fill_faa_wr(&wr, &src_sge, &dst_sge, operand);

    ret = urma_post_jfs_wr(m_jfs, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("post jfs wr faa error, ret: %u", ret);
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_sepconn::post_cas(uint32_t offset, uint64_t cmp_data, uint64_t swap_data, uint64_t wr_id) const
{
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr = nullptr;
    urma_sge_t src_sge;
    urma_sge_t dst_sge;
    urma_status_t ret;

    fill_faa_cas_sge(&src_sge, &dst_sge, offset);
    fill_base_wr(&wr, wr_id);
    fill_cas_wr(&wr, &src_sge, &dst_sge, cmp_data, swap_data);

    ret = urma_post_jfs_wr(m_jfs, &wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("post jfs wr cas error, ret: %u", ret);
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}

#ifdef UB_AGG
dlock_status_t jetty_mgr_sepconn::get_urma_bond_id_info(urma_bond_id_info_out_t *bond_id_info) const
{
    urma_bond_id_info_in_t in = {
        .jfr = m_jfr,
        .type = URMA_JFR,
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

    if (urma_user_ctl(m_jfr->urma_ctx, &user_ctl_in, &user_ctl_out)) {
        DLOCK_LOG_ERR("failed to get ub bond jfr id info");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t jetty_mgr_sepconn::add_urma_bond_rjfr_id_info(urma_bond_add_rjfr_id_info_in_t *info) const
{
    urma_user_ctl_in_t user_ctl_in = {
        .addr = (uint64_t)info,
        .len = sizeof(urma_bond_add_rjfr_id_info_in_t),
        .opcode = URMA_USER_CTL_BOND_ADD_RJFR_ID_INFO,
    };
    urma_user_ctl_out_t user_ctl_out = {
        .addr = 0,
        .len = 0,
    };

    if (urma_user_ctl(m_urma_ctx->m_urma_ctx, &user_ctl_in, &user_ctl_out)) {
        DLOCK_LOG_ERR("failed to add urma bond rjfr id info");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}
#endif /* UB_AGG */
};
