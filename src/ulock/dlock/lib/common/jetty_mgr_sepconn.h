/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : jetty_mgr_sepconn.h
 * Description   : jetty manager seperate connection transport mode
 * History       : create file & add functions
 * 1.Date        : 2022-10-18
 * Author        : wujie
 * Modification  : Created file
 */

#ifndef __JETTY_MGR_SEPCONN_H__
#define __JETTY_MGR_SEPCONN_H__

#include <mutex>

#ifdef UB_AGG
#include "urma_ubagg.h"
#endif /* UB_AGG */

#include "dlock_types.h"
#include "urma_ctx.h"
#include "dlock_cipher.h"
#include "jetty_mgr.h"

namespace dlock {
class dlock_client;
class dlock_server;
class client_entry_s;

class jetty_mgr_sepconn : public jetty_mgr {
    friend class dlock_client;
    friend class dlock_server;
    friend class client_entry_s;
public:
    jetty_mgr_sepconn() = delete;
    explicit jetty_mgr_sepconn(urma_ctx *p_urma_ctx, dlock_server *p_server) noexcept;
    ~jetty_mgr_sepconn() noexcept override;
    dlock_status_t jetty_mgr_sepconn_init(urma_ctx *p_urma_ctx, urma_jfc_t *p_jfc, uint32_t num_buf);
    dlock_status_t post_recv(uint32_t len, uint64_t wr_id) const override;
    dlock_status_t post_recv(uint32_t len) const override;
    dlock_status_t post_recv_buf(struct urma_buf* p_rx_buf) const override;
    dlock_status_t post_recv_all(void) override;
    dlock_status_t post_send(uint8_t *buf, uint32_t len, uint64_t wr_id) const override;
    dlock_status_t construct_jetty_xchg_info(struct urma_init_body *jetty_info, jetty_mgr *p_jetty_mgr) const override;
    dlock_status_t import_jfr(const urma_jfr_id_t jfr_id, uint32_t token_policy, uint32_t token);
    bool check_construct_succeed(jetty_mgr_sepconn *p_mgr_sepconn, bool rx_buf_check) const;
    dlock_status_t post_write(urma_target_seg_t *src_tseg,
        uint8_t *buf, uint32_t len, uint64_t wr_id) const override;
    void delete_urma_channel_resource(void) noexcept override;

    dlock_status_t post_read(uint32_t offset, uint64_t wr_id) const override;
    dlock_status_t post_faa(uint32_t offset, uint64_t operand, uint64_t wr_id) const override;
    dlock_status_t post_cas(uint32_t offset, uint64_t cmp_data, uint64_t swap_data, uint64_t wr_id) const override;

#ifdef UB_AGG
    dlock_status_t add_urma_bond_rjfr_id_info(urma_bond_add_rjfr_id_info_in_t *info) const;
#endif /* UB_AGG */

private:
    dlock_status_t create_jfs(void);
    dlock_status_t create_jfr(void);
    void unimport_tjfr(void);
    void delete_jfr(void);
    void delete_jfs(void);
    void modify_jfr_err(void);
    void modify_jfs_err(void);

    void fill_base_wr(urma_jfs_wr_t *wr, uint64_t wr_id) const override;

#ifdef UB_AGG
    dlock_status_t get_urma_bond_id_info(urma_bond_id_info_out_t *bond_id_info) const override;
#endif /* UB_AGG */

    urma_jfs_t *m_jfs;
    urma_jfr_t *m_jfr;

    /* client only */
    urma_target_jetty_t *m_tjfr;
};
};
#endif
