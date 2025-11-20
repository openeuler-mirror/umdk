/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : jetty_mgr_uniconn.h
 * Description   : jetty manager uni connection transport mode
 * History       : create file & add functions
 * 1.Date        : 2022-10-18
 * Author        : wujie
 * Modification  : Created file
 */

#ifndef __JETTY_MGR_UNICONN_H__
#define __JETTY_MGR_UNICONN_H__

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

class jetty_mgr_uniconn : public jetty_mgr {
    friend class dlock_client;
    friend class dlock_server;
    friend class client_entry_s;
public:
    jetty_mgr_uniconn() = delete;
    explicit jetty_mgr_uniconn(urma_ctx *p_urma_ctx, dlock_server *p_server) noexcept;
    ~jetty_mgr_uniconn() noexcept override;
    dlock_status_t jetty_mgr_uniconn_init(urma_ctx *p_urma_ctx, urma_jfc_t *p_jfc, uint32_t num_buf);
    void fill_recv_wr(urma_jfr_wr_t *wr, urma_sge_t *dst_sge, uint64_t wr_id) const;
    dlock_status_t post_recv(uint32_t len, uint64_t wr_id) const override;
    dlock_status_t post_recv(uint32_t len) const override;
    dlock_status_t post_recv_buf(struct urma_buf* p_rx_buf) const override;
    dlock_status_t post_recv_all(void) override;
    void fill_send_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge, uint64_t wr_id, uint32_t len) const;
    dlock_status_t post_send(uint8_t *buf, uint32_t len, uint64_t wr_id) const override;
    dlock_status_t construct_jetty_xchg_info(struct urma_init_body *jetty_info, jetty_mgr *p_jetty_mgr) const override;
    dlock_status_t create_jetty(void);
    dlock_status_t import_jetty(const urma_jetty_id_t jetty_id, uint32_t token_policy, uint32_t token);
    dlock_status_t bind_jetty(void) const;
    bool check_construct_succeed(jetty_mgr_uniconn *p_mgr_uniconn, bool rx_buf_check) const;
    void fill_write_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge,
        urma_sge_t *dst_sge, uint64_t wr_id, uint32_t len) const;
    dlock_status_t post_write(urma_target_seg_t *src_tseg,
        uint8_t *buf, uint32_t len, uint64_t wr_id) const override;
    void delete_urma_channel_resource(void) noexcept override;

    dlock_status_t post_read(uint32_t offset, uint64_t wr_id) const override;
    dlock_status_t post_faa(uint32_t offset, uint64_t operand, uint64_t wr_id) const override;
    dlock_status_t post_cas(uint32_t offset, uint64_t cmp_data, uint64_t swap_data, uint64_t wr_id) const override;

#ifdef UB_AGG
    dlock_status_t add_urma_bond_rjetty_id_info(urma_bond_add_rjetty_id_info_in_t *info) const;
#endif /* UB_AGG */

private:
    inline uint32_t get_jfr_depth(void) const
    {
        if (m_urma_ctx->get_urma_dev_type() == URMA_TRANSPORT_UB) {
            return m_jetty->jetty_cfg.shared.jfr->jfr_cfg.depth;
        }
 
        return m_jetty->jetty_cfg.jfr_cfg->depth;
    }
    void unbind_jetty(void);
    void unimport_tjetty(void);
    void delete_share_jfr(void);
    void delete_jetty(void);
    void modify_share_jfr_err(void);
    void modify_jetty_err(void);

    void fill_base_wr(urma_jfs_wr_t *wr, uint64_t wr_id) const override;

#ifdef UB_AGG
    dlock_status_t get_urma_bond_id_info(urma_bond_id_info_out_t *bond_id_info) const override;
#endif /* UB_AGG */

    urma_jfr_t *m_share_jfr; /* for UB dev */
    urma_jetty_t *m_jetty;
    /* client only */
    urma_target_jetty_t *m_tjetty;
};
};
#endif
