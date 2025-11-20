/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : jetty_mgr.h
 * Description   : jetty manager
 * History       : create file & add functions
 * 1.Date        : 2022-03-01
 * Author        : jiasiyuan
 * Modification  : Created file
 */

#ifndef __JETTY_MGR_H__
#define __JETTY_MGR_H__

#include <mutex>
#include <vector>
#include <cstring>

#ifdef UB_AGG
#include "urma_ubagg.h"
#endif /* UB_AGG */

#include "dlock_types.h"
#include "urma_ctx.h"
#include "dlock_cipher.h"
#include "dlock_common.h"

namespace dlock {
class dlock_client;
class dlock_server;
class client_entry_s;

constexpr unsigned int GID_INDEX = 3;

typedef enum jetty_mgr_state {
    JETTY_MGR_ACTIVE = 0,
    JETTY_MGR_BUSY,
    JETTY_MGR_INVALID
} jetty_mgr_state_t;

class jetty_mgr {
    friend class dlock_client;
    friend class dlock_server;
    friend class client_entry_s;
    friend class jetty_mgr_uniconn;
    friend class jetty_mgr_sepconn;
public:
    jetty_mgr() = delete;
    explicit jetty_mgr(urma_ctx *p_urma_ctx, dlock_server *p_server) noexcept;
    virtual ~jetty_mgr() noexcept;
    dlock_status_t jetty_mgr_init(urma_ctx *p_urma_ctx, urma_jfc_t *p_jfc, uint32_t num_buf);
    void jetty_mgr_deinit(void);
    virtual dlock_status_t post_recv(uint32_t len, uint64_t wr_id) const = 0;
    virtual dlock_status_t post_recv(uint32_t len) const = 0;
    virtual dlock_status_t post_recv_buf(struct urma_buf* p_rx_buf) const = 0;
    virtual dlock_status_t post_recv_all(void) = 0;
    void recycle_rx_buf(struct urma_buf *p_rx_buf);
    void replenish_rx_buf(void);
    virtual dlock_status_t post_send(uint8_t *buf, uint32_t len, uint64_t wr_id) const = 0;
    dlock_status_t poll_jfc(uint32_t &comp_len, int async_mode);
    dlock_status_t send_and_get_res(uint8_t *buf, uint32_t len, uint64_t wr_id, uint32_t &comp_len);
    dlock_status_t post_send_after_recv(uint8_t *buf, uint32_t len, uint64_t wr_id) const;
    virtual dlock_status_t construct_jetty_xchg_info(struct urma_init_body *jetty_info,
        jetty_mgr *p_jetty_mgr) const = 0;
    dlock_status_t gen_key(struct dlock_key *key) const;
    dlock_status_t check_recv(uint32_t &comp_len);
    virtual dlock_status_t post_write(urma_target_seg_t *src_tseg,
        uint8_t *buf, uint32_t len, uint64_t wr_id) const = 0;
    dlock_status_t import_seg(urma_seg_t *seg, uint32_t token);
    virtual void delete_urma_channel_resource(void) noexcept = 0;
    void set_peer_info(dlock_conn_peer_t peer_type, int peer_id);
    void get_peer_info(dlock_conn_peer_info_t &peer_info) const;
    int rand_init_next_message_id(void);
    uint16_t generate_message_id(void);
    uint16_t get_next_message_id(void) const;
    void set_next_message_id(uint16_t next_message_id);

    virtual dlock_status_t post_read(uint32_t offset, uint64_t wr_id) const = 0;
    virtual dlock_status_t post_faa(uint32_t offset, uint64_t operand, uint64_t wr_id) const = 0;
    virtual dlock_status_t post_cas(uint32_t offset, uint64_t cmp_data, uint64_t swap_data, uint64_t wr_id) const = 0;
    dlock_status_t poll_jfc_wait_after_post_send(uint64_t wr_id, urma_cr_t *cr) const;
    dlock_status_t post_read_and_get_res(uint64_t wr_id, uint32_t offset, uint64_t *res_val) const;
    dlock_status_t post_faa_and_get_res(uint64_t wr_id, uint32_t offset,
        uint64_t add_val, uint64_t *res_val) const;
    dlock_status_t post_cas_and_get_res(uint64_t wr_id, uint32_t offset,
        uint64_t cmp_val, uint64_t swap_val) const;

    inline bool get_m_modify_jetty2err(void) const
    {
        return m_modify_jetty2err;
    }

    inline bool get_m_flush_err_done(void) const
    {
        return m_flush_err_done;
    }

    inline void set_m_flush_err_done(void)
    {
        m_flush_err_done = true;
    }

    inline uint32_t get_jfr_token(void) const
    {
        return m_jfr_token.token;
    }

    inline uint32_t get_token_policy(void) const
    {
        return m_urma_ctx->get_token_policy();
    }

    uint64_t m_cr_data;
protected:
    void jfs_cfg_init(urma_jfs_cfg_t &jfs_cfg, urma_transport_mode_t tp_mode, uint32_t order_type) const;
    void jfr_cfg_init(urma_jfr_cfg_t &jfr_cfg, urma_transport_mode_t tp_mode, uint32_t order_type) const;
    dlock_status_t get_jfc(void);
    dlock_status_t cmd_msg_cipher(int op_type, uint8_t *buf, uint32_t len, bool ssl_enable) const;
    dlock_status_t cmd_msg_cipher(int op_type, uint8_t *buf_in, uint32_t len, uint8_t *buf_out,
        bool ssl_enable) const;
    void import_seg_flag_init(urma_import_seg_flag_t &flag) const;
    void unimport_dst_tseg(void);
    void delete_jfc(void) noexcept;

    uint8_t m_gid_idx;
    urma_ctx *m_urma_ctx;
    urma_jfc_t *m_jfc;
    trans_mode_t m_tp_mode;

    bool m_is_exe;
    dlock_cipher *m_dlock_cipher;

    /* client only */
    struct urma_buf *m_p_rx_buf;
    std::vector<struct urma_buf *> m_idle_rx_buf_pool;
    std::mutex m_idle_rx_buf_pool_lock;
    uint32_t m_missing_rx_buf_num;
    uint32_t m_ci;

    urma_target_seg_t *m_dst_tseg;
    std::atomic<jetty_mgr_state_t> m_state;
    dlock_conn_peer_info_t m_peer_info;
    uint16_t m_next_message_id;
    
private:
    virtual void fill_base_wr(urma_jfs_wr_t *wr, uint64_t wr_id) const = 0;
    void fill_read_sge(urma_sge_t *src_sge, urma_sge_t *dst_sge, uint32_t offset) const;
    void fill_read_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge, urma_sge_t *dst_sge) const;
    void fill_faa_cas_sge(urma_sge_t *src_sge, urma_sge_t *dst_sge, uint32_t offset) const;
    void fill_faa_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge,
        urma_sge_t *dst_sge, uint64_t operand) const;
    void fill_cas_wr(urma_jfs_wr_t *wr, urma_sge_t *src_sge,
        urma_sge_t *dst_sge, uint64_t cmp_data, uint64_t swap_data) const;

#ifdef UB_AGG
    virtual dlock_status_t get_urma_bond_id_info(urma_bond_id_info_out_t *bond_id_info) const = 0;
    dlock_status_t construct_urma_bond_id_xchg_info(struct urma_init_body *jetty_info) const;
#endif /* UB_AGG */

    void wait_flush_err_done(void);

    uint32_t m_local_id; /* local jetty/jfs id. */
    bool m_modify_jetty2err;
    bool m_flush_err_done;
    dlock_server *m_p_server; /* If it is the client-side jetty_mgr, m_p_server is nullptr. */
    urma_token_t m_jfr_token;
};
};
#endif
