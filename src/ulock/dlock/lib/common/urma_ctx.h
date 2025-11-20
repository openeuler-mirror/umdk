/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : urma_ctx.h
 * Description   : context of URMA
 * History       : create file & add functions
 * 1.Date        : 2022-02-24
 * Author        : jiasiyuan
 * Modification  : Created file
 */

#ifndef __URMA_CTX_H__
#define __URMA_CTX_H__

#include <cstdint>
#include <string>
#include <mutex>
#include <openssl/rand.h>

#include "urma_api.h"
#include "dlock_types.h"
#include "dlock_common.h"

namespace dlock {
class dlock_client;
class dlock_server;
class jetty_mgr;

constexpr unsigned int URMA_DEVICE_NAME_MAX_LEN = 256;
constexpr unsigned int PAGE_SHIFT = 12;
constexpr unsigned int PAGE_SIZE = 0x1 << PAGE_SHIFT;

struct urma_buf {
    uint8_t *buf;
    struct urma_buf *next;
    jetty_mgr *p_jetty_mgr;
    uint32_t jfs_ref_count;
    std::mutex b_mutex; /* To prevent buf and jfs_ref_count from being concurrently read */
};

struct urma_ctx_cfg {
    uint32_t num_buf;
    int num_cqe;
    char *dev_name;
    dlock_eid_t eid;
    trans_mode_t tp_mode;
    bool ub_token_disable;
};

class urma_ctx {
    friend class dlock_client;
    friend class dlock_server;
    friend class jetty_mgr;
    friend class jetty_mgr_sepconn;
    friend class jetty_mgr_uniconn;
public:
    urma_ctx() = delete;
    explicit urma_ctx(const struct urma_ctx_cfg &cfg);
    ~urma_ctx() noexcept;
    struct urma_buf *get_memory();
    void release_memory(struct urma_buf *p_buf) noexcept;
    urma_jfc_t *new_jfc(int num_cqe) const;
    urma_target_seg_t *register_new_seg(uint8_t *buf, uint32_t buf_len, urma_token_t &token_value);
    dlock_status_t gen_token_value(urma_token_t &token_value) const;

    inline urma_transport_type_t get_urma_dev_type(void) const
    {
        return m_urma_ctx->dev->type;
    }

    inline void set_m_jfc_polling(void)
    {
        m_jfc_polling = true;
    }

    inline void clear_m_jfc_polling(void)
    {
        m_jfc_polling = false;
    }

    inline bool is_m_jfc_polling(void)
    {
        return m_jfc_polling;
    }

    inline bool is_ub_token_disable(void) const
    {
        return m_ub_token_disable;
    }

    inline uint32_t get_token_policy(void) const
    {
        return (m_ub_token_disable ? URMA_TOKEN_NONE : URMA_TOKEN_PLAIN_TEXT);
    }

#ifdef UB_AGG
    inline bool is_ub_bonding_dev(void) const
    {
        return m_is_ub_bonding_dev;
    }
#endif /* UB_AGG */

private:
    dlock_status_t init_urma_ctx(void);
    dlock_status_t uninit_urma_ctx(void) noexcept;
    dlock_status_t check_urma_device_state(char *dev_name);
    dlock_status_t check_urma_device_state_by_eid(const dlock_eid_t eid);
    dlock_status_t query_urma_device(char *dev_name, const dlock_eid_t eid);
    dlock_status_t get_uasid(void);
    dlock_status_t create_ctx(void);
    dlock_status_t create_jfce(void);
    dlock_status_t create_jfc(int num_cqe);
    dlock_status_t register_seg(uint32_t num_buf);
    dlock_status_t get_urma_eid_index(urma_device_t *urma_dev, urma_eid_t *eid, uint32_t &eid_index) const;
    void unregister_local_tseg(void) noexcept;
    void delete_jfc(void) noexcept;
    void delete_jfce(void) noexcept;
    void delete_urma_context(void) noexcept;

    std::string m_dev_name;
    #ifdef UB_AGG
        bool m_is_ub_bonding_dev;
    #endif /* UB_AGG */
    uint32_t m_eid_index;
    trans_mode_t m_tp_mode;
    urma_context_t *m_urma_ctx;
    urma_device_attr_t m_dev_attr;
    urma_jfce_t *m_jfce;
    urma_jfc_t *m_jfc;
    bool m_jfc_polling;
    bool m_ub_token_disable;

    void *m_va;
    urma_target_seg_t *m_local_tseg; /* Exported target segment for read/write/atomic */
    urma_token_t m_local_tseg_token;
    struct urma_buf *m_p_buf_head;
    std::mutex m_mutex; /* To prevent m_p_buf_head from being concurrently read */
    bool m_ctx_inited;
};
};
#endif
