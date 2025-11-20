/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : urma_ctx.cpp
 * Description   : context of URMA
 * History       : create file & add functions
 * 1.Date        : 2022-02-24
 * Author        : jiasiyuan
 * Modification  : Created file
 */
#include <malloc.h>

#include "dlock_types.h"
#include "urma_ctx.h"

#include "dlock_log.h"
#include "dlock_common.h"
#include "utils.h"

const int URMA_USER_CTL_IGNORE_JETTY_IN_CR = 0;

namespace dlock {
static int g_urma_init_cnt = 0;
static std::mutex g_urma_ctx_mutex;

static void seg_flag_init(urma_reg_seg_flag_t &flag, uint32_t token_policy)
{
    flag.bs.token_policy = token_policy;
    flag.bs.cacheable = URMA_NON_CACHEABLE;
    flag.bs.access = DLOCK_SEG_ACCESS_FLAGS;
    flag.bs.token_id_valid = URMA_TOKEN_ID_INVALID;
    flag.bs.reserved = 0;
}

dlock_status_t urma_ctx::init_urma_ctx(void)
{
    std::unique_lock<std::mutex> locker(g_urma_ctx_mutex);

    if (g_urma_init_cnt != 0) {
        g_urma_init_cnt++;
        m_ctx_inited = true;
        return DLOCK_SUCCESS;
    }

    urma_init_attr_t init_attr = {
        .token = 0,
        .uasid = 0,
    };

    if (urma_init(&init_attr) != URMA_SUCCESS) {
        DLOCK_LOG_ERR("Failed to urma init");
        m_ctx_inited = false;
        return DLOCK_FAIL;
    }
    g_urma_init_cnt = 1;
    m_ctx_inited = true;

    return DLOCK_SUCCESS;
}

dlock_status_t urma_ctx::uninit_urma_ctx(void) noexcept
{
    if (!m_ctx_inited) {
        return DLOCK_SUCCESS;
    }
    std::unique_lock<std::mutex> locker(g_urma_ctx_mutex);

    if (g_urma_init_cnt == 0) {
        m_ctx_inited = false;
        return DLOCK_SUCCESS;
    }

    if ((--g_urma_init_cnt) != 0) {
        m_ctx_inited = false;
        return DLOCK_SUCCESS;
    }

    if (urma_uninit() != URMA_SUCCESS) {
        DLOCK_LOG_ERR("Failed to urma uninit");
        g_urma_init_cnt++;
        return DLOCK_FAIL;
    }

    m_ctx_inited = false;
    return DLOCK_SUCCESS;
}

dlock_status_t urma_ctx::get_urma_eid_index(urma_device_t *urma_dev, urma_eid_t *eid, uint32_t &eid_index) const
{
    uint32_t i;
    uint32_t eid_cnt;
    urma_eid_info_t *eid_list = nullptr;

    eid_list = urma_get_eid_list(urma_dev, &eid_cnt);
    if (eid_list == nullptr) {
        return DLOCK_FAIL;
    }

    for (i = 0; i < eid_cnt; i++) {
        if (eid != nullptr && (!check_if_eid_match(*eid, eid_list[i].eid))) {
            continue;
        }

        eid_index = i;
        urma_free_eid_list(eid_list);
        return DLOCK_SUCCESS;
    }

    urma_free_eid_list(eid_list);
    return DLOCK_FAIL;
}

dlock_status_t urma_ctx::check_urma_device_state(char *dev_name)
{
    uint32_t port_idx;
    uint32_t eid_index;

    urma_device_t *urma_dev = urma_get_device_by_name(dev_name);
    if (urma_dev == nullptr) {
        return DLOCK_FAIL;
    }

    if (urma_dev->type != URMA_TRANSPORT_UB) {
        return DLOCK_FAIL;
    }

    if (get_urma_eid_index(urma_dev, nullptr, eid_index) != DLOCK_SUCCESS) {
        return DLOCK_FAIL;
    }

    if (urma_query_device(urma_dev, &m_dev_attr) == URMA_SUCCESS) {
#ifdef UB_AGG
        /* The port_cnt value of the ub bonding device is 0 now, and the eid index is not related to the port index.
         * dlock cannot obtain the association between eid and port.
         * Therefore, we do not check whether the device port state is active.
         */
        if (check_if_ub_bonding_dev(urma_dev)) {
            if (m_tp_mode == SEPERATE_CONN) {
                /* With ub bonding devices, using the RM transport mode requires specifying CTP and multipath.
                 * However, CTP does not support loopback communication, therefore, dlock does not support
                 * SEPERATE_CONN(URMA_TM_RM) with ub bonding devices.
                 */
                DLOCK_LOG_ERR("dlock does not support SEPERATE_CONN(URMA_TM_RM) with ub bonding devices. "
                    "Please configure the tp_mode to UNI_CONN(URMA_TM_RC).");
                return DLOCK_FAIL;
            }
            m_dev_name = dev_name;
            m_eid_index = eid_index;
            m_is_ub_bonding_dev = true;
            return DLOCK_SUCCESS;
        }
#endif /* UB_AGG */

        for (port_idx = 0; port_idx < m_dev_attr.port_cnt; port_idx++) {
            if (m_dev_attr.port_attr[port_idx].state == URMA_PORT_ACTIVE) {
                m_dev_name = dev_name;
                m_eid_index = eid_index;
                return DLOCK_SUCCESS;
            }
        }
    }
    return DLOCK_FAIL;
}

static inline urma_device_t *get_urma_device_by_eid(urma_eid_t &eid)
{
    urma_device_t *urma_dev = urma_get_device_by_eid(eid, URMA_TRANSPORT_UB);
    if (urma_dev != nullptr) {
        return urma_dev;
    }

    return nullptr;
}

dlock_status_t urma_ctx::check_urma_device_state_by_eid(const dlock_eid_t eid)
{
    uint32_t port_idx;
    uint32_t eid_index;

    urma_device_t *urma_dev = get_urma_device_by_eid(*(reinterpret_cast<urma_eid_t *>(
        const_cast<dlock_eid_t *>(&eid))));
    if (urma_dev == nullptr) {
        return DLOCK_FAIL;
    }

    if (get_urma_eid_index(urma_dev, reinterpret_cast<urma_eid_t *>(const_cast<dlock_eid_t *>(&eid)),
        eid_index) != DLOCK_SUCCESS) {
        return DLOCK_FAIL;
    }

    if (urma_query_device(urma_dev, &m_dev_attr) == URMA_SUCCESS) {
#ifdef UB_AGG
        /* The port_cnt value of the ub bonding device is 0 now, and the eid index is not related to the port index.
         * dlock cannot obtain the association between eid and port.
         * Therefore, we do not check whether the device port state is active.
         */
        if (check_if_ub_bonding_dev(urma_dev)) {
            if (m_tp_mode == SEPERATE_CONN) {
                /* With ub bonding devices, using the RM transport mode requires specifying CTP and multipath.
                 * However, CTP does not support loopback communication, therefore, dlock does not support
                 * SEPERATE_CONN(URMA_TM_RM) with ub bonding devices.
                 */
                DLOCK_LOG_ERR("dlock does not support SEPERATE_CONN(URMA_TM_RM) with ub bonding devices. "
                    "Please configure the tp_mode to UNI_CONN(URMA_TM_RC).");
                return DLOCK_FAIL;
            }
            m_dev_name = urma_dev->name;
            m_eid_index = eid_index;
            m_is_ub_bonding_dev = true;
            return DLOCK_SUCCESS;
        }
#endif /* UB_AGG */
        for (port_idx = 0; port_idx < m_dev_attr.port_cnt; port_idx++) {
            if (m_dev_attr.port_attr[port_idx].state == URMA_PORT_ACTIVE) {
                m_dev_name = urma_dev->name;
                m_eid_index = eid_index;
                return DLOCK_SUCCESS;
            }
        }
    }
    return DLOCK_FAIL;
}

bool check_if_eid_nonzero(const dlock_eid_t eid)
{
    int i = 0;
    for (; i < DLOCK_EID_SIZE; i++) {
        if (eid.raw[i] != 0) {
            return true;
        }
    }

    return false;
}

dlock_status_t urma_ctx::query_urma_device(char *dev_name, const dlock_eid_t eid)
{
    int dev_num;
    int dev_idx;

    if (check_if_eid_nonzero(eid)) {
        if (check_urma_device_state_by_eid(eid) == DLOCK_SUCCESS) {
            DLOCK_LOG_DEBUG("Get urma device for eid, name:%s", m_dev_name.c_str()) ;
            return DLOCK_SUCCESS;
        }
        if (dev_name == nullptr) {
            DLOCK_LOG_ERR("Failed to query device by eid, incorrect eid or dev related to "
                "the eid is DOWN. And no dev_name specified in cfg. Check urma log for details");
            return DLOCK_FAIL;
        }
        DLOCK_LOG_ERR("Failed to query device by eid, incorrect eid or dev related to "
            "the eid is DOWN. DLock will try to find device by dev_name specified in cfg. "
            "Check urma log for details");
    }

    if (dev_name != nullptr) {
        if (check_urma_device_state(dev_name) == DLOCK_SUCCESS) {
            DLOCK_LOG_DEBUG("Get urma device, name:%s", m_dev_name.c_str());
            return DLOCK_SUCCESS;
        }
        DLOCK_LOG_ERR("Failed to query device %s, incorrect dev_name or dev is DOWN. Check urma log for details",
            dev_name);
        return DLOCK_FAIL;
    }

    urma_device_t **device_list = urma_get_device_list(&dev_num);
    if (device_list == nullptr) {
        DLOCK_LOG_ERR("Failed to get device list");
        return DLOCK_FAIL;
    }

    for (dev_idx = 0; dev_idx < dev_num; dev_idx++) {
        if (check_urma_device_state(device_list[dev_idx]->name) == DLOCK_SUCCESS) {
            DLOCK_LOG_DEBUG("Get urma device, name:%s", device_list[dev_idx]->name);
            urma_free_device_list(device_list);
            return DLOCK_SUCCESS;
        }
    }

    DLOCK_LOG_ERR("Failed to query device");
    urma_free_device_list(device_list);
    return DLOCK_FAIL;
}

dlock_status_t urma_ctx::create_ctx(void)
{
    if (m_dev_name.length() == 0u) {
        DLOCK_LOG_ERR("invalid device name, length is 0");
        return DLOCK_FAIL;
    }

    size_t len = m_dev_name.length() + 1;
    char *dev_name = (char *)malloc(len * sizeof(char));
    if (dev_name == nullptr) {
        DLOCK_LOG_ERR("malloc error (errno=%d %m)", errno);
        return DLOCK_ENOMEM;
    }

    static_cast<void>(strcpy(dev_name, m_dev_name.c_str()));
    urma_device_t *urma_dev = urma_get_device_by_name(dev_name);
    if (urma_dev == nullptr) {
        DLOCK_LOG_ERR("urma get device by eid failed!\n");
        free(dev_name);
        return DLOCK_FAIL;
    }

    m_urma_ctx = urma_create_context(urma_dev, m_eid_index);
    if (m_urma_ctx == nullptr) {
        DLOCK_LOG_ERR("Failed to create urma context");
        free(dev_name);
        return DLOCK_FAIL;
    }
    free(dev_name);
    return DLOCK_SUCCESS;
}

dlock_status_t urma_ctx::create_jfce(void)
{
    m_jfce = urma_create_jfce(m_urma_ctx);
    if (m_jfce == nullptr) {
        DLOCK_LOG_ERR("Failed to create jfce");
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}

dlock_status_t urma_ctx::create_jfc(int num_cqe)
{
    urma_jfc_cfg_t jfc_cfg = {
        .depth = 1,
        .flag = {.value = 0},
        .ceqn = 0,
        .jfce = nullptr,
        .user_ctx = 0,
    };

    if (num_cqe == 0) {
        DLOCK_LOG_INFO("It's not necessary to create jfc during creating urma ctx");
        delete_jfce();
        return DLOCK_SUCCESS;
    }

    jfc_cfg.depth = static_cast<uint32_t>(num_cqe);
    jfc_cfg.jfce = m_jfce;

    m_jfc = urma_create_jfc(m_urma_ctx, &jfc_cfg);
    if (m_jfc == nullptr) {
        DLOCK_LOG_ERR("Failed to create jfc");
        return DLOCK_FAIL;
    }

    return DLOCK_SUCCESS;
}

dlock_status_t urma_ctx::register_seg(uint32_t num_buf)
{
    struct urma_buf *tmp = nullptr;
    urma_reg_seg_flag_t flag = {.value = 0};
    urma_seg_cfg_t seg_cfg = {0};

    dlock_status_t ret = gen_token_value(m_local_tseg_token);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("Failed to generate token value");
        return DLOCK_FAIL;
    }

    m_va = memalign(PAGE_SIZE, num_buf * URMA_MTU);
    if (m_va == nullptr) {
        DLOCK_LOG_ERR("Failed to alloc buffer");
        return DLOCK_ENOMEM;
    }

    seg_flag_init(flag, get_token_policy());
    seg_cfg.va = reinterpret_cast<uint64_t>(m_va);
    seg_cfg.len = num_buf * URMA_MTU;
    seg_cfg.token_id = nullptr;
    seg_cfg.token_value = m_local_tseg_token;
    seg_cfg.flag = flag;
    seg_cfg.user_ctx = static_cast<uintptr_t>(NULL);
    seg_cfg.iova = 0;
    m_local_tseg = urma_register_seg(m_urma_ctx, &seg_cfg);
    if (m_local_tseg == nullptr) {
        DLOCK_LOG_ERR("Failed to register segment");
        free(m_va);
        m_va = nullptr;
        return DLOCK_FAIL;
    }

    for (unsigned int i = 0; i < num_buf; i++) {
        tmp = new urma_buf();
        if (tmp == nullptr) {
            DLOCK_LOG_ERR("Failed to malloc %u", i);
            return DLOCK_ENOMEM;
        }
        tmp->next = m_p_buf_head;
        tmp->buf = reinterpret_cast<uint8_t *>(reinterpret_cast<uint64_t>(m_va) + i * URMA_MTU);
        tmp->jfs_ref_count = 0;
        m_p_buf_head = tmp;
    }
    return DLOCK_SUCCESS;
}

void urma_ctx::unregister_local_tseg(void) noexcept
{
    if (m_local_tseg == nullptr) {
        return;
    }

    urma_status_t ret = urma_unregister_seg(m_local_tseg);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to unregister seg, ret: %d", static_cast<int>(ret));
    }
    m_local_tseg = nullptr;
}

void urma_ctx::delete_jfc(void) noexcept
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

void urma_ctx::delete_jfce(void) noexcept
{
    if (m_jfce == nullptr) {
        return;
    }

    urma_status_t ret = urma_delete_jfce(m_jfce);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to delete jfce, ret: %d", static_cast<int>(ret));
    }
    m_jfce = nullptr;
}

void urma_ctx::delete_urma_context(void) noexcept
{
    if (m_urma_ctx == nullptr) {
        return;
    }

    urma_status_t ret = urma_delete_context(m_urma_ctx);
    if (ret != URMA_SUCCESS) {
        DLOCK_LOG_ERR("failed to delete urma context, ret: %d", static_cast<int>(ret));
    }
    m_urma_ctx = nullptr;
}

urma_ctx::urma_ctx(const struct urma_ctx_cfg &cfg)
#ifdef UB_AGG
    : m_is_ub_bonding_dev(false), m_eid_index(0), m_tp_mode(cfg.tp_mode), m_urma_ctx(nullptr), m_jfce(nullptr),
      m_jfc(nullptr), m_jfc_polling(false), m_ub_token_disable(cfg.ub_token_disable), m_va(nullptr),
#else
    : m_eid_index(0), m_tp_mode(cfg.tp_mode), m_urma_ctx(nullptr), m_jfce(nullptr), m_jfc(nullptr),
      m_jfc_polling(false), m_ub_token_disable(cfg.ub_token_disable), m_va(nullptr),
#endif /* UB_AGG */
    m_local_tseg(nullptr), m_p_buf_head(nullptr), m_ctx_inited(false)
{
    m_local_tseg_token.token = 0;

    if (init_urma_ctx() != DLOCK_SUCCESS) {
        return;
    }

    if (query_urma_device(cfg.dev_name, cfg.eid) != DLOCK_SUCCESS) {
        goto UNINIT;
    }

    if (create_ctx() != DLOCK_SUCCESS) {
        goto UNINIT;
    }

    if (create_jfce() != DLOCK_SUCCESS) {
        goto DEL_CTX;
    }

    if (create_jfc(cfg.num_cqe) != DLOCK_SUCCESS) {
        goto DEL_JFCE;
    }

    if (register_seg(cfg.num_buf) != DLOCK_SUCCESS) {
        goto DEL_JFC;
    }

    return;
DEL_JFC:
    delete_jfc();
DEL_JFCE:
    delete_jfce();
DEL_CTX:
    delete_urma_context();
UNINIT:
    static_cast<void>(uninit_urma_ctx());
}

urma_ctx::~urma_ctx() noexcept
{
    unregister_local_tseg();
    delete_jfc();
    delete_jfce();
    delete_urma_context();
    static_cast<void>(uninit_urma_ctx());

    if (m_va != nullptr) {
        free(m_va);
        m_va = nullptr;
    }

    m_dev_name.clear();

    while (m_p_buf_head != nullptr) {
        struct urma_buf *temp = m_p_buf_head;

        m_p_buf_head = m_p_buf_head->next;
        delete temp;
    }
}

struct urma_buf *urma_ctx::get_memory()
{
    std::unique_lock<std::mutex> locker(m_mutex);
    if (m_p_buf_head == nullptr) {
        DLOCK_LOG_ERR("no registered memory left");
        return nullptr;
    }
    struct urma_buf *temp = m_p_buf_head;
    m_p_buf_head = m_p_buf_head->next;
    return temp;
}

void urma_ctx::release_memory(struct urma_buf *p_buf) noexcept
{
    std::unique_lock<std::mutex> locker(m_mutex);
    if (p_buf == nullptr) {
        DLOCK_LOG_ERR("release nullptr memory");
        return;
    }
    p_buf->next = m_p_buf_head;
    m_p_buf_head = p_buf;
}

urma_jfc_t *urma_ctx::new_jfc(int num_cqe) const
{
    urma_jfc_t *jfc = nullptr;
    urma_jfc_cfg_t jfc_cfg = {
        .depth = static_cast<uint32_t>(num_cqe),
        .flag = {.value = 0},
        .ceqn = 0,
        .jfce = m_jfce,
        .user_ctx = 0,
    };
    jfc = urma_create_jfc(m_urma_ctx, &jfc_cfg);
    if (jfc == nullptr) {
        DLOCK_LOG_ERR("Failed to create jfc");
    }

    return jfc;
}

urma_target_seg_t *urma_ctx::register_new_seg(uint8_t *buf, uint32_t buf_len, urma_token_t &token_value)
{
    urma_reg_seg_flag_t flag = {.value = 0};
    urma_seg_cfg_t seg_cfg;

    dlock_status_t ret = gen_token_value(token_value);
    if (ret != DLOCK_SUCCESS) {
        DLOCK_LOG_ERR("Failed to generate token value");
        return nullptr;
    }

    seg_flag_init(flag, get_token_policy());
    seg_cfg.va = reinterpret_cast<uint64_t>(buf);
    seg_cfg.len = buf_len;
    seg_cfg.token_id = nullptr;
    seg_cfg.token_value = token_value;
    seg_cfg.flag = flag;
    seg_cfg.user_ctx = static_cast<uintptr_t>(NULL);
    seg_cfg.iova = 0;
    return urma_register_seg(m_urma_ctx, &seg_cfg);
}

dlock_status_t urma_ctx::gen_token_value(urma_token_t &token_value) const
{
    if (m_ub_token_disable) {
        token_value.token = 0;
        return DLOCK_SUCCESS;
    }

    int ret = RAND_priv_bytes(reinterpret_cast<unsigned char *>(&token_value.token), sizeof(token_value.token));
    if (ret != 1) {
        DLOCK_LOG_ERR("failed to generate random token value, ret: %d", ret);
        return DLOCK_FAIL;
    }
    return DLOCK_SUCCESS;
}
};
