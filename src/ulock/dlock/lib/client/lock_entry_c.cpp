/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : lock_entry_c.cpp
 * Description   : lock entry class in the client lib
 * History       : create file & add functions
 * 1.Date        : 2021-06-22
 * Author        : zhangjun
 * Modification  : Created file
 */

#include "dlock_types.h"
#include "dlock_common.h"
#include "client_entry_c.h"
#include "lock_entry_c.h"

#include "dlock_log.h"

namespace dlock {
#define DEBUG_NO_STATS_INCRE DEBUG_STATS_MAX

struct op_ret_req g_atomic_state_map[LOCK_STATE_MAX][LOCK_OPS_MAX] = {
    {    /* state: LOCK_INITIALIZED */
        {DLOCK_SUCCESS, EXCLUSIVE_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_ALREADY_UNLOCKED, OP_CODE_NULL, DEBUG_STATS_ALREADY_UNLOCKED},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {   /* state: EXCLUSIVE_LOCKED */
        {DLOCK_SUCCESS, EXCLUSIVE_LOCK_EXTEND, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_SUCCESS, EXCLUSIVE_UNLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_SUCCESS, EXCLUSIVE_LOCK_EXTEND, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: SHARED_LOCKED */
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: UNLOCKED */
        {DLOCK_SUCCESS, EXCLUSIVE_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_ALREADY_UNLOCKED, OP_CODE_NULL, DEBUG_STATS_ALREADY_UNLOCKED},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: EXCLUSIVE_TICKETED */
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: SHARED_TICKETED */
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    }
};
struct op_ret_req g_rwlock_state_map[LOCK_STATE_MAX][LOCK_OPS_MAX] = {
    {    /* state: LOCK_INITIALIZED */
        {DLOCK_SUCCESS, EXCLUSIVE_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_SUCCESS, SHARED_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_ALREADY_UNLOCKED, OP_CODE_NULL, DEBUG_STATS_ALREADY_UNLOCKED},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: EXCLUSIVE_LOCKED */
        {DLOCK_ALREADY_LOCKED, OP_CODE_NULL, DEBUG_STATS_ALREADY_LOCKED},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_SUCCESS, EXCLUSIVE_UNLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: SHARED_LOCKED */
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_ALREADY_LOCKED, OP_CODE_NULL, DEBUG_STATS_ALREADY_LOCKED},
        {DLOCK_SUCCESS, SHARED_UNLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: UNLOCKED */
        {DLOCK_SUCCESS, EXCLUSIVE_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_SUCCESS, SHARED_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_ALREADY_UNLOCKED, OP_CODE_NULL, DEBUG_STATS_ALREADY_UNLOCKED},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: EXCLUSIVE_TICKETED */
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: SHARED_TICKETED */
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    }
};
struct op_ret_req g_fairlock_state_map[LOCK_STATE_MAX][LOCK_OPS_MAX] = {
    {    /* state: LOCK_INITIALIZED */
        {DLOCK_SUCCESS, EXCLUSIVE_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_SUCCESS, SHARED_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_ALREADY_UNLOCKED, OP_CODE_NULL, DEBUG_STATS_ALREADY_UNLOCKED},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: EXCLUSIVE_LOCKED */
        {DLOCK_ALREADY_LOCKED, EXCLUSIVE_LOCK_EXTEND, DEBUG_STATS_ALREADY_LOCKED},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_SUCCESS, EXCLUSIVE_UNLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_SUCCESS, EXCLUSIVE_LOCK_EXTEND, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: SHARED_LOCKED */
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_ALREADY_LOCKED, SHARED_LOCK_EXTEND, DEBUG_STATS_ALREADY_LOCKED},
        {DLOCK_SUCCESS, SHARED_UNLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_SUCCESS, SHARED_LOCK_EXTEND, DEBUG_NO_STATS_INCRE}
    },
    {    /* state: UNLOCKED */
        {DLOCK_SUCCESS, EXCLUSIVE_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_SUCCESS, SHARED_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_ALREADY_UNLOCKED, OP_CODE_NULL, DEBUG_STATS_ALREADY_UNLOCKED},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: EXCLUSIVE_TICKETED */
        {DLOCK_SUCCESS, EXCLUSIVE_TICKET_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_ETICKET, OP_CODE_NULL, DEBUG_STATS_ETICKET},
        {DLOCK_DONE, OP_LOCAL_RESET, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    },
    {    /* state: SHARED_TICKETED */
        {DLOCK_ETICKET, OP_CODE_NULL, DEBUG_STATS_ETICKET},
        {DLOCK_SUCCESS, SHARED_TICKET_TRYLOCK, DEBUG_NO_STATS_INCRE},
        {DLOCK_DONE, OP_LOCAL_RESET, DEBUG_NO_STATS_INCRE},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP},
        {DLOCK_EINVAL, OP_CODE_NULL, DEBUG_STATS_EINVAL_LOCK_OP}
    }
};

lock_entry_c::lock_entry_c(int32_t lock_id, enum dlock_type lock_type, uint32_t lock_offset, uint32_t lease_time,
    client_entry_c *client)
    : m_lock_desc(nullptr), m_lock_id(lock_id), m_lock_type(lock_type), m_lock_offset(lock_offset),
      m_lease_time(lease_time), m_ref_count(0), m_lock_state(LOCK_INITIALIZED), m_lock_val({0}),
      m_lock_updated(false), m_client(client)
{
    m_lock_val.base = 0;
    m_lock_val.fl.time_out = 0;
    m_lock_val.fl.t_value = 0;
    DLOCK_LOG_DEBUG("lock %d init", lock_id);
}

lock_entry_c::~lock_entry_c()
{
    if (m_lock_desc != nullptr) {
        delete m_lock_desc;
    }
}

void lock_entry_c::init_cmd_msg_common_field(uint16_t message_id, struct lock_cmd_msg &cmd_msg) const
{
    cmd_msg.magic_no = DLOCK_DP_MAGIC_NO;
    cmd_msg.version = DLOCK_PROTO_VERSION;
    cmd_msg.message_id = message_id;
}

int lock_entry_c::fill_cmd_msg(int client_id, uint16_t message_id,
    const struct lock_request *req, struct lock_cmd_msg &cmd_msg)
{
    init_cmd_msg_common_field(message_id, cmd_msg);

    switch (m_lock_type) {
        case DLOCK_ATOMIC:
            return atomic_fill_cmd_msg(client_id, req, cmd_msg);
        case DLOCK_RW:
            return rw_fill_cmd_msg(client_id, req, cmd_msg);
        case DLOCK_FAIR:
            return fair_fill_cmd_msg(req, cmd_msg);
        default:
            m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_TYPE]++;
            DLOCK_LOG_DEBUG("lock type %d not supported, lock %d", static_cast<uint32_t>(m_lock_type), req->lock_id);
            return static_cast<uint16_t>(DLOCK_EINVAL);
    }
}

void lock_entry_c::fill_update_msg(struct update_lock_body *p_msg_update) const
{
    p_msg_update->lock_id = m_lock_id;
    p_msg_update->lock_type = static_cast<uint32_t>(m_lock_type);
    p_msg_update->offset = m_lock_offset;
    p_msg_update->lease_time = m_lease_time;
    p_msg_update->desc_len = m_lock_desc->m_len;
    static_cast<void>(memcpy(p_msg_update->desc, m_lock_desc->m_desc, p_msg_update->desc_len));
    p_msg_update->ls.base =
        ((m_lock_state == UNLOCKED) || (m_lock_state == LOCK_INITIALIZED)) ? 0 : m_lock_val.base;

    /*
     * For a RWlock, the rcount field coincides with the timeout field of the fair lock.
     * Therefore, only need to assign a value to fl.time_out.
     */
    p_msg_update->ls.fl.time_out =
        ((m_lock_state == UNLOCKED) || (m_lock_state == LOCK_INITIALIZED)) ? 0 : m_lock_val.fl.time_out;
    p_msg_update->ls.fl.t_value = m_lock_val.fl.t_value;
    if (m_lock_type == DLOCK_FAIR) {
        p_msg_update->ls.fl.m_shared = (m_lock_state != SHARED_TICKETED) ?
            p_msg_update->ls.fl.m_shared : p_msg_update->ls.fl.m_shared + 1;
        p_msg_update->ls.fl.m_exclusive = (m_lock_state != EXCLUSIVE_TICKETED) ?
            p_msg_update->ls.fl.m_exclusive : p_msg_update->ls.fl.m_exclusive + 1;
        /* Reuse rcnt to identify the local lock state of the client,
           only if the lock state is shared_locked, ls.fl.bs.rcnt = 1 */
        p_msg_update->ls.fl.bs.rcnt = (m_lock_state == SHARED_LOCKED) ? 1 : 0;
    }
}

void lock_entry_c::lock_update(struct update_lock_body *p_msg_update)
{
    m_lock_id = p_msg_update->lock_id;
    m_lock_offset = p_msg_update->offset;
    m_lock_updated = true;
}

int lock_entry_c::update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result)
{
    switch (m_lock_type) {
        case DLOCK_ATOMIC:
            return atomic_update_state_with_cmd_msg(p_cmd_msg, result);
        case DLOCK_RW:
            return rw_update_state_with_cmd_msg(p_cmd_msg, result);
        case DLOCK_FAIR:
            return fair_update_state_with_cmd_msg(p_cmd_msg, result);
        default:
            m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_TYPE]++;
            DLOCK_LOG_DEBUG("lock type %d not supported", static_cast<uint32_t>(m_lock_type));
            return static_cast<uint16_t>(DLOCK_EINVAL);
    }
}

int lock_entry_c::atomic_fill_cmd_msg(int client_id, const struct lock_request *req, struct lock_cmd_msg &cmd_msg)
{
    int ret = static_cast<int>(DLOCK_SUCCESS);

    switch (static_cast<enum lock_ops>(req->lock_op)) {
        case LOCK_EXCLUSIVE:
            cmd_msg.op_code = static_cast<uint8_t>(EXCLUSIVE_TRYLOCK);
            if (m_lock_state == EXCLUSIVE_LOCKED) {
                /* trylock for lock with local state *_LOCKED will be transformed to an extend op */
                cmd_msg.op_code = static_cast<uint8_t>(EXCLUSIVE_LOCK_EXTEND);
                m_ref_count++;
            };
            break;

        case UNLOCK:
            cmd_msg.op_code = static_cast<uint8_t>(EXCLUSIVE_UNLOCK);
            if (m_lock_state != EXCLUSIVE_LOCKED) {
                m_client->m_stats.stats[DEBUG_STATS_ALREADY_UNLOCKED]++;
                DLOCK_LOG_DEBUG("lock %d has not been locked", m_lock_id);
                return static_cast<int>(DLOCK_ALREADY_UNLOCKED);
            };
            m_ref_count--;
            if (m_ref_count > 0u) {
                m_client->m_stats.stats[DEBUG_STATS_ALREADY_LOCKED]++;
                DLOCK_LOG_DEBUG("lock %d has still been locked", m_lock_id);
                return static_cast<int>(DLOCK_ALREADY_LOCKED);
            };
            break;

        case EXTEND_LOCK_EXCLUSIVE:
            cmd_msg.op_code = static_cast<uint8_t>(EXCLUSIVE_LOCK_EXTEND);
            if (m_lock_state != EXCLUSIVE_LOCKED) {
                m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
                DLOCK_LOG_DEBUG("lock %d has not been locked", m_lock_id);
                return static_cast<int>(DLOCK_EINVAL);
            };
            break;

        default:
            m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
            DLOCK_LOG_DEBUG("lock op %d not supported, lock %d", req->lock_op, m_lock_id);
            return static_cast<int>(DLOCK_EINVAL);
    }
    cmd_msg.lock_offset = m_lock_offset;
    cmd_msg.lock_type = static_cast<uint8_t>(m_lock_type);
    cmd_msg.ls.atomic.client_id = client_id;
    cmd_msg.ls.atomic.time_out = req->expire_time;
    return ret;
}

int lock_entry_c::rw_fill_cmd_msg(int client_id, const struct lock_request *req, struct lock_cmd_msg &cmd_msg)
{
    int ret = static_cast<int>(DLOCK_SUCCESS);

    switch (static_cast<enum lock_ops>(req->lock_op)) {
        case LOCK_EXCLUSIVE:
            cmd_msg.op_code = static_cast<uint8_t>(EXCLUSIVE_TRYLOCK);
            cmd_msg.ls.rw.client_id = client_id;
            if (m_lock_state == EXCLUSIVE_LOCKED) {
                m_ref_count++;
                m_client->m_stats.stats[DEBUG_STATS_ALREADY_LOCKED]++;
                return static_cast<int>(DLOCK_ALREADY_LOCKED);
            };
            if (m_lock_state == SHARED_LOCKED) {
                m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
                DLOCK_LOG_DEBUG("lock %d has been locked in shared mode, pls unlock first", m_lock_id);
                return static_cast<int>(DLOCK_EINVAL);
            };
            break;

        case LOCK_SHARED:
            cmd_msg.op_code = static_cast<uint8_t>(SHARED_TRYLOCK);
            cmd_msg.ls.rw.client_id = 0;
            if (m_lock_state == EXCLUSIVE_LOCKED) {
                m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
                DLOCK_LOG_DEBUG("lock %d has been locked in exclusive mode, pls unlock first in case of lock timeout",
                    m_lock_id);
                return static_cast<int>(DLOCK_EINVAL);
            };
            if (m_lock_state == SHARED_LOCKED) {
                m_ref_count++;
                m_client->m_stats.stats[DEBUG_STATS_ALREADY_LOCKED]++;
                return static_cast<int>(DLOCK_ALREADY_LOCKED);
            };
            break;

        case UNLOCK:
            if ((m_lock_state != SHARED_LOCKED) && (m_lock_state != EXCLUSIVE_LOCKED)) {
                m_client->m_stats.stats[DEBUG_STATS_ALREADY_UNLOCKED]++;
                DLOCK_LOG_DEBUG("lock %d has not been locked", m_lock_id);
                return static_cast<int>(DLOCK_ALREADY_UNLOCKED);
            };
            cmd_msg.op_code = (m_lock_state == EXCLUSIVE_LOCKED) ? static_cast<uint8_t>(EXCLUSIVE_UNLOCK) :
                static_cast<uint8_t>(SHARED_UNLOCK);
            cmd_msg.ls.rw.client_id = (m_lock_state == EXCLUSIVE_LOCKED) ? client_id : 0;
            m_ref_count--;
            if (m_ref_count > 0u) {
                m_client->m_stats.stats[DEBUG_STATS_ALREADY_LOCKED]++;
                DLOCK_LOG_DEBUG("lock %d has still been locked", m_lock_id);
                return static_cast<int>(DLOCK_ALREADY_LOCKED);
            };
            break;

        case EXTEND_LOCK_EXCLUSIVE:
        case EXTEND_LOCK_SHARED:
        case LOCK_OPS_MAX:
        default:
            m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
            DLOCK_LOG_DEBUG("lock op %d not supported, lock %d", req->lock_op, m_lock_id);
            return static_cast<int>(DLOCK_EINVAL);
    }
    cmd_msg.lock_offset = m_lock_offset;
    cmd_msg.lock_type = static_cast<uint8_t>(m_lock_type);
    cmd_msg.ls.rw.time_out = req->expire_time;
    return ret;
}

int lock_entry_c::atomic_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result)
{
    int ret = static_cast<int>(DLOCK_SUCCESS);
    atomic_state *res = reinterpret_cast<atomic_state *>(result);

    if (p_cmd_msg == nullptr) {
        res->client_id = m_lock_val.atomic.client_id;
        res->time_out = m_lock_val.atomic.time_out;
        return ret;
    }

    res->client_id = p_cmd_msg->ls.atomic.client_id;
    res->time_out = p_cmd_msg->ls.atomic.time_out;
    switch (static_cast<enum dlock_req_code>(p_cmd_msg->op_code)) {
        case EXCLUSIVE_TRYLOCK:
            m_lock_state = EXCLUSIVE_LOCKED;
            m_ref_count++;
            m_lock_val.base = p_cmd_msg->ls.base;
            break;

        case EXCLUSIVE_UNLOCK:
            m_lock_state = UNLOCKED;
            m_ref_count = 0;
            m_lock_val.base = p_cmd_msg->ls.base;
            break;

        case EXCLUSIVE_LOCK_EXTEND:
            m_lock_val.base = p_cmd_msg->ls.base;
            break;

        default:
            m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
            DLOCK_LOG_DEBUG("lock op %d not supported, lock %d", p_cmd_msg->op_code, m_lock_id);
            return static_cast<int>(DLOCK_EINVAL);
    }
    return ret;
}

int lock_entry_c::rw_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result)
{
    int ret = static_cast<int>(DLOCK_SUCCESS);
    rw_state *res = reinterpret_cast<rw_state *>(result);

    if (p_cmd_msg == nullptr) {
        DLOCK_LOG_DEBUG("p_cmd_msg is nullptr");
        res->time_out = m_lock_val.rw.time_out;
        res->client_id = m_lock_val.rw.client_id;
        res->rcount = m_lock_val.rw.rcount;
        return ret;
    }

    res->client_id = p_cmd_msg->ls.rw.client_id;
    res->time_out = p_cmd_msg->ls.rw.time_out;
    res->rcount = p_cmd_msg->ls.rw.rcount;
    switch (static_cast<enum dlock_req_code>(p_cmd_msg->op_code)) {
        case EXCLUSIVE_TRYLOCK:
            m_lock_state = EXCLUSIVE_LOCKED;
            m_ref_count++;
            m_lock_val.base = p_cmd_msg->ls.base;
            m_lock_val.rw.rcount = p_cmd_msg->ls.rw.rcount;
            break;

        case SHARED_TRYLOCK:
            m_lock_state = SHARED_LOCKED;
            m_ref_count++;
            m_lock_val.base = p_cmd_msg->ls.base;
            m_lock_val.rw.rcount = p_cmd_msg->ls.rw.rcount;
            break;

        case EXCLUSIVE_UNLOCK:
            m_lock_state = UNLOCKED;
            m_ref_count = 0;
            m_lock_val.base = p_cmd_msg->ls.base;
            m_lock_val.rw.rcount = p_cmd_msg->ls.rw.rcount;
            break;

        case SHARED_UNLOCK:
            m_lock_state = UNLOCKED;
            m_ref_count = 0;
            m_lock_val.base = p_cmd_msg->ls.base;
            m_lock_val.rw.rcount = p_cmd_msg->ls.rw.rcount;
            break;

        case EXCLUSIVE_LOCK_EXTEND:
        case SHARED_LOCK_EXTEND:
            m_lock_val.base = p_cmd_msg->ls.base;
            m_lock_val.rw.rcount = p_cmd_msg->ls.rw.rcount;
            break;

        default:
            m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
            DLOCK_LOG_DEBUG("lock op %d not supported, lock %d", p_cmd_msg->op_code, m_lock_id);
            return static_cast<int>(DLOCK_EINVAL);
    }
    return ret;
}

int lock_entry_c::fair_fill_cmd_msg(const struct lock_request *req, struct lock_cmd_msg &cmd_msg)
{
    struct op_ret_req *p_req_op = &g_fairlock_state_map[m_lock_state][req->lock_op];
    debug_stats_count_incre(p_req_op->stats_code);

    int ret = static_cast<int>((p_req_op->op_ret == DLOCK_ALREADY_LOCKED) ? DLOCK_SUCCESS : p_req_op->op_ret);
    cmd_msg.op_code = static_cast<uint8_t>(p_req_op->op_code);
    m_ref_count = (p_req_op->op_ret == DLOCK_ALREADY_LOCKED) ? (m_ref_count + 1) : m_ref_count;
    m_lock_state = (p_req_op->op_code == OP_LOCAL_RESET) ? (LOCK_INITIALIZED) : m_lock_state;

    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        return ret;
    }

    if ((req->lock_op == static_cast<int>(UNLOCK)) && (--m_ref_count > 0u)) {
        m_client->m_stats.stats[DEBUG_STATS_ALREADY_LOCKED]++;
        return static_cast<int>(DLOCK_ALREADY_LOCKED);
    }

    cmd_msg.lock_offset = m_lock_offset;
    cmd_msg.lock_type = static_cast<uint8_t>(m_lock_type);
    cmd_msg.ls.fl.m_exclusive = m_lock_val.fl.m_exclusive;
    cmd_msg.ls.fl.m_shared = m_lock_val.fl.m_shared;
    cmd_msg.ls.fl.n_exclusive = m_lock_val.fl.n_exclusive;
    cmd_msg.ls.fl.n_shared = m_lock_val.fl.n_shared;
    cmd_msg.ls.fl.time_out = req->expire_time;
    return ret;
}

int lock_entry_c::fair_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result)
{
    int ret = static_cast<int>(DLOCK_SUCCESS);
    lock_state *res = reinterpret_cast<lock_state *>(result);

    if (p_cmd_msg == nullptr) {
        res->fl.time_out = m_lock_val.fl.time_out;
        res->base = m_lock_val.base;
        return ret;
    }

    ret = static_cast<int>(p_cmd_msg->op_ret);

    switch (static_cast<dlock_status_t>(p_cmd_msg->op_ret)) {
        case DLOCK_SUCCESS:
            res->base = p_cmd_msg->ls.base;
            res->fl.time_out = p_cmd_msg->ls.fl.time_out;
            m_lock_val.base = p_cmd_msg->ls.base;
            m_lock_val.fl.time_out = p_cmd_msg->ls.fl.time_out;
            res->fl.t_value = m_lock_val.fl.t_value = p_cmd_msg->ls.fl.t_value;
            m_lock_state = ((p_cmd_msg->op_code == SHARED_TRYLOCK) || (p_cmd_msg->op_code == SHARED_TICKET_TRYLOCK))
                ? SHARED_LOCKED
                : (((p_cmd_msg->op_code == EXCLUSIVE_TRYLOCK) || (p_cmd_msg->op_code == EXCLUSIVE_TICKET_TRYLOCK))
                    ? EXCLUSIVE_LOCKED
                    : (((p_cmd_msg->op_code == EXCLUSIVE_UNLOCK) || (p_cmd_msg->op_code == SHARED_UNLOCK))
                        ? UNLOCKED : m_lock_state));
            m_ref_count = ((p_cmd_msg->op_code == SHARED_TRYLOCK) || (p_cmd_msg->op_code == SHARED_TICKET_TRYLOCK) ||
                          (p_cmd_msg->op_code == EXCLUSIVE_TRYLOCK) || (p_cmd_msg->op_code == EXCLUSIVE_TICKET_TRYLOCK))
                           ? m_ref_count + 1 : m_ref_count;
            break;

        case DLOCK_EAGAIN:
            res->base = p_cmd_msg->ls.base;
            res->fl.time_out = p_cmd_msg->ls.fl.time_out;
            res->fl.t_value = p_cmd_msg->ls.fl.t_value;
            m_lock_state = (p_cmd_msg->op_code < static_cast<uint8_t>(SHARED_TRYLOCK)) ? EXCLUSIVE_TICKETED
                                                                                       : SHARED_TICKETED;
            if ((p_cmd_msg->op_code == static_cast<uint8_t>(SHARED_TRYLOCK)) ||
                (p_cmd_msg->op_code == static_cast<uint8_t>(EXCLUSIVE_TRYLOCK))) {
                // store ticket to m_lock_val
                m_lock_val.base = p_cmd_msg->ls.base;
                m_lock_val.fl.time_out = p_cmd_msg->ls.fl.time_out;
                m_lock_val.fl.t_value = p_cmd_msg->ls.fl.t_value;
            } else {
                res->fl.m_exclusive = m_lock_val.fl.m_exclusive;
                res->fl.m_shared = m_lock_val.fl.m_shared;
                res->fl.time_out = m_lock_val.fl.time_out;
            }
            break;

        case DLOCK_FAIL:
            m_lock_state = LOCK_INITIALIZED;
            m_ref_count = 0;
            break;

        default:
            m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_RET]++;
            DLOCK_LOG_DEBUG("lock ret %d invalid, lock %d, op %d", p_cmd_msg->op_ret, m_lock_id, p_cmd_msg->op_code);
            return p_cmd_msg->op_ret;
    }

    return ret;
}

int lock_entry_c::atomic_async_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result)
{
    int ret = static_cast<int>(DLOCK_SUCCESS);
    atomic_state *res = reinterpret_cast<atomic_state *>(result);

    if (p_cmd_msg == nullptr) {
        res->client_id = m_lock_val.atomic.client_id;
        res->time_out = m_lock_val.atomic.time_out;
        return ret;
    }
    ret = static_cast<int>(p_cmd_msg->op_ret);

    switch (static_cast<dlock_status_t>(p_cmd_msg->op_ret)) {
        case DLOCK_SUCCESS:
            m_lock_val.base = p_cmd_msg->ls.base;
            res->client_id = p_cmd_msg->ls.atomic.client_id;
            res->time_out = p_cmd_msg->ls.atomic.time_out;
            if (p_cmd_msg->op_code == (static_cast<uint8_t>(EXCLUSIVE_TRYLOCK))) {
                m_lock_state = EXCLUSIVE_LOCKED;
                m_ref_count++;
            } else if (p_cmd_msg->op_code == (static_cast<uint8_t>(EXCLUSIVE_UNLOCK))) {
                m_lock_state = UNLOCKED;
                m_ref_count = 0;
            }
            break;

        case DLOCK_FAIL:
            m_lock_state = LOCK_INITIALIZED;
            m_ref_count = 0;
            break;

        default:
            DLOCK_LOG_ERR("lock ret %d invalid, lock %d, op %d", p_cmd_msg->op_ret, m_lock_id, p_cmd_msg->op_code);
            return p_cmd_msg->op_ret;
    }
    return ret;
}

int lock_entry_c::rw_async_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result)
{
    int ret = static_cast<int>(DLOCK_SUCCESS);
    rw_state *res = reinterpret_cast<rw_state *>(result);

    if (p_cmd_msg == nullptr) {
        res->time_out = m_lock_val.rw.time_out;
        res->client_id = m_lock_val.rw.client_id;
        res->rcount = m_lock_val.rw.rcount;
        return ret;
    }

    ret = static_cast<int>(p_cmd_msg->op_ret);
    switch (static_cast<dlock_status_t>(p_cmd_msg->op_ret)) {
        case DLOCK_SUCCESS:
            m_lock_val.base = p_cmd_msg->ls.base;
            m_lock_val.rw.rcount = p_cmd_msg->ls.rw.rcount;
            res->client_id = p_cmd_msg->ls.rw.client_id;
            res->time_out = p_cmd_msg->ls.rw.time_out;
            res->rcount = p_cmd_msg->ls.rw.rcount;
            if (p_cmd_msg->op_code == (static_cast<uint8_t>(EXCLUSIVE_TRYLOCK))) {
                m_lock_state = EXCLUSIVE_LOCKED;
                m_ref_count++;
            } else if (p_cmd_msg->op_code == (static_cast<uint8_t>(SHARED_TRYLOCK))) {
                m_lock_state = SHARED_LOCKED;
                m_ref_count++;
            } else if ((p_cmd_msg->op_code == (static_cast<uint8_t>(EXCLUSIVE_UNLOCK))) ||
                (p_cmd_msg->op_code == (static_cast<uint8_t>(SHARED_UNLOCK))))  {
                m_lock_state = UNLOCKED;
                m_ref_count = 0;
            }
            break;

        case DLOCK_FAIL:
            m_lock_state = LOCK_INITIALIZED;
            m_ref_count = 0;
            break;

        default:
            DLOCK_LOG_ERR("lock ret %d invalid, lock %d, op %d", p_cmd_msg->op_ret, m_lock_id, p_cmd_msg->op_code);
            return p_cmd_msg->op_ret;
    }

    return ret;
}

int lock_entry_c::fair_async_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result)
{
    int ret = static_cast<int>(DLOCK_SUCCESS);
    lock_state *res = reinterpret_cast<lock_state *>(result);

    if (p_cmd_msg == nullptr) {
        res->fl.time_out = m_lock_val.fl.time_out;
        res->base = m_lock_val.base;
        res->fl.t_value = m_lock_val.fl.t_value;
        return ret;
    }

    ret = static_cast<int>(p_cmd_msg->op_ret);
    switch (static_cast<dlock_status_t>(p_cmd_msg->op_ret)) {
        case DLOCK_SUCCESS:
            res->base = m_lock_val.base = p_cmd_msg->ls.base;
            res->fl.time_out = m_lock_val.fl.time_out = p_cmd_msg->ls.fl.time_out;
            res->fl.t_value = m_lock_val.fl.t_value = p_cmd_msg->ls.fl.t_value;
            if ((p_cmd_msg->op_code == EXCLUSIVE_UNLOCK) || (p_cmd_msg->op_code == SHARED_UNLOCK)) {
                m_lock_state = UNLOCKED;
                m_ref_count = 0;
            } else if ((p_cmd_msg->op_code == EXCLUSIVE_TRYLOCK) || (p_cmd_msg->op_code == EXCLUSIVE_TICKET_TRYLOCK)) {
                m_lock_state = EXCLUSIVE_LOCKED;
                m_ref_count++;
            } else if ((p_cmd_msg->op_code == SHARED_TRYLOCK) || (p_cmd_msg->op_code == SHARED_TICKET_TRYLOCK)) {
                m_lock_state = SHARED_LOCKED;
                m_ref_count++;
            }
            break;

        case DLOCK_EAGAIN:
            res->base = p_cmd_msg->ls.base;
            res->fl.time_out = p_cmd_msg->ls.fl.time_out;
            res->fl.t_value = p_cmd_msg->ls.fl.t_value;
            if ((p_cmd_msg->op_code == static_cast<uint8_t>(SHARED_TRYLOCK)) ||
                (p_cmd_msg->op_code == static_cast<uint8_t>(EXCLUSIVE_TRYLOCK))) {
                // store ticket to m_lock_val
                m_lock_val.base = p_cmd_msg->ls.base;
                m_lock_val.fl.time_out = p_cmd_msg->ls.fl.time_out;
                m_lock_val.fl.t_value = p_cmd_msg->ls.fl.t_value;
                m_lock_state = (p_cmd_msg->op_code < static_cast<uint8_t>(SHARED_TRYLOCK)) ? EXCLUSIVE_TICKETED
                              : SHARED_TICKETED;
            } else {
                res->fl.m_exclusive = m_lock_val.fl.m_exclusive;
                res->fl.m_shared = m_lock_val.fl.m_shared;
            }
            break;

        case DLOCK_FAIL:
            m_lock_state = LOCK_INITIALIZED;
            m_ref_count = 0;
            break;

        default:
            DLOCK_LOG_ERR("lock ret %d invalid, lock %d, op %d", p_cmd_msg->op_ret, m_lock_id, p_cmd_msg->op_code);
            return p_cmd_msg->op_ret;
    }

    return ret;
}

int lock_entry_c::async_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result)
{
    switch (m_lock_type) {
        case DLOCK_ATOMIC:
            return atomic_async_update_state_with_cmd_msg(p_cmd_msg, result);
        case DLOCK_RW:
            return rw_async_update_state_with_cmd_msg(p_cmd_msg, result);
        case DLOCK_FAIR:
            return fair_async_update_state_with_cmd_msg(p_cmd_msg, result);
        default:
            m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_TYPE]++;
            DLOCK_LOG_DEBUG("lock type %d not supported", static_cast<uint32_t>(m_lock_type));
            return static_cast<uint16_t>(DLOCK_EINVAL);
    }
}

int lock_entry_c::async_fill_cmd_msg(int client_id, uint16_t message_id,
    const struct lock_request *req, struct lock_cmd_msg &cmd_msg)
{
    init_cmd_msg_common_field(message_id, cmd_msg);

    switch (m_lock_type) {
        case DLOCK_ATOMIC:
            return atomic_async_fill_cmd_msg(client_id, req, cmd_msg);
        case DLOCK_RW:
            return rw_async_fill_cmd_msg(client_id, req, cmd_msg);
        case DLOCK_FAIR:
            return fair_async_fill_cmd_msg(req, cmd_msg);
        default:
            m_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_TYPE]++;
            DLOCK_LOG_DEBUG("lock type %d not supported, lock %d", static_cast<uint32_t>(m_lock_type), req->lock_id);
            return static_cast<uint16_t>(DLOCK_EINVAL);
    }
}

int lock_entry_c::fair_async_fill_cmd_msg(const struct lock_request *req, struct lock_cmd_msg &cmd_msg)
{
    struct op_ret_req *p_req_op = &g_fairlock_state_map[m_lock_state][req->lock_op];
    debug_stats_count_incre(p_req_op->stats_code);

    int ret = static_cast<int>((p_req_op->op_ret == DLOCK_ALREADY_LOCKED) ? DLOCK_SUCCESS : p_req_op->op_ret);
    cmd_msg.op_code = static_cast<uint8_t>(p_req_op->op_code);
    m_lock_state = (p_req_op->op_code == OP_LOCAL_RESET) ? (LOCK_INITIALIZED) : m_lock_state;

    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        return ret;
    }

    if ((req->lock_op == static_cast<int>(UNLOCK)) && (m_ref_count > 1)) {
        m_ref_count--;
        return static_cast<int>(DLOCK_ALREADY_LOCKED);
    }

    cmd_msg.lock_offset = m_lock_offset;
    cmd_msg.lock_type = static_cast<uint8_t>(m_lock_type);
    cmd_msg.ls.base = m_lock_val.base;
    cmd_msg.ls.fl.time_out = req->expire_time;
    return ret;
}

int lock_entry_c::atomic_async_fill_cmd_msg(int client_id, const struct lock_request *req, struct lock_cmd_msg &cmd_msg)
{
    struct op_ret_req *p_req_op = &g_atomic_state_map[m_lock_state][req->lock_op];
    debug_stats_count_incre(p_req_op->stats_code);

    int ret = static_cast<int>(p_req_op->op_ret);

    cmd_msg.op_code = static_cast<uint8_t>(p_req_op->op_code);

    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        return ret;
    }

    if ((req->lock_op == static_cast<int>(UNLOCK)) && (m_ref_count > 1)) {
        m_ref_count--;
        return static_cast<int>(DLOCK_ALREADY_LOCKED);
    }

    cmd_msg.lock_offset = m_lock_offset;
    cmd_msg.lock_type = static_cast<uint8_t>(m_lock_type);
    cmd_msg.ls.atomic.client_id = client_id;
    cmd_msg.ls.atomic.time_out = req->expire_time;
    return ret;
}

int lock_entry_c::rw_async_fill_cmd_msg(int client_id, const struct lock_request *req, struct lock_cmd_msg &cmd_msg)
{
    struct op_ret_req *p_req_op = &g_rwlock_state_map[m_lock_state][req->lock_op];
    debug_stats_count_incre(p_req_op->stats_code);

    int ret = static_cast<int>(p_req_op->op_ret);
    m_ref_count = (p_req_op->op_ret == DLOCK_ALREADY_LOCKED) ? (m_ref_count + 1) : m_ref_count;
    cmd_msg.op_code = static_cast<uint8_t>(p_req_op->op_code);

    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        return ret;
    }

    if ((req->lock_op == static_cast<int>(UNLOCK)) && (m_ref_count > 1)) {
        m_ref_count--;
        m_client->m_stats.stats[DEBUG_STATS_ALREADY_LOCKED]++;
        return static_cast<int>(DLOCK_ALREADY_LOCKED);
    }

    cmd_msg.ls.rw.client_id = ((cmd_msg.op_code == EXCLUSIVE_TRYLOCK) || (cmd_msg.op_code == EXCLUSIVE_UNLOCK))
                              ? client_id : 0;
    cmd_msg.lock_offset = m_lock_offset;
    cmd_msg.lock_type = static_cast<uint8_t>(m_lock_type);
    cmd_msg.ls.rw.time_out = req->expire_time;
    return ret;
}

void lock_entry_c::clear_lock_val(void)
{
    m_lock_val.base = 0;
    m_lock_val.fl.time_out = 0;
    m_lock_val.fl.t_value = 0;
}

void lock_entry_c::set_m_client(client_entry_c *p_client_entry)
{
    m_client = p_client_entry;
}

void lock_entry_c::debug_stats_count_incre(debug_stats_code_t stats_code)
{
    if (stats_code == DEBUG_NO_STATS_INCRE) {
        return;
    }
    m_client->m_stats.stats[stats_code]++;
}
};  // namespace dlock
