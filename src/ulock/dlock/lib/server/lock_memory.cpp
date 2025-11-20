/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : lock_memory.cpp
 * Description   : manager of lock memory in server
 * History       : create file & add functions
 * 1.Date        : 2021-06-22
 * Author        : zhangjun
 * Modification  : Created file
 */

#include "lock_memory.h"
#include "dlock_server.h"

#include <malloc.h>
#include <climits>
#include <sys/time.h>

#include "dlock_log.h"

namespace dlock {
uint32_t g_lock_size[DLOCK_MAX] = {
    [DLOCK_ATOMIC] = sizeof(struct atomic_lock),
    [DLOCK_RW] = sizeof(struct rw_lock),
    [DLOCK_FAIR] = sizeof(struct fair_lock)
};

int (lock_memory::* g_atomic_do[OP_CODE_MAX]) (int32_t client_id, struct lock_cmd_msg*, lock_state&) = {
    [EXCLUSIVE_TRYLOCK] = &lock_memory::atomic_trylock_do,
    [EXCLUSIVE_UNLOCK] = &lock_memory::atomic_unlock_do,
    [EXCLUSIVE_LOCK_EXTEND] = &lock_memory::atomic_extend_lock_do
};

int (lock_memory::* g_rwlock_do[OP_CODE_MAX]) (int32_t client_id, struct lock_cmd_msg*, lock_state &ls) = {
    [EXCLUSIVE_TRYLOCK] = &lock_memory::rwlock_trylock_ex_do,
    [EXCLUSIVE_UNLOCK] = &lock_memory::rwlock_unlock_ex_do,
    [EXCLUSIVE_LOCK_EXTEND] = nullptr,
    [EXCLUSIVE_TICKET_TRYLOCK] = nullptr,
    [SHARED_TRYLOCK] = &lock_memory::rwlock_trylock_sh_do,
    [SHARED_UNLOCK] = &lock_memory::rwlock_unlock_sh_do,
    [SHARED_LOCK_EXTEND] = nullptr
};

int (lock_memory::* g_fairlock_do[OP_CODE_MAX]) (int32_t client_id, struct lock_cmd_msg*, lock_state &ls) const = {
    [EXCLUSIVE_TRYLOCK] = &lock_memory::fairlock_trylock_ex_do,
    [EXCLUSIVE_UNLOCK] = &lock_memory::fairlock_unlock_ex_do,
    [EXCLUSIVE_LOCK_EXTEND] = &lock_memory::fairlock_extend_lock_do,
    [EXCLUSIVE_TICKET_TRYLOCK] = &lock_memory::fairlock_trylock_ex_ticket_do,
    [SHARED_TRYLOCK] = &lock_memory::fairlock_trylock_sh_do,
    [SHARED_UNLOCK] = &lock_memory::fairlock_unlock_sh_do,
    [SHARED_LOCK_EXTEND] = &lock_memory::fairlock_extend_lock_do,
    [SHARED_TICKET_TRYLOCK] = &lock_memory::fairlock_trylock_sh_ticket_do
};

static inline void fairlock_set_fl_state(fairlock_state &fl, const struct fair_lock &fairlock)
{
    fl.m_exclusive = fairlock.mx;
    fl.m_shared = fairlock.ms;
    fl.n_exclusive = fairlock.nx;
    fl.n_shared = fairlock.ns;
    fl.time_out = fairlock.timeout;
    fl.t_value = fairlock.t_value;
}

lock_memory::lock_memory(unsigned int size, bool is_primary, dlock_server *server)
    : m_p_lock_memory((uint8_t *)memalign(DLOCK_UB_SEG_VA_ALIGN_SIZE, size)),
      m_is_primary(is_primary), m_server(server)
{
    DLOCK_LOG_DEBUG("lock_memory init");

    if (m_p_lock_memory == nullptr) {
        DLOCK_LOG_ERR("calloc error (errno=%d %m)", errno);
        return;
    }
    static_cast<void>(memset(m_p_lock_memory, 0, size));
    m_free_memory_map[0] = size;
}

lock_memory::~lock_memory()
{
    if (m_p_lock_memory != nullptr) {
        free(m_p_lock_memory);
        m_p_lock_memory = nullptr;
    }
}

uint32_t lock_memory::get_lock_memory(enum dlock_type lock_type)
{
    memory_map_t::const_iterator iter = m_free_memory_map.cbegin();
    uint32_t lock_size = g_lock_size[lock_type];

    if (!m_is_primary) {
        return UINT_MAX;
    }

    if (m_free_memory_map.empty()) {
        DLOCK_LOG_ERR("no memory left");
        return UINT_MAX;
    }

    while (iter->second < lock_size) {
        ++iter;
        if (iter == m_free_memory_map.cend()) {
            DLOCK_LOG_ERR("not enough memory");
            return UINT_MAX;
        }
    }

    uint32_t offset = iter->first;
    uint32_t length = iter->second;

    static_cast<void>(m_free_memory_map.erase(iter));
    if (length > lock_size) {
        m_free_memory_map[offset + lock_size] = length - lock_size;
    }
    /* lock_size is smaller that the size of lock_memory */
    static_cast<void>(memset(m_p_lock_memory + offset, 0, lock_size));

    return offset;
}

uint32_t lock_memory::get_lock_memory(enum dlock_type lock_type, uint32_t offset)
{
    memory_map_t::const_iterator iter = m_free_memory_map.upper_bound(offset);
    uint32_t lock_size = g_lock_size[lock_type];

    DLOCK_LOG_DEBUG("get lock memory by offset %d", offset);
    if ((m_free_memory_map.empty()) || (iter == m_free_memory_map.cbegin())) {
        DLOCK_LOG_ERR("no memory left");
        return UINT_MAX;
    }
    --iter;

    uint32_t mem_offset = iter->first;
    uint32_t mem_end = iter->first + iter->second;    // [mem_offset, mem_end)
    uint32_t end = offset + lock_size;    // [offset, end)
    if ((offset < mem_offset) || (end > mem_end)) {
        DLOCK_LOG_ERR("not enough memory");
        return UINT_MAX;
    }

    static_cast<void>(m_free_memory_map.erase(iter));
    if (offset > mem_offset) {
        m_free_memory_map[mem_offset] = offset - mem_offset;
    }
    if (end < mem_end) {
        m_free_memory_map[end] = mem_end - end;
    }
    static_cast<void>(memset(m_p_lock_memory + offset, 0, lock_size));

    return offset;
}

void lock_memory::release_lock_memory(uint32_t offset, enum dlock_type lock_type) noexcept
{
    uint32_t new_offset = offset;
    uint32_t new_length = g_lock_size[lock_type];
    memory_map_t::const_iterator iter = m_free_memory_map.find(new_offset + new_length);
    if (iter != m_free_memory_map.cend()) {
        new_length += iter->second;
        static_cast<void>(m_free_memory_map.erase(iter));
    }

    iter = m_free_memory_map.upper_bound(new_offset);
    if (iter != m_free_memory_map.cbegin()) {
        --iter;
        if ((iter->first + iter->second) == new_offset) {
            new_offset = iter->first;
            new_length += iter->second;
            static_cast<void>(m_free_memory_map.erase(iter));
        }
    }
    m_free_memory_map[new_offset] = new_length;
    DLOCK_LOG_DEBUG("offset %d, new offset %d", offset, new_offset);
}

void lock_memory::update_lock_state(struct lock_cmd_msg *p_cmd_msg)
{
    if (p_cmd_msg->lock_type >= static_cast<uint8_t>(DLOCK_MAX)) {
        DLOCK_LOG_DEBUG("unsupported cmd message lock_type: %u", p_cmd_msg->lock_type);
        return;
    }

    if (p_cmd_msg->op_code >= static_cast<uint8_t>(OP_CODE_MAX)) {
        DLOCK_LOG_DEBUG("unsupported cmd message op_code: %u", p_cmd_msg->op_code);
        return;
    }

    if (p_cmd_msg->lock_offset > (LOCK_MEMORY_SIZE - g_lock_size[p_cmd_msg->lock_type])) {
        DLOCK_LOG_DEBUG("unsupported cmd message lock_offset: %u", p_cmd_msg->lock_offset);
        return;
    }

    if ((p_cmd_msg->op_ret == static_cast<uint16_t>(DLOCK_SUCCESS)) ||
        (p_cmd_msg->op_ret == static_cast<uint16_t>(DLOCK_EAGAIN))) {
        lock_state *p_lockstate = reinterpret_cast<lock_state*>(m_p_lock_memory + p_cmd_msg->lock_offset);
        p_lockstate->base = p_cmd_msg->ls.base;
        if (p_cmd_msg->lock_type == static_cast<uint8_t>(DLOCK_FAIR)) {
            p_lockstate->fl.time_out = p_cmd_msg->ls.fl.time_out;
            p_lockstate->fl.t_value = p_cmd_msg->ls.fl.t_value;
        }
    }
}

int lock_memory::do_lock_cmd(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls)
{
    if (p_cmd_msg->lock_type >= static_cast<uint8_t>(DLOCK_MAX)) {
        m_server->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_TYPE]++;
        DLOCK_LOG_DEBUG("unsupported cmd message lock_type: %u", p_cmd_msg->lock_type);
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EINVAL);
        return static_cast<int>(DLOCK_DONE);
    }
    if (p_cmd_msg->op_code >= static_cast<uint8_t>(OP_CODE_MAX)) {
        m_server->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
        DLOCK_LOG_DEBUG("unsupported cmd message op_code: %u", p_cmd_msg->op_code);
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EINVAL);
        return static_cast<int>(DLOCK_DONE);
    }
    if (p_cmd_msg->lock_offset > (LOCK_MEMORY_SIZE - g_lock_size[p_cmd_msg->lock_type])) {
        m_server->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OFFSET]++;
        DLOCK_LOG_DEBUG("unsupported cmd message lock_offset: %u", p_cmd_msg->lock_offset);
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EINVAL);
        return static_cast<int>(DLOCK_DONE);
    }

    switch (p_cmd_msg->lock_type) {
        case DLOCK_ATOMIC:
            if (g_atomic_do[p_cmd_msg->op_code] == nullptr) {
                m_server->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
                DLOCK_LOG_DEBUG("unsupported type of control message");
                p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EINVAL);
                return static_cast<int>(DLOCK_DONE);
            }
            return (this->*g_atomic_do[p_cmd_msg->op_code])(client_id, p_cmd_msg, ls);
        case DLOCK_RW:
            if (g_rwlock_do[p_cmd_msg->op_code] == nullptr) {
                m_server->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
                DLOCK_LOG_DEBUG("unsupported type of control message");
                p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EINVAL);
                return static_cast<int>(DLOCK_DONE);
            }
            return (this->*g_rwlock_do[p_cmd_msg->op_code])(client_id, p_cmd_msg, ls);
        case DLOCK_FAIR:
            if (g_fairlock_do[p_cmd_msg->op_code] == nullptr) {
                m_server->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
                DLOCK_LOG_DEBUG("unsupported type of control message");
                p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EINVAL);
                return static_cast<int>(DLOCK_DONE);
            }
            return (this->*g_fairlock_do[p_cmd_msg->op_code])(client_id, p_cmd_msg, ls);
        default:
            m_server->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_TYPE]++;
            p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EINVAL);
            return static_cast<int>(DLOCK_DONE);
    }
}

int lock_memory::verify_client_id(int32_t expected_client_id, int32_t actual_client_id,
    struct lock_cmd_msg *p_cmd_msg)
{
    if (actual_client_id == expected_client_id) {
        return 0;
    }

    m_server->m_stats.stats[DEBUG_STATS_CLIENT_ID_VERIFY_FAIL]++;
    DLOCK_LOG_DEBUG("Failed to verify client_id");
    p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
    return -1;
}

int lock_memory::atomic_trylock_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls)
{
    struct atomic_lock *p_atomic = reinterpret_cast<struct atomic_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);
    struct timeval tv;

    if (verify_client_id(client_id, p_cmd_msg->ls.atomic.client_id, p_cmd_msg)) {
        return static_cast<int>(DLOCK_DONE);
    }

    static_cast<void>(gettimeofday(&tv, nullptr));
    if (p_atomic->client_id != 0) {
        if (tv.tv_sec <= p_atomic->timeout) {
            m_server->m_stats.stats[DEBUG_STATS_ATOMIC_TRYLOCK_FAIL]++;
            DLOCK_LOG_DEBUG("atomic trylock fail");
            p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
            ls.atomic.client_id = p_atomic->client_id;
            ls.atomic.time_out = p_atomic->timeout;
            return static_cast<int>(DLOCK_DONE);
        }
    }

    p_atomic->client_id = p_cmd_msg->ls.atomic.client_id;
    p_atomic->timeout = p_cmd_msg->ls.atomic.time_out + static_cast<unsigned>(tv.tv_sec);
    p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
    ls.atomic.client_id = p_atomic->client_id;
    ls.atomic.time_out = p_atomic->timeout;
    return static_cast<int>(DLOCK_SUCCESS);
}

int lock_memory::atomic_unlock_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls)
{
    struct atomic_lock *p_atomic = reinterpret_cast<struct atomic_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    if (verify_client_id(client_id, p_cmd_msg->ls.atomic.client_id, p_cmd_msg)) {
        return static_cast<int>(DLOCK_DONE);
    }

    if (p_atomic->client_id != p_cmd_msg->ls.atomic.client_id) {
        m_server->m_stats.stats[DEBUG_STATS_ATOMIC_UNLOCK_FAIL]++;
        DLOCK_LOG_DEBUG("atomic unlock fail");
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        ls.atomic.client_id = p_atomic->client_id;
        ls.atomic.time_out = p_atomic->timeout;
        return static_cast<int>(DLOCK_DONE);
    }

    p_atomic->client_id = 0;
    p_atomic->timeout = 0;
    p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
    ls.base = 0;
    return static_cast<int>(DLOCK_SUCCESS);
}

int lock_memory::atomic_extend_lock_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls)
{
    struct atomic_lock *p_atomic = reinterpret_cast<struct atomic_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);
    bool b_updated;

    if (verify_client_id(client_id, p_cmd_msg->ls.atomic.client_id, p_cmd_msg)) {
        return static_cast<int>(DLOCK_DONE);
    }

    if (p_atomic->client_id != p_cmd_msg->ls.atomic.client_id) {
        m_server->m_stats.stats[DEBUG_STATS_ATOMIC_EXTEND_FAIL]++;
        DLOCK_LOG_DEBUG("invalid atomic lock");
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        ls.atomic.client_id = p_atomic->client_id;
        ls.atomic.time_out = p_atomic->timeout;
        return static_cast<int>(DLOCK_DONE);
    }
    p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
    b_updated = (p_atomic->timeout < p_cmd_msg->ls.atomic.time_out);
    p_atomic->timeout = (b_updated) ? p_cmd_msg->ls.atomic.time_out : p_atomic->timeout;
    ls.atomic.client_id = p_atomic->client_id;
    ls.atomic.time_out = p_atomic->timeout;

    return (b_updated) ? static_cast<int>(DLOCK_SUCCESS) : static_cast<int>(DLOCK_DONE);
}

int lock_memory::rwlock_trylock_ex_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls)
{
    struct rw_lock *p_rw = reinterpret_cast<struct rw_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);
    struct timeval tv;

    if (verify_client_id(client_id, static_cast<int32_t>(p_cmd_msg->ls.rw.client_id), p_cmd_msg)) {
        return static_cast<int>(DLOCK_DONE);
    }

    static_cast<void>(gettimeofday(&tv, nullptr));
    if ((p_rw->client_id != 0) || (p_rw->ref_count != 0u)) {
        m_server->m_stats.stats[DEBUG_STATS_RW_TRYLOCK_EX_FAIL]++;
        DLOCK_LOG_DEBUG("RWlock exclusive trylock fail");
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        ls.rw.client_id = p_rw->client_id;
        ls.rw.time_out = p_rw->timeout;
        ls.rw.rcount = p_rw->ref_count;
        return static_cast<int>(DLOCK_DONE);
    }

    p_rw->client_id = p_cmd_msg->ls.rw.client_id;
    p_rw->timeout = static_cast<unsigned>(tv.tv_sec);
    p_rw->ref_count = 0;
    p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
    ls.rw.client_id = p_rw->client_id;
    ls.rw.time_out = p_rw->timeout;
    ls.rw.rcount = p_rw->ref_count;
    return static_cast<int>(DLOCK_SUCCESS);
}

int lock_memory::rwlock_unlock_ex_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls)
{
    struct rw_lock *p_rw = reinterpret_cast<struct rw_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    if (verify_client_id(client_id, static_cast<int32_t>(p_cmd_msg->ls.rw.client_id), p_cmd_msg)) {
        return static_cast<int>(DLOCK_DONE);
    }

    /* Notice: value 0 of client_id field at server side means the lock is in shared mode,
     * so client_id 0 should be reserved at get_lock API */
    if (p_rw->client_id != p_cmd_msg->ls.rw.client_id) {
        m_server->m_stats.stats[DEBUG_STATS_RW_UNLOCK_EX_FAIL]++;
        DLOCK_LOG_DEBUG("RWlock exclusive unlock fail, lock is occupied or unlocked by others");
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        ls.rw.client_id = p_rw->client_id;
        ls.rw.time_out = p_rw->timeout;
        ls.rw.rcount = p_rw->ref_count;
        return static_cast<int>(DLOCK_DONE);
    }

    p_rw->client_id = 0;
    p_rw->timeout = 0;
    p_rw->ref_count = 0;
    p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
    ls.base = 0;
    return static_cast<int>(DLOCK_SUCCESS);
}

int lock_memory::rwlock_trylock_sh_do(int32_t /* client_id */, struct lock_cmd_msg *p_cmd_msg, lock_state &ls)
{
    struct rw_lock *p_rw = reinterpret_cast<struct rw_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);
    struct timeval tv;

    if (verify_client_id(0, static_cast<int32_t>(p_cmd_msg->ls.rw.client_id), p_cmd_msg)) {
        return static_cast<int>(DLOCK_DONE);
    }

    static_cast<void>(gettimeofday(&tv, nullptr));
    if (p_rw->client_id != 0) {
        m_server->m_stats.stats[DEBUG_STATS_RW_TRYLOCK_SH_FAIL]++;
        DLOCK_LOG_DEBUG("RWlock shared trylock fail");
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        ls.rw.client_id = p_rw->client_id;
        ls.rw.time_out = p_rw->timeout;
        ls.rw.rcount = p_rw->ref_count;
        return static_cast<int>(DLOCK_DONE);
    }

    p_rw->client_id = p_cmd_msg->ls.rw.client_id;
    p_rw->timeout = (p_rw->timeout == 0u) ? static_cast<unsigned>(tv.tv_sec) : p_rw->timeout;
    p_rw->ref_count++;
    p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
    ls.rw.client_id = p_rw->client_id;
    ls.rw.time_out = p_rw->timeout;
    ls.rw.rcount = p_rw->ref_count;
    return static_cast<int>(DLOCK_SUCCESS);
}

int lock_memory::rwlock_unlock_sh_do(int32_t /* client_id */, struct lock_cmd_msg *p_cmd_msg, lock_state &ls)
{
    struct rw_lock *p_rw = reinterpret_cast<struct rw_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    if (verify_client_id(0, static_cast<int32_t>(p_cmd_msg->ls.rw.client_id), p_cmd_msg)) {
        return static_cast<int>(DLOCK_DONE);
    }

    /* Notice: value 0 of client_id field at server side means the lock is in shared mode,
     * so client_id 0 should be reserved at get_lock API */
    if ((p_rw->client_id != 0) || ((p_rw->client_id == 0) && (p_rw->ref_count == 0u))) {
        m_server->m_stats.stats[DEBUG_STATS_RW_UNLOCK_SH_FAIL]++;
        DLOCK_LOG_DEBUG("RWlock shared unlock fail, lock is in exclusive mode or not locked");
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        ls.rw.client_id = p_rw->client_id;
        ls.rw.time_out = p_rw->timeout;
        ls.rw.rcount = p_rw->ref_count;
        return static_cast<int>(DLOCK_DONE);
    }

    p_rw->ref_count--;
    p_rw->timeout = (p_rw->ref_count == 0u) ? 0u : p_rw->timeout;
    ls.rw.rcount = p_rw->ref_count;
    ls.rw.time_out = p_rw->timeout;
    ls.rw.client_id = p_rw->client_id;
    p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
    return static_cast<int>(DLOCK_SUCCESS);
}

int lock_memory::fairlock_trylock_ex_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const
{
    struct fair_lock *p_fairlock = reinterpret_cast<struct fair_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    bool b_overflow =
        ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + p_fairlock->mx) - p_fairlock->nx)) >= MAX_FAIR_QUESIZE) ||
         ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + p_fairlock->ms) - p_fairlock->ns)) >= MAX_FAIR_QUESIZE);

    if (b_overflow) {
        m_server->m_stats.stats[DEBUG_STATS_FAIR_QUEUE_LIMIT]++;
        DLOCK_LOG_DEBUG("fairlock ex reach que limit, offset %x", p_cmd_msg->lock_offset);
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        return static_cast<int>(DLOCK_DONE);
    }

    struct timeval tv;
    static_cast<void>(gettimeofday(&tv, nullptr));
    if ((p_fairlock->extend.client_id == 0) &&
        (p_fairlock->nx == p_fairlock->mx) && (p_fairlock->ns == p_fairlock->ms)) {
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
        p_fairlock->timeout = p_cmd_msg->ls.fl.time_out + static_cast<unsigned>(tv.tv_sec);
        p_fairlock->extend.client_id = client_id;
    } else {
        m_server->m_stats.stats[DEBUG_STATS_EAGAIN]++;
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EAGAIN);
    }

    p_fairlock->mx++;
    fairlock_set_fl_state(ls.fl, *p_fairlock);
    DLOCK_LOG_DEBUG("fair ex trylock success");
    return static_cast<int>(p_cmd_msg->op_ret);
}

int lock_memory::fairlock_unlock_ex_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const
{
    struct fair_lock *p_fairlock = reinterpret_cast<struct fair_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    if (((p_fairlock->extend.client_id == client_id) || (p_fairlock->extend.client_id == 0)) &&
        (p_fairlock->nx == p_cmd_msg->ls.fl.n_exclusive) && (p_fairlock->ns == p_cmd_msg->ls.fl.n_shared)) {
        struct timeval tv;
        static_cast<void>(gettimeofday(&tv, nullptr));
        p_fairlock->nx++;
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
        p_fairlock->timeout = FAIR_WAIT_TIME + static_cast<unsigned>(tv.tv_sec);
        p_fairlock->bs.rflag = 0;  // ex unlock success, clear rst flag
        p_fairlock->extend.client_id = 0;
        fairlock_set_fl_state(ls.fl, *p_fairlock);
    } else {
        m_server->m_stats.stats[DEBUG_STATS_FAIR_UNLOCK_EX_FAIL]++;
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        fairlock_set_fl_state(ls.fl, *p_fairlock);
        return static_cast<int>(DLOCK_DONE);
    }
    return static_cast<int>(DLOCK_SUCCESS);
}

int lock_memory::fairlock_extend_lock_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const
{
    struct fair_lock *p_fairlock = reinterpret_cast<struct fair_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    if ((p_fairlock->extend.client_id != client_id) && (p_fairlock->extend.client_id != 0)) {
        fairlock_set_fl_state(ls.fl, *p_fairlock);
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        return static_cast<int>(DLOCK_DONE);
    }

    bool b_extend = (p_cmd_msg->ls.fl.n_exclusive == p_fairlock->nx);
    bool b_passed = (p_fairlock->bs.rflag == 1u) &&
        ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + p_cmd_msg->ls.fl.n_shared) - p_fairlock->bs.rms)) >
         MAX_FAIR_QUESIZE);
    b_extend = b_extend && (!b_passed) && ((p_cmd_msg->op_code == static_cast<uint8_t>(EXCLUSIVE_LOCK_EXTEND)) ?
                    (p_cmd_msg->ls.fl.n_shared == p_fairlock->ns) : true);
    p_cmd_msg->op_ret = static_cast<uint16_t>((b_extend) ? DLOCK_SUCCESS : DLOCK_FAIL);

    b_extend = ((b_extend) && (p_cmd_msg->ls.fl.time_out != 0u));
    if (b_extend) {
        b_extend = p_cmd_msg->ls.fl.time_out > p_fairlock->timeout;
        p_fairlock->timeout = (b_extend) ? p_cmd_msg->ls.fl.time_out : p_fairlock->timeout;
    }

    fairlock_set_fl_state(ls.fl, *p_fairlock);
    return (b_extend) ? static_cast<int>(DLOCK_SUCCESS) : static_cast<int>(DLOCK_DONE);
}

int lock_memory::fairlock_trylock_sh_do(int32_t /* client_id */, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const
{
    struct fair_lock *p_fairlock = reinterpret_cast<struct fair_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    bool b_overflow =
        ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + p_fairlock->mx) - p_fairlock->nx)) >= MAX_FAIR_QUESIZE) ||
         ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + p_fairlock->ms) - p_fairlock->ns)) >= MAX_FAIR_QUESIZE);

    if (b_overflow) {
        m_server->m_stats.stats[DEBUG_STATS_FAIR_QUEUE_LIMIT]++;
        DLOCK_LOG_DEBUG("fairlock sh reach que limit, offset %x", p_cmd_msg->lock_offset);
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        return static_cast<int>(DLOCK_DONE);
    }

    struct timeval tv;
    static_cast<void>(gettimeofday(&tv, nullptr));
    if ((p_fairlock->extend.client_id == 0) &&
        (p_fairlock->nx == p_fairlock->mx) && (p_fairlock->bs.rcnt < MAX_FAIR_LOCK_RCNT)) {
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
        p_fairlock->timeout = ((p_cmd_msg->ls.fl.time_out + static_cast<unsigned>(tv.tv_sec)) > p_fairlock->timeout) ?
                           (p_cmd_msg->ls.fl.time_out + static_cast<unsigned>(tv.tv_sec)) : p_fairlock->timeout;
        p_fairlock->bs.rcnt++;
    } else {
        m_server->m_stats.stats[DEBUG_STATS_EAGAIN]++;
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EAGAIN);
    }

    p_fairlock->ms++;
    fairlock_set_fl_state(ls.fl, *p_fairlock);
    return static_cast<int>(p_cmd_msg->op_ret);
}

int lock_memory::fairlock_unlock_sh_do(int32_t /* client_id */, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const
{
    struct fair_lock *p_fairlock = reinterpret_cast<struct fair_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    bool b_passed = (p_fairlock->bs.rflag == 1u) &&
        ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + p_cmd_msg->ls.fl.n_shared) - p_fairlock->bs.rms)) >
         MAX_FAIR_QUESIZE);
    if ((p_fairlock->extend.client_id == 0) &&
        (!b_passed) && (p_fairlock->nx == p_cmd_msg->ls.fl.n_exclusive)) {
        struct timeval tv;
        static_cast<void>(gettimeofday(&tv, nullptr));
        p_fairlock->ns++;  // ignore passed tickets ?
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
        p_fairlock->bs.rcnt--;
        p_fairlock->timeout = (p_fairlock->bs.rcnt == 0u) ?
            static_cast<unsigned>(FAIR_WAIT_TIME + tv.tv_sec) : p_fairlock->timeout;
        p_fairlock->bs.rflag = ((p_fairlock->bs.rflag == 0u) ||
            ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + p_fairlock->ns) - p_fairlock->bs.rms)) >= FAIR_RST_TH)) ?
      	    0 : 1;
        fairlock_set_fl_state(ls.fl, *p_fairlock);
    } else {
        m_server->m_stats.stats[DEBUG_STATS_FAIR_UNLOCK_SH_FAIL]++;
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        fairlock_set_fl_state(ls.fl, *p_fairlock);
        return static_cast<int>(DLOCK_DONE);
    }
    return static_cast<int>(DLOCK_SUCCESS);
}

int lock_memory::fairlock_trylock_ex_ticket_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const
{
    struct fair_lock *p_fairlock = reinterpret_cast<struct fair_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    bool b_passed =
        ((FAIR_QUE_SIZE_MASK &
          ((FAIR_QUE_SIZE_FULL + p_cmd_msg->ls.fl.m_exclusive) - p_fairlock->nx)) > MAX_FAIR_QUESIZE) ||
        ((FAIR_QUE_SIZE_MASK &
          ((FAIR_QUE_SIZE_FULL + p_cmd_msg->ls.fl.m_shared) - p_fairlock->ns)) > MAX_FAIR_QUESIZE);

    if (b_passed) {
        m_server->m_stats.stats[DEBUG_STATS_FAIR_EX_TICKET_PASSED]++;
        DLOCK_LOG_DEBUG("fairlock ex ticket passed, offset %x", p_cmd_msg->lock_offset);
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        return static_cast<int>(DLOCK_DONE);
    }
    struct timeval tv;
    static_cast<void>(gettimeofday(&tv, nullptr));
    if ((p_fairlock->extend.client_id == 0) &&
        (p_cmd_msg->ls.fl.m_exclusive == p_fairlock->nx) && (p_cmd_msg->ls.fl.m_shared == p_fairlock->ns)) {
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
        p_fairlock->timeout = p_cmd_msg->ls.fl.time_out + static_cast<unsigned>(tv.tv_sec);
        p_fairlock->extend.client_id = client_id;
    } else if (tv.tv_sec > p_fairlock->timeout) {
        p_fairlock->nx = p_cmd_msg->ls.fl.m_exclusive;
        p_fairlock->ns = p_cmd_msg->ls.fl.m_shared;
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
        p_fairlock->bs.rflag = 1;
        p_fairlock->bs.rcnt = 0;
        p_fairlock->bs.rms = p_cmd_msg->ls.fl.m_shared;
        DLOCK_LOG_DEBUG("ex, timeout %lx, lock %x", tv.tv_sec, p_fairlock->timeout);
        p_fairlock->timeout = p_cmd_msg->ls.fl.time_out + static_cast<unsigned>(tv.tv_sec);
        p_fairlock->extend.client_id = client_id;
    } else {
        m_server->m_stats.stats[DEBUG_STATS_EAGAIN]++;
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EAGAIN);
    }
    fairlock_set_fl_state(ls.fl, *p_fairlock);
    return (p_cmd_msg->op_ret == static_cast<uint16_t>(DLOCK_EAGAIN)) ? static_cast<int>(DLOCK_DONE)
        : static_cast<int>(DLOCK_SUCCESS);
}

int lock_memory::fairlock_trylock_sh_ticket_do(int32_t /* client_id */,
    struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const
{
    struct fair_lock *p_fairlock = reinterpret_cast<struct fair_lock*>(m_p_lock_memory + p_cmd_msg->lock_offset);

    bool b_passed = ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + p_cmd_msg->ls.fl.m_exclusive) - p_fairlock->nx)) >
                     MAX_FAIR_QUESIZE);
    b_passed = (b_passed || (p_fairlock->bs.rflag == 0u)) ? b_passed :
        ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + p_cmd_msg->ls.fl.m_shared) - p_fairlock->bs.rms)) >
         MAX_FAIR_QUESIZE);

    if (b_passed) {
        m_server->m_stats.stats[DEBUG_STATS_FAIR_SH_TICKET_PASSED]++;
        DLOCK_LOG_DEBUG("fairlock sh ticket passed, offset %x", p_cmd_msg->lock_offset);
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_FAIL);
        return static_cast<int>(DLOCK_DONE);
    }
    struct timeval tv;
    static_cast<void>(gettimeofday(&tv, nullptr));
    if ((p_fairlock->extend.client_id == 0) &&
        (p_cmd_msg->ls.fl.m_exclusive == p_fairlock->nx) && (p_fairlock->bs.rcnt < MAX_FAIR_LOCK_RCNT)) {
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
        p_fairlock->timeout = ((p_cmd_msg->ls.fl.time_out + static_cast<unsigned>(tv.tv_sec)) > p_fairlock->timeout) ?
                               (p_cmd_msg->ls.fl.time_out + static_cast<unsigned>(tv.tv_sec)) : p_fairlock->timeout;
        p_fairlock->bs.rcnt++;
    } else if (tv.tv_sec > p_fairlock->timeout) {
        p_fairlock->nx = p_cmd_msg->ls.fl.m_exclusive;
        p_fairlock->ns = p_cmd_msg->ls.fl.m_shared;
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_SUCCESS);
        p_fairlock->bs.rflag = 1;
        p_fairlock->bs.rcnt = 1;
        p_fairlock->bs.rms = p_cmd_msg->ls.fl.m_shared;
        DLOCK_LOG_DEBUG("sh, timeout %lx, lock %x", tv.tv_sec, p_fairlock->timeout);
        p_fairlock->timeout = p_cmd_msg->ls.fl.time_out + static_cast<unsigned>(tv.tv_sec);
        p_fairlock->extend.client_id = 0;
    } else {
        m_server->m_stats.stats[DEBUG_STATS_EAGAIN]++;
        p_cmd_msg->op_ret = static_cast<uint16_t>(DLOCK_EAGAIN);
    }
    fairlock_set_fl_state(ls.fl, *p_fairlock);

    return (p_cmd_msg->op_ret == static_cast<uint16_t>(DLOCK_EAGAIN)) ? static_cast<int>(DLOCK_DONE)
        : static_cast<int>(DLOCK_SUCCESS);
}

void lock_memory::sync_lock_state(uint32_t lock_type, uint32_t lock_offset, const lock_state &ls)
{
    switch (static_cast<enum dlock_type>(lock_type)) {
        case DLOCK_ATOMIC:
            return atomic_sync_state(lock_offset, ls);
        case DLOCK_RW:
            return rwlock_sync_state(lock_offset, ls);
        case DLOCK_FAIR:
            return fairlock_sync_state(lock_offset, ls);
        default:
            DLOCK_LOG_ERR("invalid lock type %x.", lock_type);
    }
}

void lock_memory::atomic_sync_state(uint32_t lock_offset, const lock_state &ls)
{
    struct atomic_lock *p_atomic = reinterpret_cast<struct atomic_lock*>(m_p_lock_memory + lock_offset);
    if (p_atomic->timeout < ls.atomic.time_out) {
        p_atomic->timeout = ls.atomic.time_out;
        p_atomic->client_id = ls.atomic.client_id;
    }
}

void lock_memory::rwlock_sync_state(uint32_t lock_offset, const lock_state &ls)
{
    if (ls.rw.time_out == 0u) {
        return;
    }

    struct rw_lock *p_rw = reinterpret_cast<struct rw_lock*>(m_p_lock_memory + lock_offset);

    if (ls.rw.client_id != 0) {
        if (ls.rw.time_out <= p_rw->timeout) {
            return;
        }
        p_rw->timeout = ls.rw.time_out;
        p_rw->client_id = ls.rw.client_id;
        p_rw->ref_count = ls.rw.rcount;
        return;
    }

    if (p_rw->client_id != 0) {
        if (ls.rw.time_out <= p_rw->timeout) {
            return;
        }
        p_rw->timeout = ls.rw.time_out;
        p_rw->client_id = ls.rw.client_id;
        p_rw->ref_count = 1;
        return;
    }

    p_rw->timeout = (p_rw->timeout < ls.rw.time_out) ? ls.rw.time_out : p_rw->timeout;
    p_rw->client_id = 0;
    p_rw->ref_count++;
    return;
}

void lock_memory::fairlock_sync_state(uint32_t lock_offset, const lock_state &ls)
{
    if (ls.fl.time_out == 0u) {
        return;
    }
    struct fair_lock *p_fairlock = reinterpret_cast<struct fair_lock*>(m_p_lock_memory + lock_offset);
    if (p_fairlock->timeout == 0u) {
        p_fairlock->timeout = ls.fl.time_out;
        p_fairlock->ns = ls.fl.n_shared;
        p_fairlock->nx = ls.fl.n_exclusive;
        p_fairlock->ms = ls.fl.m_shared;
        p_fairlock->mx = ls.fl.m_exclusive;
        p_fairlock->bs.rms = ls.fl.bs.rms;
        p_fairlock->bs.rflag = ls.fl.bs.rflag;
        p_fairlock->bs.rcnt = ls.fl.bs.rcnt;
        return;
    }
    if  (p_fairlock->timeout == ls.fl.time_out) {
        p_fairlock->ns =
            ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + ls.fl.n_shared) - p_fairlock->ns)) > MAX_FAIR_QUESIZE)
            ? p_fairlock->ns : ls.fl.n_shared;
        p_fairlock->nx =
            ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + ls.fl.n_exclusive) - p_fairlock->nx)) > MAX_FAIR_QUESIZE)
            ? p_fairlock->nx : ls.fl.n_exclusive;
        p_fairlock->bs.rcnt += ls.fl.bs.rcnt;
    } else if (p_fairlock->timeout < ls.fl.time_out) {
        /* Reuse rcnt to identify the local lock state of the client,
           only if the lock state is shared_locked, ls.fl.bs.rcnt = 1 */
        if ((ls.fl.bs.rcnt == 1u) && (ls.fl.n_exclusive == p_fairlock->nx)) {
            p_fairlock->bs.rcnt += ls.fl.bs.rcnt;
        } else {
            p_fairlock->bs.rcnt = ls.fl.bs.rcnt;
        }
        p_fairlock->ns = ls.fl.n_shared;
        p_fairlock->nx = ls.fl.n_exclusive;
        p_fairlock->timeout = ls.fl.time_out;
        p_fairlock->bs.rms = ls.fl.bs.rms;
        p_fairlock->bs.rflag = ls.fl.bs.rflag;
    } else {
        if ((ls.fl.bs.rcnt == 1u) && (ls.fl.n_exclusive == p_fairlock->nx)) {
            p_fairlock->bs.rcnt += ls.fl.bs.rcnt;
        }
    }

    p_fairlock->ms =
        ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + ls.fl.m_shared) - p_fairlock->ms)) > MAX_FAIR_QUESIZE)
        ? p_fairlock->ms : ls.fl.m_shared;
    p_fairlock->mx =
        ((FAIR_QUE_SIZE_MASK & ((FAIR_QUE_SIZE_FULL + ls.fl.m_exclusive) - p_fairlock->mx)) > MAX_FAIR_QUESIZE)
        ? p_fairlock->mx : ls.fl.m_exclusive;
}
};
