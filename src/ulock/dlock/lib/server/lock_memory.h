/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : lock_memory.h
 * Description   : manager of lock memory in server
 * History       : create file & add functions
 * 1.Date        : 2021-06-22
 * Author        : zhangjun
 * Modification  : Created file
 */

#ifndef __LOCK_MEMORY_H__
#define __LOCK_MEMORY_H__

#include <map>

#include "dlock_common.h"

namespace dlock {
constexpr unsigned int MAX_FAIR_QUESIZE = 0x7FFF;
constexpr unsigned int FAIR_QUE_SIZE_MASK = 0xFFFF;
constexpr unsigned int FAIR_QUE_SIZE_FULL = 0x10000;
constexpr unsigned int FAIR_WAIT_TIME = 2; // seconds
constexpr unsigned int FAIR_RST_TH = 50;
constexpr unsigned int MAX_FAIR_LOCK_RCNT = 63;
struct atomic_lock {
    int32_t client_id;
    uint32_t timeout;
};

struct rw_lock {
    uint32_t timeout;
    int32_t client_id;
    uint32_t ref_count;
    uint32_t rsvd;
};

struct fair_lock {
    uint16_t nx;
    uint16_t ns;
    uint16_t mx;
    uint16_t ms;
    uint32_t timeout;
    union {
        uint32_t t_value;
        struct {
            uint16_t rms;
            uint16_t rflag : 1;
            uint16_t rsvd : 9;
            uint16_t rcnt : 6;
        } bs;
    };

    /*
     * Extension area of the fair lock on the server, the lock state
     * cached on the client does not contain this area.
     */
    struct {
        int32_t client_id; /* Used to verify the identity of the client during lock operations. */
        uint32_t rsvd;
    } extend;
};

constexpr int MAX_NUM_LOCK = 51200;
constexpr unsigned int LOCK_MEMORY_SIZE = sizeof(struct fair_lock) * MAX_NUM_LOCK;

extern uint32_t g_lock_size[DLOCK_MAX];

using memory_map_t = std::map<uint32_t, uint32_t>;

class dlock_server;
class client_entry_s;

class lock_memory {
    friend class dlock_server;
    friend class client_entry_s;
public:
    lock_memory() = delete;
    lock_memory(unsigned int size, bool is_primary, dlock_server *server);
    ~lock_memory();
    uint32_t get_lock_memory(enum dlock_type lock_type);
    uint32_t get_lock_memory(enum dlock_type lock_type, uint32_t offset);
    void release_lock_memory(uint32_t offset, enum dlock_type lock_type) noexcept;
    void update_lock_state(struct lock_cmd_msg *p_cmd_msg);
    int do_lock_cmd(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls);
    int atomic_trylock_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls);
    int atomic_unlock_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls);
    int atomic_extend_lock_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls);
    int rwlock_trylock_ex_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls);
    int rwlock_unlock_ex_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls);
    int rwlock_trylock_sh_do(int32_t /* client_id */, struct lock_cmd_msg *p_cmd_msg, lock_state &ls);
    int rwlock_unlock_sh_do(int32_t /* client_id */, struct lock_cmd_msg *p_cmd_msg, lock_state &ls);
    int fairlock_trylock_ex_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const;
    int fairlock_unlock_ex_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const;
    int fairlock_extend_lock_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const;
    int fairlock_trylock_sh_do(int32_t /* client_id */, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const;
    int fairlock_unlock_sh_do(int32_t /* client_id */, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const;
    int fairlock_trylock_ex_ticket_do(int32_t client_id, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const;
    int fairlock_trylock_sh_ticket_do(int32_t /* client_id */, struct lock_cmd_msg *p_cmd_msg, lock_state &ls) const;
    void sync_lock_state(uint32_t lock_type, uint32_t lock_offset, const lock_state &ls);
    void atomic_sync_state(uint32_t lock_offset, const lock_state &ls);
    void rwlock_sync_state(uint32_t lock_offset, const lock_state &ls);
    void fairlock_sync_state(uint32_t lock_offset, const lock_state &ls);
    int verify_client_id(int32_t expected_client_id, int32_t actual_client_id,
        struct lock_cmd_msg *p_cmd_msg);

private:
    uint8_t *m_p_lock_memory;
    bool m_is_primary;
    memory_map_t m_free_memory_map;
    dlock_server *m_server;
};
};
#endif
