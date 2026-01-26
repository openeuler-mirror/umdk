/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc thread local closure
 * Create: 2025-07-21
 */

#include <thread>

#include "urpc_thread_closure.h"

class urpc_thread_closure {
public:
    urpc_thread_closure()
    {
        m_id = 0;
        m_closure = nullptr;
    };

    ~urpc_thread_closure()
    {
        if (m_closure != nullptr) {
            m_closure(m_id);
        }
    }

    void set(uint64_t id, void (*closure)(uint64_t id))
    {
        m_id = id;
        m_closure = closure;
    }

private:
    uint64_t m_id;
    void (*m_closure)(uint64_t id);
};

static thread_local urpc_thread_closure g_urpc_thread_closure[THREAD_CLOSURE_MAX];

void urpc_thread_closure_register(urpc_thread_closure_type_t type, uint64_t id, void (*closure)(uint64_t id))
{
    g_urpc_thread_closure[type].set(id, closure);
}
