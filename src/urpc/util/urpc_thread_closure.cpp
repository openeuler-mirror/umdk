/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc thread local closure
 * Create: 2025-07-21
 */

#include <thread>
#include <stdlib.h>

#include "urpc_thread_closure.h"

/* Defined here (not in a header) so only this TU owns the symbol; declared in
 * urpc_thread_closure.h for visibility to the C-side release_thread_cache variants. */
volatile bool g_tls_dtors_running = false;

/* Set g_tls_dtors_running=true via atexit() handler, which runs BEFORE
 * __call_tls_dtors() during exit(). This ensures the flag is only set during
 * process exit — NOT during normal thread exit (pthread_exit/return).
 *
 * Previously the flag was set in ~urpc_thread_closure() destructor, which fires
 * on BOTH normal thread exit AND process exit. Setting it on normal thread exit
 * caused release_thread_cache() to skip cleanup (buf leak) and DFX stats to
 * skip traversal (local_qbuf_pool_num=0 even when other threads are alive).
 *
 * Fix: move flag-setting to atexit(), which only fires during process exit.
 * Normal thread exit: flag stays false → full cleanup runs.
 * Process exit: atexit runs first → flag=true → TLS destructors skip list ops. */
static void set_tls_dtors_running(void)
{
    g_tls_dtors_running = true;
    __sync_synchronize();
}

/* Register the atexit handler exactly once (constructor runs at process start,
 * before any threads are created). atexit() itself is thread-safe per POSIX. */
__attribute__((constructor)) static void register_tls_dtors_handler(void)
{
    (void)atexit(set_tls_dtors_running);
}

class urpc_thread_closure {
public:
    urpc_thread_closure()
    {
        m_id = 0;
        m_closure = nullptr;
    };

    ~urpc_thread_closure()
    {
        /* Do NOT set g_tls_dtors_running here — it fires on every thread exit,
         * not just process exit. The flag is now set via atexit() handler
         * (see register_tls_dtors_handler above) which only runs during exit(). */
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
