/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: util lock module
 * Create: 2026-03-30
 */

#include <pthread.h>

#include "util_lock.h"

static util_external_mutex_lock *util_mutex_lock_create_impl(util_externel_mutex_attr_t attr)
{
    pthread_mutex_t *mutex_lock = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    if (mutex_lock == NULL) {
        return NULL;
    }

    pthread_mutexattr_t mutex_attr;
    int ret = pthread_mutexattr_init(&mutex_attr);
    if (ret != 0) {
        goto FREE_LOCK;
    }
    if (attr == UTIL_MUTEX_ATTR_RECURSIVE) {
        ret = pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);
        if (ret != 0) {
            pthread_mutexattr_destroy(&mutex_attr);
            goto FREE_LOCK;
        }
    }
 
    ret = pthread_mutex_init(mutex_lock, &mutex_attr);
    pthread_mutexattr_destroy(&mutex_attr);
    if (ret != 0) {
        goto FREE_LOCK;
    }
    return (util_external_mutex_lock *)mutex_lock;

FREE_LOCK:
    free(mutex_lock);
    return NULL;
}

static int util_mutex_lock_destroy_impl(util_external_mutex_lock *lock)
{
    (void)pthread_mutex_destroy((pthread_mutex_t *)lock);
    free(lock);
    return 0;
}

static int util_mutex_lock_impl(util_external_mutex_lock *lock)
{
    return pthread_mutex_lock((pthread_mutex_t *)lock);
}

static int util_mutex_unlock_impl(util_external_mutex_lock *lock)
{
    return pthread_mutex_unlock((pthread_mutex_t *)lock);
}

static int util_mutex_try_lock_impl(util_external_mutex_lock *lock)
{
    return pthread_mutex_trylock((pthread_mutex_t *)lock);
}

static util_external_rwlock *util_rwlock_create_impl(void)
{
    pthread_rwlock_t *rw_lock = (pthread_rwlock_t *)calloc(1, sizeof(pthread_rwlock_t));
    if (rw_lock == NULL) {
        return NULL;
    }

    int ret = pthread_rwlock_init(rw_lock, NULL);
    if (ret != 0) {
        goto FREE_LOCK;
    }
    return (util_external_rwlock *)rw_lock;

FREE_LOCK:
    free(rw_lock);
    return NULL;
}

static int util_rwlock_destroy_impl(util_external_rwlock *lock)
{
    (void)pthread_rwlock_destroy((pthread_rwlock_t *)lock);
    free(lock);
    return 0;
}

static int util_rwlock_rdlock_impl(util_external_rwlock *lock)
{
    return pthread_rwlock_rdlock((pthread_rwlock_t *)lock);
}

static int util_rwlock_wrlock_impl(util_external_rwlock *lock)
{
    return pthread_rwlock_wrlock((pthread_rwlock_t *)lock);
}

static int util_rwlock_unlock_impl(util_external_rwlock *lock)
{
    return pthread_rwlock_unlock((pthread_rwlock_t *)lock);
}

static int util_rwlock_tryrdlock_impl(util_external_rwlock *lock)
{
    return pthread_rwlock_tryrdlock((pthread_rwlock_t *)lock);
}

static int util_rwlock_trywrlock_impl(util_external_rwlock *lock)
{
    return pthread_rwlock_trywrlock((pthread_rwlock_t *)lock);
}

static util_external_mutex_lock_ops_t g_util_default_mutex_lock_ops = {
    .create = util_mutex_lock_create_impl,
    .destroy = util_mutex_lock_destroy_impl,

    .lock = util_mutex_lock_impl,
    .unlock = util_mutex_unlock_impl,
    .trylock = util_mutex_try_lock_impl,
};

static util_external_rwlock_ops_t g_util_default_rwlock_ops = {
    .create = util_rwlock_create_impl,
    .destroy = util_rwlock_destroy_impl,

    .read_lock = util_rwlock_rdlock_impl,
    .write_lock = util_rwlock_wrlock_impl,
    .unlock = util_rwlock_unlock_impl,
    .try_read_lock = util_rwlock_tryrdlock_impl,
    .try_write_lock = util_rwlock_trywrlock_impl,
};

static util_external_mutex_lock_ops_t g_util_mutex_lock_ops = {
    .create = util_mutex_lock_create_impl,
    .destroy = util_mutex_lock_destroy_impl,

    .lock = util_mutex_lock_impl,
    .unlock = util_mutex_unlock_impl,
    .trylock = util_mutex_try_lock_impl,
};

static util_external_rwlock_ops_t g_util_rwlock_ops = {
    .create = util_rwlock_create_impl,
    .destroy = util_rwlock_destroy_impl,

    .read_lock = util_rwlock_rdlock_impl,
    .write_lock = util_rwlock_wrlock_impl,
    .unlock = util_rwlock_unlock_impl,
    .try_read_lock = util_rwlock_tryrdlock_impl,
    .try_write_lock = util_rwlock_trywrlock_impl,
};

// if ops is NULL, reset global ops
void util_external_mutex_lock_ops_register(util_external_mutex_lock_ops_t *ops)
{
    if (ops == NULL) {
        g_util_mutex_lock_ops = g_util_default_mutex_lock_ops;
        return;
    }

    g_util_mutex_lock_ops = *ops;
}

void util_external_rwlock_ops_register(util_external_rwlock_ops_t *ops)
{
    if (ops == NULL) {
        g_util_rwlock_ops = g_util_default_rwlock_ops;
        return;
    }

    g_util_rwlock_ops = *ops;
}

// mutex api
util_external_mutex_lock *util_mutex_lock_create(int attr)
{
    return g_util_mutex_lock_ops.create(attr);
}

int util_mutex_lock_destroy(util_external_mutex_lock *lock)
{
    return g_util_mutex_lock_ops.destroy(lock);
}

int util_mutex_lock(util_external_mutex_lock *lock)
{
    return g_util_mutex_lock_ops.lock(lock);
}

int util_mutex_unlock(util_external_mutex_lock *lock)
{
    return g_util_mutex_lock_ops.unlock(lock);
}

int util_mutex_try_lock(util_external_mutex_lock *lock)
{
    return g_util_mutex_lock_ops.trylock(lock);
}

// read-write mutex api
util_external_rwlock *util_rwlock_create(void)
{
    return g_util_rwlock_ops.create();
}

int util_rwlock_destroy(util_external_rwlock *lock)
{
    return g_util_rwlock_ops.destroy(lock);
}

int util_rwlock_rdlock(util_external_rwlock *lock)
{
    return g_util_rwlock_ops.read_lock(lock);
}

int util_rwlock_wrlock(util_external_rwlock *lock)
{
    return g_util_rwlock_ops.write_lock(lock);
}

int util_rwlock_unlock(util_external_rwlock *lock)
{
    return g_util_rwlock_ops.unlock(lock);
}

int util_rwlock_tryrdlock(util_external_rwlock *lock)
{
    return g_util_rwlock_ops.try_read_lock(lock);
}

int util_rwlock_trywrlock(util_external_rwlock *lock)
{
    return g_util_rwlock_ops.try_write_lock(lock);
}   
