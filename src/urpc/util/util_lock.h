/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: util lock module
 * Create: 2026-03-30
 */

#ifndef UTIL_LOCK_H
#define UTIL_LOCK_H

#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum util_externel_mutex_attr {
    UTIL_MUTEX_ATTR_EXCLUSIVE = 0,
    UTIL_MUTEX_ATTR_RECURSIVE,
    UTIL_MUTEX_ATTR_BUTT
} util_externel_mutex_attr_t;

typedef void* util_external_mutex_lock;
typedef void* util_external_rwlock;

typedef struct util_external_mutex_lock_ops {
    util_external_mutex_lock *(*create)(util_externel_mutex_attr_t attr);
    int (*destroy)(util_external_mutex_lock *m);
    int (*lock)(util_external_mutex_lock *m);
    int (*unlock)(util_external_mutex_lock *m);
    int (*trylock)(util_external_mutex_lock *m);
} util_external_mutex_lock_ops_t;

typedef struct util_external_rwlock_ops {
    util_external_rwlock *(*create)(void);
    int (*destroy)(util_external_rwlock *m);
    int (*read_lock)(util_external_rwlock *m);
    int (*write_lock)(util_external_rwlock *m);
    int (*unlock)(util_external_rwlock *m);
    int (*try_read_lock)(util_external_rwlock *m);
    int (*try_write_lock)(util_external_rwlock *m);
} util_external_rwlock_ops_t;

// if ops is NULL, reset global ops
void util_external_mutex_lock_ops_register(util_external_mutex_lock_ops_t *ops);
void util_external_rwlock_ops_register(util_external_rwlock_ops_t *ops);

// mutex api
util_external_mutex_lock *util_mutex_lock_create(int attr);
int util_mutex_lock_destroy(util_external_mutex_lock *m);
int util_mutex_lock(util_external_mutex_lock *m);
int util_mutex_unlock(util_external_mutex_lock *m);
int util_mutex_try_lock(util_external_mutex_lock *m);

// read-write mutex api
util_external_rwlock *util_rwlock_create(void);
int util_rwlock_destroy(util_external_rwlock *m);
int util_rwlock_rdlock(util_external_rwlock *m);
int util_rwlock_wrlock(util_external_rwlock *m);
int util_rwlock_unlock(util_external_rwlock *m);
int util_rwlock_tryrdlock(util_external_rwlock *m);
int util_rwlock_trywrlock(util_external_rwlock *m);

#ifdef __cplusplus
}
#endif

#endif
