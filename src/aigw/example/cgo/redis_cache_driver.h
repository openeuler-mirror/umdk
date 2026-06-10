/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * @file redis_cache.h
 * @brief redis cache driver.
 *
 * @create 2026-01-26
 */

#ifndef REDIS_CACHE_DRIVER_H
#define REDIS_CACHE_DRIVER_H

#include "aigw.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get Redis cache driver (singleton, thread-safe via TLS)
 *
 * @note This implementation uses thread-local storage for Redis context.
 *       Each thread has its own connection to Redis.
 *       Ensure to call destroy_redis_context() when thread exits
 *       to avoid connection leaks.
 *
 * @return aigw_cache_driver_t*  Always valid
 */
aigw_cache_driver_t *get_redis_cache_driver(void);

// Test function to verify Redis cache operations
aigw_error_t test_redis_cache(void);

#ifdef __cplusplus
}
#endif

#endif // REDIS_CACHE_DRIVER_H