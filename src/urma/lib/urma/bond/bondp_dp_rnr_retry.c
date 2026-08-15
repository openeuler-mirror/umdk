/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond RNR retry helpers.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#include "bondp_env.h"

#include "bondp_dp_rnr_retry.h"

#define BONDP_MS_PER_SEC    1000
#define BONDP_NS_PER_MS     1000000
#define BONDP_RATIO_PERCENT 100

static uint64_t get_rnr_retry_jitter_rand(void)
{
    static thread_local struct random_data rand_data;
    static thread_local char rand_state[32] = {0};
    static thread_local bool rand_inited = false;
    int32_t rand_val = 0;

    if (!rand_inited) {
        struct timespec ts = {0};
        unsigned int seed = (unsigned int)getpid();

        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            seed ^= (unsigned int)ts.tv_nsec ^ (unsigned int)ts.tv_sec;
        }
        seed ^= (unsigned int)(uintptr_t)&rand_data;
        (void)memset(&rand_data, 0, sizeof(rand_data));
        (void)initstate_r(seed, rand_state, sizeof(rand_state), &rand_data);
        rand_inited = true;
    }

    if (random_r(&rand_data, &rand_val) != 0) {
        return 0;
    }
    return (uint64_t)(uint32_t)rand_val;
}

static uint64_t add_rnr_retry_jitter(uint64_t sleep_ms)
{
    uint32_t ratio = g_bondp_env.rnr_retry_jitter_ratio;
    if (ratio == 0) {
        return sleep_ms;
    }

    uint64_t jitter_ms = (sleep_ms / BONDP_RATIO_PERCENT) * ratio +
                         ((sleep_ms % BONDP_RATIO_PERCENT) * ratio) / BONDP_RATIO_PERCENT;
    if (jitter_ms == 0) {
        return sleep_ms;
    }
    uint64_t rand_val = get_rnr_retry_jitter_rand();
    uint64_t jitter = (jitter_ms == UINT64_MAX) ? rand_val : rand_val % (jitter_ms + 1);
    if (UINT64_MAX - sleep_ms < jitter) {
        return UINT64_MAX;
    }
    return sleep_ms + jitter;
}

void bondp_rnr_retry_sleep_before_resend(uint32_t retry_cnt)
{
    uint64_t sleep_ms = g_bondp_env.rnr_retry_sleep_ms;
    if (sleep_ms == 0) {
        return;
    }
    for (uint32_t i = 0; i < retry_cnt; i++) {
        sleep_ms <<= 1;
    }
    sleep_ms = add_rnr_retry_jitter(sleep_ms);

    struct timespec sleep_time = {
        .tv_sec = (time_t)(sleep_ms / BONDP_MS_PER_SEC),
        .tv_nsec = (long)((sleep_ms % BONDP_MS_PER_SEC) * BONDP_NS_PER_MS),
    };
    (void)nanosleep(&sleep_time, NULL);
}
