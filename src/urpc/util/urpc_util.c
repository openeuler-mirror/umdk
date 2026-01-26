/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc util function
 * Create: 2024-11-04
 */

#include <fcntl.h>
#include <openssl/rand.h>
#include <unistd.h>

#include "urpc_util.h"

#define URPC_RANDOM_SEED_SIZE 48

#if defined(__x86_64__)
#include "ub_get_clock.h"

static uint64_t g_urpc_cpu_hz;

uint64_t urpc_get_cpu_hz(void)
{
    // ub get_cpu_mhz will cost 200+ms
    if (URPC_UNLIKELY(g_urpc_cpu_hz == 0)) {
        g_urpc_cpu_hz = (uint64_t)(get_cpu_mhz(false) * US_PER_SEC);
    }

    return g_urpc_cpu_hz;
}
#elif defined(__aarch64__)
uint64_t urpc_get_cpu_hz(void)
{
    // cost x ns
    return urpc_get_cpu_hz_aarch64();
}
#else
#warning urpc_get_cpu_hz not implemented
#endif

static int read_random_seed(int fd, uint8_t *seed, int seed_len)
{
    ssize_t read_bytes;
    int total_bytes = seed_len;
    while (total_bytes > 0) {
        read_bytes = read(fd, seed, (size_t)total_bytes);
        if ((read_bytes > 0) && (read_bytes <= total_bytes)) {
            total_bytes -= read_bytes;
            seed += read_bytes;
        } else if ((errno != EINTR) || ((read_bytes == 0) && (total_bytes != 0))) {
            return -1;
        }
    }
    return 0;
}

int urpc_rand_seed_init(void)
{
    uint8_t seed[URPC_RANDOM_SEED_SIZE];
    int fd = open("/dev/random", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    int ret = read_random_seed(fd, seed, URPC_RANDOM_SEED_SIZE);
    (void)close(fd);
    if (ret != 0) {
        return -1;
    }

    RAND_seed(seed, URPC_RANDOM_SEED_SIZE);
    if (RAND_status() != 1) {
        return -1;
    }

    return 0;
}

int urpc_rand_generate(uint8_t *buf, uint32_t num)
{
    if (RAND_priv_bytes(buf, num) != 1) {
        return -1;
    }

    return 0;
}
