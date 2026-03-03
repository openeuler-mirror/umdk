/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping stat implementation file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#include "ping_log.h"

#include "ping_stat.h"

typedef struct ping_stat {
    uint32_t transmitted;
    uint32_t received;
    double rtt_min;
    double rtt_max;
    double rtt_avg;
    double rtt_m2;
    double start_time;
    double end_time;
} ping_stat_t;

static ping_stat_t g_stat = {0};

double get_time_in_ms(void)
{
    struct timespec cur;

    if (clock_gettime(CLOCK_MONOTONIC, &cur) == -1) {
        LOG_ERROR("clock_gettime failed.\n");
        return 0;
    }
    return cur.tv_sec * 1000.0 + cur.tv_nsec / 1000000.0;
}

static void print_stat(void)
{
    g_stat.end_time = get_time_in_ms();

    double total_time = g_stat.end_time - g_stat.start_time;
    double loss_rate = ((g_stat.transmitted - g_stat.received) * 100.0) / g_stat.transmitted;
    double rtt_mdev = g_stat.received > 0 ? sqrt(g_stat.rtt_m2 / g_stat.received) : 0;

    LOG_QUIET("\n");
    LOG_QUIET("--- ping statistics ---\n");
    LOG_QUIET("%u packets transmitted, %u received, %.1f%% packet loss, time %.0fms\n", g_stat.transmitted,
              g_stat.received, loss_rate, total_time);
    LOG_QUIET("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", g_stat.rtt_min, g_stat.rtt_avg, g_stat.rtt_max,
              rtt_mdev);
}

void init_stat(void)
{
    atexit(print_stat);
    g_stat.start_time = get_time_in_ms();
}

void update_stat_on_send(void)
{
    g_stat.transmitted++;
}

void update_stat_on_recv(double rtt)
{
    if (rtt < g_stat.rtt_min || g_stat.received == 0) {
        g_stat.rtt_min = rtt;
    }
    if (rtt > g_stat.rtt_max) {
        g_stat.rtt_max = rtt;
    }

    double old_rtt_avg = g_stat.rtt_avg;

    g_stat.rtt_avg = ((g_stat.rtt_avg * g_stat.received) + rtt) / (g_stat.received + 1);
    g_stat.rtt_m2 += (rtt - old_rtt_avg) * (rtt - g_stat.rtt_avg);
    g_stat.received++;
}
