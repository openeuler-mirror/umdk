/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond environment configuration file
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "urma_log.h"

#include "bondp_dp_health.h"

#include "bondp_env.h"

#define BONDP_ENV_ENABLE_FAILOVER       "BOND_ENABLE_FAILOVER"
#define BONDP_ENV_ENABLE_FAILBACK       "BOND_ENABLE_FAILBACK"
#define BONDP_ENV_ENABLE_HEALTH_CHECK   "BOND_ENABLE_HEALTH_CHECK"
#define BONDP_ENV_HEALTH_CHECK_INTERVAL "BOND_HEALTH_CHECK_ACTIVE_INTERVAL"
#define BONDP_ENV_LEN_MAX               (128)
/*
 * #define BONDP_ENV_FAILOVER_DIEX_Y_ROUTEZ          "BOND_FAILOVER_DIEX_Y_ROUTEZ"
 */

bondp_env_t g_bondp_env;

static bool read_env_bool(const char *env_name, bool default_val)
{
    const char *value = getenv(env_name);
    if (value == NULL) {
        return default_val;
    }
    if (strcmp(value, "true") == 0) {
        return true;
    }
    if (strcmp(value, "false") == 0) {
        return false;
    }
    URMA_LOG_WARN("Invalid value '%s' for env %s, using default %s\n",
                  value, env_name, default_val ? "true" : "false");
    return default_val;
}

static uint64_t read_env_uint64(const char *env_name, uint64_t default_val)
{
    const char *value = getenv(env_name);
    if (value == NULL) {
        return default_val;
    }

    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        URMA_LOG_WARN("Invalid value '%s' for env %s, using default %lu\n",
                      value, env_name, (unsigned long)default_val);
        return default_val;
    }
    return (uint64_t)parsed;
}

static void filter_balance_route_env(char *value, const char *origin_val)
{
    int i = 0;
    int j = 0;
    while (origin_val[j] != '\0') {
        if (origin_val[j] == ',' || (origin_val[j] > '0' && origin_val[j] < '9')) {
            value[i] = origin_val[j];
            i++;
        }
        j++;
    }
    value[i] = '\0';
}

static void read_env_balance_route(
    const char *env_name,
    uint32_t route[URMA_FAILOVER_LINK_NUM],
    const uint32_t default_route[URMA_FAILOVER_LINK_NUM])
{
    if (env_name == NULL) {
        memcpy(route, default_route, URMA_FAILOVER_LINK_NUM * sizeof(uint32_t));
        return;
    }
    const char *value = getenv(env_name);
    if (value == NULL || strlen(value) > BONDP_ENV_LEN_MAX) {
        memcpy(route, default_route, URMA_FAILOVER_LINK_NUM * sizeof(uint32_t));
        return;
    }

    char filtered_val[BONDP_ENV_LEN_MAX + 1] = {0};
    filter_balance_route_env(filtered_val, value);
    int ret = 0;
    ret = sscanf(filtered_val, "%u,%u,%u,%u", &route[0], &route[1], &route[2], &route[3]);
    if (ret <= 0) {
        memcpy(route, default_route, URMA_FAILOVER_LINK_NUM * sizeof(uint32_t));
        return;
    }
    for (int i = ret; i < URMA_FAILOVER_LINK_NUM; i++) {
        route[i] = UINT32_MAX;
    }
}

static void read_env_balance_route_all(bondp_env_t *env)
{
    char env_name[BONDP_ENV_LEN_MAX] = {0};
    int ret = 0;
    const uint32_t route[IODIE_NUM][IODIE_NUM][URMA_ACTIVE_PORT_PER_DIE][URMA_FAILOVER_LINK_NUM] = {
        {{{1, 6, 7, 4},
          {2, 5, 8, 3}},
         {{5, 2, 4, 7},
          {6, 1, 3, 8}}},
        {{{7, 4, 1, 6},
          {8, 3, 2, 5}},
         {{3, 8, 5, 2},
          {4, 7, 6, 1}}}};

    for (int src_die = 0; src_die < IODIE_NUM; src_die++) {
        for (int dst_die = 0; dst_die < IODIE_NUM; dst_die++) {
            for (int route_id = 0; route_id < URMA_ACTIVE_PORT_PER_DIE; route_id++) {
                ret = snprintf(env_name, sizeof(env_name), "BOND_FAILOVER_DIE%d_%d_ROUTE%d",
                               src_die + 1, dst_die + 1, route_id + 1);
                char *env_name_tmp = (ret < 0 || ret >= sizeof(env_name)) ? NULL : env_name;
                read_env_balance_route(env_name_tmp, env->failover_route[src_die][dst_die][route_id],
                                       route[src_die][dst_die][route_id]);
                uint32_t *env_route = env->failover_route[src_die][dst_die][route_id];
                URMA_LOG_DEBUG("src_die=%d, dst_die=%d, route_id=%d, route={%u,%u,%u,%u}\n",
                               src_die + 1, dst_die + 1, route_id + 1,
                               env_route[0], env_route[1], env_route[2], env_route[3]);
            }
        }
    }
}

static void read_all_env(bondp_env_t *env)
{
    const bool default_enable_health_check = true;
    const bool default_enable_failback = true;
    const bool default_enable_failover = true;
    const uint64_t default_health_check_interval_ms = BONDP_HC_DEFAULT_PROBE_INTERVAL_MS;
    env->enable_health_check = read_env_bool(
        BONDP_ENV_ENABLE_HEALTH_CHECK, default_enable_health_check);
    env->enable_failover = read_env_bool(
        BONDP_ENV_ENABLE_FAILOVER, default_enable_failover);
    env->enable_failback = read_env_bool(
        BONDP_ENV_ENABLE_FAILBACK, default_enable_failback);
    env->health_check_interval_ms = read_env_uint64(
        BONDP_ENV_HEALTH_CHECK_INTERVAL, default_health_check_interval_ms);
    read_env_balance_route_all(env);

    const uint64_t time_100ms = 100;
    const uint64_t time_60s = 60000;
    if (env->health_check_interval_ms < time_100ms || env->health_check_interval_ms > time_60s) {
        URMA_LOG_WARN("Invalid BOND_HEALTH_CHECK_ACTIVE_INTERVAL value %lu (range %lu~%lu), using default %lu\n",
                      env->health_check_interval_ms, time_100ms, time_60s,
                      default_health_check_interval_ms);
        env->health_check_interval_ms = default_health_check_interval_ms;
    }
}

static void print_all_env(const bondp_env_t *env)
{
    URMA_LOG_INFO("Health check config: enable_failover=%s, enable_failback=%s, enable_health_check=%s, "
                  "interval=%lums\n",
                  env->enable_failover ? "true" : "false",
                  env->enable_failback ? "true" : "false",
                  env->enable_health_check ? "true" : "false",
                  env->health_check_interval_ms);
}

static void init_path(bondp_env_t *env)
{
    bondp_path_t *path = env->path;
    for (int src_die = 0; src_die < IODIE_NUM; src_die++) {
        for (int port = URMA_ACTIVE_PORT_MIN; port <= URMA_ACTIVE_PORT_MAX; port++) {
            for (int dst_die = 0; dst_die < IODIE_NUM; dst_die++) {
                int idx = (src_die ^ dst_die) * URMA_FAILOVER_LINK_NUM +
                          src_die * IODIE_NUM + port - URMA_ACTIVE_PORT_MIN + 1;
                path[idx].local_idx = IODIE_NUM + src_die * PORT_NUM + port;
                path[idx].target_idx = IODIE_NUM + dst_die * PORT_NUM + port;
                URMA_LOG_DEBUG("path[%d]={%u,%u}\n", idx, path[idx].local_idx, path[idx].target_idx);
            }
        }
    }
}

void bondp_env_init(void)
{
    (void)memset(&g_bondp_env, 0, sizeof(g_bondp_env));
    read_all_env(&g_bondp_env);
    print_all_env(&g_bondp_env);
    init_path(&g_bondp_env);
}
