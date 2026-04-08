/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: ubagg statistics
 * Author: Zhang Dianhao
 * Create: 2026-04-05
 * Note:
 * History: 2026-04-05   Create File
 */

#include <stdatomic.h>
#include <stdint.h>

static atomic_uint g_ubagg_switch_cnt;

void urma_ubagg_switch_init(void)
{
    atomic_init(&g_ubagg_switch_cnt, 0);
}

void urma_ubagg_switch_inc(void)
{
    (void)atomic_fetch_add(&g_ubagg_switch_cnt, 1);
}

uint32_t urma_ubagg_switch_get(void)
{
    return atomic_load(&g_ubagg_switch_cnt);
}
