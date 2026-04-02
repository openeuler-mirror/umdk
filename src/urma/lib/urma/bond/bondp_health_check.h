/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider health check declarations
 */
#ifndef BONDP_HEALTH_CHECK_H
#define BONDP_HEALTH_CHECK_H

#include "bondp_types.h"

void bondp_health_check_global_ctx_init(bondp_global_context_t *ctx);
void bondp_health_check_ctx_init(bondp_context_t *bond_ctx);

int bondp_start_health_check_thread(void);
void bondp_stop_health_check_thread(void);

int bondp_create_health_check_ctx(bondp_context_t *bond_ctx);
void bondp_destroy_health_check_ctx(bondp_context_t *bond_ctx);

#endif // BONDP_HEALTH_CHECK_H
