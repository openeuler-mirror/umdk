/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: urma_ping stat head file
 * Author: Wang Hang
 * Create: 2026-02-03
 * Note:
 * History: 2026-02-03 Create file
 */

#ifndef URMA_PING_STAT_H
#define URMA_PING_STAT_H

double get_time_in_ms(void);
void init_stat(void);
void update_stat_on_send(void);
void update_stat_on_recv(double rtt);

#endif
