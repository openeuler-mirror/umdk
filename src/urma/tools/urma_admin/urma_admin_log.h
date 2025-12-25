/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: urma_admin log head file
 * Author: Qian Guoxin
 * Create: 2023-2-16
 * Note:
 * History: 2023-2-16 delare urma log API
 */

#ifndef URMA_ADMIN_LOG_H
#define URMA_ADMIN_LOG_H

void urma_admin_log(const char *function, int line, const char *format, ...);
#define URMA_ADMIN_LOG(...) urma_admin_log(__func__, __LINE__, __VA_ARGS__)

#endif
