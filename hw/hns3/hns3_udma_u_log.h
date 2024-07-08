/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2024-2024 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef UDMA_U_LOG_H
#define UDMA_U_LOG_H
#include <stdbool.h>
#include <pthread.h>

enum udma_log_level {
	UDMA_LOG_LEVEL_EMERG = 0,
	UDMA_LOG_LEVEL_ALERT = 1,
	UDMA_LOG_LEVEL_CRIT = 2,
	UDMA_LOG_LEVEL_ERR = 3,
	UDMA_LOG_LEVEL_WARNING = 4,
	UDMA_LOG_LEVEL_NOTICE = 5,
	UDMA_LOG_LEVEL_INFO = 6,
	UDMA_LOG_LEVEL_DEBUG = 7,
	UDMA_LOG_LEVEL_MAX = 8,
};

struct udma_log_level_st {
	enum udma_log_level level;
	pthread_mutex_t lock;
};

bool udma_log_drop(enum udma_log_level level);
void udma_getenv_log_level(void);
void udma_log(const char *function, int line, enum udma_log_level level, const char *format, ...);
enum udma_log_level udma_log_get_level_from_string(const char *level_string);

#define UDMA_LOG(l, ...)								\
	do {										\
		if (!udma_log_drop(UDMA_LOG_LEVEL_##l))					\
			udma_log(__func__, __LINE__, UDMA_LOG_LEVEL_##l, __VA_ARGS__);	\
	} while (0)

#define UDMA_LOG_INFO(...) UDMA_LOG(INFO, __VA_ARGS__)

#define UDMA_LOG_ERR(...) UDMA_LOG(ERR, __VA_ARGS__)

#define UDMA_LOG_WARN(...) UDMA_LOG(WARNING, __VA_ARGS__)

#define UDMA_LOG_DEBUG(...) UDMA_LOG(DEBUG, __VA_ARGS__)

#endif
