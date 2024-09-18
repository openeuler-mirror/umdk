/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
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

#ifndef HNS3_UDMA_U_LOG_H
#define HNS3_UDMA_U_LOG_H
#include <stdbool.h>
#include <pthread.h>

enum hns3_udma_log_level {
	HNS3_UDMA_LOG_LEVEL_EMERG = 0,
	HNS3_UDMA_LOG_LEVEL_ALERT = 1,
	HNS3_UDMA_LOG_LEVEL_CRIT = 2,
	HNS3_UDMA_LOG_LEVEL_ERR = 3,
	HNS3_UDMA_LOG_LEVEL_WARNING = 4,
	HNS3_UDMA_LOG_LEVEL_NOTICE = 5,
	HNS3_UDMA_LOG_LEVEL_INFO = 6,
	HNS3_UDMA_LOG_LEVEL_DEBUG = 7,
	HNS3_UDMA_LOG_LEVEL_MAX = 8,
};

struct hns3_udma_log_level_st {
	enum hns3_udma_log_level level;
	pthread_mutex_t lock;
};

bool hns3_udma_log_drop(enum hns3_udma_log_level level);
void hns3_udma_getenv_log_level(void);
void hns3_udma_log(const char *function, int line, enum hns3_udma_log_level level, const char *format, ...);
enum hns3_udma_log_level hns3_udma_log_get_level_from_string(const char *level_string);

#define HNS3_UDMA_LOG(l, ...)								\
	do {										\
		if (!hns3_udma_log_drop(HNS3_UDMA_LOG_LEVEL_##l))					\
			hns3_udma_log(__func__, __LINE__, HNS3_UDMA_LOG_LEVEL_##l, __VA_ARGS__);	\
	} while (0)

#define HNS3_UDMA_LOG_INFO(...) HNS3_UDMA_LOG(INFO, __VA_ARGS__)

#define HNS3_UDMA_LOG_ERR(...) HNS3_UDMA_LOG(ERR, __VA_ARGS__)

#define HNS3_UDMA_LOG_WARN(...) HNS3_UDMA_LOG(WARNING, __VA_ARGS__)

#define HNS3_UDMA_LOG_DEBUG(...) HNS3_UDMA_LOG(DEBUG, __VA_ARGS__)

#endif
