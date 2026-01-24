/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_LOG_H__
#define __UDMA_U_LOG_H__

#include <pthread.h>
#include <stdbool.h>

enum udma_vlog_level {
	UDMA_VLOG_LEVEL_EMERG,
	UDMA_VLOG_LEVEL_ALERT,
	UDMA_VLOG_LEVEL_CRIT,
	UDMA_VLOG_LEVEL_ERR,
	UDMA_VLOG_LEVEL_WARNING,
	UDMA_VLOG_LEVEL_NOTICE,
	UDMA_VLOG_LEVEL_INFO,
	UDMA_VLOG_LEVEL_DEBUG,
	UDMA_VLOG_LEVEL_MAX
};

struct udma_vlog_level_st {
	enum udma_vlog_level level;
	pthread_mutex_t lock;
};

bool udma_log_drop(enum udma_vlog_level level);
void udma_getenv_log_level(void);
void udma_log(const char *function, int line, enum udma_vlog_level level,
	      const char *format, ...) __attribute__((format(printf, 4, 5)));
enum udma_vlog_level udma_log_get_level_from_string(const char* level_string);

#define UDMA_LOG(l, ...)								\
	do {										\
		if (!udma_log_drop(UDMA_VLOG_LEVEL_##l))				\
			udma_log(__func__, __LINE__, UDMA_VLOG_LEVEL_##l, __VA_ARGS__); \
	} while (0)

#define UDMA_LOG_INFO(...) UDMA_LOG(INFO, __VA_ARGS__)

#define UDMA_LOG_ERR(...) UDMA_LOG(ERR, __VA_ARGS__)

#define UDMA_LOG_WARN(...) UDMA_LOG(WARNING, __VA_ARGS__)

#define UDMA_LOG_DEBUG(...) UDMA_LOG(DEBUG, __VA_ARGS__)

#endif /* __UDMA_U_LOG_H__ */
