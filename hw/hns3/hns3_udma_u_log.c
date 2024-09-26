// SPDX-License-Identifier: GPL-2.0
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <syslog.h>
#include "hns3_udma_u_log.h"

static struct hns3_udma_log_level_st g_hns3_udma_loglevel = {HNS3_UDMA_LOG_LEVEL_INFO, PTHREAD_MUTEX_INITIALIZER};
#define MAX_LOG_LEN 512
#define HNS3_UDMA_LOG_TAG "HNS3_UDMA_LOG_TAG"
#define HNS3_UDMA_LOG_ENV_STR "HNS3_UDMA_LOG_LEVEL"
#define HNS3_UDMA_LOG_LEVEL_ENV_MAX_BUF_LEN 32

static void hns3_udma_log_func(int level, char *message)
{
	syslog(level, "%s", message);
}

bool hns3_udma_log_drop(enum hns3_udma_log_level level)
{
	return level > g_hns3_udma_loglevel.level;
}

enum hns3_udma_log_level hns3_udma_log_get_level_from_string(const char *string)
{
	if (string == NULL)
		return HNS3_UDMA_LOG_LEVEL_MAX;

	if (strcasecmp(string, "fatal") == 0)
		return HNS3_UDMA_LOG_LEVEL_CRIT;

	if (strcasecmp(string, "error") == 0)
		return HNS3_UDMA_LOG_LEVEL_ERR;

	if (strcasecmp(string, "warning") == 0)
		return HNS3_UDMA_LOG_LEVEL_WARNING;

	if (strcasecmp(string, "info") == 0)
		return HNS3_UDMA_LOG_LEVEL_INFO;

	if (strcasecmp(string, "debug") == 0)
		return HNS3_UDMA_LOG_LEVEL_DEBUG;

	return HNS3_UDMA_LOG_LEVEL_MAX;
}

void hns3_udma_getenv_log_level(void)
{
	char *level_string = getenv(HNS3_UDMA_LOG_ENV_STR);
	enum hns3_udma_log_level log_level;

	if (level_string == NULL)
		return;

	if (strnlen(level_string, HNS3_UDMA_LOG_LEVEL_ENV_MAX_BUF_LEN) >=
	    HNS3_UDMA_LOG_LEVEL_ENV_MAX_BUF_LEN) {
		HNS3_UDMA_LOG_ERR("Invalid parameter: log level string.");
		return;
	}

	log_level = hns3_udma_log_get_level_from_string(level_string);
	if (log_level != HNS3_UDMA_LOG_LEVEL_MAX) {
		pthread_mutex_lock(&g_hns3_udma_loglevel.lock);
		g_hns3_udma_loglevel.level = log_level;
		pthread_mutex_unlock(&g_hns3_udma_loglevel.lock);
	}
}

static int hns3_udma_log_impl(const char *function, int line, enum hns3_udma_log_level level,
			      const char *format, va_list va)
{
	char newformat[MAX_LOG_LEN + 1] = {};
	char log[MAX_LOG_LEN + 1] = {};
	int ret;

	/* add log head info, "HNS3_UDMA_LOG_TAG|function|[line]|format" */
	ret = snprintf(newformat, MAX_LOG_LEN, "%s|%s[%d]|%s",
		       HNS3_UDMA_LOG_TAG, function, line, format);
	if (ret <= 0 || ret >= sizeof(newformat))
		return ret;

	ret = vsnprintf(log, MAX_LOG_LEN, newformat, va);
	if (ret == -1) {
		(void)printf("log size exceeds MAX_LOG_LEN size :%d.\n", MAX_LOG_LEN);
		return ret;
	}
	hns3_udma_log_func((int)level, log);

	return ret;
}

void hns3_udma_log(const char *function, int line, enum hns3_udma_log_level level,
		   const char *format, ...)
{
	va_list va;

	va_start(va, format);
	(void)hns3_udma_log_impl(function, line, level, format, va);
	va_end(va);
}
