// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <syslog.h>
#include "udma_u_log.h"

static struct udma_vlog_level_st g_udma_log_level = {UDMA_VLOG_LEVEL_INFO, PTHREAD_MUTEX_INITIALIZER};
static urma_log_cb_t g_udma_log_cb = udma_default_log_func;

void udma_default_log_func(int level, char *message)
{
	syslog(level, "%s", message);
}

bool udma_log_drop(enum udma_vlog_level level)
{
	return level > g_udma_log_level.level;
}

enum udma_vlog_level udma_log_get_level_from_string(const char *level_string)
{
	if (level_string == NULL)
		return UDMA_VLOG_LEVEL_MAX;

	if (strcasecmp(level_string, "fatal") == 0)
		return UDMA_VLOG_LEVEL_CRIT;

	if (strcasecmp(level_string, "error") == 0)
		return UDMA_VLOG_LEVEL_ERR;

	if (strcasecmp(level_string, "warning") == 0)
		return UDMA_VLOG_LEVEL_WARNING;

	if (strcasecmp(level_string, "info") == 0)
		return UDMA_VLOG_LEVEL_INFO;

	if (strcasecmp(level_string, "debug") == 0)
		return UDMA_VLOG_LEVEL_DEBUG;

	return UDMA_VLOG_LEVEL_MAX;
}

void udma_getenv_log_level(void)
{
	char *level_str = getenv(UDMA_LOG_ENV_STR);
	if (level_str == NULL)
		return;

	if (strnlen(level_str, UDMA_LOG_LEVEL_ENV_MAX_BUF_LEN) >=
	    UDMA_LOG_LEVEL_ENV_MAX_BUF_LEN) {
		UDMA_LOG_ERR("Invalid parameter: log level str.\n");
		return;
	}

	enum udma_vlog_level log_level = udma_log_get_level_from_string(level_str);
	if (log_level != UDMA_VLOG_LEVEL_MAX) {
		(void)pthread_mutex_lock(&g_udma_log_level.lock);
		g_udma_log_level.level = log_level;
		(void)pthread_mutex_unlock(&g_udma_log_level.lock);
	}
}

static __attribute__((format(printf, 4, 0)))
int udma_vlog(const char *function, int line, enum udma_vlog_level level, const char *format, va_list va)
{
	char newformat[MAX_LOG_LEN + 1] = {};
	char logmsg[MAX_LOG_LEN + 1] = {};
	int ret;

	/* add log head info, "[UDMA_LOG_TAG][function:line] format" */
	ret = snprintf(newformat, MAX_LOG_LEN, "[%s][%s:%d] %s", UDMA_LOG_TAG, function, line, format);
	if (ret <= 0 || ret >= (int)sizeof(newformat))
		return ret;

	ret = vsnprintf(logmsg, MAX_LOG_LEN, newformat, va);
	if (ret == -1 || ret >= (int)sizeof(newformat)) {
		(void)printf("logmsg size exceeds MAX_LOG_LEN size :%d.\n", MAX_LOG_LEN);
		return ret;
	}
	g_udma_log_cb((int)level, logmsg);

	return ret;
}

void udma_log(const char *function, int line, enum udma_vlog_level level, const char *format, ...)
{
	va_list va;

	va_start(va, format);
	(void)udma_vlog(function, line, level, format, va);
	va_end(va);
}

static void udma_u_try_register_ummu_log_backend(void)
{
	ummu_log_backend_t backend = {.emit = g_udma_log_cb};
	int ret;

	if (!udma_u_ummu_log_supported()) {
		UDMA_LOG_WARN("libummu log backend not supported, skipping.\n");
		return;
	}

	ret = ummu_log_register_backend(&backend);
	if (ret)
		UDMA_LOG_ERR("Failed to register ummu log backend, ret=%d.\n", ret);
}

static void udma_u_try_restore_ummu_log_default(void)
{
	if (!udma_u_ummu_log_supported()) {
		UDMA_LOG_WARN("libummu log restore default not supported, skipping.\n");
		return;
	}
	ummu_log_restore_default();
}

urma_status_t udma_u_register_log_func(urma_log_cb_t func)
{
	if (func == NULL) {
		UDMA_LOG_ERR("Invalid parameter: log callback func is NULL.\n");
		return URMA_EINVAL;
	}
	g_udma_log_cb = func;
	UDMA_LOG_INFO("libudma registered log successfully.\n");

	udma_u_try_register_ummu_log_backend();

	return URMA_SUCCESS;
}

urma_status_t udma_u_unregister_log_func(void)
{
	udma_u_try_restore_ummu_log_default();

	UDMA_LOG_INFO("libudma restored to default log output successfully.\n");
	g_udma_log_cb = udma_default_log_func;

	return URMA_SUCCESS;
}
