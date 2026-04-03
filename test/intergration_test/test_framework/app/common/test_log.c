/*
* SPDX-License-Identifier: MIT
* Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
* Description: log function
*/

#include "test_log.h"

#define MAX_LOG_LEN 10240
#define MAX_FILE_NAME_LEN 1024

uint32_t g_test_log_level = TEST_LOG_LEVEL_INFO;
typedef struct Test_Log_File_info_s Test_Log_File_info_t;

struct Test_Log_File_info_s {
    // File handle
    FILE *fd;
    // Log file name
    char file_name[MAX_FILE_NAME_LEN];
    // Whether initialized
    int inited : 1;
};

static Test_Log_File_info_t *g_test_log_file = NULL;

void test_log_init(void)
{
    g_test_log_file = NULL;
    char *env_log_level = getenv(TEST_LOG_LEVEL);
    if (env_log_level == NULL) {
        g_test_log_level = TEST_LOG_LEVEL_INFO;
        return;
    }
    if (strcmp(env_log_level, "debug") == 0) {
        g_test_log_level = TEST_LOG_LEVEL_DEBUG;
    } else if (strcmp(env_log_level, "error") == 0) {
        g_test_log_level = TEST_LOG_LEVEL_ERROR;
    } else if (strcmp(env_log_level, "warn") == 0) {
        g_test_log_level = TEST_LOG_LEVEL_WARN;
    } else {
        g_test_log_level = TEST_LOG_LEVEL_INFO;
    }
}

bool test_log_drop(uint32_t level)
{
    return ((level > g_test_log_level) ? true : false);
}

/********************************************************************************************
  Function Name      :  test_log_set_level
  Function Desc      :  Set log level
  Input Parameter    :  level: Log level
  Output Parameter   :  None
  Return Value       :  0 Set successfully, -1 Set failed
*********************************************************************************************/
int test_log_set_level(enum test_log_level level)
{
    if ((level < TEST_LOG_LEVEL_ERROR) || (level >= TEST_LOG_LEVEL_MAX)) {
        return -1;
    }

    g_test_log_level = level;
    return 0;
}

static const char *get_level_print(uint32_t level)
{
    switch (level) {
        case TEST_LOG_LEVEL_ERROR:
            return "ERROR";
        case TEST_LOG_LEVEL_WARN:
            return "WARNING";
        case TEST_LOG_LEVEL_DEBUG:
            return "DEBUG";
        case TEST_LOG_LEVEL_INFO:
            return "INFO";
        default:
            return "Unknown";
    }
}

static int test_vlog(const char *function, int line, unsigned int level, const char *format, va_list va)
{
    int ret;
    char newformat[MAX_LOG_LEN + 1] = {0};
    char logmsg[MAX_LOG_LEN + 1] = {0};
    char buffer[30];
    struct timeval tv;
    struct tm tm_info;
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm_info);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
    char us_str[8];
    sprintf(us_str, ".%06ld", tv.tv_usec);
    strcat(buffer, us_str);

    ret = snprintf(newformat, sizeof(newformat),  "%s [%-20s:%4d] [%s] %s", buffer, function, line,
                   get_level_print(level), format);
    if (ret <= 0 || ret >= MAX_LOG_LEN) {
        return ret;
    }

    ret = vsnprintf(logmsg, sizeof(logmsg), newformat, va);
    (void)fprintf(stdout, logmsg);
    if ((g_test_log_file != NULL) && (g_test_log_file->inited)) {
        (void)fwrite(logmsg, 1, ret, g_test_log_file->fd);
        (void)fflush(g_test_log_file->fd);
    }
    syslog((int)level, "%s", logmsg);
    return ret;
}

void test_log(const char *function, int line, uint32_t level, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    (void)test_vlog(function, line, level, format, va);
    va_end(va);
}

// 创建日志文件
int test_log_create_dir(char *dir_name)
{
    char path[MAX_FILE_NAME_LEN];
    int index;

    (void)memset(path, 0, MAX_FILE_NAME_LEN);
    (void)strncpy(path, dir_name, strlen(dir_name));

    index = 0;
    while (path[index] != '\0') {
        if ((path[index] == '/') && (index != 0)) {
            path[index] = 0;
            if (access(path, W_OK) != 0) {
                if (mkdir(path, S_IRWXU) != 0) {
                    return -1;
                }
            }
            path[index] = '/';
        }
        index++;
    }
    return 0;
}