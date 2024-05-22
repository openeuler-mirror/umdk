/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa ini file interface
 * Author: Chen Wen
 * Create: 2022-08-25
 * Note:
 * History:
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "tpsa_log.h"
#include "tpsa_ini.h"

#define TPSA_MAX_CURRENT_ERR 5
#define TPSA_MAX_ENDS 2
#define TPSA_ETC_MAX_LINE 256
#define TPSA_MAX_SAFETY_LOOPS 1000

static int tpsa_etc_locate_section(FILE *fp, const char *pSection, FILE *bak_fp);
static int tpsa_etc_locate_key_value(FILE *fp, const char *pKey, char *pValue, size_t len, FILE *bak_fp);
static char *tpsa_get_section_name(char *section_line, size_t section_len);
static int tpsa_get_key_value(char *key_line, char **mykey, char **myvalue, char delimiter);
static int tpsa_get_kv_check_para(const char *key_line, const char **mykey, const char **myvalue);

/*
 * @brief reads a value of a key in a section
 */
int tpsa_read_value_by_etc_file(file_info_t *file, char *pValue, size_t len)
{
    FILE *fp;

    char *absolute_path;
    absolute_path = realpath(file->path, NULL);
    if (absolute_path == NULL) {
        return TPSA_ETC_FILENOTFOUND;
    }

    if (!(fp = fopen(absolute_path, "r"))) {
        free(absolute_path);
        return TPSA_ETC_FILENOTFOUND;
    }
    if (tpsa_etc_locate_section(fp, file->section, NULL) != TPSA_ETC_OK) {
        (void)fclose(fp);
        free(absolute_path);
        return TPSA_ETC_SECTIONNOTFOUND;
    }
    if (tpsa_etc_locate_key_value(fp, file->key, pValue, len, NULL) != TPSA_ETC_OK) {
        (void)fclose(fp);
        free(absolute_path);
        return TPSA_ETC_KEYNOTFOUND;
    }

    (void)fclose(fp);
    free(absolute_path);
    return TPSA_ETC_OK;
}

/*
 * @brief locate a section by name
 */
static int tpsa_etc_locate_section(FILE *fp, const char *pSection, FILE *bak_fp)
{
    char szBuff[TPSA_ETC_MAX_LINE];
    char *name = NULL;

    int max_safety_loops = 0;
    while (max_safety_loops < TPSA_MAX_SAFETY_LOOPS) {
        if (!fgets(szBuff, TPSA_ETC_MAX_LINE, fp)) {
            if (feof(fp) != 0) {
                return TPSA_ETC_SECTIONNOTFOUND;
            } else {
                return TPSA_ETC_FILEIOFAILED;
            }
        } else if (bak_fp && fputs(szBuff, bak_fp) == EOF) {
            return TPSA_ETC_FILEIOFAILED;
        }

        name = tpsa_get_section_name(szBuff, strlen(szBuff));
        if (!name) {
            continue;
        }

        if (strcmp(name, pSection) == 0) {
            return TPSA_ETC_OK;
        }
        max_safety_loops++;
    }

    return TPSA_ETC_SECTIONNOTFOUND;
}

/*
 * @brief locate a specified key in the etc file.
 */
static int tpsa_etc_locate_key_value(FILE *fp, const char *pKey, char *pValue, size_t len, FILE *bak_fp)
{
    char szBuff[TPSA_ETC_MAX_LINE + 1 + 1];
    char *current = NULL;
    char *value = NULL;
    int ret;

    int max_safety_loops = 0;
    while (max_safety_loops < TPSA_MAX_SAFETY_LOOPS) {
        int bufflen;

        if (!fgets(szBuff, TPSA_ETC_MAX_LINE, fp)) {
            return TPSA_ETC_FILEIOFAILED;
        }
        bufflen = (int)strlen(szBuff);
        if (bufflen <= 0 || bufflen > TPSA_ETC_MAX_LINE) {
            return TPSA_ETC_KEYNOTFOUND;
        }
        if (szBuff[bufflen - 1] == '\n') {
            szBuff[bufflen - 1] = '\0';
        }

        ret = tpsa_get_key_value(szBuff, &current, &value, '=');
        if (ret < 0) {
            continue;
        } else if (ret > 0) {
            (void)fseek(fp, -bufflen, SEEK_CUR);
            return TPSA_ETC_KEYNOTFOUND;
        }

        if (strcmp(current, pKey) == 0) {
            if (pValue) {
                (void)strncpy(pValue, value, len - 1);
            }
            return TPSA_ETC_OK;
        } else if (bak_fp && *current != '\0') {
            if (value && strlen(value) >= 1) {
                (void)fprintf(bak_fp, "%s=%s\n", current, value);
            }
        }
        max_safety_loops++;
    }

    return TPSA_ETC_KEYNOTFOUND;
}

static char *tpsa_get_section_name(char *section_line, size_t section_len)
{
    char *name = NULL;
    size_t i = 0;

    if (!section_line) {
        return NULL;
    }

    while ((i < section_len) && (section_line[i] == ' ' || section_line[i] == '\t')) {
        i++;
    }

    if (section_line[i] == ';' || section_line[i] == '#') {
        return NULL;
    }

    if (section_line[i++] == '[') {
        while (section_line[i] == ' ' || section_line[i] == '\t') {
            i++;
        }
    } else {
        return NULL;
    }

    name = section_line + i;
    while ((i < section_len) && section_line[i] != ']' && section_line[i] != '\n' && section_line[i] != ';' &&
        section_line[i] != '#' && section_line[i] != '\0') {
        i++;
    }
    section_line[i] = '\0';
    while (section_line[i] == ' ' || section_line[i] == '\t') {
        section_line[i] = '\0';
        i--;
    }

    return name;
}

static bool tpsa_is_valid_kv(char current)
{
    char err[TPSA_MAX_CURRENT_ERR] = {';', '#', '\n', '\0', ','};
    int i;

    for (i = 0; i < TPSA_MAX_CURRENT_ERR; i++) {
        if (current == err[i]) {
            return false;
        }
    }
    return true;
}

static bool tpsa_is_end_of_value(char current, bool array)
{
    char ends[TPSA_MAX_ENDS] = {'\n', '\0'};
    int i;

    for (i = 0; i < TPSA_MAX_ENDS; i++) {
        if (current == ends[i]) {
            return true;
        }
    }
    if (!array) {
        return current == ',';
    } else {
        return current == ']';
    }
}

static int tpsa_get_key_value(char *key_line, char **mykey, char **myvalue, char delimiter)
{
    char *current = NULL;
    char *tail = NULL;
    char *value = NULL;

    if (tpsa_get_kv_check_para((const char *)key_line, (const char **)mykey, (const char **)myvalue) != 0) {
        return -1;
    }

    /* First, get key */
    current = key_line;

    while (*current == ' ' || *current == '\t') {
        current++;
    }

    if (!tpsa_is_valid_kv(*current)) {
        return -1;
    }

    if (*current == '[') {
        return 1;
    }

    /* Second, get value */
    tail = current;
    while (*tail != delimiter && tpsa_is_valid_kv(*tail)) {
        tail++;
    }
    if (*tail == '\0') {
        return -1;
    }

    value = tail + 1;
    if (*tail != delimiter) {
        *value = '\0';
    }

    /* Skip '' in the head of value */
    while (*value == ' ') {
        value++;
    }

    /* Pend \0 to the key string */
    *tail = '\0';
    if (strlen(current) == 0) {
        return -1;
    }
    tail--;
    while (*tail == ' ' || *tail == '\t') {
        *tail = '\0';
        tail--;
    }

    /* Pend \0 to the value string */
    tail = value;
    while (!tpsa_is_end_of_value(*tail, *value == '[')) {
        tail++;
    }
    *tail = '\0';

    *mykey = current;
    *myvalue = (*value == '[' ? value + 1 : value);

    return 0;
}

static int tpsa_get_kv_check_para(const char *key_line, const char **mykey, const char **myvalue)
{
    if (key_line == NULL || mykey == NULL || myvalue == NULL) {
        return -1;
    }
    return 0;
}
