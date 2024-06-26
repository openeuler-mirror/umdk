 /*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub dynamic string implemention file
 * Author: Xudingke
 * Create: 2020-10-27
 * Note:
 * History:
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "ub_util.h"
#include "ub_dstring.h"

#define DSTRING_MIN_LEN 8
#define DSTRING_MAX_LEN (1024 * 1024 * 1024) /* Max memory by one dstring limited to 1G bytes */
#define DSTRING_DOUBLE 2

/* Initializes the dstring. */
void dstring_reset(struct dstring *dstr)
{
    if (dstr == NULL) {
        return;
    }
    dstr->string = NULL;
    dstr->buf_used = 0;
    dstr->buf_len = 0;
}

/* Destroy the dstring */
void dstring_destroy(struct dstring *dstr)
{
    if (dstr == NULL) {
        return;
    }

    free(dstr->string);
    dstr->string = NULL;
    dstr->buf_len = 0;
    dstr->buf_used = 0;
}

void dstring_clear(struct dstring *dstr)
{
    if (dstr == NULL) {
        return;
    }

    dstr->buf_used = 0;
}

size_t dstring_get_len(struct dstring *dstr)
{
    if (dstr == NULL) {
        return 0;
    }

    return dstr->buf_used;
}

/* Reduces 'dstring''s length to no more than 'new_length' */
void dstring_truncate(struct dstring *dstr, size_t new_length)
{
    if (dstr == NULL) {
        return;
    }
    if (dstr->buf_used > new_length) {
        dstr->buf_used = new_length;
        dstr->string[new_length] = '\0';
    }
}

static int dstring_extend(struct dstring *dstr, size_t expected_len)
{
    char *str_tmp = NULL;
    size_t new_buf_len = DSTRING_MIN_LEN;

    if (dstr == NULL || expected_len < dstr->buf_len) {
        return 0;
    }
    new_buf_len = MAX(new_buf_len, dstr->buf_len * DSTRING_DOUBLE);
    new_buf_len = MAX(new_buf_len, dstr->buf_len + expected_len);
    new_buf_len++;

    str_tmp = calloc(1, new_buf_len);
    if (str_tmp == NULL) {
        return -1;
    }

    if (dstr->string != NULL) {
        (void)strncpy(str_tmp, dstr->string, new_buf_len);
        free(dstr->string);
    }

    dstr->buf_len = new_buf_len - 1;
    dstr->string = str_tmp;
    dstr->string[dstr->buf_len] = '\0';
    return 0;
}

/* push n byte buf at the end of dstring, the pointer will move ahead. */
char *dstring_push_buf(struct dstring *dstr, size_t n)
{
    if (dstr == NULL) {
        return NULL;
    }

    if (dstring_extend(dstr, dstr->buf_used + n) != 0) {
        return NULL;
    }
    dstr->buf_used += n;
    dstr->string[dstr->buf_used] = '\0';
    return &dstr->string[dstr->buf_used - n];
}

void dstring_put_char(struct dstring *dstr, char c)
{
    if (dstr == NULL) {
        return;
    }

    if (dstr->buf_used >= dstr->buf_len) {
        char *res_str = dstring_push_buf(dstr, 1);
        if (res_str != NULL) {
            *res_str = c;
        }
    } else {
        dstr->string[dstr->buf_used++] = c;
        dstr->string[dstr->buf_used] = '\0';
    }
}

int dstring_put_cstring(struct dstring *dstr, const char *s)
{
    if (dstr == NULL || s == NULL) {
        return -1;
    }
    size_t s_len = strlen(s);
    (void)memcpy(dstring_push_buf(dstr, s_len), s, s_len);
    return 0;
}

static int dstring_printf_(struct dstring *dstr, const char *format, va_list args_)
{
    va_list args;
    size_t buf_avail;
    int buf_needed;
    int ret;

    if (dstr == NULL) {
        return -1;
    }

    va_copy(args, args_);
    buf_needed = vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (buf_needed < 0) {
        return -1;
    }
    if (buf_needed > DSTRING_MAX_LEN) {
        return -1;
    }

    buf_avail = dstr->string ? ((dstr->buf_len - dstr->buf_used) + 1) : 0;
    if (buf_needed >= buf_avail) {
        ret = dstring_extend(dstr, dstr->buf_used + buf_needed);
        if (ret != 0) {
            return -1;
        }
    }

    va_copy(args, args_);
    buf_avail = (dstr->buf_len - dstr->buf_used) + 1;
    ret = vsnprintf(&dstr->string[dstr->buf_used], buf_avail, format, args);
    va_end(args);
    if (ret < 0) {
        return -1;
    }
    dstr->buf_used += (size_t)(unsigned int)ret;
    return 0;
}

// string actual length must not lager than 1GB
void dstring_printf(struct dstring *dstr, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    (void)dstring_printf_(dstr, format, args);
    va_end(args);
}

char *dstring_to_cstring(struct dstring *dstr)
{
    int ret;

    if (dstr == NULL) {
        return NULL;
    }
    if (!dstr->string) {
        ret = dstring_extend(dstr, 0);
        if (ret < 0) {
            return NULL;
        }
    }

    if (dstr->string != NULL) {
        dstr->string[dstr->buf_used] = '\0';
    }
    return dstr->string;
}

/* Trans dstring to cstring, and reset the metadata. */
char *dstring_pealing(struct dstring *dstr)
{
    char *str = dstring_to_cstring(dstr);
    dstring_reset(dstr);
    return str;
}

bool dstring_chomp(struct dstring *dstr, int c)
{
    if (dstr == NULL) {
        return false;
    }

    if (dstr->buf_used > 0 && dstr->string[dstr->buf_used - 1] == (char)c) {
        dstr->string[--dstr->buf_used] = '\0';
        return true;
    } else {
        return false;
    }
}

