/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub dynamic string head file
 * Author: Xudingke
 * Create: 2020-10-27
 * Note:
 * History:
 */

#ifndef UB_DSTRING_H
#define UB_DSTRING_H

#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define DSTRING_INITIALIZER { NULL, 0, 0 }

struct dstring {
    char *string;
    size_t buf_used;    /* without '\0' */
    size_t buf_len;     /* without '\0' */
};

void dstring_reset(struct dstring *ds);
void dstring_clear(struct dstring *dstr);
size_t dstring_get_len(struct dstring *ds);
void dstring_truncate(struct dstring *ds, size_t new_length);
void dstring_destroy(struct dstring *dstr);
char *dstring_push_buf(struct dstring *dstr, size_t n);
void dstring_printf(struct dstring *ds, const char *format, ...);
int dstring_put_cstring(struct dstring *ds, const char *s);

char *dstring_to_cstring(struct dstring *dstr);
char *dstring_pealing(struct dstring *dstr);
void dstring_put_char(struct dstring *dstr, char c);
bool dstring_chomp(struct dstring *ds, int c);

#ifdef __cplusplus
}
#endif

#endif
