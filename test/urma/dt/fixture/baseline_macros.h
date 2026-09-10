/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

/*
 * 门禁式回归测试的宏标注。测试代码用这些宏标注"要验什么"，跑时输出固定格式行，
 * 生成器逐行读测试代码的宏 + 输出，一一对应生成基准/比对。
 */

#ifndef URMA_BASELINE_MACROS_H
#define URMA_BASELINE_MACROS_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DT_BL_LINE(file, line, kind, name, valstr) \
    fprintf(stderr, "BASELINE|%s|%d|%s|%s|%s\n", file, line, kind, name, valstr)

#define DT_WRITE_VAL(name, val) do { \
    char _buf[32]; \
    snprintf(_buf, sizeof(_buf), "%d", (int)(long)(val)); \
    DT_BL_LINE(__FILE__, __LINE__, "VAL", name, _buf); \
} while (0)

#define DT_WRITE_HEX(name, val) do { \
    char _buf[32]; \
    snprintf(_buf, sizeof(_buf), "0x%lx", (unsigned long)(val)); \
    DT_BL_LINE(__FILE__, __LINE__, "HEX", name, _buf); \
} while (0)

#define DT_ASSERT_NONEMPTY(name, p) do { \
    char _buf[32]; \
    snprintf(_buf, sizeof(_buf), "%p", (void *)(uintptr_t)(p)); \
    DT_BL_LINE(__FILE__, __LINE__, "NONEMPTY", name, _buf); \
} while (0)

#define DT_WRITE_STR(name, s) do { \
    const char *_s = (s); \
    char _buf[128]; \
    if (_s != NULL) { \
        size_t _n = strchr(_s, '\n') ? (size_t)(strchr(_s, '\n') - _s) : strlen(_s); \
        if (_n >= sizeof(_buf)) _n = sizeof(_buf) - 1; \
        memcpy(_buf, _s, _n); _buf[_n] = '\0'; \
    } else { _buf[0] = '\0'; } \
    DT_BL_LINE(__FILE__, __LINE__, "STR", name, _buf); \
} while (0)

#endif /* URMA_BASELINE_MACROS_H */
