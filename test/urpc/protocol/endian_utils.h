/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc endian utils test
 */

#include <asm/byteorder.h>

extern "C" {
#if __BYTE_ORDER == __LITTLE_ENDIAN
/* Host Order       1111 1111 0000 0000
 * Network Order    1111 1111 0000 0000 */
static uint16_t g_ho_field16 = 0xff00;
[[maybe_unused]] static uint16_t g_no_field16 = 0xff00;

/* Host Order       1111 1111 0000 0000 1111 1111
 * Network Order    1111 1111 0000 0000 1111 1111 */
static uint32_t g_ho_field24 = 0x00ff00ff;
[[maybe_unused]] static uint32_t g_no_field24 = 0x00ff00ff;

/* Host Order       1111 1111 0000 0000 1111 1111 0000 0000
 * Network Order    1111 1111 0000 0000 1111 1111 0000 0000 */
static uint32_t g_ho_field32 = 0xff00ff00;
[[maybe_unused]] static uint32_t g_no_field32 = 0xff00ff00;

/* Host Order       1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000
 * Network Order    1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 */
static uint64_t g_ho_field48 = 0xff00ff00ff00;
[[maybe_unused]] static uint64_t g_no_field48 = 0xff00ff00ff00;

/* Host Order       1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000
 * Network Order    1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 */
static uint64_t g_ho_field64 = 0xff00ff00ff00ff00;
[[maybe_unused]] static uint64_t g_no_field64 = 0xff00ff00ff00ff00;
#else
/* Host Order       0000 0000 1111 1111
 * Network Order    1111 1111 0000 0000 */
static uint16_t g_ho_field16 = 0x00ff;
[[maybe_unused]] static uint16_t g_no_field16 = 0xff00;

/* Host Order       1111 1111 0000 0000 1111 1111
 * Network Order    1111 1111 0000 0000 1111 1111 */
static uint32_t g_ho_field24 = 0x00ff00ff;
[[maybe_unused]] static uint32_t g_no_field24 = 0x00ff00ff;

/* Host Order       0000 0000 1111 1111 0000 0000 1111 1111
 * Network Order    1111 1111 0000 0000 1111 1111 0000 0000 */
static uint32_t g_ho_field32 = 0x00ff00ff;
[[maybe_unused]] static uint32_t g_no_field32 = 0xff00ff00;

/* Host Order       0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 1111 1111
 * Network Order    1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 */
static uint64_t g_ho_field48 = 0x00ff00ff00ff;
[[maybe_unused]] static uint64_t g_no_field48 = 0xff00ff00ff00;

/* Host Order       0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 1111 1111
 * Network Order    1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 1111 1111 0000 0000 */
static uint64_t g_ho_field64 = 0x00ff00ff00ff00ff;
[[maybe_unused]] static uint64_t g_no_field64 = 0xff00ff00ff00ff00;
#endif
};
