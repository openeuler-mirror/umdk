/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.
 * Description: ub util head file
 * Author: Lilijun
 * Create: 2020-8-11
 * Note:
 * History:
 */

#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include "ub_util.h"

#define MEMSET_S_CHUNK_SZ ((1UL << 31) - 4096)
#define MEMCPY_S_CHUNK_SZ ((1UL << 31) - 4096)

/*
 * Find the first set bit in unsigned long array. For example,
 * array[2] has two unsigned long with array[1] is set to 128(1000 0000).
 * Then ub_find_first_bit returns 71(64+7). If all bits are not set,
 * then the total size of bits will be returned.
 * @array: unsigned long array for searching
 * @size: total size of bits, not the number of array elements. For example,
 *        array[2] has size 128 and array size 2.
 */
unsigned long ub_find_first_bit(const unsigned long *array, unsigned long size)
{
    unsigned long i;
    unsigned long ret = 0;
    unsigned long array_size;
    if (UB_UNLIKELY(size == 0)) {
        return size;
    }
    array_size = BITS_TO_LONGS(size);
    for (i = 0; i < array_size; i++) {
        if (array[i] != 0) {
            return (ret + ub_ffs(array[i]));
        } else {
            ret += BITS_PER_LONG;
        }
    }
    return size;
}

static unsigned long find_next_bit(const unsigned long *array, unsigned long size, unsigned long offset,
    unsigned long invert)
{
    unsigned long i;
    unsigned long ret;
    unsigned long long_offset;
    unsigned long tmp;
    unsigned long array_size;

    if (UB_UNLIKELY(offset >= size || size == 0)) {
        return size;
    }

    /* Calc the array index for offset. For example: offset=65, index=1. */
    i = offset >> BITS_PER_LONG_SHIFT;
    ret = i * BITS_PER_LONG;

    /* Calc the offset in unsigned long for "offset" bit. */
    long_offset = offset % BITS_PER_LONG;
    /* Set bits before "offset" to "0". */
    tmp = (array[i] ^ invert) & (~0UL << long_offset) ;
    if (tmp != 0) {
        return (ret + ub_ffs(tmp));
    } else {
        /* Next unsigned long. */
        ret += BITS_PER_LONG;
        i++;
    }

    array_size = BITS_TO_LONGS(size);
    for (; i < array_size; i++) {
        tmp = array[i] ^ invert;
        if (tmp != 0) {
            return (ret + ub_ffs(tmp));
        } else {
            ret += BITS_PER_LONG;
        }
    }

    return size;
}

unsigned long ub_find_next_bit(const unsigned long *array, unsigned long size, unsigned long offset)
{
    return find_next_bit(array, size, offset, 0UL);
}

unsigned long ub_find_next_zero_bit(const unsigned long *array, unsigned long size, unsigned long offset)
{
    return find_next_bit(array, size, offset, ~0UL);
}

unsigned long ub_find_first_zero_bit(const unsigned long *array, unsigned long size)
{
    unsigned long i;
    unsigned long ret = 0;
    unsigned long array_size;

    if (UB_UNLIKELY(size == 0)) {
        return size;
    }

    array_size = BITS_TO_LONGS(size);
    for (i = 0; i < array_size; i++) {
        if (array[i] != ~0UL) {
            unsigned long pos = ffz(array[i]);
            pos = (pos >= BITS_PER_LONG) ? BITS_PER_LONG - 1 : pos;
            if (ret + pos < size) {
                return ret + pos;
            } else {
                return size;
            }
        }
        ret += BITS_PER_LONG;
    }

    return size;
}

void *ub_hugemalloc(size_t i_length, urma_huge_page_size_t hps, void *p_addr_hint)
{
    void *p_addr;
    int prot = (PROT_READ | PROT_WRITE);

    if (i_length == 0) {
        return NULL;
    }

    /* By default, we do not use MAP_HUGE_1GB in flags
     * since if system is configured to have only huge pages of 2MB but not 1GB, mmap will fail. */
    unsigned int flags = (MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB);
    switch (hps) {
        case UB_HUGE_PAGE_SIZE_2MB:
            flags |= MAP_HUGE_2MB;
            break;
        case UB_HUGE_PAGE_SIZE_1GB:
            flags |= MAP_HUGE_1GB;
            break;
        default:
            break;
    }

    p_addr = mmap(p_addr_hint, i_length, prot, (int)flags, -1, 0);
    if (p_addr == MAP_FAILED) {
        return NULL;
    }

    return p_addr;
}

/**
 * free hugepages memory
 * @param p_addr - a pointer to the address
 * @param i_length - the address size_t
 * @return 0 on success, -1 on fail
 */
int ub_hugefree(void *p_addr, size_t i_length)
{
    if (p_addr == NULL) {
        return -EINVAL;
    }
    return munmap(p_addr, i_length);
}

/**
 * @brief memset_s for large buffers
 * Needed since memset_s fails with ERANGE for buffer length >= 2GB
 */
int memset_s_large_buf(void *dest, size_t destMax, int c, size_t count)
{
    size_t bytes_left = count;
    size_t copy_sz;
    uint8_t *p = (uint8_t*)dest;

    if (bytes_left > destMax) {
        bytes_left = destMax;
    }
    if (bytes_left == 0) {
        return 0;
    }
    while (bytes_left > 0) {
        copy_sz = MIN(MEMSET_S_CHUNK_SZ, bytes_left);
        memset(p, c, copy_sz);
        bytes_left -= copy_sz;
        p += copy_sz;
    }
    return 0;
}

/**
 * @brief memcpy_s for large buffers
 * Needed since memcpy_s fails with ERANGE for buffer length >= 2GB
 */
int memcpy_s_large_buf(void *dest, size_t destMax, const void *src, size_t count)
{
    size_t bytes_left = count;
    size_t copy_sz;
    uint8_t *p_dst = (uint8_t*)dest;
    uint8_t *p_src = (uint8_t*)src;

    if (bytes_left > destMax) {
        bytes_left = destMax;
    }
    if (bytes_left == 0) {
        return 0;
    }
    while (bytes_left > 0) {
        copy_sz = MIN(MEMCPY_S_CHUNK_SZ, bytes_left);
        (void)memcpy(p_dst, p_src, copy_sz);
        bytes_left -= copy_sz;
        p_dst += copy_sz;
        p_src += copy_sz;
    }
    return 0;
}

int ub_str_to_bool(const char *buf, bool *bool_res)
{
    if (buf == NULL || strlen(buf) == 0) {
        return -EINVAL;
    }

    if (!strcmp(buf, "true")) {
        *bool_res = true;
    } else if (!strcmp(buf, "false")) {
        *bool_res = false;
    } else {
        return -EINVAL;
    }

    return 0;
}

int ub_str_to_u8(const char *buf, uint8_t *u8)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }
    if (ret > UCHAR_MAX) {
        return -ERANGE;
    }
    *u8 = (uint8_t)ret;
    return 0;
}

int ub_str_to_u16(const char *buf, uint16_t *u16)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }
    if (ret > USHRT_MAX) {
        return -ERANGE;
    }
    *u16 = (uint16_t)ret;
    return 0;
}

int ub_str_to_u32(const char *buf, uint32_t *u32)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }
    if (ret > UINT_MAX) {
        return -ERANGE;
    }
    *u32 = (uint32_t)ret;
    return 0;
}

int ub_str_to_int(const char *buf, int *integer)
{
    long ret;
    char *end = NULL;

    if (buf == NULL) {
        return -EINVAL;
    }

    errno = 0;
    ret = strtol(buf, &end, 0);
    if (errno == ERANGE && ret == LONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }
    if (ret > LONG_MAX) {
        return -ERANGE;
    }
    if (ret < INT_MIN || ret > INT_MAX) {
        return -ERANGE;
    }
    *integer = (int)ret;
    return 0;
}

int ub_str_to_u64(const char *buf, uint64_t *u64)
{
    unsigned long ret;
    char *end = NULL;

    if (buf == NULL || *buf == '-') {
        return -EINVAL;
    }

    errno = 0;
    ret = strtoul(buf, &end, 0);
    if (errno == ERANGE && ret == ULONG_MAX) {
        return -EFAULT;
    }
    if (end == NULL || *end != '\0' || end == buf) {
        return -ENOEXEC;
    }

    *u64 = ret;
    return 0;
}