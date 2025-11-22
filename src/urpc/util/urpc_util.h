/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc util
 */
#ifndef URPC_UTIL_H
#define URPC_UTIL_H

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#ifdef __cplusplus
#include <cstdint>

#else
#include <stdint.h>
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if __GNUC__ && !defined(__CHECKER__)
#define URPC_LIKELY(CONDITION)        __builtin_expect(!!(CONDITION), 1)
#define URPC_UNLIKELY(CONDITION)      __builtin_expect(!!(CONDITION), 0)
#else
#define URPC_LIKELY(CONDITION)   (!!(CONDITION))
#define URPC_UNLIKELY(CONDITION) (!!(CONDITION))
#endif

#ifndef ALWAYS_INLINE
#define ALWAYS_INLINE inline __attribute__((always_inline))
#endif

#ifndef EID_FMT
#define EID_FMT "%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x"
#endif

#ifndef EID_RAW_ARGS
#define EID_RAW_ARGS(eid) eid[0], eid[1], eid[2], eid[3], eid[4], eid[5], eid[6], eid[7], eid[8], eid[9], \
        eid[10], eid[11], eid[12], eid[13], eid[14], eid[15]
#endif

#ifndef EID_ARGS
#define EID_ARGS(eid) EID_RAW_ARGS((eid).raw)
#endif

#define OBJ_OFFSETOF(obj_ptr, field) offsetof(typeof(*(obj_ptr)), field)

/* get the size of field in the struct_type. */
#define SIZEOF_FIELD(struct_type, field) (sizeof(((struct_type *)NULL)->field))

/* get the offset of the end of field in the struct. */
#define OFFSET_OF_FIELD_END(struct_type, field) (offsetof(struct_type, field) + SIZEOF_FIELD(struct_type, field))

/* get the structure object from the pointer of the given field by struct type */
#define CONTAINER_OF_FIELD(field_ptr, struct_type, field) \
    ((struct_type *)(void *)((char *)(field_ptr) - offsetof(struct_type, field)))

/* get the structure object from the pointer of the given field by type of obj_ptr */
#define OBJ_CONTAINING(field_ptr, obj_ptr, field) \
    ((typeof(obj_ptr))(void *)((char *)(field_ptr)-OBJ_OFFSETOF(obj_ptr, field)))

/* get the structure object from the pointer of the given field by struct type,
 * Then assign the structure object to the obj_ptr
 */
#define ASSIGN_CONTAINER_PTR(obj_ptr, field_ptr, field) ((obj_ptr) = OBJ_CONTAINING(field_ptr, obj_ptr, field), (void)0)

/* initialize obj_ptr and  ASSIGN_CONTAINER_PTR to avoid compile warnings. */
#define INIT_CONTAINER_PTR(obj_ptr, field_ptr, field) \
    ((obj_ptr) = NULL, ASSIGN_CONTAINER_PTR(obj_ptr, field_ptr, field))

#define URPC_RUNNING (1)
#define URPC_INVALID_TASK_ID (-1)

enum constructor_priority {
    CONSTRUCTOR_PRIORITY_GLOBAL = 101,
    CONSTRUCTOR_PRIORITY_DRIVER,
    CONSTRUCTOR_PRIORITY_LOG_URPC,
    CONSTRUCTOR_PRIORITY_LOG_UMQ,
    CONSTRUCTOR_PRIORITY_FEATURE
};

enum destructor_priority {
    DESTRUCTOR_PRIORITY_GLOBAL = 101,
    DESTRUCTOR_PRIORITY_DRIVER,
    DESTRUCTOR_PRIORITY_LOG_URPC,
    DESTRUCTOR_PRIORITY_LOG_UMQ,
    DESTRUCTOR_PRIORITY_FEATURE
};

#define URPC_CONSTRUCTOR(func, priority) static void __attribute__((constructor(priority), used)) func(void)
#define URPC_DESTRUCTOR(func, priority) static void __attribute__((destructor(priority), used)) func(void)

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define BITS_PER_LONG 64
#define BITS_PER_LONG_SHIFT 6
#define BITS_PER_LONG_MASK (BITS_PER_LONG - 1)
#define BITS_TO_LONGS(cnt) DIV_ROUND_UP((cnt), BITS_PER_LONG)

#define MS_PER_SEC 1000
#define US_PER_SEC 1000000
#define NS_PER_SEC 1000000000UL
#define NS_PER_MS 1000000
#define NS_PER_US 1000

/* Undefined when x == 0 */
static inline int urpc_count_trail_zero(uint64_t x)
{
    return (__builtin_constant_p(x <= UINT32_MAX) && x <= UINT32_MAX
            ? __builtin_ctz((unsigned int)x)
            : __builtin_ctzll(x));
}

static inline unsigned long __attribute__((always_inline)) urpc_ffs(unsigned long word)
{
    return (unsigned long)((unsigned long)__builtin_ffsl(word) - 1UL);
}

#if defined(__x86_64__)
static inline uint64_t urpc_get_cpu_cycles(void)
{
    uint32_t low, high;
    uint64_t val;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    val = high;
    // 32 is bit size of high
    val = (val << 32) | low;
    return val;
}
#elif defined(__aarch64__)
static inline uint64_t urpc_get_cpu_hz_aarch64(void)
{
    uint64_t freq;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    return freq;
}

// cpu cycles may not be monotonically increasing in multithread
static inline uint64_t urpc_get_cpu_cycles(void)
{
    uint64_t tsc;
    asm volatile("mrs %0, cntvct_el0" : "=r"(tsc));
    return tsc;
}
#else
#warning urpc_get_cpu_cycles not implemented
#endif

uint64_t urpc_get_cpu_hz(void);

// get timestamp in seconds
static inline uint32_t get_timestamp(void)
{
    struct timespec tc;
    (void)clock_gettime(CLOCK_MONOTONIC, &tc);
    return tc.tv_sec;
}

static inline uint64_t get_timestamp_ns(void)
{
    struct timespec tc;
    (void)clock_gettime(CLOCK_MONOTONIC, &tc);
    return (uint64_t)(tc.tv_sec * NS_PER_SEC + tc.tv_nsec);
}

static inline uint64_t get_timestamp_ms(void)
{
    struct timespec tc;
    (void)clock_gettime(CLOCK_MONOTONIC, &tc);
    return (uint64_t)(tc.tv_sec * MS_PER_SEC + tc.tv_nsec / NS_PER_MS);
}

int urpc_rand_seed_init(void);
int urpc_rand_generate(uint8_t *buf, uint32_t num);

#ifdef __cplusplus
}
#endif

#endif
