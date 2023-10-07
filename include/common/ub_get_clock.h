/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: clock for urma_perftest
 * Author: Qian Guoxin
 * Create: 2022-04-03
 * Note:
 * History: 2022-04-03   create file
 */

#ifndef UB_GET_CLOCK_H
#define UB_GET_CLOCK_H

#include <stdint.h>
#include <stdbool.h>

#define CLOCK_SIZE_OF_INT (32)

#if defined(__x86_64__)
static inline uint64_t get_cycles(void)
{
    uint32_t low, high;
    uint64_t val;
    asm volatile ("rdtsc" : "=a" (low), "=d" (high));
    val = high;
    val = (val << CLOCK_SIZE_OF_INT) | low;
    return val;
}
#elif defined(__aarch64__)
static inline uint64_t get_cycles(void)
{
    uint64_t freq;
    asm volatile("isb" : : : "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r" (freq));
    return freq;
}
#else
#warning get_cycles not implemented
#endif

extern double get_cpu_mhz(bool cpu_freq_warn);

#endif
