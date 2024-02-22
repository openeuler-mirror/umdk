/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub atomic head file for internal use
 * Author: Lilijun
 * Create: 2020-8-7
 * Note:
 * History: 2020-8-7  Lilijun  define atomic types
 *          2020-9-21 Lilijun  fix atomic types
 */

#ifndef UB_BARRIER_H
#define UB_BARRIER_H 1

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(__x86_64__)
#define wc_wmb() __asm__ volatile("sfence" ::: "memory")
#define rmb() __asm__ volatile("lfence" ::: "memory")
#define wmb() wc_wmb()
#define mm_store_si128(a, b) _mm_store_si128((__m128i *)(a), *(__m128i *)(b))
#elif defined(__aarch64__)
#define wc_wmb() __asm__ volatile("dsb st" ::: "memory")
#define rmb() __asm__ volatile("dsb ld" ::: "memory")
#define wmb() wc_wmb()
#define mm_store_si128(a, b) vst1q_s32((int32_t *)(a), *(int32x4_t *)(b))
#endif

#define ub_compiler_barrier() asm volatile("" : : : "memory")

#ifdef UB_ARCH_X86_64
#define dmb(opt) ub_compiler_barrier()
#else
#define dmb(opt) asm volatile("dmb " #opt : : : "memory")
#endif

#define ub_smp_mb() dmb(ish)
#define ub_smp_wmb() dmb(ishst)
#define ub_smp_rmb() dmb(ishld)


#ifdef __cplusplus
}
#endif

#endif
