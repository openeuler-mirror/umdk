/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: header of compiler's attributes
 * Author: Zhang Xu
 * Create: 2019-8-8
 * Note:
 * History: 2019-8-8 Zhang Xu support compiler's attributes
 */


#ifndef UB_COMPILER_H
#define UB_COMPILER_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

#if __GNUC__ && !defined(__CHECKER__)
#define UB_NO_RETURN __attribute__((__noreturn__))
#else
#define UB_NO_RETURN
#endif

#if __GNUC__
#define UB_PREFETCH(addr) __builtin_prefetch((addr))
#else
#define UB_PREFETCH(addr)
#endif

#ifndef BUILD_ASSERT
#define BUILD_ASSERT__(EXPR) \
        sizeof(struct { unsigned int build_assert_failed : (EXPR) ? 1 : -1; })
#define BUILD_ASSERT(EXPR) (void) BUILD_ASSERT__(EXPR)
#endif

#define BUILD_ASSERT_TYPE(POINTER, TYPE) \
    ((void)sizeof((int)((POINTER) == (TYPE)(POINTER))))

#define CONST_CAST(TYPE, POINTER)      \
    (BUILD_ASSERT_TYPE(POINTER, TYPE), \
        (TYPE)(POINTER))

#ifdef __cplusplus
}
#endif

#endif
