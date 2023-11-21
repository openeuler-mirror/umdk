/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ub util head file
 * Author: Lilijun
 * Create: 2020-8-11
 * Note:
 * History:
 */


#ifndef UB_UTIL_H
#define UB_UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
#endif

#if __GNUC__ && !defined(__CHECKER__)
#define UB_UNUSED                   __attribute__((__unused__))
#define UB_LIKELY(CONDITION)        __builtin_expect(!!(CONDITION), 1)
#define UB_UNLIKELY(CONDITION)      __builtin_expect(!!(CONDITION), 0)
#else
#define UB_UNUSED
#define UB_LIKELY(CONDITION)   (!!(CONDITION))
#define UB_UNLIKELY(CONDITION) (!!(CONDITION))
#endif

#define UB_CPU_ALLOC_SIZE(count) \
    ((((count) + __NCPUBITS - 1) / __NCPUBITS) * sizeof(__cpu_mask))
#define UB_CPU_ALLOC(count)                   (malloc(UB_CPU_ALLOC_SIZE(count)))
#define CPUSET_NBITS(setsize)                  (8 * (setsize))
#define UB_CPU_ISSET_S(cpu, setsize, cpusetp) \
    ({ size_t __cpu = (cpu);                  \
    __cpu < 8 * (setsize)                   \
      ? ((((__cpu_mask *) ((cpusetp)->__bits))[__CPUELT (__cpu)]          \
      & __CPUMASK (__cpu))) != 0               \
      : 0; })

#define UB_CONSTRUCTOR(f)                            \
    static void f(void) __attribute__((constructor)); \
    static void f(void)

#ifndef NDEBUG
#define UB_ASSERT(CONDITION)     \
    if (UB_LIKELY(!(CONDITION))) { \
        assert(CONDITION);        \
    }
#else
#define UB_ASSERT(CONDITION) ((void)(CONDITION))
#endif

static inline void ub_abort(void)
{
    abort();
}

#define UB_SOURCE_LOCATOR  __FILE__ ":" UB_STRINGIZE(__LINE__)
#define UB_STRINGIZE(AUX)  #AUX

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

typedef enum urma_huge_page_size {
    UB_HUGE_PAGE_SIZE_2MB,
    UB_HUGE_PAGE_SIZE_1GB,
    UB_HUGE_PAGE_SIZE_ANY,
} urma_huge_page_size_t;

/* get the 1 bits count. */
static inline unsigned int ub_count_1bits(uint64_t x)
{
    return (unsigned int)__builtin_popcountll(x);
}

/* get the last 1-bit of x */
static inline uintmax_t ub_rightmost_1bit(uintmax_t x)
{
    return x & (uintmax_t)(-x);
}

/* clear the last 1-bit of x */
static inline uintmax_t ub_zero_rightmost_1bit(uintmax_t x)
{
    return x & (x - 1);
}

/* Undefined when x == 0 */
static inline int ub_count_trail_zero(uint64_t x)
{
    return (__builtin_constant_p(x <= UINT32_MAX) && x <= UINT32_MAX
            ? __builtin_ctz((unsigned int)x)
            : __builtin_ctzll(x));
}

#define BITS_PER_LONG 64
#define BITS_PER_LONG_SHIFT 6
#define BITS_PER_LONG_MASK (BITS_PER_LONG - 1)
#define NANO_IN_SEC 1000000000
/** for bit ops */
#define BITS_PER_BYTE 8
#define BITS_PER_UINT32 32

#define ARRAY_SIZE(ARRAY) (sizeof(ARRAY) / sizeof((ARRAY)[0]))

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#ifndef ROUND_UP
#define ROUND_UP(n, d) (DIV_ROUND_UP(n, d) * (d))
#endif

#ifndef ROUND_DOWN
#define ROUND_DOWN(n, d) ((n) / (d) * (d))
#endif

#ifndef IS_POW2
#define IS_POW2(n) (((n) != 0) && (((n) & ((n) - 1)) == 0))
#endif

static inline bool ub_is_pow2(uint64_t x)
{
    return IS_POW2(x);
}

#define BITS_TO_LONGS(cnt) DIV_ROUND_UP((cnt), BITS_PER_LONG)

#define for_each_set_bit(bit, addr, size)            \
    for ((bit) = ub_find_first_bit((addr), (size)); \
         (bit) < (size);                             \
         (bit) = ub_find_next_bit((addr), (size), (bit) + 1))

static inline void __attribute__((always_inline)) set_bit(uint32_t nr, unsigned long *addr)
{
    addr[nr >> BITS_PER_LONG_SHIFT] |= 1UL << (nr & BITS_PER_LONG_MASK);
}

static inline void __attribute__((always_inline)) clear_bit(uint32_t nr, unsigned long *addr)
{
    addr[nr >> BITS_PER_LONG_SHIFT] &= ~(1UL << (nr & BITS_PER_LONG_MASK));
}

static inline int __attribute__((always_inline)) test_bit(unsigned int nr, const unsigned long *addr)
{
    return ((1UL << (nr & BITS_PER_LONG_MASK)) &
            (((unsigned long *)addr)[nr >> BITS_PER_LONG_SHIFT])) != 0;
}

static inline void __attribute__((always_inline)) bitmap_zero(unsigned int nbits, unsigned long *addr)
{
    size_t len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
    memset(addr, 0, len);
}

#define BITOP_WORD(nr) ((nr) >> BITS_PER_LONG_SHIFT)

static inline unsigned long __attribute__((always_inline)) ub_ffs(unsigned long word)
{
    return (unsigned long)((unsigned long)__builtin_ffsl(word) - 1UL);
}

/*
 * Find the first set bit in unsigned long array. For example,
 * array[2] has two unsigned long with array[1] is set to 128(1000 0000).
 * Then ub_find_first_bit returns 71(64+7). If all bits are not set,
 * then the total size of bits will be returned.
 * @array: unsigned long array for searching
 * @size: total size of bits, not the number of array elements. For example,
 *        array[2] has size 128 and array size 2.
 */
unsigned long ub_find_first_bit(const unsigned long *array, unsigned long size);

unsigned long ub_find_next_bit(const unsigned long *array, unsigned long size, unsigned long offset);

unsigned long ub_find_next_zero_bit(const unsigned long *array, unsigned long size, unsigned long offset);

/* ffz - find first zero bit in word */
static inline unsigned long __attribute__((always_inline)) ffz(unsigned long word)
{
    return (unsigned long)((unsigned long)__builtin_ffsl(~(word)) - 1UL);
}

unsigned long ub_find_first_zero_bit(const unsigned long *array, unsigned long size);

#define OBJ_OFFSETOF(obj_ptr, field) offsetof(typeof(*(obj_ptr)), field)

/* get the size of field in the struct_type. */
#define SIZEOF_FIELD(struct_type, field) (sizeof(((struct_type *)NULL)->field))

/* get the offset of the end of field in the struct. */
#define OFFSET_OF_FIELD_END(struct_type, field) \
    (offsetof(struct_type, field) + SIZEOF_FIELD(struct_type, field))

/* get the structure object from the pointer of the given field by struct type */
#define CONTAINER_OF_FIELD(field_ptr, struct_type, field) \
    ((struct_type *)(void *)((char *)(field_ptr) - offsetof(struct_type, field)))

/* get the structure object from the pointer of the given field by type of obj_ptr */
#define OBJ_CONTAINING(field_ptr, obj_ptr, field) \
    ((typeof(obj_ptr))(void *)((char *)(field_ptr) - OBJ_OFFSETOF(obj_ptr, field)))

/* get the structure object from the pointer of the given field by struct type,
 * Then assign the structure object to the obj_ptr
 */
#define ASSIGN_CONTAINER_PTR(obj_ptr, field_ptr, field) \
    ((obj_ptr) = OBJ_CONTAINING(field_ptr, obj_ptr, field), (void)0)

/* initialize obj_ptr and  ASSIGN_CONTAINER_PTR to avoid compile warnings. */
#define INIT_CONTAINER_PTR(obj_ptr, field_ptr, field) \
    ((obj_ptr) = NULL, ASSIGN_CONTAINER_PTR(obj_ptr, field_ptr, field))

int safe_write_value_to_file(const char *path, const char *str);

/* easy to covert string and integer */
struct str_int {
    char *s;
    int integer;
};

static inline int get_int_from_string(const struct str_int *array, int array_size, const char *str)
{
    int i;
    for (i = 0; i < array_size; i++) {
        if (strcmp(array[i].s, str) == 0) {
            return (int)array[i].integer;
        }
    }
    return -1;
}

static inline char *get_string_from_int(const struct str_int *array, int array_size, int num)
{
    int i;
    for (i = 0; i < array_size; i++) {
        if (array[i].integer == num) {
            return array[i].s;
        }
    }
    return NULL;
}

bool hexits_value(const char *s, size_t n, uintmax_t *value);

bool is_valid_digit(const char *digit_str);
int ub_str_to_bool(const char *buf, bool *bool_res);
int ub_str_to_u8(const char *buf, uint8_t *u8);
int ub_str_to_u16(const char *buf, uint16_t *u16);
int ub_str_to_u32(const char *buf, uint32_t *u32);
int ub_str_to_u64(const char *buf, uint64_t *u64);
int ub_hex_str_to_u64(const char *p, uint64_t *out, uint64_t max);
int ub_parse_sysfs_val(const char *filename, unsigned long *val);
void *ub_hugemalloc(size_t i_length, urma_huge_page_size_t hps, void *p_addr_hint);
int ub_hugefree(void *p_addr, size_t i_length);
int memset_s_large_buf(void *dest, size_t destMax, int c, size_t count);
int memcpy_s_large_buf(void *dest, size_t destMax, const void *src, size_t count);

#define RETVAL_SZ 256
static char g_ub_util_ret[RETVAL_SZ] = { 0 };

static inline const char *ub_strerror(int errnum)
{
    if (strerror_r(errnum, g_ub_util_ret, RETVAL_SZ) != 0) {
        if (snprintf(g_ub_util_ret, RETVAL_SZ - 1, "Unknown error %d", errnum) <= 0) {
            return NULL;
        }
    }
    return g_ub_util_ret;
}

static inline uint64_t gethrtime_epoch(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return (uint64_t)(-1);
    }

    return (uint64_t)((ts.tv_sec * NANO_IN_SEC) + ts.tv_nsec);
}

#ifdef __cplusplus
}
#endif

#endif
