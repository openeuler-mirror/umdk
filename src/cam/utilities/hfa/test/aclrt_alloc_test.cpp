/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HFA test
 * Author: Nikita Merkulov
 * Note:
 * History:
 */

#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <sstream>
#include <set>
#include <vector>
#include <utility>
#include <chrono>

#include <acl/acl.h>

#define ACL_CHECK(ret) do { \
    if(ret != ACL_SUCCESS)\
    {\
        printf("acl interface return err %s:%d, retcode: %d %s\n\n", __FILE__, __LINE__, ret, aclGetRecentErrMsg());\
        exit(EXIT_FAILURE);\
    }\
} while(0)

// general measures
static const size_t GIGA = 1024UL * 1024UL * 1024UL;
static const size_t MEGA = 1024UL * 1024UL;
static const size_t PAGE_ALIGN = 2UL * MEGA;
static const size_t MEGA_IN_GIGA = 1024UL;

#define INITIAL_FREE_CHUNKS 1024
static constexpr const char* RANDOM_FILE = "/dev/urandom";

static int32_t dev_id = 6;  //  NPU 7
static size_t vr_mem_size = 128UL * GIGA;  // in bytes, must be physical page aligned (2M)
static size_t ph_mem_size = 28000UL * MEGA;  // in bytes, must be physical page aligned (2M)
static size_t ph_page_size = 1UL * PAGE_ALIGN;  // PAGE_ALIGN=2MB

#define NANO_TO_MICRO(x) ((double)(x) / 1000.0)
#define NANO_TO_MILLI(x) ((double)(x) / 1000000.0)
#define GET_TIME_NOW() std::chrono::steady_clock::now()
#define GET_TIME_DIFF_MILLI(start_time) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time).count()
#define GET_TIME_DIFF_MICRO(start_time) std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time).count()
#define GET_TIME_DIFF_NANO(start_time) std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start_time).count()

int aclrt_malloc_warmup()
{
    size_t iters = 1000;
    size_t size = 1000;

    std::vector<void *> alloc_vec;
    void *ptr;
    double total_allocation_duration_nsec = 0;
    aclError err;
    for (size_t i = 0; i < iters; i++) {
        err = aclrtMalloc(&ptr, size, ACL_MEM_MALLOC_HUGE_FIRST);
        if (err != ACL_SUCCESS) {
            break;
        }
        if (ptr == nullptr) {
            break;
        }
        alloc_vec.push_back(ptr);
    }

    for (auto free_ptr : alloc_vec) {
        if (free_ptr == nullptr) {
            break;
        }
        err = aclrtFree(free_ptr);
        if (err != ACL_SUCCESS) {
            fprintf(stderr, "aclrtFree() failed\n");
            return 1;
        }
    }
    return 0;
}

int test_aclrt_perf()
{
    size_t iters = 1000;

    std::vector<void *> alloc_vec;
    for (size_t size = 1000; size <= 1000000000; size *= 10) {

        // measure alloc time
        size_t i;
        void *ptr;
        double total_allocation_duration_nsec = 0;
        aclError err;
        for (i = 0; i < iters; i++) {
            auto start = GET_TIME_NOW();
            err = aclrtMalloc(&ptr, size, ACL_MEM_MALLOC_HUGE_FIRST);
            if (err != ACL_SUCCESS) {
                break;
            }
            auto allocation_duration = GET_TIME_DIFF_NANO(start);
            total_allocation_duration_nsec += allocation_duration;
            if (ptr == nullptr) {
                break;
            }
            alloc_vec.push_back(ptr);
        }
        printf("alloc obj size %lu. average allocation time %.3f [usec]. num_iterations:%lu\n",
            size, total_allocation_duration_nsec / 1000.0 / i, i);

        auto free_start = GET_TIME_NOW();
        for (auto free_ptr : alloc_vec) {
            if (free_ptr == nullptr) {
                break;
            }
            err = aclrtFree(free_ptr);
            if (err != ACL_SUCCESS) {
                fprintf(stderr, "aclrtFree() failed\n");
                return 1;
            }
        }
        auto free_duration = GET_TIME_DIFF_MICRO(free_start);
        printf("free obj size %lu. average free time %.3f [usec]. num_iterations:%lu\n",
            size, (double)free_duration / alloc_vec.size(), alloc_vec.size());

        alloc_vec.clear();
    }

    return 0;
}

int main(int argc, char* argv[])
{
    setbuf(stdout, NULL); // printf completely unbuffered

    if (aclInit(nullptr) != ACL_SUCCESS) {
        printf("aclInit has failed: %s\n", aclGetRecentErrMsg());
        return -1;
    }
    aclError err;
    if ((err = aclrtSetDevice(dev_id)) != ACL_SUCCESS) {
        printf("Error. aclrtSetDevice() has failed\n");
        return -1;
    }

    aclrt_malloc_warmup();
    test_aclrt_perf();

    // clean up
    printf("starting free memory ...\n");
    printf("free memory successful!\n");
    return 0;
}
