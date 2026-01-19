/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HFA test
 * Author: David Yaron
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
#include <random>

#include <acl/acl.h>
#include <gtest/gtest.h>
#include "test_utils.h"

#define ACL_CHECK(ret) do { \
    if(ret != ACL_SUCCESS) \
    { \
        printf("acl interface return err %s:%d, retcode: %d %s\n\n", __FILE__, __LINE__, ret, aclGetRecentErrMsg()); \
        FAIL(); \
    } \
} while(0)

// general measures
static const size_t GIGA = 1024UL * 1024UL * 1024UL;
static const size_t MEGA = 1024UL * 1024UL;
static const size_t KILO = 1024UL;
static const size_t PAGE_ALIGN = 2UL * MEGA;
static const size_t MEGA_IN_GIGA = 1024UL;

#define INITIAL_FREE_PAGES 1024
static constexpr const char* RANDOM_FILE = "/dev/urandom";

static int32_t dev_id = 6;  //  NPU 7

#define NANO_TO_MICRO(x) ((double)(x) / 1000.0)
#define NANO_TO_MILLI(x) ((double)(x) / 1000000.0)
#define GET_TIME_NOW() std::chrono::steady_clock::now()
#define GET_TIME_DIFF_MILLI(start_time) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time).count()
#define GET_TIME_DIFF_MICRO(start_time) std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time).count()
#define GET_TIME_DIFF_NANO(start_time) std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start_time).count()

class AclrtUtilizationTest : public ::testing::Test {
protected:

    AclrtUtilizationTest() { }

    void SetUp() override {
    }

    void TearDown() override {
    }
};

static const char *g_rand_file_name = "../test/random_integers.txt";

TEST_F(AclrtUtilizationTest, RandomSizeUtil) {

    std::vector<size_t> rand_numbers;
    if (read_rands_from_file(g_rand_file_name, rand_numbers) != 0) {
        fprintf(stderr, "Error: failed to read rand numbers from file '%s'\n", g_rand_file_name);
        FAIL();
        return;
    }
    if (rand_numbers.size() == 0) {
        fprintf(stderr, "Error: read zero rand numbers from file '%s'\n", g_rand_file_name);
        FAIL();
        return;
    }

    std::vector<void *> alloc_vec;
    size_t total_allocated_size = 0;
    size_t num_allocs = 0;

    aclError err;
    if ((err = aclrtSetDevice(dev_id)) != ACL_SUCCESS) {
        printf("Error. aclrtSetDevice() has failed\n");
        return;
    }

    size_t i_free_mem;
    size_t i_total_mem;
    size_t i_free_mem_after;

    if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem, &i_total_mem)) != ACL_SUCCESS) {
            printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
            return;
    }

    printf("Starting allocations using aclrtMalloc():\n");
    for (size_t size : rand_numbers) {
        void *ptr;
        err = aclrtMalloc(&ptr, size, ACL_MEM_MALLOC_HUGE_FIRST);
        if (err != ACL_SUCCESS) {
            break;
        }
        if (ptr == nullptr) {
            break;
        }
        alloc_vec.push_back(ptr);
        total_allocated_size += size;
        num_allocs++;
    }

    if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem_after, &i_total_mem)) != ACL_SUCCESS) {
            printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
            return;
    }

    size_t consumed_mem = i_free_mem - i_free_mem_after;
    printf("Total allocation size: %lu bytes. usage percentage: %.2f%% num_allocs:%lu avg_alloc_size:%lu\n",
        total_allocated_size, (double)total_allocated_size * 100.0 / (double)consumed_mem,
        num_allocs, total_allocated_size / num_allocs);


    // free every 2nd alloc
    size_t num_removed = 0;
    size_t sum_removed = 0;
    size_t num_elems = alloc_vec.size();
    for (size_t i = 0; i < num_elems; i += 2) {
        sum_removed += rand_numbers[i];
        total_allocated_size -= rand_numbers[i];
        aclrtFree(alloc_vec[i]);
        num_removed++;
        num_allocs--;
    }

    // remove them from vector
    for (int i = alloc_vec.size() - 1; i >= 0; --i) {
        if (i % 2 == 0) {  // even index
            alloc_vec.erase(alloc_vec.begin() + i);
        }
    }

    // try to allocate big budder which is the sum of all
    void *ptr;
    err = aclrtMalloc(&ptr, sum_removed, ACL_MEM_MALLOC_HUGE_FIRST);
    if (err != ACL_SUCCESS || ptr == nullptr) {
        fprintf(stderr, "Error: failed to alloc big buffer of %lu bytes", sum_removed);
        return;
    }

    alloc_vec.push_back(ptr);
    total_allocated_size += sum_removed;
    num_allocs++;

    if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem_after, &i_total_mem)) != ACL_SUCCESS) {
            printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
            return;
    }

    consumed_mem = i_free_mem - i_free_mem_after;
    printf("After free every other buffer and allocating big one. Total allocation size: %lu bytes. "
        "usage percentage: %.2f%% num_allocs:%lu avg_alloc_size:%lu\n",
        total_allocated_size, (double)total_allocated_size * 100.0 / (double)consumed_mem,
        num_allocs, total_allocated_size / num_allocs);

    for (auto free_ptr : alloc_vec) {
        aclrtFree(free_ptr);
    }
}

TEST_F(AclrtUtilizationTest, FixedSizeUtilNon64ModuloSize) {
    std::vector<size_t> sizes_vec = {150, 1000, 4000, 10700, 100000, 1200005, 133000030};

    aclError err;
    if ((err = aclrtSetDevice(dev_id)) != ACL_SUCCESS) {
        printf("Error. aclrtSetDevice() has failed\n");
        return;
    }

    printf("Starting allocations using aclrtMalloc():\n");
    for (size_t size : sizes_vec) {
        std::vector<void *> alloc_vec;
        size_t total_allocated_size = 0;
        size_t num_allocs = 0;
        size_t i_free_mem;
        size_t i_total_mem;
        size_t i_free_mem_after;

        if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem, &i_total_mem)) != ACL_SUCCESS) {
            printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
            return;
        }

        while (true) {

            void *ptr;
            err = aclrtMalloc(&ptr, size, ACL_MEM_MALLOC_HUGE_FIRST);
            if (err != ACL_SUCCESS) {
                break;
            }

            if (ptr == nullptr) {
                break;
            }

            alloc_vec.push_back(ptr);
            total_allocated_size += size;
            num_allocs++;
        }

        if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem_after, &i_total_mem)) != ACL_SUCCESS) {
            printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
            return;
        }

        size_t consumed_mem = i_free_mem - i_free_mem_after;
        printf("alloc_size %lu usage percentage: %.2f%% . total_allocated_size: %lu consumed_mem: %lu. num_allocs:%lu\n",
            size, (double)total_allocated_size * 100.0 / (double)consumed_mem, total_allocated_size, consumed_mem,
            num_allocs);

        for (auto free_ptr : alloc_vec) {
            aclrtFree(free_ptr);
        }
    }
}

TEST_F(AclrtUtilizationTest, FixedSizeUtil64ModuloSize) {

    std::vector<size_t> sizes_vec = {KILO, 10*KILO, MEGA, 10*MEGA, 100*MEGA, GIGA};

    aclError err;
    if ((err = aclrtSetDevice(dev_id)) != ACL_SUCCESS) {
        printf("Error. aclrtSetDevice() has failed\n");
        return;
    }

    printf("Starting allocations using aclrtMalloc():\n");
    for (size_t size : sizes_vec) {
        std::vector<void *> alloc_vec;
        size_t total_allocated_size = 0;
        size_t num_allocs = 0;
        size_t i_free_mem;
        size_t i_total_mem;
        size_t i_free_mem_after;

        if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem, &i_total_mem)) != ACL_SUCCESS) {
                printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
                return;
        }

        while (true) {

            void *ptr;
            err = aclrtMalloc(&ptr, size, ACL_MEM_MALLOC_HUGE_FIRST);
            if (err != ACL_SUCCESS) {
                break;
            }

            if (ptr == nullptr) {
                break;
            }
            alloc_vec.push_back(ptr);
            total_allocated_size += size;
            num_allocs++;
        }

        if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem_after, &i_total_mem)) != ACL_SUCCESS) {
                printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
                return;
        }

        size_t consumed_mem = i_free_mem - i_free_mem_after;
        printf("size %lu Total allocation size: %lu bytes. usage percentage: %.2f%% num_allocs:%lu avg_alloc_size:%lu\n",
            size, total_allocated_size, (double)total_allocated_size * 100.0 / (double)consumed_mem,
            num_allocs, total_allocated_size / num_allocs);

        for (auto free_ptr : alloc_vec) {
            aclrtFree(free_ptr);
        }
    }
}

/**
 * check how much HBM memory can be used with aclrtMalloc() and allocation size of 1kb
 * answer: with ACL_MEM_MALLOC_HUGE_FIRST only ~1.5 GB out of ~28 GB
*/
TEST_F(AclrtUtilizationTest, MaxSmallAllocations) {
    aclError err;
    if ((err = aclrtSetDevice(dev_id)) != ACL_SUCCESS) {
        printf("Error. aclrtSetDevice() has failed\n");
        return;
    }

    printf("Starting allocations using aclrtMalloc():\n");

    size_t total_allocated_size = 0;
    size_t num_allocs = 0;
    size_t i_free_mem;
    size_t i_total_mem;
    size_t i_free_mem_after;
    size_t size = 1024;
    std::vector<void *> alloc_vec;

    if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem, &i_total_mem)) != ACL_SUCCESS) {
            printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
            return;
    }

    while (true) {

        void *ptr;
        err = aclrtMalloc(&ptr, size, ACL_MEM_MALLOC_HUGE_FIRST);
        if (err != ACL_SUCCESS) {
            err = aclrtMalloc(&ptr, size, ACL_MEM_MALLOC_NORMAL_ONLY);
            if (err != ACL_SUCCESS) {
                printf("OOM-error (triggered on purpose, to demonstrate aclrtMalloc's limitations for small objects)\n: aclrtGetMemInfo has failed: aclError:%d error:'%s'", err, aclGetRecentErrMsg());
                break;
            }
        }

        if (ptr == nullptr) {
            break;
        }

        alloc_vec.push_back(ptr);
        total_allocated_size += size;
        num_allocs++;
    }

    if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem_after, &i_total_mem)) != ACL_SUCCESS) {
            printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
            return;
    }

    size_t consumed_mem = i_free_mem - i_free_mem_after;
    printf("\n\nsize %zu Total allocation size: %zu (%.6f GB) num_allocs:%zu consumed_mem by "
        "aclrtGetMemInfo:%zu (%.6f GB) i_free_mem_before:%zu, i_free_mem_after:%zu\n",
        size, total_allocated_size, (double)total_allocated_size / GIGA, num_allocs, consumed_mem,
        (double)consumed_mem / GIGA, i_free_mem, i_free_mem_after);

    for (auto free_ptr : alloc_vec) {
        aclrtFree(free_ptr);
    }
}
