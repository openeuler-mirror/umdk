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
#include <fstream>
#include <string>
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

#include "flex_alloc.h"
#include "acl_virtual_memory.h"
#include "hbm_fast_alloc.h"
#include "test_utils.h"

using namespace hfa;

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

static size_t ph_margin = 10UL * MEGA;
static int32_t dev_id = 6;  //  NPU 7
static size_t vr_mem_size = 128UL * GIGA;  // in bytes, must be physical page aligned (2M)
static size_t ph_mem_size_default = 10UL * GIGA + ph_margin;  // in bytes, must be physical page aligned (2M)
static size_t ph_mem_size = ph_mem_size_default;  // in bytes, must be physical page aligned (2M)
static size_t ph_page_size = 1UL * PAGE_ALIGN;  // PAGE_ALIGN=2MB
static const char *g_rand_file_name = "../test/random_integers.txt";
static const size_t num_inits_uninits = 10; // increase to increase the tests' reliability
static const size_t leak_treshold = PAGE_ALIGN;

#define NANO_TO_MICRO(x) ((double)(x) / 1000.0)
#define NANO_TO_MILLI(x) ((double)(x) / 1000000.0)
#define GET_TIME_NOW() std::chrono::steady_clock::now()
#define GET_TIME_DIFF_MILLI(start_time) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time).count()
#define GET_TIME_DIFF_MICRO(start_time) std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time).count()
#define GET_TIME_DIFF_NANO(start_time) std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start_time).count()

static int hfa_warmup(HbmFastAlloc &hfa)
{
    size_t iters = 1000;
    size_t size = 1000;

    std::vector<void *> alloc_vec;
    void *ptr;
    for (size_t i = 0; i < iters; i++) {
        ptr = hfa.alloc(size);
        if (ptr == nullptr) {
            break;
        }
        alloc_vec.push_back(ptr);
    }

    for (auto free_ptr : alloc_vec) {
        if (free_ptr == nullptr) {
            break;
        }
        hfa.free(free_ptr);
    }
    return 0;
}

static size_t align_up(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

class HfaInitUninitTest : public ::testing::Test {
protected:
    HbmFastAlloc hfa;
    std::vector<size_t> m_rand_numbers;

    HfaInitUninitTest() { }

    void SetUp() override {

        if (aclrtSetDevice(dev_id) != ACL_SUCCESS) {
            printf("Error. aclrtSetDevice() has failed\n");
            FAIL();
            return;
        }

    }

    void TearDown() override {

    }

    size_t GetFreeMem(const char *caller) {
        aclError err;
        size_t i_free_mem, i_total_mem;
        if ((err = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem, &i_total_mem)) != ACL_SUCCESS) {
            printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
            return 0;
        }
        printf("\n============== %s: free memory: %lu\n", caller, i_free_mem);
        return i_free_mem;
    }
};

/**
 * init-uninit test to ensure no memory leaks
 */
TEST_F(HfaInitUninitTest, TestJustInitUninit) {

    ph_mem_size = ph_mem_size_default;
    size_t free_mem_initial = GetFreeMem(__FUNCTION__);
    size_t free_mem = free_mem_initial;
    for (size_t k = 0; k < num_inits_uninits; ++k) {
        if (!hfa.init(dev_id, vr_mem_size, ph_mem_size, ph_page_size, DEF_INITIAL_FREE_PAGES)) {
            FAIL();
        }

        // just verify log level methods work
        int curr_log_level = hfa.get_log_level();
        hfa.set_log_level(0);
        hfa.set_log_level(curr_log_level);

        hfa_warmup(hfa);
        hfa.deinit();
        free_mem = GetFreeMem(__FUNCTION__);
        if (free_mem < free_mem_initial) {
            if (free_mem_initial - free_mem > leak_treshold) {
                fprintf(stderr, "Error: memory leak detected: started with %lu memory but after %lu iterations have %lu memory\n",
                    free_mem_initial, k, free_mem);
                FAIL();
            }
        }
    }
}

/**
 * init-defrag-uninit test to ensure no memory leaks
 */
TEST_F(HfaInitUninitTest, TestInitDefragUninit) {

    if (read_rands_from_file(g_rand_file_name, m_rand_numbers) != 0) {
        fprintf(stderr, "Error: failed to read rand numbers from file '%s'\n", g_rand_file_name);
        FAIL();
        return;
    }
    size_t sum_of_all_random_sizes = ph_margin;
    for (size_t num : m_rand_numbers) {
        sum_of_all_random_sizes += num;
    }
    ph_mem_size = align_up(sum_of_all_random_sizes, PH_PAGE_ALIGN_SIZE);

    size_t free_mem_initial = GetFreeMem(__FUNCTION__);
    size_t free_mem = free_mem_initial;
    for (size_t k = 0; k < num_inits_uninits; ++k) {
        if (!hfa.init(dev_id, vr_mem_size, ph_mem_size, ph_page_size, DEF_INITIAL_FREE_PAGES)) {
            FAIL();
        }
        hfa_warmup(hfa);

        if (m_rand_numbers.size() == 0) {
            fprintf(stderr, "Error: read zero rand numbers from file '%s'\n", g_rand_file_name);
            FAIL();
            return;
        }

        std::vector<void *> alloc_vec;
        size_t total_allocated_size = 0;
        size_t num_allocs = 0;

        for (size_t size : m_rand_numbers) {
            void *ptr = hfa.alloc(size);
            if (ptr == nullptr) {
                break;
            }
            alloc_vec.push_back(ptr);
            total_allocated_size += size;
            num_allocs++;
        }

        printf("Total allocation size: %lu bytes. usage percentage: %.2f%%. num_allocs:%lu avg_alloc_size:%lu\n",
            total_allocated_size, (double)total_allocated_size * 100.0 / (double)ph_mem_size, num_allocs,
            total_allocated_size / num_allocs);

        // free every 2nd alloc
        size_t num_removed = 0;
        size_t sum_removed = 0;
        size_t num_elems = alloc_vec.size();
        for (size_t i = 0; i < num_elems; i += 2) {
            sum_removed += m_rand_numbers[i];
            hfa.free(alloc_vec[i]);
            num_removed++;
        }

        // remove the freed elements from vector
        for (int i = alloc_vec.size() - 1; i >= 0; --i) {
            if (i % 2 == 0) {  // even index
                alloc_vec.erase(alloc_vec.begin() + i);
            }
        }

        bool success = true;
        void *ptr = hfa.alloc(sum_removed);
        if (ptr == nullptr) {
            success = false;
            if (hfa.get_last_defrag_elem_size() == 0) {
                fprintf(stderr, "Error: failed to alloc buf of size %lu and didn't get big contig range\n",
                    sum_removed);
            }
            ptr = hfa.alloc(hfa.get_last_defrag_elem_size());
            if (ptr == nullptr) {
                fprintf(stderr, "Error: failed to alloc buf of size %lu (which is the sum of %lu freed elements) "
                    "and also failed to alloc buf of size %lu of contig range after defrag\n",
                    sum_removed, num_removed, hfa.get_last_defrag_elem_size());
            } else {
                success = true;
            }
        }
        if (success) {
            printf("after %lu elements removed of total sum:%lu. succeed to alloc buf of size %lu. utilization %.2f%%.\n",
                num_removed, sum_removed, hfa.get_last_defrag_elem_size(),
                (double)(total_allocated_size - sum_removed + hfa.get_last_defrag_elem_size()) * 100.0 / (double)ph_mem_size);
        }

        if (ptr != nullptr) {
            hfa.free(ptr);
        }
        for (auto free_ptr : alloc_vec) {
            hfa.free(free_ptr);
        }
        hfa.free_all();

        hfa.deinit();
        free_mem = GetFreeMem(__FUNCTION__);
        if (free_mem < free_mem_initial) {
            if (free_mem_initial - free_mem > leak_treshold) {
                fprintf(stderr, "Error: memory leak detected: started with %lu memory but after %lu iterations have %lu memory\n",
                    free_mem_initial, k, free_mem);
                FAIL();
            }
        }
    }
}