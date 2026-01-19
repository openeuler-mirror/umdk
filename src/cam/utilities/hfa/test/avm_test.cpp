/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HFA test
 * Author: Adi Amir
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

#include "acl_virtual_memory.h"

using namespace hfa;

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
static size_t ph_mem_size = 10000UL * MEGA;  // in bytes, must be physical page aligned (2M)
static size_t ph_page_size = 1UL * PAGE_ALIGN;  // PAGE_ALIGN=2MB

#define NANO_TO_MICRO(x) ((double)(x) / 1000.0)
#define NANO_TO_MILLI(x) ((double)(x) / 1000000.0)
#define GET_TIME_NOW() std::chrono::steady_clock::now()
#define GET_TIME_DIFF_MILLI(start_time) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time).count()
#define GET_TIME_DIFF_MICRO(start_time) std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time).count()
#define GET_TIME_DIFF_NANO(start_time) std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start_time).count()

size_t print_mem()
{
    aclError ret;
    size_t free_mem, total_mem;
    aclrtContext context;

    if ((ret = aclrtSetDevice(dev_id)) != ACL_SUCCESS) {
        printf("Error. aclrtSetDevice() has failed");
        exit(-1);
    }
    if ((ret = aclrtGetMemInfo(ACL_HBM_MEM, &free_mem, &total_mem)) != ACL_SUCCESS) {
        printf("Error: aclrtGetMemInfo has failed: '%s'", aclGetRecentErrMsg());
        exit(-1);
    }

    printf("\ncurrent free memory: %lu", free_mem);
    return free_mem;
}

ssize_t AclVirtualMemory_basic_alloc_free(size_t alloc_mem_size)
{
    AclVirtualMemory avm;
    size_t mem_before, mem_after_alloc, mem_after_free;

    printf("\n ****** starting AclVirtualMemory_basic_alloc_free. dev_id=%d, alloc_size(mb)=%lu", dev_id, alloc_mem_size /  MEGA);
    mem_before = print_mem();

    // allocate memory
    printf("\nallocating %lu bytes ...", alloc_mem_size);
    auto result = avm.alloc(dev_id, vr_mem_size, alloc_mem_size, ph_page_size);
    if (result.first != VmRet::SUCCESS) {
        printf("\nfailed to initialize AclVirtualMemory. error=%s", avm.error_info(result.first).c_str());
        exit(-1);
    }
    printf("\nallocated successfully %lu bytes.", alloc_mem_size);
    mem_after_alloc = print_mem();

    // free memory
    printf("\ntrying to free all allocated memory ...");
    avm.free();
    mem_after_free = print_mem();
    ssize_t unreleased_mem = mem_before - mem_after_free;
    if (unreleased_mem > 0) {
        printf("\nunreleased memory=%ld", unreleased_mem);
    } else if (unreleased_mem == 0) {
        printf("\nunreleased memory=ZERO");
    } else {
        printf("\nunreleased memory=%ld", unreleased_mem);
    }
    printf("\n ****** end AclVirtualMemory_basic_alloc_free. dev_id=%d\n", dev_id);
    //usleep(1000000); // 100ms
    return unreleased_mem;
}

void test()
{
    aclError ret;
    size_t free_mem, total_mem;
    std::vector<size_t> alloc_vec = {2UL*MEGA, 10UL*MEGA, 1000UL*MEGA, 10000*MEGA, 12000UL*MEGA, 14000UL*MEGA, 28000UL*MEGA};
    std::vector<ssize_t> unrelesed_vec;

    setbuf(stdout, NULL); // printf immediately unbuffered

    aclInit(nullptr);

    for (size_t alloc_size: alloc_vec) {
        ssize_t unrelesed_mem = AclVirtualMemory_basic_alloc_free(alloc_size);
        unrelesed_vec.push_back(unrelesed_mem);
    }

    printf("\nSUMMARY:");
    size_t unreleased_count = 0;
    for (int i = 0; i < alloc_vec.size(); i++ ) {
        size_t alloc_size = alloc_vec.at(i);
        ssize_t unreleased_mem = unrelesed_vec.at(i);
        printf("\nTest:%d -  For alloc size(mb)=%lu - unreleased mem=%ld", i, alloc_size / MEGA, unreleased_mem);
        if (unreleased_mem > 0) {
            unreleased_count++;
        }
    }
    printf("\nnumber of unreleased tests: %lu", unreleased_count);
    printf("\nEND");

    aclFinalize();
}

void long_test()
{
    aclError ret;
    size_t free_mem, total_mem;
    std::vector<size_t> alloc_vec = {2UL*MEGA, 10UL*MEGA, 1000UL*MEGA, 10000*MEGA, 12000UL*MEGA, 14000UL*MEGA, 28000UL*MEGA};
    std::vector<ssize_t> unrelesed_vec;

    setbuf(stdout, NULL); // printf immediately unbuffered

    aclInit(nullptr);

    alloc_vec.clear();
    for (int i = 0; i < 1000; i++) {
        alloc_vec.push_back(30UL*MEGA);
    }
    int i;
    for (size_t alloc_size: alloc_vec) {
        printf("\nTest: %d", i);
        ssize_t unrelesed_mem = AclVirtualMemory_basic_alloc_free(alloc_size);
        unrelesed_vec.push_back(unrelesed_mem);
        i++;
    }

    printf("\nSUMMARY:");
    size_t unreleased_count = 0;
    for (int i = 0; i < alloc_vec.size(); i++ ) {
        size_t alloc_size = alloc_vec.at(i);
        ssize_t unreleased_mem = unrelesed_vec.at(i);
        if (unreleased_mem > 0) {
            unreleased_count++;
        }
    }
    printf("\nnumber of unreleased tests: %lu", unreleased_count);
    printf("\nEND");

    aclFinalize();
}

int main(int argc, char* argv[])
{
    //test();
    long_test();
    return 0;
}
