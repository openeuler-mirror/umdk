/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HFA test
 * Author: Nikita Merkulov
 * Note:
 * History:
 */

#include <unistd.h>
#include <iostream>
#include <cstring>
#include <sstream>
#include <set>
#include <vector>
#include <utility>
#include <chrono>

#include <acl/acl.h>
#include <gtest/gtest.h>

#include "acl_virtual_memory.h"

using namespace std::chrono;
using namespace hfa;

#define ACL_CHECK(ret) do { \
    if(ret != ACL_SUCCESS)\
    {\
        printf("acl interface return err %s:%d, retcode: %d %s\n", __FILE__, __LINE__, ret, aclGetRecentErrMsg());\
        FAIL();\
    }\
} while(0)

// general measures
const size_t GIGA = 1024*1024*1024;
const size_t MEGA = 1024*1024;
const size_t PAGE_ALIGN = 2 * MEGA;
const size_t MEGA_IN_GIGA = 1024;

#define INITIAL_FREE_PAGES 1024

class ReallocTest : public ::testing::Test {
protected:
    AclVirtualMemory vm;

    ReallocTest() : vm(INITIAL_FREE_PAGES) { }

    void SetUp() override {
        int32_t dev_id = 6;  //  NPU 7
        size_t vr_mem_size = 4 * GIGA;  // in bytes, must be physical page aligned (2M)
        size_t ph_mem_size = 2 * GIGA;  // in bytes, must be physical page aligned (2M)
        size_t ph_page_size = 1 * PAGE_ALIGN;  // PAGE_ALIGN=2MB
        printf("\nallocating memory - npu: %d, virtual: %zuG, physical: %zuG, page size: %zuMB",
               dev_id, vr_mem_size / GIGA, ph_mem_size / GIGA, ph_page_size / MEGA);
        auto result = vm.alloc(dev_id, vr_mem_size, ph_mem_size, ph_page_size);
        if (result.first != VmRet::SUCCESS) {
            printf("\nfailed to initialize AclVirtualMemory. error=%s", vm.error_info(result.first).c_str());
            FAIL();
        }
        printf("\nallocating memory completed successfully");
    }

    void TearDown() override {
        printf("\nstarting free memory ...");
        vm.free();
        printf("\nfree memory successful!\n");
    }
};

void test_read_write(void* addr, const char* tag)
{
    printf("\ntest_read_write(%s)", tag);

    // Example write and read
    const int BUF_SIZE = 100;
    char in_buffer [BUF_SIZE] = { 0 };
    for (int i = 0; i < BUF_SIZE - 1; ++i) {
        in_buffer[i] = 'A' + (i % 63); // 63 is the number of regular printable symbols after 'A'
    }
    char out_buffer [BUF_SIZE] = {0};
    size_t buf_size = strlen(in_buffer);
    // test write
    printf("\ntest write: in_buffer=%s, vr_addr=%p, size=%lu", in_buffer, addr, strlen(in_buffer));
    ACL_CHECK(aclrtMemcpy(addr, BUF_SIZE, (void*)in_buffer, strlen(in_buffer), ACL_MEMCPY_HOST_TO_DEVICE));
    // test read
    printf("\ntest read: in_buffer=%s, vr_addr=%p, size=%lu", in_buffer, addr, strlen(in_buffer));
    ACL_CHECK(aclrtMemcpy((void*)out_buffer, BUF_SIZE, addr, strlen(in_buffer), ACL_MEMCPY_DEVICE_TO_HOST));
    printf("\nsuccessfuly read(out_buffer): %s", out_buffer);
    ASSERT_EQ(strcmp(in_buffer, out_buffer), 0);
}

TEST_F(ReallocTest, TestReadWrite) {
    test_read_write(vm.get_base_addr(), "AFTER ALLOC on base_addr");
}

TEST_F(ReallocTest, TestSingleRealloc) {
    void* base_addr = vm.get_base_addr();
    AclFreeChunks free_chunks;

    printf("\ntesting 3 free chunks ...");
    // add 1 free chunk of 2MB (aligned on page 0)
    free_chunks.add_chunk(base_addr, 2 * MEGA);
    // add 1 free chunk of 1MB (occupies pages )
    free_chunks.add_chunk(static_cast<uint8_t *>(base_addr) + 15 * MEGA, 1 * MEGA);
    // add 1 free chunk of 6MB
    void *chunk_ptr_start = static_cast<uint8_t *>(base_addr) + 5 * MEGA;
    size_t chunk_size = 6 * MEGA;
    free_chunks.add_chunk(chunk_ptr_start, chunk_size);

    auto start = high_resolution_clock::now();
    // realloc the example free chunks
    VmRet ret = vm.defrag(&free_chunks);
    auto end = high_resolution_clock::now();
    auto duration_realloc = duration_cast<microseconds>(end - start);
    printf("\nrealloc result: %s, duration: %ld", vm.error_info(ret).c_str(), duration_realloc.count());
    ASSERT_EQ(ret, VmRet::SUCCESS);

    printf("\nfound %lu free chunks after realloc", free_chunks.size());
    ASSERT_EQ(free_chunks.size(), 4);
    for (size_t i = 0; i < free_chunks.size(); i++) {
        AclChunk* p_chunk = free_chunks.at(i);
        printf("\nchunk%lu: vr_addr=%p, size=%lu", i, p_chunk->m_ptr, p_chunk->m_size);
    }
    AclChunk* realloc_chunk = free_chunks.at(free_chunks.size() - 1);
    printf("\nrealloc_chunk: vr_addr=%p, size=%lu", realloc_chunk->m_ptr, realloc_chunk->m_size);
    ASSERT_EQ(realloc_chunk->m_size, 6 * MEGA);

    start = high_resolution_clock::now();
    // Example write and read - on a newly realloced chunk and on chunks we didn't touch
    test_read_write(realloc_chunk->m_ptr, "AFTER REALLOC on realloc_chunk");
    chunk_ptr_start = static_cast<uint8_t *>(base_addr) + 100 * MEGA;
    test_read_write(chunk_ptr_start, "AFTER REALLOC on base_addr+100MB");
    chunk_ptr_start = static_cast<uint8_t *>(base_addr) + GIGA + 1;
    test_read_write(chunk_ptr_start, "AFTER REALLOC on base_addr+GB+1");
    end = high_resolution_clock::now();
    auto duration_read_write = duration_cast<microseconds>(end - start);
    double average_duration_per_read_write = static_cast<double>(duration_read_write.count()) / 3;

    // output the time measurements
    printf("\nTime taken by AclVirtualMemory::realloc: %ld us", duration_realloc.count());
    printf("\nTime taken by 3 test_read_write: %ld us, average of the 3: %f us",
        duration_read_write.count(), average_duration_per_read_write);
}

TEST_F(ReallocTest, TestMultiRealloc) {
    void* base_addr = vm.get_base_addr();
    AclFreeChunks free_chunks;

    printf("\ntesting 3 free chunks ...");
    // add 1 free chunk of 2MB (aligned on page 0)
    free_chunks.add_chunk(base_addr, 2 * MEGA);
    // add 1 free chunk of 1MB (occupies pages )
    free_chunks.add_chunk(static_cast<uint8_t *>(base_addr) + 15 * MEGA, 1 * MEGA);
    // add 1 free chunk of 6MB
    void *chunk_ptr_start = static_cast<uint8_t *>(base_addr) + 5 * MEGA;
    size_t chunk_size = 6 * MEGA;
    free_chunks.add_chunk(chunk_ptr_start, chunk_size);

    auto start = high_resolution_clock::now();
    // realloc the example free chunks
    VmRet ret = vm.defrag(&free_chunks);
    auto end = high_resolution_clock::now();
    auto duration_realloc1 = duration_cast<microseconds>(end - start);
    printf("\nrealloc result: %s", vm.error_info(ret).c_str());
    ASSERT_EQ(ret, VmRet::SUCCESS);

    printf("\nfound %lu free chunks after realloc:", free_chunks.size());
    ASSERT_EQ(free_chunks.size(), 4);
    for (size_t i = 0; i < free_chunks.size(); i++) {
        AclChunk* p_chunk = free_chunks.at(i);
        printf("\nchunk%lu: vr_addr=%p, size=%lu", i, p_chunk->m_ptr, p_chunk->m_size);
    }
    AclChunk* realloc_chunk = free_chunks.at(free_chunks.size() - 1);
    printf("\nrealloc_chunk: vr_addr=%p, size=%lu", realloc_chunk->m_ptr, realloc_chunk->m_size);
    ASSERT_EQ(realloc_chunk->m_size, 6 * MEGA);

    start = high_resolution_clock::now();
    // Example write and read - on a newly realloced chunk
    test_read_write(realloc_chunk->m_ptr, "AFTER REALLOC on realloc_chunk");
    end = high_resolution_clock::now();
    auto duration_read_write1 = duration_cast<microseconds>(end - start);

    printf("\ntesting 4 more free chunks ...");
    free_chunks.clear();
    // add 1 free chunk of 1.5MB (0 full pages)
    free_chunks.add_chunk(static_cast<uint8_t *>(base_addr) + 100 * MEGA, 1.5 * MEGA);
    // add 1 free chunk of 3.5MB (1 page)
    free_chunks.add_chunk(static_cast<uint8_t *>(base_addr) + 110 * MEGA, 3.5 * MEGA);
    // add 1 free chunk of 11MB (4 pages)
    free_chunks.add_chunk(static_cast<uint8_t *>(base_addr) + (int)(120.1 * MEGA), 11 * MEGA);
    // add 1 free chunk as a part of the previously realloced chunk of 4MB (2 pages)
    free_chunks.add_chunk(static_cast<uint8_t *>(realloc_chunk->m_ptr) + 2 * MEGA, 4 * MEGA);

    start = high_resolution_clock::now();
    // realloc the example free chunks
    ret = vm.defrag(&free_chunks);
    end = high_resolution_clock::now();
    auto duration_realloc2 = duration_cast<microseconds>(end - start);
    printf("\nrealloc result: %s", vm.error_info(ret).c_str());
    ASSERT_EQ(ret, VmRet::SUCCESS);

    printf("\nfound %lu free chunks after realloc:", free_chunks.size());
    ASSERT_EQ(free_chunks.size(), 5);
    for (size_t i = 0; i < free_chunks.size(); i++) {
        AclChunk* p_chunk = free_chunks.at(i);
        printf("\nchunk%lu: vr_addr=%p, size=%lu", i, p_chunk->m_ptr, p_chunk->m_size);
    }
    realloc_chunk = free_chunks.at(free_chunks.size() - 1);
    printf("\nrealloc_chunk: vr_addr=%p, size=%lu", realloc_chunk->m_ptr, realloc_chunk->m_size);
    ASSERT_EQ(realloc_chunk->m_size, 14 * MEGA);


    start = high_resolution_clock::now();
    // Example write and read - on a newly realloced chunk
    test_read_write(realloc_chunk->m_ptr, "AFTER REALLOC on realloc_chunk");
    end = high_resolution_clock::now();
    auto duration_read_write2 = duration_cast<microseconds>(end - start);

    // output the time measurements
    printf("\nTime taken by the 1st AclVirtualMemory::realloc: %ld us", duration_realloc1.count());
    printf("\nTime taken by the 2nd AclVirtualMemory::realloc: %ld us", duration_realloc2.count());
    printf("\nTime taken by the 1st test_read_write: %ld us", duration_read_write1.count());
    printf("\nTime taken by the 2nd test_read_write: %ld us", duration_read_write2.count());
}

