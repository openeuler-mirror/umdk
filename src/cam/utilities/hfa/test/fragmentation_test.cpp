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
#include <gtest/gtest.h>

#include "flex_alloc.h"
#include "acl_virtual_memory.h"

using namespace hfa;

#define ACL_CHECK(ret) do { \
    if(ret != ACL_SUCCESS)\
    {\
        printf("acl interface return err %s:%d, retcode: %d %s\n\n", __FILE__, __LINE__, ret, aclGetRecentErrMsg());\
        FAIL();\
    }\
} while(0)

// general measures
static const size_t GIGA = 1024UL * 1024UL * 1024UL;
static const size_t MEGA = 1024UL * 1024UL;
static const size_t PAGE_ALIGN = 2UL * MEGA;
static const size_t MEGA_IN_GIGA = 1024UL;

#define INITIAL_FREE_PAGES 1024
static constexpr const char* RANDOM_FILE = "/dev/urandom";

static int32_t dev_id = 6;  //  NPU 7
static size_t vr_mem_size = 128UL * GIGA;  // in bytes, must be physical page aligned (2M)

// todo: revert
// static size_t ph_mem_size = 28000UL * MEGA;  // in bytes, must be physical page aligned (2M)
static size_t ph_mem_size = 2048UL * MEGA;  // in bytes, must be physical page aligned (2M)

static size_t ph_page_size = 1UL * PAGE_ALIGN;  // PAGE_ALIGN=2MB

class DefragTest : public ::testing::Test {
protected:
    AclVirtualMemory vm;
    FlexAlloc flex;
    uint8_t* p_va;

    DefragTest() : vm(INITIAL_FREE_PAGES) { }

    void SetUp() override {
        printf("allocating memory - npu: %d, virtual: %zuG, physical: %zuG, page size: %zuMB\n",
            dev_id, vr_mem_size/GIGA, ph_mem_size/GIGA, ph_page_size/MEGA);
        auto result = vm.alloc(dev_id, vr_mem_size, ph_mem_size, ph_page_size);
        if (result.first != VmRet::SUCCESS) {
            printf("Error. failed to initialize AclVirtualMemory. error=%s\n", vm.error_info(result.first).c_str());
            FAIL();
        }
        p_va = (uint8_t *)result.second;
        printf("\nAclVirtualMemory memory allocation has completed successfully\n");

        if (!flex.init(ph_mem_size)) {
            printf("Error. failed to initialize flex allocator. region size:%lu\n", ph_mem_size);
            FAIL();
        }
        printf("FlexAlloc init has completed successfully. region size:%lu\n", ph_mem_size);
    }

    void TearDown() override {
        printf("\nstarting free memory ...");
        vm.free();
        printf("\nfree memory successful!\n");
    }
};

static int fill_buf_with_rands(void *p_buf, size_t size)
{
    int rc = 0;
    int fd = 0;
    do {
        fd = open(RANDOM_FILE, O_RDONLY);
        if (fd < 0) {
            printf("Error: fail to open %s file. error:'%s'\n", RANDOM_FILE, strerror(errno));
            rc = 1;
            break;
        }
        if (read(fd, p_buf, size) < 0) {
            printf("Error: fail to read from %s file to buffer. error:'%s'\n", RANDOM_FILE, strerror(errno));
            rc = 1;
            break;
        }
    } while (false);

    if (fd >= 0) {
        if (close(fd) < 0) {
            printf("Error: fail to close %s file. error:'%s'\n", RANDOM_FILE, strerror(errno));
        }
    }
    return rc;
}

TEST_F(DefragTest, TestSimpleDefrag) {
    size_t alloc_offset;
    size_t alloc_size;
    void *p_w_buf = nullptr;
    void *p_r_buf = nullptr;
    int rc = 0;
    aclError err;

    do {
        if ((err = aclrtSetDevice(dev_id)) != ACL_SUCCESS) {
            printf("Error. aclrtSetDevice() has failed\n");
            rc = -1;
            break;
        }

        p_w_buf = malloc(ph_mem_size);
        if (p_w_buf == nullptr) {
            printf("Error. failed to allocate DRAM buf of size %lu\n", ph_mem_size);
            rc = -1;
            break;
        }
        p_r_buf = malloc(ph_mem_size);
        if (p_r_buf == nullptr) {
            printf("Error. failed to allocate DRAM buf of size %lu\n", ph_mem_size);
            rc = -1;
            break;
        }
        if (fill_buf_with_rands(p_w_buf, ph_mem_size) != 0) {
            printf("Error. failed to buffer of size %lu with rand content\n", ph_mem_size);
            rc = -1;
            break;
        }

        // verify all region is valid for read and write
        ACL_CHECK(aclrtMemcpy(p_va, ph_mem_size, p_w_buf, ph_mem_size, ACL_MEMCPY_HOST_TO_DEVICE));
        ACL_CHECK(aclrtMemcpy(p_r_buf, ph_mem_size, p_va, ph_mem_size, ACL_MEMCPY_DEVICE_TO_HOST));
        if (memcmp(p_w_buf, p_r_buf, ph_mem_size) != 0) {
            printf("Error. content mismatch after write and read ro HBM memory of size %lu\n", ph_mem_size);
            rc = -1;
            break;
        }
        std::vector<FlexAlloc::FreeRange> alloc_objs;
        size_t num_allocs = ph_mem_size / ph_page_size;
        for (size_t i = 0; i < num_allocs; ++i) {
            if (flex.alloc(ph_page_size, alloc_offset, alloc_size) != FlexAlloc::FlexRetCode::FLEX_RC_SUCCESS) {
                printf("Error. failed to allocate object of size:%lu. id %lu out of %lu\n",
                    ph_page_size, i, num_allocs);
                rc = -1;
                break;
            }
            alloc_objs.push_back(FlexAlloc::FreeRange(alloc_offset, alloc_size));
        }
        if (rc != 0) {
            break;
        }
        printf("Flex: succeeded to allocate %lu objects of size:%lu each\n", num_allocs, ph_page_size);

        if (flex.alloc(2 * ph_page_size, alloc_offset, alloc_size) == FlexAlloc::FlexRetCode::FLEX_RC_SUCCESS) {
            printf("Error. succeed to allocate object of size:%lu but shouldn't\n", 2UL * ph_page_size);
            rc = -1;
            break;
        }

        // free first object
        FlexAlloc::FreeRange fr = alloc_objs[0];
        if (!flex.free(fr.m_offset, fr.m_size)) {
            printf("Error. failed to free first allocated obj. offset:%lu size:%lu\n", fr.m_offset, fr.m_size);
            rc = -1;
            break;
        }
        alloc_objs.erase(alloc_objs.begin());

        // free last object
        FlexAlloc::FreeRange frl = alloc_objs[alloc_objs.size() - 1];
        if (!flex.free(frl.m_offset, frl.m_size)) {
            printf("Error. failed to free first allocated obj. offset:%lu size:%lu\n", frl.m_offset, frl.m_size);
            rc = -1;
            break;
        }
        alloc_objs.pop_back();

        if (flex.alloc(2 * ph_page_size, alloc_offset, alloc_size) == FlexAlloc::FlexRetCode::FLEX_RC_SUCCESS) {
            printf("Error. succeed to allocate object of size:%lu but shouldn't\n", 2 * ph_page_size);
            rc = -1;
            break;
        }

        // ************************* start defrag ********************************
        std::vector<FlexAlloc::FreeRange> frs;
        flex.get_all_free_ranges(frs);
        if (frs.size() != 2UL) {
            printf("Error. number of free ranges before defrag is %lu. expecting %u\n", frs.size(), 2);
            rc = -1;
            break;
        }
        flex.clear_all_free_ranges();

        AclFreeChunks acl_free_chunks;
        for (auto &fr : frs) {
            acl_free_chunks.add_chunk(p_va + fr.m_offset, fr.m_size);
        }

        printf("================== Before vm realloc. number of chunks before realloc %lu\n", acl_free_chunks.size());
        ASSERT_EQ(acl_free_chunks.size(), 2);
        VmRet ret = vm.defrag(&acl_free_chunks);
        if (ret != VmRet::SUCCESS) {
            printf("Error. realloc failed\n");
            rc = -1;
            break;
        }
        printf("\n============== Done vm realloc. number of chunks after realloc %lu\n", acl_free_chunks.size());
        ASSERT_EQ(acl_free_chunks.size(), 1);

        if (acl_free_chunks.size() != 1UL) {
            printf("Error. number of chunks after merge is %lu expecting %lu\n", acl_free_chunks.size(), 1UL);
            rc = -1;
            break;
        }

        // add new free ranges after realloc
        frs.clear();
        for (size_t idx = 0; idx < acl_free_chunks.size(); ++idx) {
            AclChunk *p_chunk = acl_free_chunks.at(idx);
            if (p_chunk == nullptr) {
                printf("Error. failed to get chunk at index %lu after realloc\n", idx);
                rc = -1;
                break;
            }
            if (p_chunk->m_ptr <= p_va) {
                printf("Error. after realloc. invalid chunk addr:%p <= base region address %p\n", p_chunk->m_ptr, p_va);
                rc = -1;
                break;
            }
            size_t offset = (uint8_t *)p_chunk->m_ptr - p_va;
            frs.push_back(FlexAlloc::FreeRange(offset, p_chunk->m_size));
            printf("============= after realloc: add free range to flex. offset:%lu size:%lu\n",
                offset, p_chunk->m_size);
        }
        flex.add_free_ranges(frs);

        // ************************* done defrag ********************************

        printf("flex free ranges after defrag\n");
        flex.print_ranges();

        // try to alloc after defrag
        size_t alloc_size_after_defrag = 2 * ph_page_size;
        if (flex.alloc(alloc_size_after_defrag, alloc_offset, alloc_size) !=
            FlexAlloc::FlexRetCode::FLEX_RC_SUCCESS) {
            printf("Error. failed to allocate object of size:%lu after defrag\n", alloc_size_after_defrag);
            rc = -1;
            break;
        }
        printf("succeeded to allocate object of size:%lu after defrag. offset %lu size:%lu\n",
            alloc_size_after_defrag, alloc_offset, alloc_size);

        if (alloc_offset != frs[0].m_offset) {
            printf("Error. offset of allocated object after defrag %lu differ from new chunk offset %lu\n",
                alloc_offset, frs[0].m_offset);
            rc = -1;
            break;
        }

        // verify new object read write is correct after defrag
        ACL_CHECK(aclrtMemcpy(p_va + alloc_offset, alloc_size_after_defrag, p_r_buf, alloc_size_after_defrag,
            ACL_MEMCPY_HOST_TO_DEVICE));
        ACL_CHECK(aclrtMemcpy(p_w_buf, alloc_size_after_defrag, p_va + alloc_offset, alloc_size_after_defrag,
            ACL_MEMCPY_DEVICE_TO_HOST));
        if (memcmp(p_w_buf, p_r_buf, alloc_size_after_defrag) != 0) {
            printf("Error. content mismatch after write and read ro HBM memory of size %lu\n", alloc_size_after_defrag);
            rc = -1;
            break;
        }
        printf("succeeded to write and read to object of size:%lu after defrag\n", alloc_size_after_defrag);
    } while (false);

    if (p_w_buf != nullptr) {
        free(p_w_buf);
    }
    if (p_r_buf != nullptr) {
        free(p_r_buf);
    }
    ASSERT_EQ(rc, 0);
}





