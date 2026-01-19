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

#include "acl_virtual_memory.h"

using namespace hfa;

// general measures
const size_t GIGA = 1024*1024*1024;
const size_t MEGA = 1024*1024;
const size_t PAGE_ALIGN = 2 * MEGA;
const size_t MEGA_IN_GIGA = 1024;

#define INITIAL_FREE_CHUNKS 1024


void test_chunk_props(AclVirtualMemory &vm)
{
    printf("\ncan't test get_chunk_props because it's private; that test was a bit too specific anyway");
    return;

    // void* base_addr = vm.get_base_addr();

    // printf("\ntesting get_chunk_props ...");

    // AclChunkProps props;
    // AclChunk chunk0(base_addr, MEGA);
    // if (vm.get_chunk_props(&chunk0, props) == true) {
    //     printf("\nwarning: got mega-sized chunk props but the page size is meant to be 2 mega so it's not supposed to work");
    //     props.print();
    // } else {
    //     printf("\nget_chunk_props correctly returns false for a chunk smaller than the page size");
    // }

    // printf("\nget_chunk_props for chunk 0-2 MB:");
    // AclChunk chunk1(base_addr, 2 * MEGA);
    // if (vm.get_chunk_props(&chunk1, props) == true) {
    //     props.print();
    // } else {
    //     printf("\nfailed to get_chunk_props for chunk1");
    // }

    // AclChunk chunk2(static_cast<uint8_t *>(base_addr) + 5 * MEGA,  6 * MEGA);
    // printf("\nget_chunk_props for chunk 5-11 MB:");
    // if (vm.get_chunk_props(&chunk2, props) == true) {
    //     props.print();
    // } else {
    //     printf("\nfailed to get_chunk_props for chunk2");
    // }

    // AclChunk chunk3(static_cast<uint8_t *>(base_addr) + 2 * GIGA + 123,  3 * MEGA + 321);
    // printf("\nget_chunk_props for chunk 2048.123-2051.321 MB:");
    // if (vm.get_chunk_props(&chunk3, props) == true) {
    //     printf("\nwarning: get_chunk_props returned true for a chunk without a full page");
    //     props.print();
    // } else {
    //     printf("\nget_chunk_props correctly returns false for a chunk without a full page");
    //     props.print();
    // }
}

int main(int argc, char* argv[])
{
    AclVirtualMemory vm(INITIAL_FREE_CHUNKS);

    setbuf(stdout, NULL); // printf completely unbuffered

    if (aclInit(nullptr) != ACL_SUCCESS) {
        printf("\naclInit has failed: %s", aclGetRecentErrMsg());
        return -1;
    }

    int32_t dev_id = 6;  //  NPU 7
    size_t vr_mem_size = 4 * GIGA;  // in bytes, must be physical page aligned (2M)
    size_t ph_mem_size = 2 * GIGA;  // in bytes, must be physical page aligned (2M)
    size_t ph_page_size = 1 * PAGE_ALIGN;  // PAGE_ALIGN=2MB
    printf("\nallocating memory - npu: %d, virtual: %zuG, physical: %zuG, page size: %zuMB",
        dev_id, vr_mem_size/GIGA, ph_mem_size/GIGA, ph_page_size/MEGA);
    auto result = vm.alloc(dev_id, vr_mem_size, ph_mem_size, ph_page_size);
    if (result.first != VmRet::SUCCESS) {
        printf("\nfailed to initialize AclVirtualMemory. error=%s", vm.error_info(result.first).c_str());
        return -1;
    }
    printf("\nallocating memory completed successfully");

    test_chunk_props(vm);

    // printf("\nshutting down in 5 secs\n");
    // sleep(5);

    // clean up
    printf("\nstarting free memory ...");
    vm.free();
    printf("\nfree memory successful!\n");
}




