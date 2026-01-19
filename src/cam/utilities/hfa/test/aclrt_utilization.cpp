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
#include <vector>
#include <acl/acl.h>

/**
 * The purpose of this test is to check if aclrtMalloc() has better utilization of HBM memory after
 * aclrtFree() creates holes in process virtual address space used for HBM.
 * We first use aclrtMalloc() to allocate 1MB buffers from HBM
 * then we free every 2nd buffer, so holes are created.
 * Then try to allocate buffers of size 2MB.
 */
int main() {
    // 1. Allocate 32000 1MB HBM buffers
    std::vector<void*> buffers1;
    const size_t buffer_size = 4 * 1024 * 1024;  // 1MB

    const int num_buffers_32000 = 32000;
    int num_buffers_allocated = 0;
    size_t i_free_mem;
    size_t i_total_mem;
    int value = 0;
    double percentage;

    aclError ret;
    int device_id = 7;
    if ((ret = aclInit(nullptr)) != ACL_SUCCESS) {
        std::cerr << "aclInit has failed:" << aclGetRecentErrMsg() << std::endl;
        return 1;
    }
    if ((ret = aclrtSetDevice(device_id)) != ACL_SUCCESS) {
        std::cerr << "aclrtSetDevice has failed:" << aclGetRecentErrMsg() << std::endl;
        return 1;
    }

    aclrtStream stream;
    aclrtCreateStream(&stream);

    if ((ret = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem, &i_total_mem)) != ACL_SUCCESS) {
        std::cerr << "aclrtGetMemInfo has failed:" << aclGetRecentErrMsg() << std::endl;
        return 1;
    }
    std::cout << " Before allocations. device id: " << device_id << ". total HBM memory " <<
        i_total_mem << " MB. total_free_mem: " << i_free_mem << std::endl;

    while (true) {
        void* buffer = nullptr;
        ret = aclrtMalloc(&buffer, buffer_size, ACL_MEM_MALLOC_HUGE_FIRST);
        if (ret != ACL_SUCCESS) {
            break;
        }
        if (buffer != nullptr) {
            ret = aclrtMemset(buffer, buffer_size, value, buffer_size);
            if (ret != ACL_SUCCESS) {
                std::cerr << "aclrtMemset has failed:" << aclGetRecentErrMsg() << std::endl;
                return 1;
            }
        }
        buffers1.push_back(buffer);
    }

    size_t total_allocated = buffers1.size() * buffer_size;
    percentage = 100.0 * (double)total_allocated / ((double)i_free_mem);
    std::cout << "when allocating buffers of size " << buffer_size << " bytes, aclrtMalloc() can use only " <<
        percentage << "% of total freed memory. total_allocated: " << total_allocated << " free_mem: " <<
        i_free_mem << std::endl;

    if ((ret = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem, &i_total_mem)) != ACL_SUCCESS) {
        std::cerr << "aclrtGetMemInfo has failed:" << aclGetRecentErrMsg() << std::endl;
        return 1;
    }
    std::cout << " Succeed to allocate " << buffers1.size() << " buffers each of size " << buffer_size <<
        " bytes. total allocated " << total_allocated << ". total_free_mem: " << i_free_mem << std::endl;

    // 2. Release each buffer with an odd index
    aclrtSynchronizeStream(stream);
    size_t num_freed_buffers = 0;
    for (int i = 0; i < buffers1.size(); ++i) {
        if (i % 2 == 1) {
            if ((ret = aclrtFree(buffers1[i]) != ACL_SUCCESS)) {
                std::cerr << "aclrtFree() has failed for HBM address " << buffers1[i] << " Error: " <<
                    aclGetRecentErrMsg() << std::endl;
                return 1;
            }
            buffers1[i] = nullptr;
            num_freed_buffers++;
        }
    }
    aclrtSynchronizeStream(stream);

    sleep(2);
    if ((ret = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem, &i_total_mem)) != ACL_SUCCESS) {
        std::cerr << "aclrtGetMemInfo has failed:" << aclGetRecentErrMsg() << std::endl;
        return 1;
    }
    std::cout << " Succeed to free " << num_freed_buffers << " buffers. total_free_mem: " << i_free_mem << std::endl;

    // 3. Allocate more 2MB HBM buffers
    std::vector<void*> buffers2;
    const size_t buffer_size_2MB = 2 * 1024 * 1024;  // 2MB
    while (true) {
        void* buffer = nullptr;
        aclError error = aclrtMalloc(&buffer, buffer_size_2MB, ACL_MEM_MALLOC_HUGE_FIRST);
        if (error != ACL_SUCCESS) {
            break;
        }
        if (buffer != nullptr) {  // Only process non-released buffers
            aclrtMemset(buffer, buffer_size_2MB, value, buffer_size_2MB);
        }
        buffers2.push_back(buffer);
    }

    std::cerr << "After free, succeeded to allocate " << buffers2.size() << " buffers, each of size " <<
        buffer_size_2MB << ". total_free_mem: " << i_free_mem << std::endl;
    if ((ret = aclrtGetMemInfo(ACL_HBM_MEM, &i_free_mem, &i_total_mem)) != ACL_SUCCESS) {
        std::cerr << "aclrtGetMemInfo has failed:" << aclGetRecentErrMsg() << std::endl;
        return 1;
    }
    std::cout << "total_free_mem: " << i_free_mem << std::endl;

    percentage = 100.0 * ((double)buffer_size_2MB * buffers2.size()) / ((double)num_freed_buffers * buffer_size);
    std::cout << "after aclrtFree(), aclrtMalloc can reuse only " << percentage << "% of freed memory" << std::endl;

    // Free all allocated buffers
    for (void* buffer : buffers1) {
        if (buffer != nullptr) {
            aclrtFree(buffer);
        }
    }
    for (void* buffer : buffers2) {
        if (buffer != nullptr) {
            aclrtFree(buffer);
        }
    }
    return 0;
}