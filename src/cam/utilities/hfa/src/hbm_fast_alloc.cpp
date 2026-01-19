/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HBM fast allocator
 * Author: David Yaron
 * Note:
 * History:
 */

#include <acl/acl.h>
#include <cstdio>
#include <vector>
#include <utility>

#include "hfa_log.h"
#include "hbm_fast_alloc.h"
#include "acl_virtual_memory.h"
#include "flex_alloc.h"


using namespace hfa;

// general measures
static const size_t GIGA = 1024UL * 1024UL * 1024UL;
static const size_t MEGA = 1024UL * 1024UL;
static const size_t KILO = 1024UL;

/**
 * @brief Initialize the HBM fast allocator
 * @param p_avm Pointer to the AclVirtualMemory object
 * @param p_fa Pointer to the FlexAlloc object
 * @return True if initialization is successful, false otherwise
 */
bool HbmFastAlloc::init(int32_t device_id,
                        size_t vr_mem_size,
                        size_t ph_mem_size,
                        size_t ph_page_size,
                        size_t initial_free_pages)
{
    mp_avm = new (std::nothrow) AclVirtualMemory(initial_free_pages);
    mp_fa = new (std::nothrow) FlexAlloc;
    if (mp_avm == nullptr) {
        ERROR_PRINT("failed to init HbmFastAlloc. ph_mem_size=%lu\n", ph_mem_size);
        return false;
    }
    if (mp_fa == nullptr) {
        ERROR_PRINT("failed to init HbmFastAlloc. ph_mem_size=%lu\n", ph_mem_size);
        return false;
    }
    INFO_PRINT("allocating memory - npu: %d, virtual: %zuG, physical: %zuG, page size: %zuMB\n",
        device_id, vr_mem_size/GIGA, ph_mem_size/GIGA, ph_page_size/MEGA);
    auto result = mp_avm->alloc(device_id, vr_mem_size, ph_mem_size, ph_page_size);
    if (result.first != VmRet::SUCCESS) {
        ERROR_PRINT("failed to initialize AclVirtualMemory. error=%s\n", mp_avm->error_info(result.first).c_str());
        return false;
    }
    INFO_PRINT("AclVirtualMemory memory allocation has completed successfully\n");

    if (!mp_fa->init(ph_mem_size)) {
        ERROR_PRINT("failed to initialize flex allocator. region size:%lu\n", ph_mem_size);
        return false;
    }
    INFO_PRINT("FlexAlloc init has completed successfully. region size:%lu\n", ph_mem_size);

    return true;
}

/**
 * @brief Deinitialize the HBM fast allocator
 */
void HbmFastAlloc::deinit()
{
    if (mp_fa != nullptr) {
        mp_fa->deinit();
        delete mp_fa;
        mp_fa = nullptr;
    }
    if (mp_avm != nullptr) {
        mp_avm->free();
        delete mp_avm;
        mp_avm = nullptr;
    }
    m_alloc_map.clear();
    m_last_defrag_elem_size = 0;
    m_defrag_ctr = 0;
    m_defrag_failed = 0;
}

/**
 * @brief Attempt to defragment the memory
 * @return True if defragmentation is successful, false otherwise
 */
bool HbmFastAlloc::try_defrag()
{
    std::vector<FlexAlloc::FreeRange> frs;
    mp_fa->get_all_free_ranges(frs);
    if (frs.size() == 0) {
        DEBUG_PRINT("avoiding defrag. has 0 free ranges\n");
        return false;
    }
    mp_fa->clear_all_free_ranges();

    AclFreeChunks acl_free_chunks;
    for (auto &fr : frs) {
        acl_free_chunks.add_chunk(static_cast<void*>(static_cast<uint8_t*>(
            mp_avm->get_base_addr()) + fr.m_offset), fr.m_size);
    }

    DEBUG_PRINT("AVM is about to defrag with %lu free chunks\n", acl_free_chunks.size());
    VmRet ret = mp_avm->defrag(&acl_free_chunks);
    if (ret != VmRet::SUCCESS) {
        ERROR_PRINT("defrag failed\n");
        return false;
    }
    if (acl_free_chunks.size() == 0) {
        ERROR_PRINT("defrag claims it succeeded but size of returned free-chunks-list is zero\n");
        return false;
    }

    m_last_defrag_elem_size = acl_free_chunks.at(acl_free_chunks.size() - 1)->m_size;

    // after defrag: add new free ranges to flex
    frs.clear();
    for (size_t i = 0; i < acl_free_chunks.size(); ++i) {
        FlexAlloc::FreeRange fr;
        AclChunk *p_chunk = acl_free_chunks.at(i);
        if (p_chunk == nullptr) {
            ERROR_PRINT("after defrag fail to get chunk at index %lu out of %lu\n",
                i, acl_free_chunks.size());
            return false;
        }
        fr.m_offset = (size_t)p_chunk->m_ptr - (size_t)mp_avm->get_base_addr();
        fr.m_size = p_chunk->m_size;
        frs.push_back(fr);
    }
    if (!mp_fa->add_free_ranges(frs)) {
        ERROR_PRINT("failed to add %lu free ranges to flex after defrag\n", frs.size());
        return false;
    }
    return true;
}

bool HbmFastAlloc::handle_defrag(size_t size, size_t &alloc_offset, size_t &alloc_size)
{
    // try to defrag physical pages
    m_defrag_ctr++;
    DEBUG_PRINT("failed to alloc size %lu due to fragmentation. will try to defrag\n", size);
    if (!try_defrag()) {
        ERROR_PRINT("defrag has failed\n");
        m_defrag_failed++;
        return false;
    }
    DEBUG_PRINT("defrag succeeded. will try again to alloc size %lu\n", size);

    // try again to alloc from Flex
    FlexAlloc::FlexRetCode ret =
        mp_fa->alloc(size, alloc_offset, alloc_size);
    if (ret != FlexAlloc::FLEX_RC_SUCCESS) {
        ERROR_PRINT("failed to alloc size %lu after defrag\n", size);
        return false;
    }
    DEBUG_PRINT("succeed to alloc size %lu after defrag\n", size);
    return true;
}

/**
 * @brief Allocate memory from HBM
 * @param size Requested size of the allocation
 * @return Pointer to the allocated memory, or nullptr if allocation fails
 */
void *HbmFastAlloc::alloc(size_t size)
{
    size_t alloc_offset;
    size_t alloc_size;
    std::lock_guard<std::mutex> lock(m_alloc_map_lock);
    FlexAlloc::FlexRetCode ret = mp_fa->alloc(size, alloc_offset, alloc_size);
    if (ret != FlexAlloc::FLEX_RC_SUCCESS) {
        if (ret != FlexAlloc::FLEX_RC_ERR_FRAGMENTATION) {
            return nullptr;
        }
        if (!handle_defrag(size, alloc_offset, alloc_size)) {
            return nullptr;
        }
    }
    uint8_t *p_obj_addr = static_cast<uint8_t*>(mp_avm->get_base_addr()) + alloc_offset;
    m_alloc_map.insert({p_obj_addr, std::make_pair(alloc_offset, alloc_size)});
    return p_obj_addr;
}

/**
 * @brief Free allocated memory
 * @param ptr Pointer to the memory to free
 * @return True if the memory was successfully freed, false otherwise
 */
bool HbmFastAlloc::free(void *ptr)
{
    if (ptr == nullptr) {
        ERROR_PRINT("invalid hbm address to free\n");
        return false;
    }

    std::lock_guard<std::mutex> lock(m_alloc_map_lock);
    AllocMapIter iter = m_alloc_map.find(static_cast<uint8_t*>(ptr));
    if (iter == m_alloc_map.end()) {
        ERROR_PRINT("fail to find info for HBM address %p to free\n", ptr);
        return false;
    }
    if (!mp_fa->free(iter->second.first, iter->second.second)) {
        ERROR_PRINT("Flex failed to free HBM address %p (offset:%lu size:%lu)\n",
            ptr, iter->second.first, iter->second.second);
        return false;
    }
    m_alloc_map.erase(iter);
    return true;
}

/**
 * @brief Free all allocated memory
 */
void HbmFastAlloc::free_all()
{
    std::lock_guard<std::mutex> lock(m_alloc_map_lock);
    for (auto &it : m_alloc_map) {
        size_t &offset = it.second.first;
        size_t &size = it.second.second;
        if (!mp_fa->free(offset, size)) {
            ERROR_PRINT("Flex failed to free HBM address %p (offset:%lu size:%lu)\n", it.first, offset, size);
        }
    }
    m_alloc_map.clear();
}

void HbmFastAlloc::get_defrag_ctrs(size_t &defrag_ctr, size_t &defrag_failed)
{
    defrag_ctr = m_defrag_ctr;
    defrag_failed = m_defrag_failed;
}

void HbmFastAlloc::set_log_level(int lvl)
{
    if (lvl < static_cast<int>(HFA_LOG_DEBUG) || lvl > static_cast<int>(HFA_LOG_ERROR)) {
        ERROR_PRINT("invalid log level %d. should be 0==DEBUG, 1==INFO, 2==WARNING, 3==ERROR\n", lvl);
        return;
    }
    hfa_set_log_level(static_cast<HfaLogLevel>(lvl));
}

int HbmFastAlloc::get_log_level()
{
    return static_cast<int>(hfa_get_log_level());
}
