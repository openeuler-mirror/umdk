/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: HBM Fast Allocator
 * Author: David Yaron
 * Note:
 * A high-performance HBM memory allocator (HFA) for Ascend
 * Consistent ~99.7% HBM utilization across all object sizes
 * Ultra-low, stable allocation/free latency (~0.5 µs)
 * Enables large models, fewer OOM events, and smoother LLM execution
 * History:
 */

#ifndef HBM_FAST_ALLOC_H
#define HBM_FAST_ALLOC_H

#include <cstddef>
#include <unordered_map>
#include <utility>
#include <mutex>

namespace hfa {

class FlexAlloc;
class AclVirtualMemory;

using AllocMap = std::unordered_map<uint8_t *, std::pair<size_t, size_t>>;
using AllocMapIter = AllocMap::iterator;

/**
 * @brief Fast allocator for HBM (High Bandwidth Memory)
 */
class HbmFastAlloc {
public:
    /**
     * @brief Initialize the HBM fast allocator
     * @param  device_id    [IN] NPU id (0..7)
     * @param  vr_mem_size  [IN] Virtual memory size to be allocated in bytes (up to 128GB, card-dependant)
     * @param  ph_mem_size  [IN] Physical memory size to be allocated on HBM in bytes (up to 32GB, card-dependant)
     * @param  ph_page_size [IN] Physical page size to use while allocating pages on HBM in bytes
     *                           must be 2M aligned (2M, 4M, 6M, etc ..., card-dependant)
     * @param  initial_free_pages [IN] Initial number of pages for AclVirtualMemory
     * @return True if initialization is successful, false otherwise
     */
    bool init(int32_t device_id,
              size_t vr_mem_size,
              size_t ph_mem_size,
              size_t ph_page_size,
              size_t initial_free_pages);

    /**
    * @brief Deinitialize the HBM fast allocator
    */
    void deinit();

    /**
     * @brief Allocate memory from HBM
     * @param req_size Requested size of the allocation
     * @return Pointer to the allocated memory, or nullptr if allocation fails
     */
    void *alloc(size_t req_size);

    /**
     * @brief Free allocated memory
     * @param ptr Pointer to the memory to free
     * @return True if the memory was successfully freed, false otherwise
     */
    bool free(void *ptr);

    /**
     * @brief Free all allocated memory
     */
    void free_all();

    /**
     * @brief returns the last chunk size after defrag performed.
     * uses to verify that defrag action has succeeded to allocate
     * enough memory for the the next allocation request.
     */
    size_t get_last_defrag_elem_size() { return m_last_defrag_elem_size; }

    /**
     * @brief Set the global log level for HFA
     * @param lvl Log level to set. 0==DEBUG, 1==INFO, 2==WARNING, 3==ERROR
     */
    static void set_log_level(int lvl);

    /**
     * @brief Get the current global log level for HFA
     * @return Current log level.0==DEBUG, 1==INFO, 2==WARNING, 3==ERROR
     */
    static int get_log_level();

private:
    void get_defrag_ctrs(size_t &defrag_ctr, size_t &defrag_failed);

    /**
     * @brief Attempt to defragment the memory
     * @return True if defragmentation is successful, false otherwise
     */
    bool try_defrag();

    /**
     * @brief handle defragmentation
     * @return True if succeed to allocate after defragmentation
     */
    bool handle_defrag(size_t size, size_t &alloc_offset, size_t &alloc_size);

private:
    AclVirtualMemory        *mp_avm { nullptr };                // pointer to the AclVirtualMemory object
    FlexAlloc               *mp_fa { nullptr };                 // pointer to the FlexAlloc object
    std::mutex              m_alloc_map_lock;                   // mutex for thread safety
    AllocMap                m_alloc_map;                        // map of allocated memory
    size_t                  m_last_defrag_elem_size { 0 };      // holds the size of the last defrag size
    size_t                  m_defrag_ctr { 0 };                 // for statistics: number of successful defrag(s)
    size_t                  m_defrag_failed { 0 };              // for statistics: number of defrag(s) failures
};

} // namespace hfa

#endif  // HBM_FAST_ALLOC_H