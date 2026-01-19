/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Flexible allocator for HBM or DRAM
 * Author: David Yaron
 * Note:
 * History:
 */

#ifndef FLEX_ALLOC_H
#define FLEX_ALLOC_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace hfa {

static size_t const OBJ_SIZE_BITS = 6; ///< Number of bits for object size alignment
static size_t const MIN_OBJ_SIZE = (1UL << OBJ_SIZE_BITS); ///< Minimum object size

/**
 * Flexible allocator for HBM or DRAM
 * Not thread safe.
 */
class FlexAlloc {
public:
    using offset_t = std::size_t;
    using length_t = std::size_t;

    /**
     * @brief Return codes for allocation operations
     */
    enum FlexRetCode {
        FLEX_RC_SUCCESS,            ///< Operation successful
        FLEX_RC_ERROR,              ///< General error
        FLEX_RC_ERR_INVAL_ARG,      ///< Invalid argument
        FLEX_RC_ERR_NO_MEM,         ///< Out of memory
        FLEX_RC_ERR_FRAGMENTATION   ///< Memory fragmentation
    };

    struct FreeRange {
        FreeRange() {}
        FreeRange(size_t offset, size_t size) : m_offset(offset), m_size(size) {}
        bool operator<(const FreeRange& other) const {
            return m_offset < other.m_offset;
        }
        size_t m_offset; ///< Offset of the free range
        size_t m_size;   ///< Size of the free range
    };

private:
    struct Range {
        length_t size;   // length of this free range
    };

    // All free ranges, ordered by start offset.
    using StartMap = std::map<offset_t, Range>;

    // Index of free ranges, ordered by size.
    // Value is an iterator into StartMap (the main storage).
    using SizeMap = std::multimap<length_t, typename StartMap::iterator>;

    StartMap m_free_ranges_by_offset;
    SizeMap  m_free_ranges_by_size;
    size_t m_mem_size { 0 };
    size_t m_total_alloc_bytes { 0 }; ///< Total bytes of allocated memory
    size_t m_total_free_bytes { 0 }; ///< Total bytes of allocated memory
    size_t m_total_alloc_objs { 0 }; ///< Total number of allocated objects

    void eraseFromSizeIndex(typename StartMap::iterator it);

public:
    FlexAlloc() {}

    // avoid copy ctor and assignment operator since SizeMap value StartMap::iterator might point to old FlexAlloc
    // so dandling pointer might occur.
    // use move semantics instead, if needed
    FlexAlloc(const FlexAlloc&) = delete;
    FlexAlloc& operator=(const FlexAlloc&) = delete;

    FlexAlloc(FlexAlloc&&) = default;
    FlexAlloc& operator=(FlexAlloc&&) = default;

    // Initialize with one big free range [start, start+size)
    bool init(length_t size);

    void deinit();

    /**
     * @brief Find a free range with size >= 'size', split if needed.
     * @return true on success and fills outStart; false if no space.
     */
    FlexRetCode alloc(length_t req_size, size_t &outStart, size_t &alloc_size);

    /**
     * @brief Free [start, start+size) and coalesce with neighbors if possible.
     * @return true on success. false if no space.
     */
    bool free(offset_t start, length_t size);

    void get_all_free_ranges(std::vector<FreeRange> &fr_vec);

    void clear_all_free_ranges();

    bool add_free_ranges(std::vector<FreeRange> &frs);

    /**
     * @brief Get the total amount of free memory
     * @return Total free memory in bytes
     */
    size_t get_total_free_mem();

    /**
     * @brief Print the current state of the allocator without locking
     */
    void print_ranges();
};

} // namespace hfa

#endif