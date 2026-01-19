/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: flexible allocator for HBM or DRAM
 * Author: David Yaron
 * Note:
 * History:
 */

#include <cstdio>
#include <algorithm>
#include <utility>
#include "hfa_log.h"
#include "flex_alloc.h"

using namespace hfa;

/**
 * @brief Round up a number to the nearest multiple of 2^n
 * @param num Number to round up
 * @param nbits Number of bits for the alignment
 * @return Rounded up number
 */
template <typename T>
T round_up_bits(T num, uint32_t nbits) {
    T shift = ((static_cast<T>(1)) << nbits) - 1;
    return (num + shift) & ~(shift);
}

// Initialize with one big free range
bool FlexAlloc::init(length_t size)
{
    if (size < MIN_OBJ_SIZE) {
        ERROR_PRINT("init failed size %lu too small\n", size);
        return false;
    }
    auto it = m_free_ranges_by_offset.emplace(0UL, Range{size}).first;
    m_free_ranges_by_size.emplace(size, it);
    m_mem_size = size;
    m_total_free_bytes = size;
    return true;
}

void FlexAlloc::deinit()
{
    m_free_ranges_by_offset.clear();
    m_free_ranges_by_size.clear();
    m_mem_size = 0;
    m_total_alloc_bytes = 0;
    m_total_alloc_objs = 0;
}

// Find a free range with size >= 'size', split if needed.
// Returns true on success and fills out args; false if no space or having fragmentation
FlexAlloc::FlexRetCode FlexAlloc::alloc(length_t req_size, size_t &offset, size_t &alloc_size)
{
    if (req_size == 0) {
        return FLEX_RC_ERR_INVAL_ARG;
    }
    alloc_size = round_up_bits(req_size, OBJ_SIZE_BITS);

    // first range with size >= requested
    auto sizeIt = m_free_ranges_by_size.lower_bound(alloc_size);
    if (sizeIt == m_free_ranges_by_size.end()) {
        if (get_total_free_mem() >= alloc_size) {
            ERROR_PRINT("flex_region:%p. fail to alloc obj due to fragmentation. req_size:%lu alloc_size:%lu "
                "total_free_mem:%lu m_mem_size:%lu m_total_alloc_bytes:%lu total_alloc_objs:%lu\n",
                this, req_size, alloc_size, get_total_free_mem(), m_mem_size, m_total_alloc_bytes, m_total_alloc_objs);
            return FLEX_RC_ERR_FRAGMENTATION;
        } else {
            ERROR_PRINT("flex_region:%p. fail to alloc obj due to lack of memory. of req_size:%lu "
                "alloc_size:%lu total_free_mem:%lu m_mem_size:%lu m_total_alloc_bytes:%lu total_alloc_objs:%lu\n",
                this, req_size, alloc_size, get_total_free_mem(), m_mem_size, m_total_alloc_bytes, m_total_alloc_objs);
            return FLEX_RC_ERR_NO_MEM;
        }
    }

    auto rangeIt = sizeIt->second;      // iterator in m_all_free_ranges_set
    offset = rangeIt->first;
    length_t blkSz = rangeIt->second.size;

    // Remove this free range from both indices
    m_free_ranges_by_size.erase(sizeIt);
    m_free_ranges_by_offset.erase(rangeIt);

    // If there's leftover, insert the remainder back as a free range
    if (blkSz > alloc_size) {
        offset_t newStart = offset + alloc_size;
        length_t newSize  = blkSz - alloc_size;

        auto newIt = m_free_ranges_by_offset.emplace(newStart, Range{newSize}).first;
        m_free_ranges_by_size.emplace(newSize, newIt);
    }

    // update counters
    m_total_alloc_bytes += alloc_size;
    m_total_free_bytes -= std::min(alloc_size, m_total_free_bytes);
    m_total_alloc_objs++;
    return FLEX_RC_SUCCESS;
}

// Free [offset, offset+size) and coalesce with neighbors if possible.
bool FlexAlloc::free(offset_t offset, length_t size)
{
    if (size == 0) {
        ERROR_PRINT("flex_region:%p. failed to free range {offset:%lu, size:%lu}\n", this, offset, size);
        return false;
    }

    // Find first range with start >= 'start'
    auto next = m_free_ranges_by_offset.lower_bound(offset);

    offset_t newStart = offset;
    length_t newSize  = size;

    // Try to merge with previous range: [...prevEnd) [start, ... )
    if (next != m_free_ranges_by_offset.begin()) {
        auto prev = std::prev(next);
        offset_t prevStart = prev->first;
        length_t prevSize  = prev->second.size;
        offset_t prevEnd   = prevStart + prevSize;

        if (prevEnd == offset) {
            // Remove prev from size index
            eraseFromSizeIndex(prev);
            // Merge
            newStart = prevStart;
            newSize += prevSize;
            m_free_ranges_by_offset.erase(prev);
        }
    }

    // Try to merge with following ranges while adjacent
    while (next != m_free_ranges_by_offset.end()) {
        offset_t rangeStart = next->first;
        length_t rangeSize  = next->second.size;

        if (newStart + newSize == rangeStart) {
            // Adjacent on the right, merge
            eraseFromSizeIndex(next);
            newSize += rangeSize;
            auto toErase = next++;
            m_free_ranges_by_offset.erase(toErase);
        } else {
            break; // not adjacent
        }
    }

    // Insert the merged range back
    auto it = m_free_ranges_by_offset.emplace(newStart, Range{newSize}).first;
    m_free_ranges_by_size.emplace(newSize, it);

    // update counters
    m_total_alloc_bytes -= std::min(size, m_total_alloc_bytes);
    m_total_free_bytes += size;
    if (m_total_alloc_objs > 0) {
        m_total_alloc_objs--;
    }

    return true;
}

void FlexAlloc::get_all_free_ranges(std::vector<FreeRange> &fr_vec)
{
    FreeRange fr;
    for (auto &it : m_free_ranges_by_offset) {
        fr.m_offset = it.first;
        fr.m_size = it.second.size;
        fr_vec.push_back(fr);
    }
}

void FlexAlloc::clear_all_free_ranges()
{
    m_free_ranges_by_offset.clear();
    m_free_ranges_by_size.clear();
}

bool FlexAlloc::add_free_ranges(std::vector<FreeRange> &frs)
{
    bool success = true;
    for (auto &fr : frs) {
        if (!free(fr.m_offset, fr.m_size)) {
            ERROR_PRINT("flex_region:%p. failed to add a free range "
                "{offset:%lu, size:%lu}\n", this, fr.m_offset, fr.m_size);
            success = false;
        }
    }
    return success;
}

/**
 * @brief Get the total amount of free memory
 * @return Total free memory in bytes
 */
size_t FlexAlloc::get_total_free_mem()
{
    return m_total_free_bytes;
}

/**
 * @brief Print the current state of the allocator without locking
 */
void FlexAlloc::print_ranges()
{
    DEBUG_PRINT("\nall free ranges:\n");
    for (auto iter : m_free_ranges_by_offset) {
        DEBUG_PRINT("range:[%lu %lu] size:%lu\n",
            iter.first, iter.first + iter.second.size - 1, iter.second.size);
    }
}

void FlexAlloc::eraseFromSizeIndex(typename StartMap::iterator it)
{
    length_t sz = it->second.size;
    auto range = m_free_ranges_by_size.equal_range(sz);
    for (auto sIt = range.first; sIt != range.second; ++sIt) {
        if (sIt->second == it) {
            m_free_ranges_by_size.erase(sIt);
            break;
        }
    }
}