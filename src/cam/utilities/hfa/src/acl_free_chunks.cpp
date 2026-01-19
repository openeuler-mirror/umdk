/**
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * This object manages a list of free chunks to be used both by the flex manager and the AclVirtualMemory module
 * Author: Adi Amir
 */

#include <vector>
#include <unordered_map>
#include <utility>  // for std::move

#include "acl_virtual_memory.h"

using namespace hfa;

size_t AclFreeChunks::size() {
    return m_free_chunks.size();
}

AclChunk* AclFreeChunks::at(size_t index) {
    if (index < m_free_chunks.size())
        return &m_free_chunks.at(index);
    return nullptr;
}

void AclFreeChunks::add_chunk(void* p_vr_addr, size_t size) {
    m_free_chunks.emplace_back(p_vr_addr, size);
    m_chunk_location.emplace(p_vr_addr, m_free_chunks.size() - 1);
}

void AclFreeChunks::add_chunk(AclChunk* p_chunk) {
    m_free_chunks.emplace_back(*p_chunk);
    m_chunk_location.emplace(p_chunk->m_ptr, m_free_chunks.size() - 1);
}

bool AclFreeChunks::remove_chunk(void* p_vr_addr) {
    // first, find and remove this entry from 'm_chunk_location'
    auto it = m_chunk_location.find(p_vr_addr);
    if (it == m_chunk_location.end()) {
        return false;  // entry not found
    }
    size_t index = it->second;

    // verify that index exists in 'm_free_chunks'
    if (index >= m_free_chunks.size()) {
        return false;
    }
    // remove from 'm_chunk_location' only after the verification
    m_chunk_location.erase(it);

    // remove from 'm_free_chunks'
    if (index == m_free_chunks.size() - 1) {
        // it's the last element in vector, just remove the last element
        m_free_chunks.pop_back();
    } else {
        // the element is in the middle:
        // 1) replace the "deleted" location with the last element
        // 2) delete the last element
        m_free_chunks[index] = std::move(m_free_chunks.back());
        m_free_chunks.pop_back();
        // update the moved entry with the new location
        update_chunk_location(m_free_chunks[index].m_ptr, index);
    }
    return true;
}

void AclFreeChunks::update_chunk_location(void* p_vr_addr, size_t new_index) {
    auto it = m_chunk_location.find(p_vr_addr);
    if (it != m_chunk_location.end()) {
        it->second = new_index;
    }
}

void AclFreeChunks::clear() {
    m_free_chunks.clear();
    m_chunk_location.clear();
}
