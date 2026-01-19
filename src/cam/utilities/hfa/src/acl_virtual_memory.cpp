/**
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * This object enables increasing allocated virtual memory on HBM up to 128GB
 * Author: Adi Amir
 */

#include <securec.h>
#include <acl/acl.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <set>
#include <vector>
#include <utility>
#include <chrono>
#include <string>

#include "hfa_log.h"
#include "acl_virtual_memory.h"

using std::cout;
using std::endl;
using std::make_pair;
using std::pair;
using std::size_t;
using std::string;
using std::vector;
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::microseconds;

using namespace hfa;

AclVirtualMemory::AclVirtualMemory(size_t initial_free_pages) {
    m_initial_free_pages = initial_free_pages;
}

AclVirtualMemory::~AclVirtualMemory() {
    cleanup();
}

/**
 * @brief Allocates memory on HBM. Allocation starts with 'ph_mem_size' and can be expanded up to 'vr_mem_size'
 * @param  device_id    [IN] NPU id (0..7)
 * @param  vr_mem_size  [IN] Virtual memory size to be allocated in bytes (up to 128GB, card-dependant)
 * @param  ph_mem_size  [IN] Physical memory size to be allocated on HBM in bytes (up to 32GB, card-dependant)
 * @param  ph_page_size [IN] Physical page size to use while allocating pages on HBM in bytes
 *                           must be 2M aligned (2M, 4M, 6M, etc ..., card-dependant)
 * @retval A pair containing VmRet and address of the virtual memory allocated.
 */
std::pair<VmRet, void*> AclVirtualMemory::alloc(int32_t device_id,
                                                size_t vr_mem_size,
                                                size_t ph_mem_size,
                                                size_t ph_page_size) {
    VmRet ret;

    if ((ret = validate_params(&device_id, &vr_mem_size,
            &ph_mem_size, &ph_page_size)) != VmRet::SUCCESS) {
        return make_pair(ret, nullptr);
    }

    m_device_id = device_id;
    m_vr_mem_size = vr_mem_size;
    m_ph_mem_size = ph_mem_size;
    m_ph_page_size = ph_page_size;

    // Init buffers
    if ((ret = initialize_buffers()) != VmRet::SUCCESS) {
        cleanup();
        return make_pair(ret, nullptr);
    }

    // Setup device
    if ((ret = setup_device()) != VmRet::SUCCESS) {
        cleanup();
        return make_pair(ret, nullptr);
    }

    // Allocate virtual memory
    if ((ret = alloc_virtual_memory()) != VmRet::SUCCESS) {
        cleanup();
        return make_pair(ret, nullptr);
    }

    // Allocate physical pages & map to allocated virtual memory
    if ((ret = alloc_and_map_physical_memory()) != VmRet::SUCCESS) {
        cleanup();
        return make_pair(ret, nullptr);
    }

    m_initialized = true;
    mp_vr_end_addr = static_cast<uint8_t *>(mp_vr_base_addr) + m_ph_mem_size;

    return make_pair(VmRet::SUCCESS, mp_vr_base_addr);
}

VmRet AclVirtualMemory::validate_params(int32_t* p_device_id,
                                        size_t* p_vr_mem_size,
                                        size_t* p_ph_mem_size,
                                        size_t* p_ph_page_size) {
    // Validate device id
    // - must be 0..aclrtGetDeviceCount()-1
    if (p_device_id != nullptr) {
        uint32_t num_devices = 8;
        if (aclrtGetDeviceCount(&num_devices) != ACL_SUCCESS) {
            ERROR_PRINT("aclrtGetDeviceCount() has failed\n");
            return VmRet::E_ACL_GET_NUM_DEVICES_FAILED;
        }
        if (!(*p_device_id >= 0 && *p_device_id < static_cast<int32_t>(num_devices))) {
            ERROR_PRINT("invalid device id %d\n", *p_device_id);
            return VmRet::E_INVALID_PARAMETER_DEVICE_ID;
        }
    }

    // Validate virtual memory size
    // - should range: 0..MAX_VIRTUAL_MEM_SIZE
    if (p_vr_mem_size != nullptr) {
        if (*p_vr_mem_size == 0 || !(*p_vr_mem_size <= MAX_VIRTUAL_MEM_SIZE)) {
            return VmRet::E_INVALID_PARAMETER_MAX_VR_ADDR_SIZE;
        }
    }

    // Validate physical memory size
    // - should be multiple of 2MB
    if (p_ph_mem_size != nullptr) {
        if (*p_ph_mem_size == 0 || !((*p_ph_mem_size % PH_PAGE_ALIGN_SIZE) == 0)) {
            return VmRet::E_INVALID_PARAMETER_PH_MEM_SIZE;
        }
    }

    // Validate physical page size
    // - should be multiple of 2MB
    if (p_ph_page_size != nullptr) {
        if (*p_ph_page_size == 0 || !((*p_ph_page_size % PH_PAGE_ALIGN_SIZE) == 0)) {
            return VmRet::E_INVALID_PARAMETER_PH_PAGE_SIZE;
        }
    }

    return VmRet::SUCCESS;
}

bool AclVirtualMemory::get_chunk_props(
    const AclChunk* p_chunk, AclChunkProps& props) {
    if (p_chunk == nullptr) {
        return false;
    }
    if (p_chunk->m_size < m_ph_page_size) {
        return false;
    }

    // Get chunk's first page
    props.chunk_offset_start = static_cast<uint8_t*>(p_chunk->m_ptr) -
        static_cast<uint8_t*>(mp_vr_base_addr);
    props.first_page_no = props.chunk_offset_start / m_ph_page_size;
    props.is_first_page_aligned =
        (props.chunk_offset_start % m_ph_page_size) == 0;
    DEBUG_PRINT("first page: no=%lu,  aligned=%s\n", props.first_page_no,
        (props.is_first_page_aligned) ? "true" : "false");

    // Get chunk's last page
    props.chunk_offset_end = props.chunk_offset_start + p_chunk->m_size;
    // If the chunk ends exactly at the end of a page, the page's number is X,
    // but if the chunk ends 1 byte later, it is X+1
    props.last_page_no = (props.chunk_offset_end - 1) / m_ph_page_size;
    props.is_last_page_aligned = (props.chunk_offset_end % m_ph_page_size) == 0;
    DEBUG_PRINT("last page: no=%lu,  aligned=%s\n", props.last_page_no,
        (props.is_last_page_aligned) ? "true" : "false");

    // Calc the number of complete pages in the middle of the chunk
    if (props.first_page_no == props.last_page_no) {
        props.num_pages_in_middle = 0;
    } else {
        props.num_pages_in_middle =
            props.last_page_no - (props.first_page_no + 1);
    }

    // The chunk is valid only if it has >=1 complete page, i.e. if either
    // 1. first/last pages are complete pages
    // 2. or, we have >=1 complete page in the middle
    return (props.is_first_page_aligned || props.is_last_page_aligned ||
        props.num_pages_in_middle >= 1);
}

/**
 * @brief Re-allocates fragments of virtual memory to a single contiguous chunk (plus possibly residual partial pages) on HBM.
 * @param  p_free_chunks list of currently available chunks, to be provided by flex manager and modified by this function
 * @retval returns VmRet::SUCCESS or VmRet::E_XXX on error
 */
VmRet AclVirtualMemory::defrag(AclFreeChunks* p_free_chunks) {
    size_t num_complete_pages = 0L;
    VmRet ret;

    if (m_initialized == false) {
        return VmRet::E_INSTANCE_NOT_INITIALIZED;
    }
    m_free_pages.clear();

    DEBUG_PRINT("num free chunks: %lu\n", p_free_chunks->size());
    size_t num_free_chunks = p_free_chunks->size();
    for (std::size_t i = 0; i < num_free_chunks; ++i) {
        // Reference to element, no copy!
        AclChunk* p_chunk = p_free_chunks->at(i);

        AclChunkProps props;
        memset_s(&props, sizeof(AclChunkProps), 0, sizeof(AclChunkProps));
        // get_chunk_props includes nullptr check
        // relevant in case we've been removing chunks
        if (!get_chunk_props(p_chunk, props)) {
            continue;
        }
        DEBUG_PRINT("parsed free chunk: p=%p, size=%lu\n",
            p_chunk->m_ptr, p_chunk->m_size);

        if (props.is_first_page_aligned) {
            // Add a complete page to free pages list
            m_free_pages.emplace_back(
                props.first_page_no, p_chunk->m_ptr, m_ph_page_size);
            num_complete_pages++;
        } else {
            // Add only the available portion of this chunk
            size_t size_left = (props.first_page_no + 1) * m_ph_page_size -
                props.chunk_offset_start;
            m_free_pages.emplace_back(
                props.first_page_no, p_chunk->m_ptr, size_left);
        }

        if (props.last_page_no != props.first_page_no) {
            if (props.is_last_page_aligned) {
                // Add a complete page to free pages list
                m_free_pages.emplace_back(props.last_page_no,
                    mp_mem_pages[props.last_page_no].m_vr_addr,
                    m_ph_page_size);
                num_complete_pages++;
            } else {
                // Add only the available portion of this chunk
                size_t size_left = props.chunk_offset_end -
                    props.last_page_no * m_ph_page_size;
                m_free_pages.emplace_back(props.last_page_no,
                    mp_mem_pages[props.last_page_no].m_vr_addr,
                    size_left);
            }
        }

        // Collect all complete free pages in the middle of the chunk
        for (size_t i = props.first_page_no + 1; i < props.last_page_no; i++) {
            m_free_pages.emplace_back(
                i, mp_mem_pages[i].m_vr_addr, m_ph_page_size);
            num_complete_pages++;
        }

        // Remove this chunk as it is not valid anymore
        if (p_free_chunks->remove_chunk(p_chunk->m_ptr)) {
            // Since we didn't actually delete this entry
            // but instead moved the last one to "deleted" location,
            // the next entry to check resides now in the same 'i' location,
            // so take 'i' one step back to catch the one we moved here.
            --i;
        }
    }

    // Print for debug - here not including chunks of a single incomplete page,
    // they were ruled out on get_chunk_props step
    DEBUG_PRINT("found %lu free pages:\n", m_free_pages.size());
    for (std::size_t i = 0; i < m_free_pages.size(); ++i) {
        AclFreePage& p = m_free_pages.at(i);
        DEBUG_PRINT("page%lu: vr_addr=%p, size=%lu\n",
            p.m_page_no, p.mp_vr_addr, p.m_size);
    }

    DEBUG_PRINT("complete_pages=%lu(%lu)\n",
        num_complete_pages, num_complete_pages * m_ph_page_size);

    // Start re-ordering physical pages
    // 1. Move free complete pages to the end of the virtual memory
    // 2. Create chunks for partial free pages
    // We do this for all the free/partially free pages
    uint8_t* p_realloc_addr = static_cast<uint8_t*>(mp_vr_end_addr);
    size_t realloc_size = 0;
    uint8_t* p_vr_end_addr = p_realloc_addr;
    for (std::size_t i = 0; i < m_free_pages.size(); ++i) {
        AclFreePage& page = m_free_pages.at(i);

        if (page.m_size < m_ph_page_size) {
            // It's a partial page - add it as a chunk to the output
            p_free_chunks->add_chunk(page.mp_vr_addr, page.m_size);
        } else {
            // It's a full page - remap it to a chunk in the end
            ret = remap_page(page.m_page_no, p_vr_end_addr);
            if (ret != VmRet::SUCCESS) {
                return ret;
            }
            // Advance current end addr
            p_vr_end_addr =
                static_cast<uint8_t*>(p_vr_end_addr) + m_ph_page_size;
            realloc_size += m_ph_page_size;
        }
    }

    // Add newly allocated chunk (of full pages that were remapped) to output
    p_free_chunks->add_chunk(p_realloc_addr, realloc_size);

    // Update end of virtual buffer addr
    mp_vr_end_addr = static_cast<uint8_t*>(mp_vr_end_addr) + realloc_size;

    return VmRet::SUCCESS;
}

/**
 * @brief Frees memory on HBM. Opposite to AclVirtualMemory::alloc()
 */
void AclVirtualMemory::free() {
    cleanup();
}

/**
 * @brief Remap a given page to a given virtual address
 * @param  page_no    [IN] page number to move
 * @param  p_vr_addr  [IN] new address location of given page
 * @retval returns VmRet::SUCCESS or relevant error
 */
VmRet AclVirtualMemory::remap_page(size_t page_no, uint8_t* p_vr_addr) {
    aclError acl_ret;

    if (m_initialized == false) {
        return VmRet::E_INSTANCE_NOT_INITIALIZED;
    }

    AclMemPage* p_page = &mp_mem_pages[page_no];
    DEBUG_PRINT("remap page:%lu from vr_addr=%p to vr_addr=%p, handle=%p ...\n",
        page_no, p_page->m_vr_addr, p_vr_addr, p_page->m_handle);

    // Unmapping page from current address (aclrtUnmapMem) is not needed

    // Map to the end of virtual memory block
    if ((acl_ret = aclrtMapMem(p_vr_addr, m_ph_page_size, 0,
            p_page->m_handle, 0)) != ACL_SUCCESS) {
        return VmRet::E_ACL_MAP_MEM_FAILED;
    }
    DEBUG_PRINT("remap success! page:%lu from vr_addr=%p to vr_addr=%p, handle=%p\n",
        page_no, p_page->m_vr_addr, p_vr_addr, p_page->m_handle);

    // Update MemPages: the virtual-physical pair gets a new (virtual) number,
    // the previous number is invalidated
    uint64_t new_page_offset_start = static_cast<uint8_t*>(p_vr_addr) -
        static_cast<uint8_t*>(mp_vr_base_addr);
    size_t new_page_no = new_page_offset_start / m_ph_page_size;
    mp_mem_pages[new_page_no].m_handle = p_page->m_handle;
    mp_mem_pages[new_page_no].m_vr_addr = p_vr_addr;
    if (new_page_no != m_num_pages) {
        WARNING_PRINT("supposed to remap to the end of mp_mem_pages "
            "array, new_page_no=%zu, m_num_pages=%zu\n", new_page_no, m_num_pages);
    }
    m_num_pages++;
    p_page->m_handle = nullptr;
    return VmRet::SUCCESS;
}

void AclVirtualMemory::cleanup() {
    // Release physical address
    if (mp_mem_pages) {
        for (int i = 0; i < m_num_pages; i++) {
            aclrtUnmapMem(mp_mem_pages[i].m_vr_addr);
            if (mp_mem_pages[i].m_handle != nullptr) {
                aclrtFreePhysical(mp_mem_pages[i].m_handle);
            }
        }
        delete[] mp_mem_pages;
        mp_mem_pages = nullptr;
    }

    // Release virtual memory address
    if (mp_vr_base_addr) {
        aclrtReleaseMemAddress(mp_vr_base_addr);
        mp_vr_base_addr = nullptr;
    }

    // Delete/free buffers
    m_free_pages.clear();
}

VmRet AclVirtualMemory::initialize_buffers() {
    // Reserve complete pages
    m_free_pages.reserve(m_initial_free_pages);

    return VmRet::SUCCESS;
}

VmRet AclVirtualMemory::setup_device() {
    aclError ret;

    // Set device
    if ((ret = aclrtSetDevice(m_device_id)) != ACL_SUCCESS) {
        return VmRet::E_ACL_SET_CURRENT_CONTEXT_FAILED;
    }

    return VmRet::SUCCESS;
}

VmRet AclVirtualMemory::alloc_virtual_memory() {
    aclError ret = aclrtReserveMemAddress(
        &mp_vr_base_addr, m_vr_mem_size, 0, nullptr, 1);
    if (ret != ACL_SUCCESS) {
        return VmRet::E_ACL_RESERVED_MEM_ADDRESS_FAILED;
    }
    return VmRet::SUCCESS;
}

VmRet AclVirtualMemory::alloc_and_map_physical_memory() {
    aclrtPhysicalMemProp prop;
    aclrtDrvMemHandle ph_mem_handle{nullptr};
    aclError ret;

    size_t num_ph_pages = m_ph_mem_size / m_ph_page_size;
    size_t num_vr_pages = m_vr_mem_size / m_ph_page_size;
    // Allocate virtual pages array
    mp_mem_pages = new (std::nothrow) AclMemPage[num_vr_pages];
    if (mp_mem_pages == nullptr) {
        return VmRet::E_OUT_OF_MEMORY;
    }

    // Setup physical page properties
    memset(&prop, 0, sizeof(prop));
    prop.handleType = ACL_MEM_HANDLE_TYPE_NONE;
    prop.allocationType = ACL_MEM_ALLOCATION_TYPE_PINNED;
    prop.memAttr = ACL_HBM_MEM_NORMAL;
    prop.location.id = m_device_id;
    prop.location.type = ACL_MEM_LOCATION_TYPE_DEVICE;

    // Allocate each physical page and map it to virtual address
    uint8_t* vr_current_addr = static_cast<uint8_t*>(mp_vr_base_addr);
    for (size_t i = 0; i < num_ph_pages; i++) {
        // Allocate handle
        if ((ret = aclrtMallocPhysical(
                &ph_mem_handle, m_ph_page_size, &prop, 0)) != ACL_SUCCESS) {
            ERROR_PRINT("aclrtMallocPhysical() has failed for size %zu\n", m_ph_page_size);
            return VmRet::E_ACL_MALLOC_PHYSICAL_FAILED;
        }
        // Map to virtual address
        if ((ret = aclrtMapMem(vr_current_addr, m_ph_page_size, 0,
                ph_mem_handle, 0)) != ACL_SUCCESS) {
            ERROR_PRINT("aclrtMapMem() has failed for size %zu\n", m_ph_page_size);
            return VmRet::E_ACL_MAP_MEM_FAILED;
        }

        // Add page
        mp_mem_pages[i].m_vr_addr = vr_current_addr;
        mp_mem_pages[i].m_handle = ph_mem_handle;
        m_num_pages++;
        // Inc base addr
        vr_current_addr += m_ph_page_size;
    }
    DEBUG_PRINT("done mapping %zu physical pages to virtual address space\n", m_num_pages);
    return VmRet::SUCCESS;
}

/**
 * @brief Deciphers a status returned by another API
 * @param  error    [IN] return value of another AclVirtualMemory API
 * @retval A string describing the error
 */
std::string AclVirtualMemory::error_info(VmRet error) {
    if (static_cast<int>(error) < ACL_BASE_ERROR) {
        return vm_error(error);
    } else {
        string s_error = string(vm_error(error)) + string("  aclError: ") +
            string(aclGetRecentErrMsg());
        return s_error;
    }
}
