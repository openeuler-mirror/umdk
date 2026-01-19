/**
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * This object enables increasing allocated virtual memory on HBM up to 128GB
 * Author: Adi Amir
 */

#ifndef ACL_VIRTUAL_MEMORY
#define ACL_VIRTUAL_MEMORY

#include <acl/acl.h>
#include <cstddef>
#include <cstdio>  // for printf
#include <string>  // for std::string
#include <unordered_map>
#include <utility>  // for std::pair
#include <vector>  // for std::vector

namespace hfa {

// card-dependant consts
const size_t MAX_VIRTUAL_MEM_SIZE = 128UL * 1024 * 1024 * 1024;  // 128GB
const size_t PH_PAGE_ALIGN_SIZE = 2 * 1024 * 1024;

// defaults
// initial number free pages
const size_t DEF_INITIAL_FREE_PAGES = 1024;
// initial number of free chunks
const size_t DEF_INITIAL_FREE_CHUNKS = 1024;

const int ACL_BASE_ERROR = 0x200;

// VmRet
// error enumeration for AclVirtualMemory object
enum class VmRet {
    SUCCESS                                              = 0,
    // general errors
    // failed to malloc/new
    E_OUT_OF_MEMORY                                      = 0x100,
    // trying to call api(s) before instance initialized
    E_INSTANCE_NOT_INITIALIZED                           = 0x101,
    // defrag() failed to obtain enough free memory
    E_INSUFFICIENT_MEM                                   = 0x102,
    E_INVALID_PARAMETER                                  = 0x103,
    // invalid device id parameter
    E_INVALID_PARAMETER_DEVICE_ID                        = 0x104,
    // invalid max virtual memory size parameter
    E_INVALID_PARAMETER_MAX_VR_ADDR_SIZE                 = 0x105,
    // invalid physical memory size parameter
    E_INVALID_PARAMETER_PH_MEM_SIZE                      = 0x106,
    // invalid physical PAGE size parameter
    E_INVALID_PARAMETER_PH_PAGE_SIZE                     = 0x107,

    // acl api errors
    E_ACL_INIT_FAILED                                    = ACL_BASE_ERROR,
    E_ACL_CREATE_CONTEXT_FAILED                          = ACL_BASE_ERROR + 1,
    E_ACL_SET_CURRENT_CONTEXT_FAILED                     = ACL_BASE_ERROR + 2,
    E_ACL_RESERVED_MEM_ADDRESS_FAILED                    = ACL_BASE_ERROR + 3,
    E_ACL_MALLOC_PHYSICAL_FAILED                         = ACL_BASE_ERROR + 4,
    E_ACL_MAP_MEM_FAILED                                 = ACL_BASE_ERROR + 5,
    E_ACL_UNMAP_MEM_FAILED                               = ACL_BASE_ERROR + 6,
    E_ACL_GET_NUM_DEVICES_FAILED                         = ACL_BASE_ERROR + 7
};

inline const char* vm_error(VmRet error) {
    switch (error) {
        case VmRet::SUCCESS:
            return "SUCCESS";
        case VmRet::E_OUT_OF_MEMORY:
            return "E_OUT_OF_MEMORY";
        case VmRet::E_INSTANCE_NOT_INITIALIZED:
            return "E_INSTANCE_NOT_INITIALIZED";
        case VmRet::E_INSUFFICIENT_MEM:
            return "E_INSUFFICIENT_MEM";
        case VmRet::E_INVALID_PARAMETER:
            return "E_INVALID_PARAMETER";
        case VmRet::E_INVALID_PARAMETER_DEVICE_ID:
            return "E_INVALID_PARAMETER_DEVICE_ID";
        case VmRet::E_INVALID_PARAMETER_MAX_VR_ADDR_SIZE:
            return "E_INVALID_PARAMETER_MAX_VR_ADDR_SIZE";
        case VmRet::E_INVALID_PARAMETER_PH_MEM_SIZE:
            return "E_INVALID_PARAMETER_PH_MEM_SIZE";
        case VmRet::E_INVALID_PARAMETER_PH_PAGE_SIZE:
            return "E_INVALID_PARAMETER_PH_PAGE_SIZE";
        // ACL API(s) errors
        case VmRet::E_ACL_INIT_FAILED:
            return "E_ACL_INIT_FAILED";
        case VmRet::E_ACL_CREATE_CONTEXT_FAILED:
            return "E_ACL_CREATE_CONTEXT_FAILED";
        case VmRet::E_ACL_SET_CURRENT_CONTEXT_FAILED:
            return "E_ACL_SET_CURRENT_CONTEXT_FAILED";
        case VmRet::E_ACL_RESERVED_MEM_ADDRESS_FAILED:
            return "E_ACL_RESERVED_MEM_ADDRESS_FAILED";
        case VmRet::E_ACL_MALLOC_PHYSICAL_FAILED:
            return "E_ACL_MALLOC_PHYSICAL_FAILED";
        case VmRet::E_ACL_MAP_MEM_FAILED:
            return "E_ACL_MAP_MEM_FAILED";
        case VmRet::E_ACL_UNMAP_MEM_FAILED:
            return "E_ACL_UNMAP_MEM_FAILED";
        default:
            return "UNKNOWN";
    }
}

// AclChunk
// a memory chunk that was freed by the flex memory manager
class AclChunk {
 public:
    AclChunk() {}
    explicit AclChunk(void* ptr, size_t size) : m_ptr(ptr), m_size(size) {}

    void* m_ptr{nullptr};
    size_t m_size{0L};
};

// AclFreeChunks
// a wrapper over vector of free chunks + a map for efficient access
class AclFreeChunks {
 public:
    explicit AclFreeChunks(
        size_t initial_free_chunks = DEF_INITIAL_FREE_CHUNKS) {
        // reserve free chunks in advance to avoid re-allocation of vector
        m_free_chunks.reserve(initial_free_chunks);
    }

    ~AclFreeChunks() {
        clear();
    }

    size_t size();
    AclChunk* at(size_t index);
    void add_chunk(void* p_vr_addr, size_t size);
    void add_chunk(AclChunk* p_chunk);
    bool remove_chunk(void* p_vr_addr);
    void update_chunk_location(void* p_vr_addr, size_t new_index);
    void clear();

 private:
    // list containing free memory chunks
    std::vector<AclChunk> m_free_chunks;
    // for fast retrieval of a chunk location by its addr
    std::unordered_map<void*, size_t> m_chunk_location;
};

// AclChunkProps
// a set of properties of a chunk
struct AclChunkProps {
    uint64_t chunk_offset_start;
    size_t first_page_no;
    bool is_first_page_aligned;
    uint64_t chunk_offset_end;
    size_t last_page_no;
    bool is_last_page_aligned;
    size_t num_pages_in_middle;

    void print() {
        printf("chunk props: chunk_offset_start=%lu, first_page_no=%lu, "
               "is_first_page_aligned=%d, chunk_offset_end=%lu, "
               "last_page_no=%lu, is_last_page_aligned=%d, "
               "num_pages_in_middle=%lu\n",
               chunk_offset_start, first_page_no, is_first_page_aligned,
               chunk_offset_end, last_page_no,
               is_last_page_aligned, num_pages_in_middle);
    }
};

// AclFreePage
// contains a full physical page to be moved to its new destination
// or existing partial page (still used by another allocation, can't be moved)
// (partial page is actually the first/last page of a free chunk)
class AclFreePage {
 public:
    AclFreePage() {}
    explicit AclFreePage(
        size_t page_no, void* p_vr_addr = nullptr, size_t size = 0L) :
        m_page_no(page_no), mp_vr_addr(p_vr_addr), m_size(size) {}

    size_t m_page_no{0L};  // physical page no. in 'mp_mem_pages' array
    void* mp_vr_addr{nullptr};
    size_t m_size{0L};
};

// AclMemPage
// contains physical memory page info created by alloc() function
struct AclMemPage {
    aclrtDrvMemHandle m_handle{nullptr};
    void* m_vr_addr{nullptr};
};

class AclVirtualMemory {
 public:
    explicit AclVirtualMemory(size_t initial_free_pages = DEF_INITIAL_FREE_PAGES);
    ~AclVirtualMemory();

    /**
     * @brief allocated HBA memory segment
     * @param  device_id    [IN] NPU id (0..7)
     * @param  vr_mem_size  [IN] Virtual memory size to be allocated in bytes (up to 128GB, card-dependant)
     * @param  ph_mem_size  [IN] Physical memory size to be allocated on HBM in bytes (up to 32GB, card-dependant)
     * @param  ph_page_size [IN] Physical page size to use while allocating pages on HBM in bytes
     *                           must be 2M aligned (2M, 4M, 6M, etc ..., card-dependant)
     * @return True/False and the address of the allocated segment
     */
    std::pair<VmRet, void*> alloc(int32_t device_id,
                                  size_t vr_mem_size,
                                  size_t ph_mem_size,
                                  size_t ph_page_size);

    /**
     * @brief Re-allocates fragments of virtual memory to a single contiguous chunk (plus possibly residual partial pages) on HBM.
     * @param  p_free_chunks list of currently available chunks, to be provided by flex manager and modified by this function
     * @retval returns VmRet::SUCCESS or VmRet::E_XXX on error
     */
    VmRet defrag(AclFreeChunks* p_free_chunks);

    /**
     * @brief returns the address to the begining of the allocated segment
     */
    void* get_base_addr() { return mp_vr_base_addr; }

    /**
     * @brief free the allocated segment allocated by alloc()
     */
    void free();

    /**
     * @brief A helper function for printing a detailed description of the error
     */
    std::string error_info(VmRet error);

 private:
    VmRet validate_params(int32_t* p_device_id,
                          size_t* p_vr_mem_size,
                          size_t* p_ph_mem_size,
                          size_t* p_ph_page_size);
    VmRet remap_page(size_t page_no, uint8_t* p_vr_addr);
    VmRet initialize_buffers();
    VmRet setup_device();
    VmRet alloc_virtual_memory();
    VmRet alloc_and_map_physical_memory();
    bool get_chunk_props(const AclChunk* chunk, AclChunkProps& properties);
    void cleanup();

    // indicates whether this instance initialized successfully
    bool m_initialized{false};
    // size of virtual memory allocated
    size_t m_vr_mem_size{0};
    // size of physical memory allocated
    size_t m_ph_mem_size{0};
    // physical page size
    size_t m_ph_page_size{0};
    // addresses of the beginning and the end of virtual memory
    void* mp_vr_base_addr{nullptr};
    void* mp_vr_end_addr{nullptr};
    // npu id, 0..7
    int32_t m_device_id{-1};
    // array of virtual memory pages
    AclMemPage* mp_mem_pages{nullptr};
    // number of elements in 'mp_mem_pages'
    size_t m_num_pages{0};

    // realloc helpers
    // helper array for helping realloc() to collect physical pages
    std::vector<AclFreePage> m_free_pages;
    // initial number of reserved elements in 'm_free_pages'
    size_t m_initial_free_pages{0};
};

} // namespace hfa

#endif  // ACL_VIRTUAL_MEMORY
