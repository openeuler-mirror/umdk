/**
 * @cond IGNORE_COPYRIGHT
 * Copyright (c) 2025 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 * @endcond
 */
#ifndef SHMEM_DEVICE_RDMA_H
#define SHMEM_DEVICE_RDMA_H

#include "kernel_operator.h"
#include "device/shmem_def.h"
#include "gm2gm/engine/shmem_device_rdma.hpp"

/**
 * @brief Translate an local symmetric address to remote symmetric address on the specified PE used by RDMA.
 *
 * @param ptr               [in] Symmetric address on local PE.
 * @param pe                [in] The number of the remote PE.
 * @return A remote symmetric address on the specified PE that can be accessed using memory loads and stores.
 */
ACLSHMEM_DEVICE __gm__ void *aclshmem_roce_ptr(__gm__ void *ptr, int pe);
#define shmem_roce_ptr aclshmem_roce_ptr

/**
 * @brief Asynchronous interface. Copy contiguous data on symmetric memory from the specified
 * PE to address on the local device.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations
 *        to the same PE are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 *
 * @param dst               [in] Pointer on local device of the destination data.
 * @param src               [in] Pointer on Symmetric memory of the source data.
 * @param buf               [in] Pointer on local UB, available space larger than 64 Bytes.
 * @param elem_size         [in] Number of elements in the destination and source arrays.
 * @param pe                [in] PE number of the remote PE.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_get_nbi(__gm__ T *dst, __gm__ T *src, __ubuf__ T *buf, uint32_t elem_size, int pe);

/**
 * @brief Asynchronous interface. Copy contiguous data on symmetric memory from the specified
 * PE to address on the local device.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations
 *        to the same PE are not supported.
 *
 * @param dst               [in] Pointer on local device of the destination data.
 * @param src               [in] Pointer on Symmetric memory of the source data.
 * @param buf               [in] Pointer on local UB, available space larger than 64 Bytes.
 * @param elem_size         [in] Number of elements in the destination and source arrays.
 * @param pe                [in] PE number of the remote PE.
 * @param sync_id           [in] ID used to Sync S\\MTE3 Event.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_get_nbi(__gm__ T *dst, __gm__ T *src, __ubuf__ T *buf, uint32_t elem_size, int pe,
                                            uint32_t sync_id);

/**
 * @brief Asynchronous interface. Copy contiguous data on symmetric memory from the specified
 * PE to address on the local PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations
 *        to the same PE are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 *
 * @param dst               [in] GlobalTensor on local device of the destination data.
 * @param src               [in] GlobalTensor on Symmetric memory of the source data.
 * @param buf               [in] LocalTensor on local UB, available space larger than 64 Bytes.
 * @param elem_size         [in] Number of elements in the destination and source arrays.
 * @param pe                [in] PE number of the remote PE.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_get_nbi(AscendC::GlobalTensor<T> dst, AscendC::GlobalTensor<T> src,
                                            AscendC::LocalTensor<T> buf, uint32_t elem_size, int pe);

/**
 * @brief Asynchronous interface. Copy contiguous data on symmetric memory from the specified
 * PE to address on the local PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations
 *        to the same PE are not supported.
 *
 * @param dst               [in] GlobalTensor on local device of the destination data.
 * @param src               [in] GlobalTensor on Symmetric memory of the source data.
 * @param buf               [in] LocalTensor on local UB, available space larger than 64 Bytes.
 * @param elem_size         [in] Number of elements in the destination and source arrays.
 * @param pe                [in] PE number of the remote PE.
 * @param sync_id           [in] ID used to Sync S\\MTE3 Event.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_get_nbi(AscendC::GlobalTensor<T> dst, AscendC::GlobalTensor<T> src,
                                            AscendC::LocalTensor<T> buf, uint32_t elem_size, int pe, uint32_t sync_id);
#define shmem_roce_get_mem_nbi aclshmemx_roce_get_nbi
/**
 * @brief Asynchronous interface. Copy contiguous data on local PE to symmetric address on the specified PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 *
 * @param dst               [in] Pointer on Symmetric memory of the destination data.
 * @param src               [in] Pointer on local device of the source data.
 * @param buf               [in] Pointer on local UB, available space larger than 64 Bytes.
 * @param elem_size         [in] Number of elements in the destination and source arrays.
 * @param pe                [in] PE number of the remote PE.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_put_nbi(__gm__ T *dst, __gm__ T *src, __ubuf__ T *buf, uint32_t elem_size, int pe);

/**
 * @brief Asynchronous interface. Copy contiguous data on local PE to symmetric address on the specified PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported.
 *
 * @param dst               [in] Pointer on Symmetric memory of the destination data.
 * @param src               [in] Pointer on local device of the source data.
 * @param buf               [in] Pointer on local UB, available space larger than 64 Bytes.
 * @param elem_size         [in] Number of elements in the destination and source arrays.
 * @param pe                [in] PE number of the remote PE.
 * @param sync_id           [in] ID used to Sync S\\MTE3 Event.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_put_nbi(__gm__ T *dst, __gm__ T *src, __ubuf__ T *buf, uint32_t elem_size, int pe,
                                            uint32_t sync_id);

/**
 * @brief Asynchronous interface. Copy contiguous data on local PE to symmetric address on the specified PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same
 *        PE are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 *
 * @param dst               [in] GlobalTensor on Symmetric memory of the destination data.
 * @param src               [in] GlobalTensor on local device of the source data.
 * @param buf               [in] Pointer on local UB, available space larger than 64 Bytes.
 * @param elem_size         [in] Number of elements in the destination and source arrays.
 * @param pe                [in] PE number of the remote PE.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_put_nbi(AscendC::GlobalTensor<T> dst, AscendC::GlobalTensor<T> src,
                                            AscendC::LocalTensor<T> buf, uint32_t elem_size, int pe);

/**
 * @brief Asynchronous interface. Copy contiguous data on local PE to symmetric address on the specified PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same
 *        PE are not supported.
 *
 * @param dst               [in] GlobalTensor on Symmetric memory of the destination data.
 * @param src               [in] GlobalTensor on local device of the source data.
 * @param buf               [in] Pointer on local UB, available space larger than 64 Bytes.
 * @param elem_size         [in] Number of elements in the destination and source arrays.
 * @param pe                [in] PE number of the remote PE.
 * @param sync_id           [in] ID used to Sync S\\MTE3 Event.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_put_nbi(AscendC::GlobalTensor<T> dst, AscendC::GlobalTensor<T> src,
                                            AscendC::LocalTensor<T> buf, uint32_t elem_size, int pe, uint32_t sync_id);
#define shmem_roce_put_mem_nbi aclshmemx_roce_put_nbi

/**
 * @brief RDMA Quiet function. This synchronous function ensures all previous RDMA WQEs are completed
 * (data has arrived at the destination NIC).
 *
 * @param pe                [in] PE number of the remote PE.
 * @param buf               [in] Pointer on local UB, available space larger than 64 Bytes.
 * @param sync_id           [in] ID used to Sync S\\MTE3 Event.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_quiet(uint32_t pe, __ubuf__ T *buf, uint32_t sync_id);

/**
 * @brief Synchronous interface. Returns the value at the source address on the specified PE.
 * Supported hardware platform: Ascend950.
 *        The function returns after the remote atomic operation has completed and is visible on the remote PE.
 *        An internal quiet operation is performed before returning.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit data types.
 *
 * @param src               [in] Symmetric address of the source data.
 * @param pe                [in] PE number of the remote PE.
 * @return The value at the source address.
 */
template <typename T>
ACLSHMEM_DEVICE T aclshmemx_roce_atomic_fetch(__gm__ T *src, int32_t pe);

/**
 * @brief Asynchronous interface. Sets the value at the destination address on the specified PE.
 * Supported hardware platform: Ascend950.
 *        This is an asynchronous operation. The caller must invoke aclshmemx_roce_quiet to ensure
 *        the operation has completed and the data is visible on the remote PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit data types.
 *
 * @param dst               [in] Symmetric address of the destination data.
 * @param value             [in] Value to be set.
 * @param pe                [in] PE number of the remote PE.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_atomic_set(__gm__ T *dst, T value, int32_t pe);

/**
 * @brief Synchronous interface. Conditionally updates the value at the destination address.
 * Supported hardware platform: Ascend950.
 *        The function returns after the remote atomic operation has completed and is visible on the remote PE.
 *        An internal quiet operation is performed before returning.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers.
 *
 * @param dst               [in] Symmetric address of the destination data.
 * @param cond              [in] Value to compare against.
 * @param value             [in] Value to be written if comparison succeeds.
 * @param pe                [in] PE number of the remote PE.
 * @return The original value at the destination address.
 */
template <typename T>
ACLSHMEM_DEVICE T aclshmemx_roce_atomic_compare_swap(__gm__ T *dst, T cond, T value, int32_t pe);

/**
 * @brief Synchronous interface. Swaps the value at the destination address. Supported hardware platform: Ascend950.
 *        The function returns after the remote atomic operation has completed and is visible on the remote PE.
 *        An internal quiet operation is performed before returning.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers.
 *
 * @param dst               [in] Symmetric address of the destination data.
 * @param value             [in] Value to be swapped.
 * @param pe                [in] PE number of the remote PE.
 * @return The original value at the destination address.
 */
template <typename T>
ACLSHMEM_DEVICE T aclshmemx_roce_atomic_swap(__gm__ T *dst, T value, int32_t pe);

/**
 * @brief Asynchronous interface. Increments the value at the destination address by 1.
 * Supported hardware platform: Ascend950.
 *        This is an asynchronous operation. The caller must invoke aclshmemx_roce_quiet to ensure
 *        the operation has completed and the data is visible on the remote PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers.
 *
 * @param dst               [in] Symmetric address of the destination data.
 * @param pe                [in] PE number of the remote PE.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_atomic_inc(__gm__ T *dst, int32_t pe);

/**
 * @brief Asynchronous interface. Adds the value to the destination address. Supported hardware platform: Ascend950.
 *        This is an asynchronous operation. The caller must invoke aclshmemx_roce_quiet to ensure
 *        the operation has completed and the data is visible on the remote PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers.
 *
 * @param dst               [in] Symmetric address of the destination data.
 * @param value             [in] Value to be added.
 * @param pe                [in] PE number of the remote PE.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_atomic_add(__gm__ T *dst, T value, int32_t pe);

/**
 * @brief Asynchronous interface. Perform a bitwise AND operation on dst (remote symmetric address) on the
 * specified PE pe with the operand value, without returning a value. Supported types: int32, uint32, int64, uint64.
 * Supported hardware platform: Ascend950.
 *        This is an asynchronous operation. The caller must invoke aclshmemx_roce_quiet to ensure
 *        the operation has completed and the data is visible on the remote PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers. Using unsupported types or platforms results in undefined behavior.
 *
 * @param dst               [in] Symmetric address of the destination data. Must be a valid symmetric address.
 * @param value             [in] Operand of bitwise AND operation.
 * @param pe                [in] PE number of the remote PE. Must be a valid PE number within the active set.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_atomic_and(__gm__ T *dst, T value, int32_t pe);

/**
 * @brief Asynchronous interface. Perform a bitwise OR operation on dst (remote symmetric address) on the
 * specified PE pe with the operand value, without returning a value. Supported types: int32, uint32, int64, uint64.
 * Supported hardware platform: Ascend950.
 *        This is an asynchronous operation. The caller must invoke aclshmemx_roce_quiet to ensure
 *        the operation has completed and the data is visible on the remote PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers. Using unsupported types or platforms will result in a compile-time
 * error.
 *
 * @param dst               [in] Symmetric address of the destination data. Must be a valid symmetric address.
 * @param value             [in] Operand of bitwise OR operation.
 * @param pe                [in] PE number of the remote PE. Must be a valid PE number within the active set.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_atomic_or(__gm__ T *dst, T value, int32_t pe);

/**
 * @brief Asynchronous interface. Perform a bitwise XOR operation on dst (remote symmetric address) on the
 * specified PE pe with the operand value, without returning a value. Supported types: int32, uint32, int64, uint64.
 * Supported hardware platform: Ascend950.
 *        This is an asynchronous operation. The caller must invoke aclshmemx_roce_quiet to ensure
 *        the operation has completed and the data is visible on the remote PE.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers. Using unsupported types or platforms results in undefined behavior.
 *
 * @param dst               [in] Symmetric address of the destination data. Must be a valid symmetric address.
 * @param value             [in] Operand of bitwise XOR operation.
 * @param pe                [in] PE number of the remote PE. Must be a valid PE number within the active set.
 */
template <typename T>
ACLSHMEM_DEVICE void aclshmemx_roce_atomic_xor(__gm__ T *dst, T value, int32_t pe);

/**
 * @brief Synchronous interface. Increments the value at the destination address by 1 and returns the old
 * value. Supported hardware platform: Ascend950.
 *        The function returns after the remote atomic operation has completed and is visible on the remote PE.
 *        An internal quiet operation is performed before returning.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers.
 *
 * @param dst               [in] Symmetric address of the destination data.
 * @param pe                [in] PE number of the remote PE.
 * @return The original value at the destination address before increment.
 */
template <typename T>
ACLSHMEM_DEVICE T aclshmemx_roce_atomic_fetch_inc(__gm__ T *dst, int32_t pe);
/**
 * @brief Synchronous interface. Adds the value to the destination address and returns the old value.
 * Supported hardware platform: Ascend950.
 *        The function returns after the remote atomic operation has completed and is visible on the remote PE.
 *        An internal quiet operation is performed before returning.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers.
 *
 * @param dst               [in] Symmetric address of the destination data.
 * @param value             [in] Value to be added.
 * @param pe                [in] PE number of the remote PE.
 * @return The original value at the destination address before addition.
 */
template <typename T>
ACLSHMEM_DEVICE T aclshmemx_roce_atomic_fetch_add(__gm__ T *dst, T value, int32_t pe);

/**
 * @brief Synchronous interface. Perform a bitwise AND operation on dst (remote symmetric address) on the
 * specified PE pe with the operand value, and return the previous contents of dst. Supported types:
 * int32, uint32, int64, uint64. Supported hardware platform: Ascend950.
 *        The function returns after the remote atomic operation has completed and is visible on the remote PE.
 *        An internal quiet operation is performed before returning.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers. Using unsupported types or platforms will result in a compile-time
 * error.
 *
 * @param dst               [in] Symmetric address of the destination data. Must be a valid symmetric address.
 * @param value             [in] Operand of bitwise AND operation.
 * @param pe                [in] PE number of the remote PE. Must be a valid PE number within the active set.
 * @return                  Return the previous contents of dst.
 */
template <typename T>
ACLSHMEM_DEVICE T aclshmemx_roce_atomic_fetch_and(__gm__ T *dst, T value, int32_t pe);

/**
 * @brief Synchronous interface. Perform a bitwise OR operation on dst (remote symmetric address) on the
 * specified PE pe with the operand value, and return the previous contents of dst. Supported types:
 * int32, uint32, int64, uint64. Supported hardware platform: Ascend950.
 *        The function returns after the remote atomic operation has completed and is visible on the remote PE.
 *        An internal quiet operation is performed before returning.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers. Using unsupported types or platforms results in undefined behavior.
 *
 * @param dst               [in] Symmetric address of the destination data. Must be a valid symmetric address.
 * @param value             [in] Operand of bitwise OR operation.
 * @param pe                [in] PE number of the remote PE. Must be a valid PE number within the active set.
 * @return                  Return the previous contents of dst.
 */
template <typename T>
ACLSHMEM_DEVICE T aclshmemx_roce_atomic_fetch_or(__gm__ T *dst, T value, int32_t pe);

/**
 * @brief Synchronous interface. Perform a bitwise XOR operation on dst (remote symmetric address) on the
 * specified PE pe with the operand value, and return the previous contents of dst. Supported types:
 * int32, uint32, int64, uint64. Supported hardware platform: Ascend950.
 *        The function returns after the remote atomic operation has completed and is visible on the remote PE.
 *        An internal quiet operation is performed before returning.
 *        WARNING: When using RDMA as the underlying transport, concurrent RMA/AMO operations to the same PE
 *        are not supported. Use sync_id in device_state.rdma_config for pipeline synchronization.
 * @note T only supports 32-bit and 64-bit integers. Using unsupported types or platforms will result in a compile-time
 * error.
 *
 * @param dst               [in] Symmetric address of the destination data. Must be a valid symmetric address.
 * @param value             [in] Operand of bitwise XOR operation.
 * @param pe                [in] PE number of the remote PE. Must be a valid PE number within the active set.
 * @return                  Return the previous contents of dst.
 */
template <typename T>
ACLSHMEM_DEVICE T aclshmemx_roce_atomic_fetch_xor(__gm__ T *dst, T value, int32_t pe);

#endif
