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
template <typename T> ACLSHMEM_DEVICE void aclshmemx_roce_quiet(uint32_t pe, __ubuf__ T *buf, uint32_t sync_id);

#endif
