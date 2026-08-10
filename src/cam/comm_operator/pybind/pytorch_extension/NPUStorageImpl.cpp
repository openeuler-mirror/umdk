/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: npu storage implementation file
 * Create: 2026-01-13
 * Note:
 * History: 2026-01-13 create npu storage implementation file
 */

#include "NPUStorageImpl.h"

namespace umdk {

NPUStorageImpl::NPUStorageImpl(use_byte_size_t use_byte_size, size_t size_bytes, at::DataPtr data_ptr,
                               at::Allocator *allocator, bool resizable)
    : c10::StorageImpl(use_byte_size, size_bytes, at::DataPtr(std::move(data_ptr)), allocator, resizable)
{
}

void NPUStorageImpl::release_resources()
{
    StorageImpl::release_resources();
}

c10::intrusive_ptr<c10::StorageImpl> make_npu_storage_impl(c10::StorageImpl::use_byte_size_t, c10::SymInt size_bytes,
                                                           c10::DataPtr data_ptr, c10::Allocator *allocator,
                                                           bool resizable)
{
    if (data_ptr == nullptr) {
        data_ptr = allocator->allocate(size_bytes.as_int_unchecked());
    }
    // Correctly create NPUStorageImpl object.
    c10::intrusive_ptr<c10::StorageImpl> npu_storage_impl = c10::make_intrusive<NPUStorageImpl>(
        c10::StorageImpl::use_byte_size_t(), size_bytes.as_int_unchecked(), std::move(data_ptr), allocator, resizable);
    // There is no need to consider the NPUStorageDesc information, it will be carried out in the subsequent processing.
    return npu_storage_impl;
}

} // namespace umdk
