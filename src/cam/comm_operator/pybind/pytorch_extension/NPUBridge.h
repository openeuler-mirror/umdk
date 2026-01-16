/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: npu bridge header file
 * Create: 2026-01-13
 * Note:
 * History: 2026-01-13 create npu bridge header file
 */

#pragma once
#include "NPUStorageImpl.h"
#include <c10/core/StorageImpl.h>

namespace umdk {

class NPUBridge {
public:
    // at::tensor to NPUStorageImpl
    static NPUStorageImpl *GetNpuStorageImpl(const at::Tensor &tensor);

    // c10::StorageImpl to NPUStorageImpl
    static NPUStorageImpl *GetNpuStorageImpl(c10::StorageImpl *storageImpl);

    // c10::Storage to NPUStorageImpl
    static NPUStorageImpl *GetNpuStorageImpl(c10::Storage &&storage);

    // tensor to NPUStorageDesc
    static NPUStorageDesc &GetNpuStorageImplDesc(const at::Tensor &tensor);
};
} // namespace umdk
