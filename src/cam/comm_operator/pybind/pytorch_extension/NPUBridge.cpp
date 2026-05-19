/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: npu bridge file
 * Create: 2026-01-13
 * Note:
 * History: 2026-01-13 create npu bridge file
 *
 * Part of codes modified from: DIOPI
 * Original Source: https://github.com/DeepLink-org/deeplink.framework.git
 * Licensed under BSD-3-Clause. (the "License")
 * Copyright (c) 2024, DeepLink.
 */

#include "NPUBridge.h"

namespace umdk {
NPUStorageImpl *NPUBridge::GetNpuStorageImpl(c10::StorageImpl *storageImpl)
{
    return static_cast<NPUStorageImpl *>(storageImpl);
}

NPUStorageImpl *NPUBridge::GetNpuStorageImpl(c10::Storage &&storage)
{
    return static_cast<NPUStorageImpl *>(storage.unsafeGetStorageImpl());
}

NPUStorageImpl *NPUBridge::GetNpuStorageImpl(const at::Tensor &tensor)
{
    return static_cast<NPUStorageImpl *>(tensor.storage().unsafeGetStorageImpl());
}

NPUStorageDesc &NPUBridge::GetNpuStorageImplDesc(const at::Tensor &tensor)
{
    return static_cast<NPUStorageImpl *>(tensor.storage().unsafeGetStorageImpl())->npu_desc_;
}
} // namespace umdk
