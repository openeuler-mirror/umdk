// SPDX-License-Identifier: MIT
// Common required ND tensor port used by the Ascend950 AFD OpDefs.
#pragma once

#include "register/op_def_registry.h"

namespace ops {
inline void RequiredAfdNdTensor(OpParamDef &port, ge::DataType dtype)
{
    port.ParamType(REQUIRED).DataType({dtype}).Format({ge::FORMAT_ND}).UnknownShapeFormat({ge::FORMAT_ND});
}
} // namespace ops
