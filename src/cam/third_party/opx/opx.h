/*
* Copyright (c) 2025 Huawei Technologies Co., Ltd.
* This file is a part of the CANN Open Software.
* Licensed under CANN Open Software License Agreement Version 1.0 (the "License").
* Please refer to the License for details. You may not use this file except in compliance with the License.
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
* INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
* See LICENSE in the root of the software repository for the full text of the License.
*/

#pragma once

#include "kernel_operator.h"

#include "opx/type_traits.h"
#include "opx/ub_queue.h"
#include "opx/comm_def.h"
#include "opx/fused.h"
#include "opx/dep_catlass.h"
#include "opx/swizzle.h"
#include "opx/matrix_data_reader.h"
#include "opx/matrix_data_writer.h"
#include "opx/matrix_op_start.h"
#include "opx/matrix_op_end.h"
#include "opx/vector_coord.h"
#include "opx/vector_data_ctx.h"
#include "opx/vector_op_start.h"
