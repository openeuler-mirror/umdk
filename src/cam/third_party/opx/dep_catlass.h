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


#ifndef OPX_USE_OLD_CATLASS

#include "catlass/epilogue/tile/copy_ub_to_gm.hpp"
#include "catlass/epilogue/tile/copy_gm_to_ub.hpp"
#include "catlass/epilogue/tile/tile_swizzle.hpp"
#include "catlass/gemm/block/block_swizzle.hpp"
#include "catlass/gemm/gemm_type.hpp"
#include "catlass/gemm_coord.hpp"
#include "catlass/layout/layout.hpp"
#include "catlass/matrix_coord.hpp"

#define CATLASS_NS Catlass

#else

#include "catlass/act/epilogue/tile/copy_ub_to_gm.hpp"
#include "catlass/act/epilogue/tile/copy_gm_to_ub.hpp"
#include "catlass/act/epilogue/tile/tile_swizzle.hpp"
#include "catlass/act/gemm/block/block_swizzle.hpp"
#include "catlass/act/gemm/gemm_type.hpp"
#include "catlass/act/gemm_coord.hpp"
#include "catlass/act/layout/layout.hpp"
#include "catlass/act/matrix_coord.hpp"

#define CATLASS_NS Act

#endif

namespace opx
{

using namespace CATLASS_NS;
using namespace CATLASS_NS::Epilogue::Tile;
using namespace CATLASS_NS::Gemm;
using namespace CATLASS_NS::Gemm::Block;
using namespace CATLASS_NS::layout;

} // end namespace opx
