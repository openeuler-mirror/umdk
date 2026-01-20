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

#include "opx/dep_catlass.h"
#include "opx/type_traits.h"

namespace opx
{

template <
    uint32_t LENGTH_ = 1
>
struct VectorShape
{
    static constexpr uint32_t LENGTH = LENGTH_;
    static constexpr int64_t COUNT = LENGTH;

    OPX_HOST_DEVICE
    static auto ToCoord()
    {
        return MakeCoord(LENGTH);
    }
};

struct VectorCoord : public CATLASS_NS::Coord<1, uint32_t>
{
    using Index = uint32_t;

    using Base = Coord<1, Index>;

    using LongIndex = typename Base::LongIndex;

    static constexpr uint32_t LENGTH_INDEX = 0;

    OPX_HOST_DEVICE
    VectorCoord() {}

    OPX_HOST_DEVICE
    VectorCoord(Coord<1, Index> const &coord) : Base(coord) {}

    OPX_HOST_DEVICE
    VectorCoord(Index length) : Base(MakeCoord(length)) {}

    OPX_HOST_DEVICE
    VectorCoord(LongIndex length) : Base(MakeCoord(Index(length))) {}

    OPX_HOST_DEVICE
    Index const &length() const { return this->At(LENGTH_INDEX); }

    OPX_HOST_DEVICE
    Index &length() { return this->At(LENGTH_INDEX); }

    OPX_HOST_DEVICE
    VectorCoord operator+(Base const &b) const
    {
        return VectorCoord(Base::operator+(b));
    }

    OPX_HOST_DEVICE
    VectorCoord &operator+=(Base const &b)
    {
        Base::operator+=(b);
        return *this;
    }
};

} // end namespace opx
