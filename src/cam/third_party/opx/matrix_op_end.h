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


#include "opx/matrix_data_ctx.h"

namespace opx
{

// MatrixOpEnd definition
template <
    typename WriterTuple = tuple<>
> class MatrixOpEnd;

template <
    typename... Writer
>
class MatrixOpEnd<
    tuple<Writer...>
>
{
public:
    OPX_INPUT_PARAM_DECLARE(Writer::DST_PIPE...);
    OPX_OUTPUT_PARAM_DECLARE();

    // Type definition
    using Self = MatrixOpEnd<tuple<Writer...>>;

public:
    struct Factory
    {
        template <typename Writer_>
        OPX_DEVICE
        decltype(auto) AddWriter(Writer_&& writer)
        {
            using NewFactory = typename MatrixOpEnd<
                tuple<Writer..., Writer_>
            >::Factory;

            NewFactory factory;
            factory.product.writers = apply([&](auto&&... args) {
                return make_tuple(
                    move(args)...,
                    forward<Writer_>(writer)
                );
            }, move(product.writers));
            return factory;
        }

        OPX_DEVICE
        auto Build()
        {
            return product;
        }

    public:
        Self product;
    };

    OPX_DEVICE
    static Factory GetFactory()
    {
        return Factory{};
    }

public:
    template <size_t I>
    OPX_DEVICE
    QueUsageInfo GetInQueUsage(const MatrixCoord& tile_shape) {
        return std::get<I>(writers).GetQueUsage(tile_shape);
    }

    OPX_PROCESS_TEMPLATE
    OPX_DEVICE
    void Process(OPX_PROCESS_ARGLIST(input, output))
    {
        CopyOut<decltype(input.que_tuple), sizeof...(Writer)>(input.que_tuple);
    }

    template <typename QueTuple, size_t I>
    OPX_DEVICE
    void CopyOut(QueTuple &que_tuple)
    {
        if constexpr (I > 0) {
            CopyOut<QueTuple, I - 1>(que_tuple);
        }

        if constexpr (I < sizeof...(Writer)) {
            using Element = typename std::tuple_element_t<I, decltype(writers)>::Element;
            auto &out_que = std::get<I>(que_tuple);
            auto tensor = out_que.template DeQue<Element>();
            std::get<I>(writers).DoCopy(*ctx, tensor);
            out_que.FreeTensor(tensor);
        }
    }

    OPX_DEVICE
    void SetContext(const MatrixDataContext &ctx_)
    {
        ctx = &ctx_;
    }

public:
    const MatrixDataContext *ctx = nullptr;
    tuple<Writer...> writers;
};

}; /* end namespace opx */
