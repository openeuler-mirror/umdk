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


#include "opx/data_looper.h"
#include "opx/matrix_data_ctx.h"

namespace opx
{

template <
    typename BlockSwizzle = GemmIdentityBlockSwizzle<>,
    typename TileSwizzle = EpilogueIdentityTileSwizzle,
    typename CallbackTuple = tuple<>,
    typename ReaderTuple = tuple<>,
    typename GroupList = Null
>
class MatrixOpStart;

#define MATRIX_OP_START_PART_SPEC_TEMPLATE_ARGS \
    typename BlockSwizzle, \
    typename TileSwizzle, \
    typename... Callback, \
    typename... Reader, \
    typename GroupList \

#define MATRIX_OP_START_PART_SPEC_ARGS \
    BlockSwizzle, \
    TileSwizzle, \
    tuple<Callback...>, \
    tuple<Reader...>, \
    GroupList \

#define MATRIX_OP_START_BASE \
DataLooper< \
    BlockSwizzle, \
    TileSwizzle, \
    tuple<Callback...>, \
    MatrixOpStart<MATRIX_OP_START_PART_SPEC_ARGS>>

/// @brief Override the default ctx in base
template <MATRIX_OP_START_PART_SPEC_TEMPLATE_ARGS>
struct LooperContextTrait<MatrixOpStart<MATRIX_OP_START_PART_SPEC_ARGS>>
{
    using Type = MatrixDataContext;
};

template <MATRIX_OP_START_PART_SPEC_TEMPLATE_ARGS>
class MatrixOpStart<MATRIX_OP_START_PART_SPEC_ARGS> : public MATRIX_OP_START_BASE
{
public:
    static constexpr bool NEED_POLLING = true;

    OPX_INPUT_PARAM_DECLARE();
    OPX_OUTPUT_PARAM_DECLARE(Reader::SRC_PIPE...);

    // Type definition
    using Self = MatrixOpStart<MATRIX_OP_START_PART_SPEC_ARGS>;
    using Base = MATRIX_OP_START_BASE;

public:
    struct Factory
    {
        using ProductType = Self;
        ProductType product;

    public:
        OPX_DEVICE
        Factory() = default;

        template <
            typename BlockSwizzle_,
            typename TileSwizzle_,
            typename... Callback_,
            typename... Reader_,
            typename GroupList_
        >
        OPX_DEVICE
        Factory(
            MatrixOpStart<
                BlockSwizzle_,
                TileSwizzle_,
                tuple<Callback_...>,
                tuple<Reader_...>,
                GroupList_
            >&& other)
        {
            product.ctx = move(other.ctx);
            product.is_accu_sum_group_list = other.is_accu_sum_group_list;
            if constexpr (std::is_same_v<decltype(product.block_swizzle), decltype(other.block_swizzle)>) {
                product.block_swizzle = move(other.block_swizzle);
            }
            if constexpr (std::is_same_v<decltype(product.tile_swizzle), decltype(other.tile_swizzle)>) {
                product.tile_swizzle = move(other.tile_swizzle);
            }
            if constexpr (std::is_same_v<decltype(product.callbacks), decltype(other.callbacks)>) {
                product.callbacks = move(other.callbacks);
            }
            if constexpr (std::is_same_v<decltype(product.readers), decltype(other.readers)>) {
                product.readers = move(other.readers);
            }
            if constexpr (std::is_same_v<decltype(product.group_list), decltype(other.group_list)>) {
                product.group_list = move(other.group_list);
            }
        }

        OPX_DEVICE
        decltype(auto) SetProblemShape(uint32_t m, uint32_t n)
        {
            product.ctx.problem_shape_m = m;
            product.ctx.problem_shape_n = n;
            return *this;
        }

        template <typename GroupList_>
        OPX_DEVICE
        decltype(auto) SetProblemShape(GroupList_&& group_list, uint32_t group_list_len, uint32_t n,
            bool is_accu_sum_group_list = false)
        {
            using NewFactory = typename MatrixOpStart<
                BlockSwizzle,
                TileSwizzle,
                tuple<Callback...>,
                tuple<Reader...>,
                remove_cvref_t<GroupList_>
            >::Factory;

            NewFactory factory{move(product)};
            factory.product.is_accu_sum_group_list = is_accu_sum_group_list;
            factory.product.group_list = forward<GroupList_>(group_list);
            factory.product.ctx.group_list_len = group_list_len;
            factory.product.ctx.problem_shape_n = n;
            return factory;
        }

        template <typename BlockSwizzle_>
        OPX_DEVICE
        decltype(auto) SetBlockSwizzle()
        {
            using NewFactory = typename MatrixOpStart<
                BlockSwizzle_,
                TileSwizzle,
                tuple<Callback...>,
                tuple<Reader...>,
                GroupList
            >::Factory;
            NewFactory factory{move(product)};
            return factory;
        }

        OPX_DEVICE
        decltype(auto) SetBlockShape(const MatrixCoord& block_shape)
        {
            product.ctx.block_shape = block_shape;
            return *this;
        }

        OPX_DEVICE
        decltype(auto) SetBlockInfo(uint32_t block_num, uint32_t block_idx)
        {
            product.ctx.block_num = block_num;
            product.ctx.block_idx = block_idx;
            return *this;
        }

        template <typename TileSwizzle_>
        OPX_DEVICE
        decltype(auto) SetTileSwizzle()
        {
            using NewFactory = typename MatrixOpStart<
                BlockSwizzle,
                TileSwizzle_,
                tuple<Callback...>,
                tuple<Reader...>,
                GroupList
            >::Factory;
            NewFactory factory{move(product)};
            return factory;
        }

        OPX_DEVICE
        decltype(auto) SetTileShape(const MatrixCoord& tile_shape)
        {
            product.ctx.tile_shape = tile_shape;
            if (product.ctx.block_shape == MatrixCoord{}) {
                product.ctx.block_shape = tile_shape;
            }
            return *this;
        }

        OPX_DEVICE
        decltype(auto) SetTileInfo(uint32_t sub_block_num, uint32_t sub_block_idx)
        {
            product.ctx.sub_block_num = sub_block_num;
            product.ctx.sub_block_idx = sub_block_idx;
            return *this;
        }

        template <typename Reader_>
        OPX_DEVICE
        decltype(auto) AddReader(Reader_&& reader)
        {
            using NewFactory = typename MatrixOpStart<
                BlockSwizzle,
                TileSwizzle,
                tuple<Callback...>,
                tuple<Reader..., Reader_>,
                GroupList
            >::Factory;

            NewFactory factory{move(product)};
            factory.product.readers = apply([&](auto&&... args) {
                return make_tuple(
                    move(args)...,
                    forward<Reader_>(reader)
                );
            }, move(product.readers));
            return factory;
        }

        template <DataLooperCallbackEnum Index, typename Callback_>
        OPX_DEVICE
        decltype(auto) RegisterCallback(Callback_&& cb)
        {
            using NewFactory = typename MatrixOpStart<
                BlockSwizzle,
                TileSwizzle,
                tuple<Callback..., CallbackItem<Index, Callback_>>,
                tuple<Reader...>,
                GroupList
            >::Factory;

            NewFactory factory{move(product)};
            factory.product.callbacks = apply([&](auto&&... args) {
                return tuple{
                    move(args)...,
                    CallbackItem<Index, Callback_>{ forward<Callback_>(cb) }
                };
            }, move(product.callbacks));
            return factory;
        }

        OPX_DEVICE
        auto Build()
        {
            return product;
        }
    };

    OPX_DEVICE
    static Factory GetFactory()
    {
        return Factory{};
    }

public:
    template <size_t I>
    OPX_DEVICE
    QueUsageInfo GetOutQueUsage(const MatrixCoord& tile_shape) {
        return std::get<I>(readers).GetQueUsage(tile_shape);
    }

    OPX_PROCESS_TEMPLATE
    OPX_DEVICE
    uint32_t Process(OPX_PROCESS_ARGLIST(input, output))
    {
        Base::DoEpilogueLoop();
        auto state = Base::GetState();
        if (state != PROC_DONE) {
            CopyIn<decltype(output.que_tuple), sizeof...(Reader)>(output.que_tuple);
        }
        return state;
    }

    template <typename QueTuple, size_t I>
    OPX_DEVICE
    void CopyIn(QueTuple& que_tuple)
    {
        if constexpr (I > 0) {
            CopyIn<QueTuple, I - 1>(que_tuple);
        }

        if constexpr (I < sizeof...(Reader)) {
            using Element = typename std::tuple_element_t<I, decltype(readers)>::Element;
            auto &in_que = std::get<I>(que_tuple);
            auto tensor = in_que.template AllocTensor<Element>();
            std::get<I>(readers).DoCopy(ctx, tensor);
            in_que.EnQue(tensor);
        }
    }

    OPX_DEVICE
    const MatrixDataContext& GetContext() const
    {
        return ctx;
    }

    OPX_DEVICE
    void SetLogicCoreGroup(const LogicCoreGroup& grp)
    {
        ctx.block_num = grp.lgc_core_num;
        ctx.block_idx = grp.lgc_core_idx;
        ctx.sub_block_num = 1;
        ctx.sub_block_idx = 0;
    }

    template <typename Context>
    OPX_DEVICE
    void SetContext(const Context&)
    {
        // noop
    }

protected:
    // CRTP enable access from Base
    friend Base;

    OPX_DEVICE
    uint32_t GetGroupListValue(uint32_t group_idx)
    {
        if constexpr (!std::is_same_v<Null, GroupList>) {
            uint32_t group_m_val = group_list.GetValue(group_idx);
            if (!is_accu_sum_group_list) {
                return group_m_val;
            } else {
                return group_m_val - ctx.group_m_sum;
            }
        } else {
            return ctx.problem_shape_m;
        }
    }

    OPX_DEVICE
    void UpdateBlockSwizzle()
    {
        ctx.in_group_problem_shape = MatrixCoord{ctx.group_m, ctx.problem_shape_n};
        block_swizzle.Update(
            GemmCoord{ctx.in_group_problem_shape.row(), ctx.in_group_problem_shape.column(), 0},
            ctx.block_shape
        );
    }

    OPX_DEVICE
    void GetCoordAndShapeFromBlockSwizzle()
    {
        auto gmm_block_coord = block_swizzle.GetBlockCoord(ctx.block_loop_i);
        auto gmm_actual_block_shape = block_swizzle.GetActualBlockShape(gmm_block_coord);
        ctx.block_coord = gmm_block_coord.GetCoordMN();
        ctx.actual_block_shape = gmm_actual_block_shape.GetCoordMN();
    }

public:
    using Base::ctx;
    using Base::block_swizzle;
    GroupList group_list;
    tuple<Reader...> readers;
    bool is_accu_sum_group_list = false;
};

#undef MATRIX_OP_START_BASE
#undef MATRIX_OP_START_PART_SPEC_ARGS
#undef MATRIX_OP_START_PART_SPEC_TEMPLATE_ARGS

};
