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


#include "opx/data_looper_ctx.h"

namespace opx
{

template <typename T, typename U>
struct IsSameSignatureMemberFunc : std::false_type { };

template <
    typename R1, typename C1, typename... Args1,
    typename R2, typename C2, typename... Args2
>
struct IsSameSignatureMemberFunc<R1(C1::*)(Args1...), R2(C2::*)(Args2...)> :
    std::bool_constant<
        std::is_same_v<R1, R2> &&
        std::is_same_v<tuple<Args1...>, tuple<Args2...>>
    >
{
    using Ret1 = R1;
    using Ret2 = R2;
    using Class1 = C1;
    using Class2 = C2;
    using Arguments1 = tuple<Args1...>;
    using Arguments2 = tuple<Args2...>;
};

template <typename T, typename U>
struct IsSameSignDiffClassMemberFunc {
    static constexpr bool value = []() {
        using Trait = IsSameSignatureMemberFunc<T, U>;
        if constexpr (Trait::value) {
            return !std::is_same_v<typename Trait::Class1, typename Trait::Class2>;
        }
        return false;
    }();
};


enum DataLooperCallbackEnum
{
    EPILOGUE_PRE_LOOP_CB,
    EPILOGUE_PST_LOOP_CB,
    EPILOGUE_PRE_GROUP_LOOP_CB,
    EPILOGUE_PST_GROUP_LOOP_CB,
    EPILOGUE_PRE_BLOCK_LOOP_CB,
    EPILOGUE_PST_BLOCK_LOOP_CB,
    EPILOGUE_PRE_TILE_LOOP_CB,
    EPILOGUE_PST_TILE_LOOP_CB
};

template <size_t Index_, typename Fn_>
struct CallbackItem
{
    static constexpr auto Index = Index_;
    using Fn = Fn_;

    Fn fn;
};


template <
    typename BlockSwizzle,
    typename TileSwizzle,
    typename CallbackTuple,
    typename Derived
>
class DataLooper;

template <
    typename BlockSwizzle,
    typename TileSwizzle,
    typename... Callback,
    typename Derived
>
class DataLooper<
    BlockSwizzle,
    TileSwizzle,
    tuple<Callback...>,
    Derived
>
{
public:
    using Context = typename LooperContextTrait<Derived>::Type;

public:
    OPX_DEVICE
    DataLooper()
    {
        ctx.block_num = get_block_num();
        ctx.block_idx = get_block_idx();
        ctx.sub_block_num = get_subblockdim();
        ctx.sub_block_idx = get_subblockid();
    }

    OPX_DEVICE
    void Reset()
    {
        ctx.Reset();
    }

    OPX_DEVICE
    void DoEpilogueLoop()
    {
        if (ctx.process_state == PROC_NEED_POLLING) {
            goto yield_enter;
        } else if (ctx.process_state == PROC_DONE) {
            goto yield_exit;
        }

        ctx.process_state = PROC_NEED_POLLING;

        InvokeCallback<EPILOGUE_PRE_LOOP_CB>(static_cast<const Context&>(ctx));

        for (ctx.group_loop_i = 0; ctx.group_loop_i < ctx.group_list_len; ctx.group_loop_i++) {
            ctx.group_m = GetGroupListValue(ctx.group_loop_i);
            UpdateBlockSwizzle();
            ctx.block_loop_cnt = block_swizzle.GetCoreLoops();
            if (ctx.block_idx >= ctx.group_start_block_idx) {
                ctx.block_loop_start_i = ctx.block_idx - ctx.group_start_block_idx;
            } else {
                ctx.block_loop_start_i = ctx.block_idx + ctx.block_num - ctx.group_start_block_idx;
            }

            InvokeCallback<EPILOGUE_PRE_GROUP_LOOP_CB>(static_cast<const Context&>(ctx));

            for (ctx.block_loop_i = ctx.block_loop_start_i; ctx.block_loop_i < ctx.block_loop_cnt;
                 ctx.block_loop_i += ctx.block_num) {

                GetCoordAndShapeFromBlockSwizzle();
                ctx.block_offset = ctx.block_coord * ctx.block_shape;

                InvokeCallback<EPILOGUE_PRE_BLOCK_LOOP_CB>(static_cast<const Context&>(ctx));

                tile_swizzle = TileSwizzle(ctx.actual_block_shape, ctx.tile_shape);
                ctx.tile_loop_cnt = tile_swizzle.GetLoops();
                for (ctx.tile_loop_i = ctx.sub_block_idx; ctx.tile_loop_i < ctx.tile_loop_cnt;
                     ctx.tile_loop_i += ctx.sub_block_num) {

                    ctx.tile_coord = tile_swizzle.GetTileCoord(ctx.tile_loop_i);
                    ctx.actual_tile_shape = tile_swizzle.GetActualTileShape(ctx.tile_coord);
                    ctx.tile_offset_in_block = ctx.tile_coord * ctx.tile_shape;
                    ctx.tile_offset = ctx.block_offset + ctx.tile_offset_in_block;

                    InvokeCallback<EPILOGUE_PRE_TILE_LOOP_CB>(static_cast<const Context&>(ctx));

                    goto yield_exit;
yield_enter:

                    InvokeCallback<EPILOGUE_PST_TILE_LOOP_CB>(static_cast<const Context&>(ctx));
                    ctx.tile_loop_times++;
                }

                InvokeCallback<EPILOGUE_PST_BLOCK_LOOP_CB>(static_cast<const Context&>(ctx));
                ctx.block_loop_times++;
            }

            InvokeCallback<EPILOGUE_PST_GROUP_LOOP_CB>(static_cast<const Context&>(ctx));
            ctx.group_m_sum += ctx.group_m;
            ctx.group_start_block_idx = (ctx.group_start_block_idx + ctx.block_loop_cnt) % ctx.block_num;
        }

        InvokeCallback<EPILOGUE_PST_LOOP_CB>(static_cast<const Context&>(ctx));
        ctx.process_state = PROC_DONE;

yield_exit:
        return;
    }

    OPX_DEVICE
    ProcessStatusEnum GetState()
    {
        return ctx.process_state;
    }

protected:
    // CRTP + constexpr IILM
#define IS_DERIVED_OVERRIDED(func_name)                                         \
    []() {                                                                      \
        constexpr auto checker = [](auto&& obj) constexpr ->                    \
            decltype(&remove_cvref_t<decltype(obj)>::func_name) { };            \
        using CheckTrait = InvocableSFINAE<Derived, decltype(checker)>;         \
        if constexpr (CheckTrait::value) {                                      \
            return IsSameSignDiffClassMemberFunc<                               \
                decltype(&std::remove_pointer_t<decltype(this)>::func_name),    \
                typename CheckTrait::Type                                       \
            >::value;                                                           \
        } else {                                                                \
            return false;                                                       \
        }                                                                       \
    }()

    OPX_DEVICE
    uint32_t GetGroupListValue(uint32_t group_idx)
    {
        if constexpr (!IS_DERIVED_OVERRIDED(GetGroupListValue)) {
            return ctx.problem_shape_m;
        } else {
            return static_cast<Derived*>(this)->GetGroupListValue(group_idx);
        }
    }

    OPX_DEVICE
    void UpdateBlockSwizzle()
    {
        if constexpr (!IS_DERIVED_OVERRIDED(UpdateBlockSwizzle)) {
            ctx.in_group_problem_shape = GemmCoord{ctx.group_m, ctx.problem_shape_n, ctx.problem_shape_k};
            block_swizzle.Update(ctx.in_group_problem_shape, ctx.block_shape);
        } else {
            return static_cast<Derived*>(this)->UpdateBlockSwizzle();
        }
    }

    OPX_DEVICE
    void GetCoordAndShapeFromBlockSwizzle()
    {
        if constexpr (!IS_DERIVED_OVERRIDED(GetCoordAndShapeFromBlockSwizzle)) {
            ctx.gmm_block_coord = block_swizzle.GetBlockCoord(ctx.block_loop_i);
            ctx.gmm_actual_block_shape = block_swizzle.GetActualBlockShape(ctx.gmm_block_coord);
            ctx.block_coord = ctx.gmm_block_coord.GetCoordMN();
            ctx.actual_block_shape = ctx.gmm_actual_block_shape.GetCoordMN();
        } else {
            return static_cast<Derived*>(this)->GetCoordAndShapeFromBlockSwizzle();
        }
    }

    template <size_t Index, typename... Args>
    OPX_DEVICE
    void InvokeCallback(Args&&... args)
    {
        constexpr size_t tpsz = std::tuple_size_v<decltype(callbacks)>;
        if constexpr (tpsz > 0) {
            InvokeCallbackImpl<Index, tpsz - 1>(forward<Args>(args)...);
        }
    }

    template <size_t Index, size_t I, typename... Args>
    OPX_DEVICE
    void InvokeCallbackImpl(Args&&... args)
    {
        using CBItem = std::tuple_element_t<I, decltype(callbacks)>;
        if constexpr ((size_t)CBItem::Index == Index) {
            if constexpr (is_invocable_v<typename CBItem::Fn, Args...>) {
                std::get<I>(callbacks).fn(forward<Args>(args)...);
            } else {
                std::get<I>(callbacks).fn(); // Try void parameters, otherwise failed
            }
        } else if constexpr (I > 0) {
            InvokeCallbackImpl<Index, I - 1>(forward<Args>(args)...);
        }
    }

public:
    tuple<Callback...> callbacks;
    Context ctx;

    BlockSwizzle block_swizzle;
    TileSwizzle tile_swizzle;
};

}; // end namespace opx
