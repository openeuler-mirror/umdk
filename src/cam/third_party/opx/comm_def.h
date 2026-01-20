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


#include "opx/type_traits.h"
#include "opx/ub_queue.h"

namespace opx
{

using Null = std::monostate;

/// SFINAE Helper definitions
template <typename T, typename Invocable, typename = void>
struct InvocableSFINAE
    : std::false_type { };

template <typename T, typename Invocable>
struct InvocableSFINAE<T, Invocable, std::void_t<decltype(declval<Invocable>()(declval<T>()))>>
    : std::true_type
{
    using Type = decltype(declval<Invocable>()(declval<T>()));
};

template <typename T, template <typename> class Tmpl, typename = void>
struct TemplateUsingSFINAE
    : std::false_type { };

template <typename T, template <typename> class Tmpl>
struct TemplateUsingSFINAE<T, Tmpl, std::void_t<Tmpl<T>>>
    : std::true_type
{
    using Type = Tmpl<T>;
};

struct QueUsageInfo
{
    uint32_t buf_num = 0;
    uint32_t buf_size = 0;
};

enum ProcessStatusEnum {
    PROC_NOT_START,
    PROC_NEED_POLLING,
    PROC_DONE
};

// Pipes Declaration Types
template <auto... pipes>
struct Pipes { };

template <auto pipe, typename Seq>
struct RepeatPipes;

template <auto pipe, size_t... I>
struct RepeatPipes<pipe, std::index_sequence<I...>> {
    using Type = Pipes<((void)I, pipe)...>;
};

template <auto pipe, size_t N>
using RepPipes = typename RepeatPipes<pipe, std::make_index_sequence<N>>::Type;

/// ProcessParam definition
template <typename SrcPipes, typename DstPipes>
struct ProcessParam;

template <template <auto...> class Vs, auto... src_pipe, auto... dst_pipe>
struct ProcessParam<Vs<src_pipe...>, Vs<dst_pipe...>>
{
    static_assert(sizeof...(src_pipe) == sizeof...(dst_pipe),
        "The src_pipe list must have the same len as the dst_pipe list!"
    );

    using SrcPipes = Vs<src_pipe...>;
    using DstPipes = Vs<dst_pipe...>;
    static constexpr size_t pipe_num = sizeof...(src_pipe);

    template <typename T>
    struct MemberDeducedTrait;

    template <size_t... I>
    struct MemberDeducedTrait<std::index_sequence<I...>>
    {
        static constexpr auto src_pipe_tp = make_tuple(src_pipe...);
        static constexpr auto dst_pipe_tp = make_tuple(dst_pipe...);
        template <size_t J>
        using Item = UBQue<std::get<J>(src_pipe_tp), std::get<J>(dst_pipe_tp)>;
        using QueTp = tuple<Item<I>...>;
        using QueRefTp = tuple<std::add_lvalue_reference_t<Item<I>>...>;
    };

    using QueTpType = typename MemberDeducedTrait<
        std::make_index_sequence<pipe_num>>::QueTp;

    using QueRefTpType = typename MemberDeducedTrait<
        std::make_index_sequence<pipe_num>>::QueRefTp;

public:
    /// Data members
    QueRefTpType que_tuple;

    /// Methods
    template <typename... Args>
    OPX_DEVICE
    ProcessParam(Args&&... args) :
        que_tuple(forward<Args>(args)...)
    { }

    template <size_t... I>
    OPX_DEVICE
    ProcessParam(std::index_sequence<I...>, QueTpType& inst) :
        ProcessParam(get<I>(inst)...)
    { }

    OPX_DEVICE
    ProcessParam(QueTpType& inst) :
        ProcessParam(std::make_index_sequence<pipe_num>(), inst)
    { }
};

template <template <auto...> class Vs, auto... src_pipe, typename T>
struct ProcessParam<Vs<src_pipe...>, T>
{
    using SrcPipes = Vs<src_pipe...>;
    using DstPipes = T;
    static constexpr size_t pipe_num = sizeof...(src_pipe);
};

template <template <auto...> class Vs, typename T, auto... dst_pipe>
struct ProcessParam<T, Vs<dst_pipe...>>
{
    using SrcPipes = T;
    using DstPipes = Vs<dst_pipe...>;
    static constexpr size_t pipe_num = sizeof...(dst_pipe);
};

using NoneParam = ProcessParam<Pipes<>, Pipes<>>;

} // end namespace opx


#define OPX_INPUT_PARAM_DECLARE(...) \
    template <typename SrcPipes> \
    using InputParam = opx::ProcessParam<SrcPipes, opx::Pipes<__VA_ARGS__>>

#define OPX_REP_INPUT_PARAM_DECLARE(PIPE, N) \
    template <typename SrcPipes> \
    using InputParam = opx::ProcessParam<SrcPipes, opx::RepPipes<PIPE, N>>

#define OPX_OUTPUT_PARAM_DECLARE(...) \
    template <typename DstPipes> \
    using OutputParam = opx::ProcessParam<opx::Pipes<__VA_ARGS__>, DstPipes>

#define OPX_REP_OUTPUT_PARAM_DECLARE(PIPE, N) \
    template <typename DstPipes> \
    using OutputParam = opx::ProcessParam<opx::RepPipes<PIPE, N>, DstPipes>

#define OPX_PROCESS_TEMPLATE \
    template <typename SrcPipes, typename DstPipes>

#define OPX_PROCESS_ARGLIST(IN_NAME, OUT_NAME) \
    InputParam<SrcPipes>& IN_NAME, OutputParam<DstPipes>& OUT_NAME

#define OPX_DEFAULT_PROCESS_ARGLIST \
    OPX_PROCESS_ARGLIST(input, output)

#define OPX_NULL_PROCESS_ARGLIST \
    const opx::NoneParam&, const opx::NoneParam&
