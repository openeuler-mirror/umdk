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


#include "opx/comm_def.h"

namespace opx
{

template <
    typename PreOp,
    typename PstOp
>
struct DeducedProcessParamTrait
{
    template <typename, typename, typename = void>
    struct HasMatchedParamDef
        : std::false_type { };

    template <typename T, typename U>
    struct HasMatchedParamDef<T, U,
        std::enable_if_t<std::is_same_v<typename T::OutputParam, typename U::InputParam>>>
        : std::true_type { };

    template <typename, typename, typename = void>
    struct HasMatchedTemplateParamDef
        : std::false_type { };

    template <typename T, typename U>
    struct HasMatchedTemplateParamDef<T, U,
        std::enable_if_t<
            T::template OutputParam<void>::pipe_num ==
            U::template InputParam<void>::pipe_num>>
        : std::true_type { };

    static_assert(
        HasMatchedParamDef<PreOp, PstOp>::value ^
        HasMatchedTemplateParamDef<PreOp, PstOp>::value,
        "PreOp and PstOp must have the matched param def!"
    );

    template <bool cond, typename T, typename U>
    struct ConditionalTrait;

    template <typename T, typename U>
    struct ConditionalTrait<true, T, U> {
        using Type = typename T::OutputParam;
        static constexpr size_t ub_que_num = 0;
    };

    template <typename T, typename U>
    struct ConditionalTrait<false, T, U> {
        using Type = ProcessParam<
            typename T::template OutputParam<void>::SrcPipes,
            typename U::template InputParam<void>::DstPipes
        >;
        static constexpr size_t ub_que_num = Type::pipe_num;
    };

    static constexpr bool is_template_param_def = HasMatchedParamDef<PreOp, PstOp>::value;
    using CondTrait = ConditionalTrait<is_template_param_def, PreOp, PstOp>;
    using Type = typename CondTrait::Type;
    static constexpr size_t ub_que_num = CondTrait::ub_que_num;
};

template <typename T>
struct HasNoneInput {
    template <typename U>
    using Checker = std::enable_if_t<remove_cvref_t<U>::template InputParam<void>::pipe_num == 0>;

    static constexpr bool value = TemplateUsingSFINAE<T, Checker>::value;
};

template <typename T>
struct HasNoneOutput {
    template <typename U>
    using Checker = std::enable_if_t<remove_cvref_t<U>::template OutputParam<void>::pipe_num == 0>;

    static constexpr bool value = TemplateUsingSFINAE<T, Checker>::value;
};

template <typename T>
struct IsNeedPolling {
    template <typename U>
    using Checker = std::enable_if_t<remove_cvref_t<U>::NEED_POLLING>;

    static constexpr bool value = TemplateUsingSFINAE<T, Checker>::value;
};

template <typename T, typename Ctx>
struct CanSetContext {
    template <typename U>
    using Checker = decltype(declval<remove_cvref_t<U>>().SetContext(declval<Ctx>()));

    static constexpr bool value = TemplateUsingSFINAE<T, Checker>::value;
};

template <typename T>
struct CanLazyInit {
    template <typename U>
    using Checker = decltype(declval<remove_cvref_t<U>>().LazyInit());

    static constexpr bool value = TemplateUsingSFINAE<T, Checker>::value;
};

struct LogicCoreGroup
{
    uint32_t lgc_core_num;
    uint32_t lgc_core_idx;
};

template <typename T>
struct CanSetLogicCoreGroup {
    template <typename U>
    using Checker = decltype(declval<remove_cvref_t<U>>().SetLogicCoreGroup(declval<LogicCoreGroup>()));

    static constexpr bool value = TemplateUsingSFINAE<T, Checker>::value;
};

template <typename T>
struct HasTemplateInputParam {
    template <typename U>
    using Checker = typename remove_cvref_t<U>::template InputParam<void>;

    static constexpr bool value = TemplateUsingSFINAE<T, Checker>::value;
};

// FusedVV
template <
    typename PreOp,
    typename PstOp
>
class FusedVV
{
public:
    using PreOpT = remove_cvref_t<PreOp>;
    using PstOpT = remove_cvref_t<PstOp>;

    static_assert(HasTemplateInputParam<PreOpT>::value);
    static_assert(HasTemplateInputParam<PstOpT>::value);
    static_assert(HasNoneOutput<PstOpT>::value, "Unsupport OutputParam is not none!");

    template <typename SrcPipes>
    using InputParam = typename PreOpT::template InputParam<SrcPipes>;

    template <typename DstPipes>
    using OutputParam = typename PstOpT::template OutputParam<DstPipes>;

    using IntermediateParam = typename DeducedProcessParamTrait<PreOpT, PstOpT>::Type;
    using QueTpType = typename IntermediateParam::QueTpType;

    static constexpr bool NEED_POLLING = IsNeedPolling<PreOpT>::value;

protected:
    template <typename T>
    struct IsFusedVVTemplate : std::false_type { };

    template <typename T, typename U>
    struct IsFusedVVTemplate<FusedVV<T, U>>: std::true_type { };

public:
    OPX_DEVICE
    void LazyInit()
    {
        if (is_lazy_inited) {
            return;
        } else {
            is_lazy_inited = true;
        }

        if constexpr (CanLazyInit<PreOpT>::value) {
            pre_op.LazyInit();
        }
        if constexpr (NEED_POLLING) {
            // A polling point is required to provide GetContext() method, return ref
            auto& ctx = pre_op.GetContext();
            pst_op.SetContext(ctx);
            RecurseInitQueues(ctx.tile_shape);
        }
        if constexpr (CanLazyInit<PstOpT>::value) {
            pst_op.LazyInit();
        }
    }

    template <typename T>
    OPX_DEVICE
    void RecurseInitQueues(const T& tile_shape)
    {
        if (is_que_inited) {
            return;
        } else {
            is_que_inited = true;
        }

        InitQueues(*GetTPipePtr(), tile_shape);
        if constexpr (IsFusedVVTemplate<PstOpT>::value) {
            pst_op.RecurseInitQueues(tile_shape);
        }
    }

    template <typename TBufPool, typename T, size_t I = std::tuple_size_v<QueTpType>>
    OPX_DEVICE
    void InitQueues(TBufPool& pool, const T& tile_shape)
    {
        static_assert(I <= std::tuple_size_v<QueTpType>, "Index is out of range!");

        if constexpr (I > 0) {
            InitQueues<TBufPool, T, I - 1>(pool, tile_shape);
        }

        if constexpr (I < std::tuple_size_v<QueTpType>) {
            QueUsageInfo pre_o_q = pre_op.template GetOutQueUsage<I>(tile_shape);
            QueUsageInfo pst_i_q = pst_op.template GetInQueUsage<I>(tile_shape);

            uint32_t max_que_buf_num = AscendC::Std::max(
                pre_o_q.buf_num,
                pst_i_q.buf_num
            );
            uint32_t max_que_buf_size = AscendC::Std::max(
                pre_o_q.buf_size,
                pst_i_q.buf_size
            );

            auto &ub_que = get<I>(que_tp_inst);
            pool.InitBuffer(
                ub_que,
                max_que_buf_num,
                max_que_buf_size
            );
        }
    }

    OPX_DEVICE
    void Reset()
    {
        is_lazy_inited = false;
        is_que_inited = false;
        if constexpr (IsFusedVVTemplate<PstOpT>::value) {
            pst_op.Reset();
        }
    }

    OPX_DEVICE
    void SetLogicCoreGroup(const LogicCoreGroup& grp)
    {
        if constexpr (CanSetLogicCoreGroup<PreOpT>::value) {
            pre_op.SetLogicCoreGroup(grp);
        }
        if constexpr (CanSetLogicCoreGroup<PstOpT>::value) {
            pst_op.SetLogicCoreGroup(grp);
        }
    }

    template <typename PreOp_ = PreOpT>
    OPX_DEVICE
    std::enable_if_t<std::is_same_v<PreOp_, PreOpT> && HasNoneInput<PreOp_>::value, void>
    Process()
    {
        LazyInit();
        NoneParam input;
        NoneParam output;
        (void)Process(input, output);
    }

    template <typename SrcPipes>
    OPX_DEVICE
    uint32_t Process(InputParam<SrcPipes> &input, NoneParam &output)
    {
        IntermediateParam pre_op_output(que_tp_inst);
        if constexpr (NEED_POLLING) {
            pre_op.Reset();
            while (true) {
                auto proc_state = pre_op.Process(input, pre_op_output);
                if (proc_state == PROC_DONE) {
                    break; // no data out
                }
                pst_op.Process(pre_op_output, output);
            }
        } else {
            pre_op.Process(input, pre_op_output);
            pst_op.Process(pre_op_output, output);
        }

        return PROC_DONE;
    }

    template <size_t I, typename T>
    OPX_DEVICE
    QueUsageInfo GetInQueUsage(const T& tile_shape) {
        return pre_op.template GetInQueUsage<I>(tile_shape);
    }

    template <size_t I, typename T>
    OPX_DEVICE
    QueUsageInfo GetOutQueUsage(const T& tile_shape) {
        return pst_op.template GetOutQueUsage<I>(tile_shape);
    }

    template <typename Context>
    OPX_DEVICE
    void SetContext(const Context &ctx)
    {
        if constexpr (CanSetContext<PreOpT, decltype(ctx)>::value) {
            pre_op.SetContext(ctx);
        }

        if constexpr (!IsNeedPolling<PstOpT>::value) {
            // if the pst op is another polling point, don't set context further down
            pst_op.SetContext(ctx);
        }
    }

public:
    PreOp pre_op;
    PstOp pst_op;
    QueTpType que_tp_inst;
    bool is_lazy_inited = false;
    bool is_que_inited = false;
};

template <typename Op, typename... Rest>
OPX_DEVICE
auto MakeFusedVV(Op&& op, Rest&&... rest) {
    static_assert(sizeof...(Rest) > 0, "Cannot create fused_vv from single element!");

    // storage ref if op is l-ref, storage instance if op is r-ref
    if constexpr (sizeof...(Rest) == 1) {
        using Rest0 = std::tuple_element_t<0, tuple<Rest...>>;
        return FusedVV<Op, Rest0>{forward<Op>(op), forward<Rest>(rest)...};
    } else {
        auto tail_fused = MakeFusedVV(forward<Rest>(rest)...);
        return FusedVV<Op, std::decay_t<decltype(tail_fused)>>{forward<Op>(op), move(tail_fused)};
    }
}

// Sequential
template <
    typename... Op
>
class Sequential
{
    static_assert(sizeof...(Op) > 0);

    template <typename T>
    using ProcessCheck = decltype(&declval<T>().Process(declval<NoneParam&>(), declval<NoneParam&>()));

public:
    OPX_DEVICE
    void Process()
    {
        ProcessImpl<std::tuple_size_v<decltype(op_tuple)> - 1>();
    }

    OPX_DEVICE
    void SetLogicCoreGroup(const LogicCoreGroup& grp)
    {
        SetLogicCoreGroupImpl<std::tuple_size_v<decltype(op_tuple)> - 1>(grp);
    }

private:
    template <size_t I>
    OPX_DEVICE
    void ProcessImpl()
    {
        if constexpr (I > 0) {
            ProcessImpl<I - 1>();
        }
        if constexpr (CanLazyInit<decltype(get<I>(op_tuple))>::value) {
            get<I>(op_tuple).LazyInit();
        }
        if constexpr (TemplateUsingSFINAE<decltype(get<I>(op_tuple)), ProcessCheck>::value) {
            NoneParam none_input, none_output;
            get<I>(op_tuple).Process(none_input, none_output);
        } else {
            get<I>(op_tuple).Process();
        }
    }

    template <size_t I>
    OPX_DEVICE
    void SetLogicCoreGroupImpl(const LogicCoreGroup& grp)
    {
        if constexpr (I > 0) {
            SetLogicCoreGroupImpl<I - 1>(grp);
        }
        if constexpr (CanSetLogicCoreGroup<decltype(get<I>(op_tuple))>::value) {
            get<I>(op_tuple).SetLogicCoreGroup(grp);
        }
    }

public:
    tuple<Op...> op_tuple;
};

template <typename... Args>
OPX_DEVICE
auto MakeSequential(Args&&... args)
{
    static_assert(sizeof...(Args) > 0, "At least one op is required!");
    return Sequential<Args...>{ { forward<Args>(args)... } };
}


template <bool use_even_core = true>
struct OddEvenParallelStrategy
{
    OPX_DEVICE
    bool operator()(const LogicCoreGroup& grp) {
        constexpr uint32_t target_val = use_even_core ? 0 : 1;
        return grp.lgc_core_idx % 2 == target_val;
    }

    OPX_DEVICE
    LogicCoreGroup GetNewLogicGroup(const LogicCoreGroup& grp)
    {
        return {grp.lgc_core_num / 2, grp.lgc_core_idx / 2};
    }
};

using OddParallelStrategy = OddEvenParallelStrategy<false>;
using EvenParallelStrategy = OddEvenParallelStrategy<true>;

template <uint32_t lower, uint32_t upper>
struct RangeParallelStrategy
{
    static_assert(upper >= lower, "Invalid range!");

    OPX_DEVICE
    bool operator()(const LogicCoreGroup& grp) {
        return lower <= grp.lgc_core_idx && grp.lgc_core_idx <= upper;
    }

    OPX_DEVICE
    LogicCoreGroup GetNewLogicGroup(const LogicCoreGroup& grp)
    {
        return {upper - lower + 1, grp.lgc_core_idx - lower};
    }
};


template <typename T>
struct StrategyCheck {
    template <typename U>
    using Checker = std::enable_if_t<
        is_invocable_r_v<bool, remove_cvref_t<U>, LogicCoreGroup> &&
        is_invocable_r_v<LogicCoreGroup, decltype(&remove_cvref_t<U>::GetNewLogicGroup),
            remove_cvref_t<U>, LogicCoreGroup>
    >;

    static constexpr bool value = TemplateUsingSFINAE<T, Checker>::value;
};

// Parallel
template <
    typename OpTuple = tuple<>,
    typename StrategyTuple = tuple<>
> class Parallel;

template <
    typename... Op,
    typename... Strategy
>
class Parallel<
    tuple<Op...>,
    tuple<Strategy...>
>
{
    static_assert(sizeof...(Op) > 0 && sizeof...(Op) == sizeof...(Strategy));

    static_assert((StrategyCheck<Strategy>::value && ...));

    template <typename T>
    using ProcessCheck = decltype(&declval<T>().Process(declval<NoneParam&>(), declval<NoneParam&>()));

public:
    OPX_DEVICE
    Parallel() { SetDefaultLogicCoreGroup(); }

    template <typename OpTuple, typename StrategyTuple, typename = std::enable_if_t<
        std::is_constructible_v<tuple<Op...>, OpTuple&&> &&
        std::is_constructible_v<tuple<Strategy...>, StrategyTuple&&>
    >>
    OPX_DEVICE
    Parallel(OpTuple&& op_tuple_, StrategyTuple&& strategy_tuple_)
        : op_tuple(forward<OpTuple>(op_tuple_)),  strategy_tuple(forward<StrategyTuple>(strategy_tuple_))
    {
        SetDefaultLogicCoreGroup();
    }

    OPX_DEVICE
    void Process()
    {
        ProcessImpl<std::tuple_size_v<decltype(op_tuple)> - 1>();
    }

    OPX_DEVICE
    void SetLogicCoreGroup(const LogicCoreGroup& grp)
    {
        this->logic_core_group = grp;
    }

private:
    OPX_DEVICE
    void SetDefaultLogicCoreGroup()
    {
        if ASCEND_IS_AIV {
            logic_core_group.lgc_core_num = get_block_num() * get_subblockdim();
            logic_core_group.lgc_core_idx = get_block_idx() * get_subblockdim() + get_subblockid();
        } else {
            logic_core_group.lgc_core_num = get_block_num();
            logic_core_group.lgc_core_idx = get_block_idx();
        }
    }

    template <size_t I>
    OPX_DEVICE
    void ProcessImpl()
    {
        auto &split_strategy = get<I>(strategy_tuple);
        if (split_strategy(logic_core_group)) {
            if constexpr (CanSetLogicCoreGroup<decltype(get<I>(op_tuple))>::value) {
                LogicCoreGroup new_grp = split_strategy.GetNewLogicGroup(logic_core_group);
                get<I>(op_tuple).SetLogicCoreGroup(new_grp);
            }

            if constexpr (CanLazyInit<decltype(get<I>(op_tuple))>::value) {
                get<I>(op_tuple).LazyInit();
            }

            if constexpr (TemplateUsingSFINAE<decltype(get<I>(op_tuple)), ProcessCheck>::value) {
                NoneParam none_input, none_output;
                get<I>(op_tuple).Process(none_input, none_output);
            } else {
                get<I>(op_tuple).Process();
            }
            return;
        }

        if constexpr (I > 0) {
            ProcessImpl<I - 1>();
        }
    }

public:
    tuple<Op...> op_tuple;
    tuple<Strategy...> strategy_tuple;
    LogicCoreGroup logic_core_group;
};

namespace detail {

OPX_DEVICE
auto MakeParallelImpl()
{
    return tuple<tuple<>, tuple<>>();
}

template <typename Op, typename Strategy, typename... Rest>
OPX_DEVICE
auto MakeParallelImpl(Op&& op, Strategy&& strategy, Rest&&... rest)
{
    static_assert(StrategyCheck<decltype(strategy)>::value,
        "Strategy type is incorrect!");

    auto rest_ret = MakeParallelImpl(forward<Rest>(rest)...);

    return make_tuple(
        tuple_cat(tuple<Op>(forward<Op>(op)), get<0>(rest_ret)),
        tuple_cat(tuple<Strategy>(forward<Strategy>(strategy)), get<1>(rest_ret))
    );
}

} // end namespace detail

template <typename... Args>
OPX_DEVICE
auto MakeParallel(Args&&... args)
{
    static_assert(sizeof...(Args) % 2 == 0, "Both operators and parallel strategies need to be specified!");
    auto ret_tuple = detail::MakeParallelImpl(forward<Args>(args)...);
    return Parallel<
        std::tuple_element_t<0, decltype(ret_tuple)>,
        std::tuple_element_t<1, decltype(ret_tuple)>
    >{ move(get<0>(ret_tuple)), move(get<1>(ret_tuple)) };
}

// Sync Op
struct SyncOp
{
    OPX_DEVICE
    void Process()
    {
        AscendC::SyncAll<true>();
    }
};

}; /* end namespace opx */
