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

#ifdef inline
#pragma push_macro("inline")
#undef inline
#define RECOVER_INLINE
#endif

#include <tuple>
#include <variant>


#ifndef __opx_inline__
#define __opx_inline__ __forceinline__
#endif

#ifndef __host_aicore__
#define __host_aicore__
#endif

#ifndef __global__
#define __global__
#endif

#ifndef OPX_DEVICE
#define OPX_DEVICE __opx_inline__ __aicore__
#endif

#ifndef OPX_HOST_DEVICE
#define OPX_HOST_DEVICE __opx_inline__ __host_aicore__
#endif

#ifndef OPX_GLOBAL
#define OPX_GLOBAL __global__ __aicore__
#endif


namespace opx
{

/// declval
template <typename T>
OPX_HOST_DEVICE constexpr
std::add_rvalue_reference_t<T> declval() noexcept;
// No implement cause declval() only can be used in compile-time type deduction

/// move
template <typename T>
OPX_HOST_DEVICE constexpr
std::remove_reference_t<T>&& move(T&& t) noexcept
{
    return static_cast<std::remove_reference_t<T>&&>(t);
}

/// forward
template <typename T>
OPX_HOST_DEVICE constexpr
T&& forward(std::remove_reference_t<T>& t) noexcept
{
    return static_cast<T&&>(t);
}

template <typename T>
OPX_HOST_DEVICE constexpr
T&& forward(std::remove_reference_t<T>&& t) noexcept
{
    static_assert(!std::is_lvalue_reference<T>::value, "bad forward of rvalue as lvalue");
    return static_cast<T&&>(t);
}

/// tuple
template <typename... Ts>
struct tuple;

template <>
struct tuple<> { };

template <typename Head, typename... Tail>
struct tuple<Head, Tail...> : tuple<Tail...>
{
    Head value;

    OPX_HOST_DEVICE constexpr
    tuple() = default;

    // forwarding constructor (perfect-forwarding) with SFINAE constraints
    template <typename Head_, typename... Tail_, typename = std::enable_if_t<
        sizeof...(Tail) == sizeof...(Tail_) &&
        std::is_constructible_v<Head, Head_&&> &&
        (std::is_constructible_v<Tail, Tail_&&> && ...)
    >>
    OPX_HOST_DEVICE constexpr
    tuple(Head_&& h, Tail_&&... t) :
        tuple<Tail...>(opx::forward<Tail_>(t)...),
        value(opx::forward<Head_>(h))
    { }

    // copy from another tuple with possibly different element types
    template <typename Head_, typename... Tail_, typename = std::enable_if_t<
        sizeof...(Tail) == sizeof...(Tail_) &&
        std::is_constructible_v<Head, const Head_&> &&
        (std::is_constructible_v<Tail, const Tail_&> && ...)
    >>
    OPX_HOST_DEVICE constexpr
    tuple(const tuple<Head_, Tail_...>& tp) :
        tuple<Tail...>(static_cast<const tuple<Tail_...>&>(tp)),
        value(tp.value)
    { }

    // move from another tuple with possibly different element types
    template <typename Head_, typename... Tail_, typename = std::enable_if_t<
        sizeof...(Tail) == sizeof...(Tail_) &&
        std::is_constructible_v<Head, Head_&&> &&
        (std::is_constructible_v<Tail, Tail_&&> && ...)
    >>
    OPX_HOST_DEVICE constexpr
    tuple(tuple<Head_, Tail_...>&& tp) :
        tuple<Tail...>(static_cast<tuple<Tail_...>&&>(tp)),
        value(opx::move(tp.value))
    { }
};

// CTAD for tuple
template <typename... T>
tuple(T&&...) -> tuple<std::decay_t<T>...>;

/// get for tuple
template <size_t Index, typename Head, typename... Tail>
OPX_HOST_DEVICE constexpr
decltype(auto) get(tuple<Head, Tail...>& t)
{
    if constexpr (Index == 0) {
        return (t.value);
    } else {
        return get<Index - 1>(static_cast<tuple<Tail...>&>(t));
    }
}

template <size_t Index, typename Head, typename... Tail>
OPX_HOST_DEVICE constexpr
decltype(auto) get(const tuple<Head, Tail...>& t)
{
    if constexpr (Index == 0) {
        return (t.value);
    } else {
        return get<Index - 1>(static_cast<const tuple<Tail...>&>(t));
    }
}

template <size_t Index, typename Head, typename... Tail>
OPX_HOST_DEVICE constexpr
decltype(auto) get(tuple<Head, Tail...>&& t)
{
    if constexpr (Index == 0) {
        return static_cast<Head &&>(t.value);
    } else {
        return get<Index - 1>(static_cast<tuple<Tail...>&&>(t));
    }
}

template <size_t Index, typename Head, typename... Tail>
OPX_HOST_DEVICE constexpr
decltype(auto) get(const tuple<Head, Tail...>&& t)
{
    if constexpr (Index == 0) {
        return static_cast<const Head &&>(t.value);
    } else {
        return get<Index - 1>(static_cast<const tuple<Tail...>&&>(t));
    }
}

/// forward_as_tuple
template <typename... Args>
OPX_HOST_DEVICE constexpr
tuple<Args&&...> forward_as_tuple(Args&&... args) noexcept
{
    return tuple<Args&&...>(opx::forward<Args>(args)...);
}

/// make_tuple
template <typename... Args>
OPX_HOST_DEVICE constexpr
tuple<std::decay_t<Args>...> make_tuple(Args&&... args)
{
    return tuple<std::decay_t<Args>...>(opx::forward<Args>(args)...);
}

/// tie
template <typename... Args>
OPX_HOST_DEVICE constexpr
tuple<Args&...> tie(Args&... args) noexcept
{
    return tuple<Args&...>(args...);
}

} // end namespace opx


// Add tuple utils support for opx::tuple in std
namespace std
{

template <typename... Types>
struct tuple_size<opx::tuple<Types...>> : std::integral_constant<size_t, sizeof...(Types)> {};

template <typename Head, typename... Tail>
struct tuple_element<0, opx::tuple<Head, Tail...>> {
    using type = Head;
};

template <size_t I, typename Head, typename... Tail>
struct tuple_element<I, opx::tuple<Head, Tail...>> {
    static_assert(I < std::tuple_size<opx::tuple<Head, Tail...>>::value, "Index out of bounds");
    using type = typename tuple_element<I - 1, opx::tuple<Tail...>>::type;
};

template <size_t N, typename... Ts>
OPX_HOST_DEVICE constexpr
decltype(auto) get(opx::tuple<Ts...>& t)
{
    return opx::get<N>(t);
}

template <size_t N, typename... Ts>
OPX_HOST_DEVICE constexpr
decltype(auto) get(const opx::tuple<Ts...>& t)
{
    return opx::get<N>(t);
}

template <size_t N, typename... Ts>
OPX_HOST_DEVICE constexpr
decltype(auto) get(opx::tuple<Ts...>&& t)
{
    return opx::get<N>(opx::move(t));
}

template <size_t N, typename... Ts>
OPX_HOST_DEVICE constexpr
decltype(auto) get(const opx::tuple<Ts...>&& t)
{
    return opx::get<N>(opx::move(t));
}

} // end namespace std


namespace opx
{

/// tuple_cat
namespace detail
{

template <typename Tuple, size_t... I>
OPX_HOST_DEVICE constexpr
auto tuple_cat_one(
    Tuple&& t,
    std::index_sequence<I...>)
{
    return tuple<
        std::tuple_element_t<I, std::decay_t<Tuple>>...
    >(
        std::get<I>(opx::forward<Tuple>(t))...
    );
}

template <typename Tuple1, typename Tuple2, size_t... I1, size_t... I2>
OPX_HOST_DEVICE constexpr
auto tuple_cat_two(
    Tuple1&& t1,
    Tuple2&& t2,
    std::index_sequence<I1...>,
    std::index_sequence<I2...>)
{
    return tuple<
        std::tuple_element_t<I1, std::decay_t<Tuple1>>...,
        std::tuple_element_t<I2, std::decay_t<Tuple2>>...
    >(
        std::get<I1>(opx::forward<Tuple1>(t1))...,
        std::get<I2>(opx::forward<Tuple2>(t2))...
    );
}

} // end namespace detail

template <typename Tuple>
OPX_HOST_DEVICE constexpr
auto tuple_cat(Tuple&& t)
{
    return detail::tuple_cat_one(
        opx::forward<Tuple>(t),
        std::make_index_sequence<std::tuple_size_v<std::decay_t<Tuple>>>{}
    );
}

template <typename Tuple1, typename Tuple2, typename... Rest>
OPX_HOST_DEVICE constexpr
auto tuple_cat(
    Tuple1&& t1,
    Tuple2&& t2,
    Rest&&... rest)
{
    if constexpr (sizeof...(Rest) == 0) {
        return detail::tuple_cat_two(
            opx::forward<Tuple1>(t1),
            opx::forward<Tuple2>(t2),
            std::make_index_sequence<std::tuple_size_v<std::decay_t<Tuple1>>>{},
            std::make_index_sequence<std::tuple_size_v<std::decay_t<Tuple2>>>{}
        );
    } else {
        return tuple_cat(
            detail::tuple_cat_two(
                opx::forward<Tuple1>(t1),
                opx::forward<Tuple2>(t2),
                std::make_index_sequence<std::tuple_size_v<std::decay_t<Tuple1>>>{},
                std::make_index_sequence<std::tuple_size_v<std::decay_t<Tuple2>>>{}
            ),
            opx::forward<Rest>(rest)...
        );
    }
}

/// apply
namespace detail
{

template <typename Fn, typename Tuple, size_t... I>
OPX_HOST_DEVICE constexpr
decltype(auto) apply_impl(Fn&& fn, Tuple&& tup, std::index_sequence<I...>)
{
    return fn(std::get<I>(opx::forward<Tuple>(tup))...);
}

} // end namespace detail

template <typename Fn, typename Tuple>
OPX_HOST_DEVICE constexpr
decltype(auto) apply(Fn&& fn, Tuple&& tup)
{
    constexpr size_t size = std::tuple_size<std::decay_t<Tuple>>::value;
    return detail::apply_impl(
        opx::forward<Fn>(fn), opx::forward<Tuple>(tup), std::make_index_sequence<size>{});
}

/// remove_cvref
template <class T>
struct remove_cvref {
    using type = std::remove_cv_t<std::remove_reference_t<T>>;
};

template <class T>
using remove_cvref_t = typename remove_cvref<T>::type;

/// is_reference_wrapper
template <typename T>
struct is_reference_wrapper : std::false_type {};

template <typename U>
struct is_reference_wrapper<std::reference_wrapper<U>> : std::true_type {};

template <typename T>
inline constexpr bool is_reference_wrapper_v = is_reference_wrapper<T>::value;

/// invoke_result
namespace detail
{

// member_pointer_class: extract class type from member pointer
template <typename T>
struct member_pointer_class;

template <typename C, typename R, typename... Args>
struct member_pointer_class<R (C::*)(Args...)> { using type = C; };

template <typename C, typename R, typename... Args>
struct member_pointer_class<R (C::*)(Args...) const> { using type = C; };

template <typename C, typename R, typename... Args>
struct member_pointer_class<R (C::*)(Args...) volatile> { using type = C; };

template <typename C, typename R, typename... Args>
struct member_pointer_class<R (C::*)(Args...) const volatile> { using type = C; };

template <typename C, typename R>
struct member_pointer_class<R C::*> { using type = C; };

template <typename T>
using member_pointer_class_t = typename member_pointer_class<std::decay_t<T>>::type;

// Primary template for invoke_result_impl
template <typename Enable, typename F, typename... Args>
struct invoke_result_impl {};

// 1) General callable: f(args...)
template <typename F, typename... Args>
struct invoke_result_impl<
    std::void_t<decltype(opx::declval<F>()(opx::declval<Args>()...))>,
    F, Args...
>
{
    using type = decltype(opx::declval<F>()(opx::declval<Args>()...));
};

// 2) Member function pointer + object (non-pointer, non-reference_wrapper)
//    Object type must be the member's class or a derived class
template <typename F, typename T, typename... Args>
struct invoke_result_impl<
    std::enable_if_t<
        std::is_member_function_pointer_v<std::decay_t<F>> &&
        !is_reference_wrapper_v<std::decay_t<T>> &&
        !std::is_pointer_v<std::decay_t<T>> &&
        std::is_base_of_v<member_pointer_class_t<F>, std::decay_t<T>>,
        std::void_t<decltype((opx::declval<T>().*opx::declval<F>())(opx::declval<Args>()...))>
    >,
    F, T, Args...
>
{
    using type = decltype((opx::declval<T>().*opx::declval<F>())(opx::declval<Args>()...));
};

// 3) Member function pointer + reference_wrapper<C>
template <typename F, typename T, typename... Args>
struct invoke_result_impl<
    std::enable_if_t<
        std::is_member_function_pointer_v<std::decay_t<F>> &&
        is_reference_wrapper_v<std::decay_t<T>> &&
        std::is_same_v<member_pointer_class_t<F>, typename std::decay_t<T>::type>,
        std::void_t<decltype((opx::declval<T>().get().*opx::declval<F>())(opx::declval<Args>()...))>
    >,
    F, T, Args...
>
{
    using type = decltype((opx::declval<T>().get().*opx::declval<F>())(opx::declval<Args>()...));
};

// 4) Member function pointer + pointer (pointer to class or derived)
template <typename F, typename T, typename... Args>
struct invoke_result_impl<
    std::enable_if_t<
        std::is_member_function_pointer_v<std::decay_t<F>> &&
        std::is_pointer_v<std::decay_t<T>> &&
        std::is_base_of_v<member_pointer_class_t<F>, std::remove_pointer_t<std::decay_t<T>>>,
        std::void_t<decltype(((*opx::declval<T>()).*opx::declval<F>())(opx::declval<Args>()...))>
    >,
    F, T, Args...
>
{
    using type = decltype(((*opx::declval<T>()).*opx::declval<F>())(opx::declval<Args>()...));
};

// 5) Member object pointer + object (non-pointer, non-reference_wrapper)
//    Object type must be the member's class or a derived class
template <typename F, typename T>
struct invoke_result_impl<
    std::enable_if_t<
        std::is_member_object_pointer_v<std::decay_t<F>> &&
        !is_reference_wrapper_v<std::decay_t<T>> &&
        !std::is_pointer_v<std::decay_t<T>> &&
        std::is_base_of_v<member_pointer_class_t<F>, std::decay_t<T>>,
        std::void_t<decltype(opx::declval<T>().*opx::declval<F>())>
    >,
    F, T
>
{
    using type = decltype(opx::declval<T>().*opx::declval<F>());
};

// 6) Member object pointer + reference_wrapper<C>
template <typename F, typename T>
struct invoke_result_impl<
    std::enable_if_t<
        std::is_member_object_pointer_v<std::decay_t<F>> &&
        is_reference_wrapper_v<std::decay_t<T>> &&
        std::is_same_v<member_pointer_class_t<F>, typename std::decay_t<T>::type>,
        std::void_t<decltype(opx::declval<T>().get().*opx::declval<F>())>
    >,
    F, T
>
{
    using type = decltype(opx::declval<T>().get().*opx::declval<F>());
};

// 7) Member object pointer + pointer (pointer to class or derived)
template <typename F, typename T>
struct invoke_result_impl<
    std::enable_if_t<
        std::is_member_object_pointer_v<std::decay_t<F>> &&
        std::is_pointer_v<std::decay_t<T>> &&
        std::is_base_of_v<member_pointer_class_t<F>, std::remove_pointer_t<std::decay_t<T>>>,
        std::void_t<decltype((*opx::declval<T>()).*opx::declval<F>())>
    >,
    F, T
>
{
    using type = decltype((*opx::declval<T>()).*opx::declval<F>());
};

} // end namespace detail

template <typename F, typename... Args>
struct invoke_result : detail::invoke_result_impl<void, F, Args...> {};

template <typename F, typename... Args>
using invoke_result_t = typename invoke_result<F, Args...>::type;

/// is_invocable
namespace detail
{

template <class, class F, class... Args>
struct is_invocable_impl : std::false_type {};

template <class F, class... Args>
struct is_invocable_impl<
    std::void_t<invoke_result_t<F, Args...>>, F, Args...> : std::true_type {};

template <class, class R, class F, class... Args>
struct is_invocable_r_impl : std::false_type {};

template <class R, class F, class... Args>
struct is_invocable_r_impl<
    std::void_t<invoke_result_t<F, Args...>>, R, F, Args...> :
        std::is_convertible<invoke_result_t<F, Args...>, R> {};

} // end namespace detail

template <class F, class... Args>
struct is_invocable : detail::is_invocable_impl<void, F, Args...> {};

template <class F, class... Args>
inline constexpr bool is_invocable_v = is_invocable<F, Args...>::value;

/// is_invocable_r
template <class R, class F, class... Args>
struct is_invocable_r : detail::is_invocable_r_impl<void, R, F, Args...> {};

template <class R, class F, class... Args>
inline constexpr bool is_invocable_r_v = is_invocable_r<R, F, Args...>::value;

// TypePrinter used for DFX
template <typename... Ts>
struct TypePrinter;

} // end namespace opx


#ifdef RECOVER_INLINE
#undef RECOVER_INLINE
#pragma pop_macro("inline")
#endif
