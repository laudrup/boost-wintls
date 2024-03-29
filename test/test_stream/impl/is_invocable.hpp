//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef WINTLS_TEST_TEST_STREAM_IMPL_IS_INVOCABLE_HPP
#define WINTLS_TEST_TEST_STREAM_IMPL_IS_INVOCABLE_HPP

#include <type_traits>
#include <utility>

namespace wintls {
namespace test {

// Note: This is prefixed to avoid conflicts with boost::beast::detail::is_invocable_test
template<class R, class C, class ...A>
auto
wintls_is_invocable_test(C&& c, int, A&& ...a)
    -> decltype(std::is_convertible<
        decltype(c(std::forward<A>(a)...)), R>::value ||
            std::is_same<R, void>::value,
                std::true_type());

template<class R, class C, class ...A>
std::false_type
wintls_is_invocable_test(C&& c, long, A&& ...a);

/** Metafunction returns `true` if F callable as R(A...)

    Example:

    @code
    is_invocable<T, void(std::string)>::value
    @endcode
*/
/** @{ */
template<class C, class F>
struct is_invocable : std::false_type
{
};

template<class C, class R, class ...A>
struct is_invocable<C, R(A...)>
    : decltype(wintls_is_invocable_test<R>(
        std::declval<C>(), 1, std::declval<A>()...))
{
};
/** @} */

} // namespace test
} // namespace wintls

#endif // WINTLS_TEST_TEST_STREAM_IMPL_IS_INVOCABLE_HPP
