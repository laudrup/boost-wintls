//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef BOOST_WINTLS_TEST_TEST_STREAM_IMPL_ERROR_HPP
#define BOOST_WINTLS_TEST_TEST_STREAM_IMPL_ERROR_HPP

#include <type_traits>

#ifdef WINTLS_USE_STANDALONE_ASIO
namespace std {
template<>
struct is_error_code_enum<
    boost::wintls::test::error>
        : std::true_type
{
};
} // std
#else // WINTLS_USE_STANDALONE_ASIO
namespace boost {
namespace system {
template<>
struct is_error_code_enum<
    boost::wintls::test::error>
        : std::true_type
{
};
} // system
} // boost
#endif // !WINTLS_USE_STANDALONE_ASIO

namespace boost {
namespace wintls {
namespace test {

inline
error_code
make_error_code(error e) noexcept;

} // namespace test
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_TEST_TEST_STREAM_IMPL_ERROR_HPP
