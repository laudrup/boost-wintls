//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef WINTLS_TEST_TEST_STREAM_ALLOCATOR_HPP
#define WINTLS_TEST_TEST_STREAM_ALLOCATOR_HPP

#include <memory>

namespace wintls {
namespace test {

// This is a workaround for allocator_traits
// implementations which falsely claim C++11
// compatibility.
template<class Alloc>
using allocator_traits = std::allocator_traits<Alloc>;

} // namespace test
} // namespace wintls

#endif // WINTLS_TEST_TEST_STREAM_ALLOCATOR_HPP
