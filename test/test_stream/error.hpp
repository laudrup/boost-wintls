//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef BOOST_WINTLS_TEST_STREAM_ERROR_HPP
#define BOOST_WINTLS_TEST_STREAM_ERROR_HPP

namespace boost {
namespace wintls {
namespace test {

/// Error codes returned from unit testing algorithms
enum class error
{
    /** The test stream generated a simulated testing error

        This error is returned by a @ref fail_count object
        when it generates a simulated error.
    */
    test_failure = 1
};

} // namespace test
} // namespace wintls
} // namespace boost

#include "impl/error.ipp"
#include "impl/error.hpp"

#endif
