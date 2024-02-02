//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef WINTLS_TEST_TEST_STREAM_FAIL_COUNT_HPP
#define WINTLS_TEST_TEST_STREAM_FAIL_COUNT_HPP

#include "config.hpp"
#include "error.hpp"
#include <cstdlib>

namespace wintls {
namespace test {

/** A countdown to simulated failure

    On the Nth operation, the class will fail with the specified
    error code, or the default error code of @ref error::test_failure.

    Instances of this class may be used to build objects which
    are specifically designed to aid in writing unit tests, for
    interfaces which can throw exceptions or return `error_code`
    values representing failure.
*/
class fail_count
{
    std::size_t n_;
    std::size_t i_ = 0;
    error_code ec_;

public:
    fail_count(fail_count&&) = default;

    /** Construct a counter

        @param n The 0-based index of the operation to fail on or after
        @param ev An optional error code to use when generating a simulated failure
    */
    inline
    explicit
    fail_count(
        std::size_t n,
        error_code ev = error::test_failure);

    /// Throw an exception on the Nth failure
    inline
    void
    fail();

    /// Set an error code on the Nth failure
    inline
    bool
    fail(error_code& ec);
};

} // namespace test
} // namespace wintls

#include "impl/fail_count.ipp"

#endif // WINTLS_TEST_TEST_STREAM_FAIL_COUNT_HPP
