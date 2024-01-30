//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef BOOST_WINTLS_TEST_STREAM_IMPL_FAIL_COUNT_IPP
#define BOOST_WINTLS_TEST_STREAM_IMPL_FAIL_COUNT_IPP

namespace boost {
namespace wintls {
namespace test {

fail_count::
fail_count(
    std::size_t n,
    error_code ev)
    : n_(n)
    , ec_(ev)
{
}

void
fail_count::
fail()
{
    if(i_ < n_)
        ++i_;
    if(i_ == n_)
        throw system_error{ec_};
}

bool
fail_count::
fail(error_code& ec)
{
    if(i_ < n_)
        ++i_;
    if(i_ == n_)
    {
        ec = ec_;
        return true;
    }
    ec = {};
    return false;
}

} // namespace test
} // namespace wintls
} // namespace boost

#endif
