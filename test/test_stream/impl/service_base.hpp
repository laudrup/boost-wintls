//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef BOOST_WINTLS_TEST_TEST_STREAM_IMPL_SERVICE_BASE_HPP
#define BOOST_WINTLS_TEST_TEST_STREAM_IMPL_SERVICE_BASE_HPP

namespace boost {
namespace wintls {
namespace test {

template<class T>
struct service_base : net::execution_context::service
{
    static net::execution_context::id const id;

    explicit
    service_base(net::execution_context& ctx)
        : net::execution_context::service(ctx)
    {
    }
};

template<class T>
net::execution_context::id const service_base<T>::id;

} // namespace test
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_TEST_TEST_STREAM_IMPL_SERVICE_BASE_HPP
