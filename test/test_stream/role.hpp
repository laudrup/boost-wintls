//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef WINTLS_TEST_TEST_STREAM_ROLE_HPP
#define WINTLS_TEST_TEST_STREAM_ROLE_HPP

namespace wintls {
namespace test {

#ifdef WINTLS_USE_STANDALONE_ASIO
/** The role of local or remote peer.

    Whether the endpoint is a client or server affects the
    behavior of teardown.
    The teardown behavior also depends on the type of the stream
    being torn down.

    The default implementation of teardown for regular
    TCP/IP sockets is as follows:

    @li In the client role, a TCP/IP shutdown is sent after
    reading all remaining data on the connection.

    @li In the server role, a TCP/IP shutdown is sent before
    reading all remaining data on the connection.

    When the next layer type is a `net::ssl::stream`,
    the connection is closed by performing the SSL closing
    handshake corresponding to the role type, client or server.
*/
enum class role_type
{
    /// The stream is operating as a client.
    client,

    /// The stream is operating as a server.
    server
};
#else // WINTLS_USE_STANDALONE_ASIO
#include <boost/beast/core.hpp>

using role_type = boost::beast::role_type;
#endif // !WINTLS_USE_STANDALONE_ASIO

} // namespace test
} // namespace wintls

#endif // WINTLS_TEST_TEST_STREAM_ROLE_HPP
