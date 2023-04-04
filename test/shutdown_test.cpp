//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "echo_server.hpp"
#include "echo_client.hpp"
#include "async_echo_server.hpp"
#include "async_echo_client.hpp"
#include "asio_ssl_client_stream.hpp"
#include "asio_ssl_server_stream.hpp"
#include "wintls_client_stream.hpp"
#include "wintls_server_stream.hpp"
#include "unittest.hpp"

#include <boost/wintls.hpp>

template <typename NextLayer>
auto stream_truncated_error(const asio_ssl::stream<NextLayer>&) {
  return asio_ssl::error::stream_truncated;
}

template<typename NextLayer>
auto stream_truncated_error(const boost::wintls::stream<NextLayer>&) {
  return net::error::eof; // #TODO: This should be a separate error code.
}

using TestTypes = std::tuple<std::tuple<asio_ssl_client_stream, asio_ssl_server_stream>,
                             std::tuple<wintls_client_stream, asio_ssl_server_stream>,
                             std::tuple<asio_ssl_client_stream, wintls_server_stream>,
                             std::tuple<wintls_client_stream, wintls_server_stream>>;

TEMPLATE_LIST_TEST_CASE("shutdown test", "", TestTypes) {
  using ClientStream = typename std::tuple_element<0, TestType>::type;
  using ServerStream = typename std::tuple_element<1, TestType>::type;

  SECTION("stream truncated - client closes after server shutdown") {
    net::io_context io_context;
    echo_client<ClientStream> client(io_context);
    echo_server<ServerStream> server(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    auto shutdown_result = server.shutdown();
    client.stream.next_layer().close();
    CHECK(shutdown_result.get() == stream_truncated_error(server.stream));
  }

  SECTION("stream truncated  - client closes before server shutdown") {
    net::io_context io_context;
    echo_client<ClientStream> client(io_context);
    echo_server<ServerStream> server(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    client.stream.next_layer().close();
    auto shutdown_result = server.shutdown();
    CHECK(shutdown_result.get() == stream_truncated_error(server.stream));
  }

  SECTION("stream truncated - server closes after client shutdown") {
    net::io_context io_context;
    echo_client<ClientStream> client(io_context);
    echo_server<ServerStream> server(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    auto client_shutdown_result = client.launch_shutdown();
    server.stream.next_layer().close();
    CHECK(client_shutdown_result.get() == stream_truncated_error(client.stream));
  }

  SECTION("stream truncated - server closes before client shutdown") {
    net::io_context io_context;
    echo_client<ClientStream> client(io_context);
    echo_server<ServerStream> server(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    server.stream.next_layer().close();
    CHECK(client.launch_shutdown().get() == stream_truncated_error(client.stream));
  }

  SECTION("okay") {
    net::io_context io_context;
    echo_client<ClientStream> client(io_context);
    echo_server<ServerStream> server(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    auto shutdown_result = server.shutdown();
    client.shutdown();
    // according to https://stackoverflow.com/a/25703699/16814536 this should produce asio::error::eof
    // is that information outdated?
    CHECK_FALSE(shutdown_result.get());
  }
}
