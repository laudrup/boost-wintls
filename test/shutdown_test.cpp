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


TEST_CASE("Asio.SSL shutdown test") {
  SECTION("stream truncated - client closes after server shutdown") {
    net::io_context io_context;
    echo_server<asio_ssl_server_stream> server(io_context);
    echo_client<asio_ssl_client_stream> client(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    auto shutdown_result = server.shutdown();
    client.stream.lowest_layer().close();
    CHECK(shutdown_result.get() == asio_ssl::error::stream_truncated);
  }

  SECTION("stream truncated  - client closes before server shutdown") {
    net::io_context io_context;
    echo_server<asio_ssl_server_stream> server(io_context);
    echo_client<asio_ssl_client_stream> client(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    client.stream.lowest_layer().close();
    auto shutdown_result = server.shutdown();
    CHECK(shutdown_result.get() == asio_ssl::error::stream_truncated);
  }

  SECTION("okay") {
    net::io_context io_context;
    echo_server<asio_ssl_server_stream> server(io_context);
    echo_client<asio_ssl_client_stream> client(io_context);

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

TEST_CASE("WinTLS shutdown test") {
  SECTION("stream truncated - client closes after server shutdown") {
    net::io_context io_context;
    echo_server<wintls_server_stream> server(io_context);
    echo_client<wintls_client_stream> client(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    auto shutdown_result = server.shutdown();
    client.stream.next_layer().close();
    // #TODO: this documents the current behavior, that is likely wrong
    CHECK_FALSE(shutdown_result.get());
  }

  SECTION("stream truncated  - client closes before server shutdown") {
    net::io_context io_context;
    echo_server<wintls_server_stream> server(io_context);
    echo_client<wintls_client_stream> client(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    client.stream.next_layer().close();
    auto shutdown_result = server.shutdown();
    // #TODO: this documents the current behavior, that is likely wrong
    CHECK_FALSE(shutdown_result.get());
  }

  SECTION("okay") {
    net::io_context io_context;
    echo_server<wintls_server_stream> server(io_context);
    echo_client<wintls_client_stream> client(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    auto handshake_result = server.handshake();
    client.handshake();
    REQUIRE_FALSE(handshake_result.get());

    auto shutdown_result = server.shutdown();
    client.shutdown();
    CHECK_FALSE(shutdown_result.get());
  }
}
