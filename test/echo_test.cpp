//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "async_echo_server.hpp"
#include "async_echo_client.hpp"

#ifdef _WIN32
#include <boost/windows_sspi.hpp>
#endif

#include <catch2/catch.hpp>

#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <string>
#include <thread>
#include <tuple>
#include <cstdint>

namespace net = boost::asio;
namespace asio_ssl = boost::asio::ssl;
using test_stream = boost::beast::test::stream;

namespace {
std::string generate_data(std::size_t size) {
  std::string ret(size, '\0');
  for (std::size_t i = 0; i < size - 1; ++i) {
  const char cur_char = i % 26;
    ret[i] = cur_char + 65;
  }
  return ret;
}
}

// TODO: Find some more sane way to handle testing both OpenSSL and
// this SSPI/SChannel implementation in a generic way
using SSLTypes = std::tuple<asio_ssl::context,
                            asio_ssl::stream<test_stream>,
                            asio_ssl::stream_base,
                            asio_ssl::context_base,
                            asio_ssl::context_base>;
#ifdef _WIN32
using SSPITypes = std::tuple<boost::windows_sspi::context,
                             boost::windows_sspi::stream<test_stream>,
                             boost::windows_sspi::handshake_type,
                             boost::windows_sspi::method,
                             boost::windows_sspi::file_format>;
#endif

#ifdef _WIN32
using TestTypes = std::tuple<std::tuple<SSLTypes, SSLTypes>,
                             std::tuple<SSPITypes, SSLTypes>,
                             std::tuple<SSLTypes, SSPITypes>,
                             std::tuple<SSPITypes, SSPITypes>>;
#else
using TestTypes = std::tuple<std::tuple<SSLTypes, SSLTypes>>;
#endif

TEMPLATE_LIST_TEST_CASE("echo test", "", TestTypes) {
  static_assert(std::tuple_size<TestType>::value == 2, "Expected exactly two implementation types");
  using ClientTypes = typename std::tuple_element<0, TestType>::type;
  static_assert(std::tuple_size<ClientTypes>::value == 5, "Expected exactly five client implementaion types");
  using ServerTypes = typename std::tuple_element<1, TestType>::type;
  static_assert(std::tuple_size<ServerTypes>::value == 5, "Expected exactly five server implementaion types");

  using ClientTLSContext = typename std::tuple_element<0, ClientTypes>::type;
  using ClientTLSStream = typename std::tuple_element<1, ClientTypes>::type;
  using ClientHandshakeType = typename std::tuple_element<2, ClientTypes>::type;
  using ClientMethodType = typename std::tuple_element<3, ClientTypes>::type;
  using ClientFileFormatType = typename std::tuple_element<4, ClientTypes>::type;

  using ServerTLSContext = typename std::tuple_element<0, ServerTypes>::type;
  using ServerTLSStream = typename std::tuple_element<1, ServerTypes>::type;
  using ServerHandshakeType = typename std::tuple_element<2, ServerTypes>::type;
  using ServerMethodType = typename std::tuple_element<3, ServerTypes>::type;
  using ServerFileFormatType = typename std::tuple_element<4, ServerTypes>::type;

  auto test_data_size = GENERATE(0x100, 0x100 - 1, 0x100 + 1,
                                 0x1000, 0x1000 - 1, 0x1000 + 1,
                                 0x10000, 0x10000 - 1, 0x10000 + 1,
                                 0x100000, 0x100000 - 1, 0x100000 + 1);
  const std::string test_data = generate_data(test_data_size);
  boost::system::error_code client_ec;
  boost::system::error_code server_ec;

  ClientTLSContext client_ctx(ClientMethodType::tlsv12);
  client_ctx.load_verify_file(TEST_CERTIFICATE_PATH, client_ec);
  REQUIRE_FALSE(client_ec);

  ServerTLSContext server_ctx(ServerMethodType::tlsv12);
  server_ctx.use_certificate_file(TEST_CERTIFICATE_PATH, ServerFileFormatType::pem, server_ec);
  REQUIRE_FALSE(server_ec);

  server_ctx.use_private_key_file(TEST_PRIVATE_KEY_PATH, ServerFileFormatType::pem, server_ec);
  REQUIRE_FALSE(server_ec);

  net::io_context io_context;
  ClientTLSStream client_stream(io_context, client_ctx);
  ServerTLSStream server_stream(io_context, server_ctx);

  client_stream.next_layer().connect(server_stream.next_layer());

  SECTION("sync test") {
    // As the handshake requires multiple read and writes between client
    // and server, we have to run the synchronous version in a separate
    // thread. Unfortunately.
    std::thread server_handshake([&server_stream, &server_ec]() {
      server_stream.handshake(ServerHandshakeType::server, server_ec);
      REQUIRE_FALSE(server_ec);
    });
    client_stream.handshake(ClientHandshakeType::client, client_ec);
    REQUIRE_FALSE(client_ec);

    server_handshake.join();
    REQUIRE_FALSE(server_ec);

    net::write(client_stream, net::buffer(test_data));

    net::streambuf server_data;
    net::read_until(server_stream, server_data, '\0');
    net::write(server_stream, server_data);

    net::streambuf client_data;
    net::read_until(client_stream, client_data, '\0');

    // As a shutdown potentially requires multiple read and writes
    // between client and server, we have to run the synchronous version
    // in a separate thread. Unfortunately.
    std::thread server_shutdown([&server_stream, &server_ec]() {
      server_stream.shutdown(server_ec);
      REQUIRE_FALSE(server_ec);
    });
    client_stream.shutdown(client_ec);
    REQUIRE_FALSE(client_ec);

    server_shutdown.join();
    REQUIRE_FALSE(server_ec);

    CHECK(std::string(net::buffers_begin(client_data.data()),
                      net::buffers_begin(client_data.data()) + client_data.size()) == test_data);
  }

  SECTION("async test") {
    async_server<ServerTLSContext,
                 ServerTLSStream,
                 ServerHandshakeType>
      server(server_stream, server_ctx);

    async_client<ClientTLSContext,
                 ClientTLSStream,
                 ClientHandshakeType>
      client(client_stream, client_ctx, test_data);

    io_context.run();
    CHECK(client.received_message() == test_data);
  }
}
