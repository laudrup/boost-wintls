//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "async_echo_server.hpp"
#include "async_echo_client.hpp"
#include "asio_ssl_client_stream.hpp"
#include "asio_ssl_server_stream.hpp"
#include "wintls_client_stream.hpp"
#include "wintls_server_stream.hpp"
#include "unittest.hpp"

#include <boost/wintls.hpp>

#include <boost/asio.hpp>

#include <string>
#include <thread>
#include <tuple>
#include <cstdint>

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

using TestTypes = std::tuple<std::tuple<asio_ssl_client_stream, asio_ssl_server_stream>,
                             std::tuple<wintls_client_stream, asio_ssl_server_stream>,
                             std::tuple<asio_ssl_client_stream, wintls_server_stream>,
                             std::tuple<wintls_client_stream, wintls_server_stream>>;

TEMPLATE_LIST_TEST_CASE("echo test", "", TestTypes) {
  using Client = typename std::tuple_element<0, TestType>::type;
  using Server = typename std::tuple_element<1, TestType>::type;

  auto test_data_size = GENERATE(0x100, 0x100 - 1, 0x100 + 1,
                                 0x1000, 0x1000 - 1, 0x1000 + 1,
                                 0x10000, 0x10000 - 1, 0x10000 + 1,
                                 0x100000, 0x100000 - 1, 0x100000 + 1);
  const std::string test_data = generate_data(test_data_size);

  boost::system::error_code client_ec{};
  boost::system::error_code server_ec{};

  net::io_context io_context;

  SECTION("sync test") {
    Client client(io_context);
    Server server(io_context);

    client.stream.next_layer().connect(server.stream.next_layer());

    // As the handshake requires multiple read and writes between client
    // and server, we have to run the synchronous version in a separate
    // thread. Unfortunately.
    std::thread server_handshake([&server, &server_ec]() {
      server.stream.handshake(Server::handshake_type::server, server_ec);
    });
    client.stream.handshake(Client::handshake_type::client, client_ec);
    REQUIRE_FALSE(client_ec);

    server_handshake.join();
    REQUIRE_FALSE(server_ec);

    net::write(client.stream, net::buffer(test_data));

    net::streambuf server_data;
    net::read_until(server.stream, server_data, '\0');
    net::write(server.stream, server_data);

    net::streambuf client_data;
    net::read_until(client.stream, client_data, '\0');

    // As a shutdown potentially requires multiple read and writes
    // between client and server, we have to run the synchronous version
    // in a separate thread. Unfortunately.
    std::thread server_shutdown([&server, &server_ec]() {
      server.stream.shutdown(server_ec);
    });
    client.stream.shutdown(client_ec);
    REQUIRE_FALSE(client_ec);

    server_shutdown.join();
    REQUIRE_FALSE(server_ec);

    CHECK(std::string(net::buffers_begin(client_data.data()),
                      net::buffers_begin(client_data.data()) + client_data.size()) == test_data);
  }

  SECTION("async test") {
    async_server<Server> server(io_context);
    async_client<Client> client(io_context, test_data);
    client.stream.next_layer().connect(server.stream.next_layer());
    server.run();
    client.run();
    io_context.run();
    CHECK(client.received_message() == test_data);
  }
}
