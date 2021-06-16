//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "async_echo_server.hpp"
#include "async_echo_client.hpp"

#include <boost/wintls.hpp>

#include <catch2/catch.hpp>

#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <fstream>
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

std::vector<char> pem_cert_bytes() {
  std::ifstream ifs{TEST_CERTIFICATE_PATH};
  REQUIRE(ifs.good());
  return {std::istreambuf_iterator<char>{ifs}, {}};
}

}

struct asio_ssl_client_context : public asio_ssl::context {
  asio_ssl_client_context()
    : asio_ssl::context(asio_ssl::context_base::tlsv12) {
    load_verify_file(TEST_CERTIFICATE_PATH);
  }
};

struct asio_ssl_server_context : public asio_ssl::context {
  asio_ssl_server_context()
    : asio_ssl::context(asio_ssl::context_base::tlsv12) {
    use_certificate_file(TEST_CERTIFICATE_PATH, asio_ssl::context_base::pem);
    use_private_key_file(TEST_PRIVATE_KEY_PATH, asio_ssl::context_base::pem);
  }
};

struct asio_ssl_client_stream {
  using handshake_type = asio_ssl::stream_base::handshake_type;

  template <class... Args>
  asio_ssl_client_stream(Args&&... args)
    : tst(std::forward<Args>(args)...)
    , stream(tst, ctx) {
  }

  asio_ssl_client_context ctx;
  test_stream tst;
  asio_ssl::stream<test_stream&> stream;
};

struct asio_ssl_server_stream {
  using handshake_type = asio_ssl::stream_base::handshake_type;

  template <class... Args>
  asio_ssl_server_stream(Args&&... args)
    : tst(std::forward<Args>(args)...)
    , stream(tst, ctx) {
  }

  asio_ssl_server_context ctx;
  test_stream tst;
  asio_ssl::stream<test_stream&> stream;
};

struct wintls_client_context : public boost::wintls::context {
  wintls_client_context()
    : boost::wintls::context(boost::wintls::method::system_default) {
    const auto x509 = pem_cert_bytes();
    const auto cert_ptr = x509_to_cert_context(net::buffer(x509), boost::wintls::file_format::pem);
    add_certificate_authority(cert_ptr.get());
  }
};

struct wintls_server_context : public boost::wintls::context {
  wintls_server_context()
    : boost::wintls::context(boost::wintls::method::system_default) {
    use_certificate_file(TEST_CERTIFICATE_PATH, boost::wintls::file_format::pem);
    use_private_key_file(TEST_PRIVATE_KEY_PATH, boost::wintls::file_format::pem);
  }
};

struct wintls_client_stream {
  using handshake_type = boost::wintls::handshake_type;

  template <class... Args>
  wintls_client_stream(Args&&... args)
    : tst(std::forward<Args>(args)...)
    , stream(tst, ctx) {
  }

  wintls_client_context ctx;
  test_stream tst;
  boost::wintls::stream<test_stream&> stream;
};

struct wintls_server_stream {
  using handshake_type = boost::wintls::handshake_type;

  template <class... Args>
  wintls_server_stream(Args&&... args)
    : tst(std::forward<Args>(args)...)
    , stream(tst, ctx) {
  }

  wintls_server_context ctx;
  test_stream tst;
  boost::wintls::stream<test_stream&> stream;
};

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
