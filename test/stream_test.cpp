//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "unittest.hpp"
#include "asio_ssl_server_stream.hpp"
#include "wintls_client_stream.hpp"
#include "echo_server.hpp"
#include "async_echo_server.hpp"

#include <boost/wintls.hpp>
#include <boost/wintls/detail/config.hpp>

#include <boost/asio/io_context.hpp>

#include <array>
#include <thread>

class test_server : public async_echo_server<asio_ssl_server_stream> {
public:
  test_server(net::io_context& context)
    : async_echo_server<asio_ssl_server_stream>(context) {
  }

  void do_read() final {
  }
};

TEST_CASE("handshake not done") {
  boost::wintls::context ctx{boost::wintls::method::system_default};
  boost::asio::io_context ioc;
  std::array<char, 4> buf{};

  boost::wintls::stream<boost::asio::ip::tcp::socket> stream(ioc, ctx);
  boost::system::error_code ec{};

  SECTION("write fails") {
    boost::wintls::net::write(stream, boost::wintls::net::buffer(buf), ec);
    CHECK(ec);
  }

  SECTION("async_write fails") {
    boost::wintls::net::async_write(stream, boost::wintls::net::buffer(buf),
                                    [&ec](const boost::system::error_code& error, std::size_t) {
                                      ec = error;
                                    });
    ioc.run_one();
    CHECK(ec);
  }

  SECTION("read fails") {
    boost::wintls::net::read(stream, boost::wintls::net::buffer(buf), ec);
    CHECK(ec);
  }

  SECTION("async_read fails") {
    boost::wintls::net::async_read(stream, boost::wintls::net::buffer(buf),
                                   [&ec](const boost::system::error_code& error, std::size_t) {
                                      ec = error;
                                    });
    ioc.run_one();
    CHECK(ec);
  }
}

TEST_CASE("underlying stream errors") {
  SECTION("sync test") {
    net::io_context io_context;
    echo_server<asio_ssl_server_stream> server(io_context);
    boost::system::error_code client_ec{};
    boost::system::error_code server_ec{};

    SECTION("handshake error") {
      boost::beast::test::fail_count fc(4);
      wintls_client_stream client(io_context, fc);

      client.stream.next_layer().connect(server.stream.next_layer());

      auto handshake_result = server.handshake();
      client.stream.handshake(wintls_client_stream::handshake_type::client, client_ec);
      REQUIRE_FALSE(handshake_result.get());
      CHECK(client_ec.value() == 1);
    }

    SECTION("failing read/write") {
      boost::beast::test::fail_count fc(5);
      wintls_client_stream client(io_context, fc);

      client.stream.next_layer().connect(server.stream.next_layer());

      auto handshake_result = server.handshake();
      client.stream.handshake(wintls_client_stream::handshake_type::client, client_ec);
      REQUIRE_FALSE(handshake_result.get());
      REQUIRE_FALSE(client_ec);

      SECTION("read error") {
        net::streambuf client_data;
        net::read(client.stream, client_data, client_ec);
        CHECK(client_ec.value() == 1);
      }

      SECTION("write error") {
        std::string str{"abcd"};
        net::write(client.stream, net::buffer(str), client_ec);
        CHECK(client_ec.value() == 1);
      }
    }
  }

  SECTION("async test") {
    net::io_context io_context;
    boost::system::error_code client_ec{};

    test_server server(io_context);

    SECTION("handshake error") {
      boost::beast::test::fail_count fc(4);
      wintls_client_stream client(io_context, fc);
      client.stream.next_layer().connect(server.stream.next_layer());
      server.run();
      client.stream.async_handshake(wintls_client_stream::handshake_type::client,
                                    [&client_ec](const boost::system::error_code& ec) {
                                      client_ec = ec;
                                    });
      io_context.run();
      CHECK(client_ec.value() == 1);
    }

    SECTION("failing read/write") {
      boost::beast::test::fail_count fc(5);
      wintls_client_stream client(io_context, fc);
      client.stream.next_layer().connect(server.stream.next_layer());
      boost::asio::streambuf buffer;
      server.run();

      SECTION("read error") {
        client.stream.async_handshake(wintls_client_stream::handshake_type::client,
                                      [&client_ec, &client, &buffer](const boost::system::error_code& ec) {
                                        REQUIRE_FALSE(ec);
                                        net::async_read(client.stream, buffer, [&client_ec](const boost::system::error_code& ec, std::size_t) {
                                          client_ec = ec;
                                        });
                                      });
        io_context.run();
        CHECK(client_ec.value() == 1);
      }

      SECTION("write error") {
        client.stream.async_handshake(wintls_client_stream::handshake_type::client,
                                      [&client_ec, &client, &buffer](const boost::system::error_code& ec) {
                                        REQUIRE_FALSE(ec);
                                        net::async_write(client.stream, buffer, [&client_ec](const boost::system::error_code& ec, std::size_t) {
                                          client_ec = ec;
                                        });
                                      });
        io_context.run();
        CHECK(client_ec.value() == 1);
      }
    }
  }
}

