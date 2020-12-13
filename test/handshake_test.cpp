//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "async_echo_server.hpp"
#include "async_echo_client.hpp"
#include "tls_record.hpp"

#include <boost/windows_tls.hpp>

#include <catch2/catch.hpp>

#include <boost/system/error_code.hpp>
#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace net = boost::asio;

TEST_CASE("handshake") {
  using namespace std::string_literals;

  boost::windows_tls::context client_ctx(boost::windows_tls::method::tls_client);

  boost::asio::ssl::context server_ctx(boost::asio::ssl::context::tls_server);
  server_ctx.use_certificate_chain_file(TEST_CERTIFICATE_PATH);
  server_ctx.use_private_key_file(TEST_PRIVATE_KEY_PATH, boost::asio::ssl::context::pem);

  net::io_context io_context;
  boost::windows_tls::stream<boost::beast::test::stream> client_stream(io_context, client_ctx);
  boost::asio::ssl::stream<boost::beast::test::stream> server_stream(io_context, server_ctx);

  client_stream.next_layer().connect(server_stream.next_layer());

  SECTION("invalid certificate data") {
    using namespace boost::system;

    auto error = errc::make_error_code(errc::not_supported);
    const std::string bad_cert = "DECAFBAD";
    client_ctx.add_certificate_authority(net::buffer(bad_cert), error);
    CHECK(error.category() == boost::system::system_category());
    CHECK(error.value() == ERROR_INVALID_DATA);
  }

  SECTION("no certificate validation") {
    using namespace boost::system;

    auto client_error = errc::make_error_code(errc::not_supported);
    client_stream.async_handshake(boost::windows_tls::handshake_type::client,
                                  [&client_error, &io_context](const boost::system::error_code& ec) {
                                    client_error = ec;
                                    io_context.stop();
                                  });

    auto server_error = errc::make_error_code(errc::not_supported);
    server_stream.async_handshake(boost::asio::ssl::stream_base::server,
                                  [&server_error](const boost::system::error_code& ec) {
                                    server_error = ec;
                                  });
    io_context.run();
    CHECK_FALSE(client_error);
    CHECK_FALSE(server_error);
  }

  SECTION("no trusted certificate") {
    using namespace boost::system;

    client_ctx.verify_server_certificate(true);

    auto client_error = errc::make_error_code(errc::not_supported);
    client_stream.async_handshake(boost::windows_tls::handshake_type::client,
                                  [&client_error](const boost::system::error_code& ec) {
                                    client_error = ec;
                                  });

    auto server_error = errc::make_error_code(errc::not_supported);
    server_stream.async_handshake(boost::asio::ssl::stream_base::server,
                                  [&server_error](const boost::system::error_code& ec) {
                                    server_error = ec;
                                  });

    io_context.run();
    CHECK(client_error.category() == boost::system::system_category());
    CHECK(client_error.value() == CERT_E_UNTRUSTEDROOT);
    CHECK_FALSE(server_error);
  }

  SECTION("trusted certificate verified") {
    using namespace boost::system;

    client_ctx.verify_server_certificate(true);

    auto certificate_error = errc::make_error_code(errc::not_supported);
    client_ctx.load_verify_file(TEST_CERTIFICATE_PATH, certificate_error);
    REQUIRE_FALSE(certificate_error);

    auto client_error = errc::make_error_code(errc::not_supported);
    client_stream.async_handshake(boost::windows_tls::handshake_type::client,
                                  [&client_error, &io_context](const boost::system::error_code& ec) {
                                    client_error = ec;
                                    io_context.stop();
                                  });

    auto server_error = errc::make_error_code(errc::not_supported);
    server_stream.async_handshake(boost::asio::ssl::stream_base::server,
                                  [&server_error](const boost::system::error_code& ec) {
                                    server_error = ec;
                                  });
    io_context.run();
    CHECK_FALSE(client_error);
    CHECK_FALSE(server_error);
  }

  SECTION("invalid server reply") {
    using namespace boost::system;

    auto error = errc::make_error_code(errc::not_supported);
    client_stream.async_handshake(boost::windows_tls::handshake_type::client,
                                  [&error](const boost::system::error_code& ec) {
                                    error = ec;
                                  });

    std::array<char, 1024> buffer;
    server_stream.next_layer().async_read_some(net::buffer(buffer, buffer.size()),
                                               [&buffer, &server_stream](const boost::system::error_code&, std::size_t length) {
                                                 tls_record rec(net::buffer(buffer, length));
                                                 REQUIRE(rec.type == tls_record::record_type::handshake);
                                                 auto handshake = boost::get<tls_handshake>(rec.message);
                                                 REQUIRE(handshake.type == tls_handshake::handshake_type::client_hello);
                                                 // Echoing the client_hello message back should cause the handshake to fail
                                                 net::write(server_stream.next_layer(), net::buffer(buffer));
                    });

    io_context.run();
    CHECK(error.category() == boost::system::system_category());
    CHECK(error.value() == SEC_E_ILLEGAL_MESSAGE);
  }
}
