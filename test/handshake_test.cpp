//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "async_echo_server.hpp"
#include "async_echo_client.hpp"
#include "tls_record.hpp"

#include <boost/wintls.hpp>

#include <catch2/catch.hpp>

#include <boost/system/error_code.hpp>
#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <fstream>

namespace net = boost::asio;

namespace {
std::vector<char> pem_cert_bytes() {
  std::ifstream ifs{TEST_CERTIFICATE_PATH};
  REQUIRE(ifs.good());
  return {std::istreambuf_iterator<char>{ifs}, {}};
}
}

TEST_CASE("certificates") {
  using namespace std::string_literals;

  boost::wintls::context client_ctx(boost::wintls::method::system_default);

  boost::asio::ssl::context server_ctx(boost::asio::ssl::context::tls_server);
  server_ctx.use_certificate_chain_file(TEST_CERTIFICATE_PATH);
  server_ctx.use_private_key_file(TEST_PRIVATE_KEY_PATH, boost::asio::ssl::context::pem);

  net::io_context io_context;
  boost::wintls::stream<boost::beast::test::stream> client_stream(io_context, client_ctx);
  boost::asio::ssl::stream<boost::beast::test::stream> server_stream(io_context, server_ctx);

  client_stream.next_layer().connect(server_stream.next_layer());

  SECTION("invalid certificate data") {
    // TODO: Instead of returning an error when given a null pointer
    // or other easily detectable invalid input, the Windows crypto
    // libraries cause the Windows equivalent of a segfault. This is
    // pretty consistent with the rest of the Windows API though.
    //
    // Figure out a way to generate invalid data that doesn't make the
    // test crash.
    /*
    using namespace boost::system;

    auto error = errc::make_error_code(errc::not_supported);

    CERT_INFO cert_info{};
    const CERT_CONTEXT bad_cert{
      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
      nullptr,
      0,
      &cert_info,
      0};
    client_ctx.add_certificate_authority(&bad_cert, error);

    CHECK(error.category() == boost::system::system_category());
    CHECK(error.value() == CRYPT_E_ASN1_EOD);
    */
  }

  SECTION("no certificate validation") {
    using namespace boost::system;

    auto client_error = errc::make_error_code(errc::not_supported);
    client_stream.async_handshake(boost::wintls::handshake_type::client,
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
    client_stream.async_handshake(boost::wintls::handshake_type::client,
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

    const auto x509 = pem_cert_bytes();
    const auto cert_ptr = x509_to_cert_context(net::buffer(x509), boost::wintls::file_format::pem);
    client_ctx.add_certificate_authority(cert_ptr.get());

    auto client_error = errc::make_error_code(errc::not_supported);
    client_stream.async_handshake(boost::wintls::handshake_type::client,
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
}

TEST_CASE("failing handshakes") {
  boost::wintls::context client_ctx(boost::wintls::method::system_default);
  net::io_context io_context;
  boost::wintls::stream<boost::beast::test::stream> client_stream(io_context, client_ctx);
  boost::beast::test::stream server_stream(io_context);

  client_stream.next_layer().connect(server_stream);

  SECTION("invalid server reply") {
    using namespace boost::system;

    auto error = errc::make_error_code(errc::not_supported);
    client_stream.async_handshake(boost::wintls::handshake_type::client,
                                  [&error](const boost::system::error_code& ec) {
                                    error = ec;
                                  });

    std::array<char, 1024> buffer;
    server_stream.async_read_some(net::buffer(buffer, buffer.size()),
                                  [&buffer, &server_stream](const boost::system::error_code&, std::size_t length) {
                                    tls_record rec(net::buffer(buffer, length));
                                    REQUIRE(rec.type == tls_record::record_type::handshake);
                                    auto handshake = boost::get<tls_handshake>(rec.message);
                                    REQUIRE(handshake.type == tls_handshake::handshake_type::client_hello);
                                    // Echoing the client_hello message back should cause the handshake to fail
                                    net::write(server_stream, net::buffer(buffer));
                                  });

    io_context.run();
    CHECK(error.category() == boost::system::system_category());
    CHECK(error.value() == SEC_E_ILLEGAL_MESSAGE);
  }
}

TEST_CASE("ssl/tls versions") {
  const auto value = GENERATE(values<std::pair<boost::wintls::method, tls_version>>({
        { boost::wintls::method::tlsv1, tls_version::tls_1_0 },
        { boost::wintls::method::tlsv1_client, tls_version::tls_1_0 },
        { boost::wintls::method::tlsv11, tls_version::tls_1_1 },
        { boost::wintls::method::tlsv11_client, tls_version::tls_1_1 },
        { boost::wintls::method::tlsv12, tls_version::tls_1_2 },
        { boost::wintls::method::tlsv12_client, tls_version::tls_1_2 }
      })
    );

  const auto method = value.first;
  const auto version = value.second;

  boost::wintls::context client_ctx(method);
  net::io_context io_context;
  boost::wintls::stream<boost::beast::test::stream> client_stream(io_context, client_ctx);
  boost::beast::test::stream server_stream(io_context);

  client_stream.next_layer().connect(server_stream);

  client_stream.async_handshake(boost::wintls::handshake_type::client,
                                [](const boost::system::error_code& ec) {
                                  REQUIRE(ec == boost::asio::error::eof);
                                });

  std::array<char, 1024> buffer;
  server_stream.async_read_some(net::buffer(buffer, buffer.size()),
                                [&buffer, &server_stream, &version](const boost::system::error_code&, std::size_t length) {
                                  tls_record rec(net::buffer(buffer, length));
                                  REQUIRE(rec.type == tls_record::record_type::handshake);
                                  CHECK(rec.version == version);
                                  server_stream.close();
                                  });

    io_context.run();
}
