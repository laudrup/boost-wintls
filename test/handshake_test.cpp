#include "async_echo_server.hpp"
#include "async_echo_client.hpp"
#include "tls_record.hpp"

#include <boost/windows_sspi/windows_sspi.hpp>

#include <catch2/catch.hpp>

#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace net = boost::asio;

TEST_CASE("handshake") {
  using namespace std::string_literals;

  boost::windows_sspi::context client_ctx(boost::windows_sspi::context::tls_client);

  boost::asio::ssl::context server_ctx(boost::asio::ssl::context::tls_server);
  server_ctx.use_certificate_chain_file(TEST_CERTIFICATE_PATH);
  server_ctx.use_private_key_file(TEST_PRIVATE_KEY_PATH, boost::asio::ssl::context::pem);

  net::io_context io_context;
  boost::windows_sspi::stream<boost::beast::test::stream> client_stream(io_context, client_ctx);
  boost::asio::ssl::stream<boost::beast::test::stream> server_stream(io_context, server_ctx);

  client_stream.next_layer().connect(server_stream.next_layer());

  SECTION("invalid server reply") {
    boost::system::error_code error{};
    client_stream.async_handshake(boost::windows_sspi::stream_base::client,
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
    CHECK(error.category() == boost::windows_sspi::error::get_sspi_category());
    CHECK(error.value() == SEC_E_ILLEGAL_MESSAGE);
  }
}
