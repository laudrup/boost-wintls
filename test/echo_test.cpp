#include "async_echo_server.hpp"
#include "async_echo_client.hpp"

#ifdef _WIN32
#include <boost/windows_sspi/windows_sspi.hpp>
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

using SSLClientTypes = std::tuple<asio_ssl::context, asio_ssl::stream<test_stream>, asio_ssl::stream_base>;
#ifdef _WIN32
using SSPIClientTypes = std::tuple<boost::windows_sspi::context, boost::windows_sspi::stream<test_stream>, boost::windows_sspi::stream_base>;
#endif

#ifdef _WIN32
using ClientTypes = std::tuple<SSLClientTypes, SSPIClientTypes>;
#else
using ClientTypes = std::tuple<SSLClientTypes>;
#endif

TEMPLATE_LIST_TEST_CASE("echo test", "", ClientTypes) {
  static_assert(std::tuple_size<TestType>::value == 3, "Expected exactly three client TLS types");
  using ClientTLSContext = typename std::tuple_element<0, TestType>::type;
  using ClientTLSStream = typename std::tuple_element<1, TestType>::type;
  using ClientTLSStreamBase = typename std::tuple_element<2, TestType>::type;

  auto test_data_size = GENERATE(0x100, 0x100 - 1, 0x100 + 1,
                                 0x1000, 0x1000 - 1, 0x1000 + 1,
                                 0x10000, 0x10000 - 1, 0x10000 + 1,
                                 0x100000, 0x100000 - 1, 0x100000 + 1);
  const std::string test_data = generate_data(test_data_size);

  ClientTLSContext client_ctx(ClientTLSContext::tls_client);

  boost::asio::ssl::context server_ctx(boost::asio::ssl::context::tls_server);
  server_ctx.use_certificate_chain_file(TEST_CERTIFICATE_PATH);
  server_ctx.use_private_key_file(TEST_PRIVATE_KEY_PATH, boost::asio::ssl::context::pem);

  net::io_context io_context;
  ClientTLSStream client_stream(io_context, client_ctx);
  boost::asio::ssl::stream<boost::beast::test::stream> server_stream(io_context, server_ctx);

  client_stream.next_layer().connect(server_stream.next_layer());

  SECTION("sync test") {
    // As the handshake requires multiple read and writes between client
    // and server, we have to run the synchronous version in a separate
    // thread. Unfortunately.
    std::thread server_handshake([&server_stream]() {
      server_stream.handshake(boost::asio::ssl::stream_base::server);
    });
    boost::system::error_code ec;
    client_stream.handshake(ClientTLSStreamBase::client, ec);
    REQUIRE_FALSE(ec);
    server_handshake.join();

    net::write(client_stream, net::buffer(test_data));

    net::streambuf server_data;
    net::read_until(server_stream, server_data, '\0');
    net::write(server_stream, server_data);

    net::streambuf client_data;
    net::read_until(client_stream, client_data, '\0');

    // As a shutdown potentially requires multiple read and writes
    // between client and server, we have to run the synchronous version
    // in a separate thread. Unfortunately.
    std::thread server_shutdown([&server_stream]() {
      server_stream.shutdown();
    });
    client_stream.shutdown(ec);
    REQUIRE_FALSE(ec);
    server_shutdown.join();

    CHECK(std::string(net::buffers_begin(client_data.data()),
                      net::buffers_begin(client_data.data()) + client_data.size()) == test_data);
  }

  SECTION("async test") {
    async_server<boost::asio::ssl::context,
                 boost::asio::ssl::stream<boost::beast::test::stream>,
                 boost::asio::ssl::stream_base>
      server(server_stream, server_ctx);

    async_client<ClientTLSContext,
                 ClientTLSStream,
                 ClientTLSStreamBase>
      client(client_stream, client_ctx, test_data);

    io_context.run();
    CHECK(client.received_message() == test_data);
  }
}
