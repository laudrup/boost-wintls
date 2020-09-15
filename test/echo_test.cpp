#define BOOST_TEST_MODULE boost-windows-sspi-test
#include <boost/test/unit_test.hpp>
#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <boost/windows_sspi/windows_sspi.hpp>

#include <array>
#include <thread>

namespace net = boost::asio;

BOOST_AUTO_TEST_CASE(sync_echo_test) {
  const std::string test_data("Hello world");
  net::io_context io_context;

  boost::windows_sspi::context client_ctx(boost::windows_sspi::context::tls_client);

  boost::asio::ssl::context server_ctx(boost::asio::ssl::context::tls_server);
  server_ctx.use_certificate_chain_file(TEST_CERTIFICATE_PATH);
  server_ctx.use_private_key_file(TEST_PRIVATE_KEY_PATH, boost::asio::ssl::context::pem);

  boost::windows_sspi::stream<boost::beast::test::stream> client_stream(io_context, client_ctx);
  boost::asio::ssl::stream<boost::beast::test::stream> server_stream(io_context, server_ctx);

  client_stream.next_layer().connect(server_stream.next_layer());

  // As the handshake requires multiple read and writes between client
  // and server, we have to run the synchronous version in a separate
  // thread. Unfortunately.
  std::thread server_handshake([&server_stream]() {
    server_stream.handshake(boost::asio::ssl::stream_base::server);
  });
  client_stream.handshake(boost::windows_sspi::stream_base::client);
  server_handshake.join();

  net::write(client_stream, net::buffer(test_data));

  std::array<char, 1024> data;
  size_t reply_length = server_stream.read_some(net::buffer(data));

  BOOST_CHECK_EQUAL(std::string(data.data(), reply_length), test_data);
}
