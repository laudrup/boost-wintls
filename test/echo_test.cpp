#include <boost/core/lightweight_test.hpp>
#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#ifdef _WIN32
#include <boost/windows_sspi/windows_sspi.hpp>
#endif

#include <array>
#include <thread>

namespace net = boost::asio;

template<typename ClientTLSContext, typename ClientTLSStream, typename ClientTLSStreamBase>
void sync_echo_test() {
  const std::string test_data("Hello world");
  net::io_context io_context;

  ClientTLSContext client_ctx(ClientTLSContext::tls_client);

  boost::asio::ssl::context server_ctx(boost::asio::ssl::context::tls_server);
  server_ctx.use_certificate_chain_file(TEST_CERTIFICATE_PATH);
  server_ctx.use_private_key_file(TEST_PRIVATE_KEY_PATH, boost::asio::ssl::context::pem);

  ClientTLSStream client_stream(io_context, client_ctx);
  boost::asio::ssl::stream<boost::beast::test::stream> server_stream(io_context, server_ctx);

  client_stream.next_layer().connect(server_stream.next_layer());

  // As the handshake requires multiple read and writes between client
  // and server, we have to run the synchronous version in a separate
  // thread. Unfortunately.
  std::thread server_handshake([&server_stream]() {
    server_stream.handshake(boost::asio::ssl::stream_base::server);
  });
  client_stream.handshake(ClientTLSStreamBase::client);
  server_handshake.join();

  net::write(client_stream, net::buffer(test_data));

  std::array<char, 1024> data;
  size_t reply_length = server_stream.read_some(net::buffer(data));

  BOOST_TEST_EQ(std::string(data.data(), reply_length), test_data);
}

int main() {
  using test_stream = boost::beast::test::stream;
#ifdef _WIN32
  sync_echo_test<boost::windows_sspi::context, boost::windows_sspi::stream<test_stream>, boost::windows_sspi::stream_base>();
#endif
  sync_echo_test<boost::asio::ssl::context, boost::asio::ssl::stream<test_stream>, boost::asio::ssl::stream_base>();
  return boost::report_errors();
}
