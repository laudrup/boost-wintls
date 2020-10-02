#include "async_echo_server.hpp"
#include "async_echo_client.hpp"

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

namespace {
std::string generate_data(std::size_t size) {
  std::string ret(size, '\0');
  for (auto i = 0; i < size - 1; ++i) {
  const char cur_char = i % 26;
    ret[i] = cur_char + 65;
  }
  return ret;
}
}

template<typename ClientTLSContext, typename ClientTLSStream, typename ClientTLSStreamBase>
void async_echo_test(std::size_t test_data_size) {
  const std::string test_data = generate_data(test_data_size);
  net::io_context io_context;

  ClientTLSContext client_ctx(ClientTLSContext::tls_client);

  boost::asio::ssl::context server_ctx(boost::asio::ssl::context::tls_server);
  server_ctx.use_certificate_chain_file(TEST_CERTIFICATE_PATH);
  server_ctx.use_private_key_file(TEST_PRIVATE_KEY_PATH, boost::asio::ssl::context::pem);

  ClientTLSStream client_stream(io_context, client_ctx);
  boost::asio::ssl::stream<boost::beast::test::stream> server_stream(io_context, server_ctx);

  client_stream.next_layer().connect(server_stream.next_layer());

  async_server<boost::asio::ssl::context,
               boost::asio::ssl::stream<boost::beast::test::stream>,
               boost::asio::ssl::stream_base>
    server(server_stream, server_ctx);

  async_client<boost::asio::ssl::context,
               boost::asio::ssl::stream<boost::beast::test::stream>,
               boost::asio::ssl::stream_base>
    client(client_stream, client_ctx, test_data);

  io_context.run();
  BOOST_TEST_EQ(client.received_message(), test_data);
}

template<typename ClientTLSContext, typename ClientTLSStream, typename ClientTLSStreamBase>
void sync_echo_test(std::size_t test_data_size) {
  const std::string test_data = generate_data(test_data_size);
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

  net::streambuf server_data;
  net::read_until(server_stream, server_data, '\0');
  net::write(server_stream, server_data);

  net::streambuf client_data;
  net::read_until(client_stream, client_data, '\0');

  BOOST_TEST_EQ(std::string(net::buffers_begin(client_data.data()), net::buffers_begin(client_data.data()) + client_data.size()), test_data);
}

int main() {
  using test_stream = boost::beast::test::stream;
  for (const auto size : std::vector<std::size_t>{
      0x100, 0x100 - 1, 0x100 + 1,
      0x1000, 0x1000 - 1, 0x1000 + 1,
      0x10000, 0x10000 - 1, 0x10000 + 1,
      0x100000, 0x100000 - 1, 0x100000 + 1}) {
#ifdef _WIN32
    sync_echo_test<boost::windows_sspi::context, boost::windows_sspi::stream<test_stream>, boost::windows_sspi::stream_base>(size);
#endif
    sync_echo_test<boost::asio::ssl::context, boost::asio::ssl::stream<test_stream>, boost::asio::ssl::stream_base>(size);
    async_echo_test<boost::asio::ssl::context, boost::asio::ssl::stream<test_stream>, boost::asio::ssl::stream_base>(size);
  }
  return boost::report_errors();
}
