#ifndef BOOST_WINTLS_TEST_ASYNC_ECHO_CLIENT
#define BOOST_WINTLS_TEST_ASYNC_ECHO_CLIENT

#include <catch2/catch.hpp>

#include <boost/asio.hpp>

template<typename Stream>
struct async_client : public Stream {
public:
  using Stream::stream;

  async_client(boost::asio::io_context& context, const std::string& message)
    : Stream(context)
    , m_message(message) {
  }

  void run() {
    do_handshake();
  }

  std::string received_message() const {
    return std::string(boost::asio::buffers_begin(m_recv_buffer.data()),
                       boost::asio::buffers_begin(m_recv_buffer.data()) + m_recv_buffer.size());
  }

private:
  void do_handshake() {
    stream.async_handshake(Stream::handshake_type::client,
                           [this](const boost::system::error_code& ec) {
                             REQUIRE_FALSE(ec);
                             do_write();
                           });
  }

  void do_write() {
    boost::asio::async_write(stream, boost::asio::buffer(m_message),
                             [this](const boost::system::error_code& ec, std::size_t) {
                               REQUIRE_FALSE(ec);
                               do_read();
                             });
  }

  void do_read() {
    boost::asio::async_read_until(stream, m_recv_buffer, '\0',
                                  [this](const boost::system::error_code& ec, std::size_t) {
                                    REQUIRE_FALSE(ec);
                                    do_shutdown();
                                  });
  }

  void do_shutdown() {
    stream.async_shutdown([](const boost::system::error_code& ec) {
      REQUIRE_FALSE(ec);
    });
  }

  std::string m_message;
  boost::asio::streambuf m_recv_buffer;
};

#endif
