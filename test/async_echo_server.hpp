#ifndef BOOST_WINTLS_TEST_ASYNC_ECHO_SERVER
#define BOOST_WINTLS_TEST_ASYNC_ECHO_SERVER

#include <catch2/catch.hpp>

#include <boost/asio.hpp>

template<typename Stream>
class async_server : public Stream {
public:
  using Stream::stream;

  async_server(boost::asio::io_context& context)
    : Stream(context) {
  }

  void run() {
    do_handshake();
  }

private:
  void do_handshake() {
    stream.async_handshake(Stream::handshake_type::server,
                           [this](const boost::system::error_code& ec) {
                             REQUIRE_FALSE(ec);
                             do_read();
                           });
  }

  void do_read() {
    boost::asio::async_read_until(stream, recv_buffer, '\0',
                                  [this](const boost::system::error_code& ec, std::size_t) {
                                    REQUIRE_FALSE(ec);
                                    do_write();
                                  });
  }

  void do_write() {
    boost::asio::async_write(stream, recv_buffer,
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

  boost::asio::streambuf recv_buffer;
};

#endif
