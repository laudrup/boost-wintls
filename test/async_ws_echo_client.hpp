//
// Copyright (c) 2023 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_TEST_ASYNC_ECHO_CLIENT_HPP
#define BOOST_WINTLS_TEST_ASYNC_ECHO_CLIENT_HPP

#include "unittest.hpp"

template<typename Stream>
struct async_ws_echo_client : public Stream {
public:
  using Stream::stream;

  async_ws_echo_client(net::io_context& context, const std::string& message)
      : Stream(context)
      , message_(message)
      , ws_(stream) {
  }

  void run() {
    do_tls_handshake();
  }

  std::string received_message() const {
    return std::string(net::buffers_begin(recv_buffer_.data()),
                       net::buffers_begin(recv_buffer_.data()) + static_cast<std::ptrdiff_t>(recv_buffer_.size()));
  }

private:
  void do_tls_handshake() {
    ws_.next_layer().async_handshake(Stream::handshake_type::client, [this](const boost::system::error_code& ec) {
      REQUIRE_FALSE(ec);
      do_ws_handshake();
    });
  }

  void do_ws_handshake() {
    ws_.async_handshake("localhost", "/", [this](const boost::system::error_code& ec) {
      REQUIRE_FALSE(ec);
      do_write();
    });
  }

  void do_write() {
    ws_.async_write(net::buffer(message_), [this](const boost::system::error_code& ec, std::size_t) {
      REQUIRE_FALSE(ec);
      do_read();
    });
  }

  void do_read() {
    ws_.async_read(recv_buffer_, [this](const boost::system::error_code& ec, std::size_t) {
      REQUIRE_FALSE(ec);
      do_shutdown();
    });
  }

  void do_shutdown() {
    ws_.async_close(websocket::close_code::normal, [](const boost::system::error_code& ec) {
      REQUIRE_FALSE(ec);
    });
  }

  std::string message_;
  beast::flat_buffer recv_buffer_;
  websocket::stream<decltype(stream)&> ws_;
};

#endif // BOOST_WINTLS_TEST_ASYNC_ECHO_CLIENT_HPP
