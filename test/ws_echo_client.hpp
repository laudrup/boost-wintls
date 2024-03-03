//
// Copyright (c) 2023 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_TEST_ECHO_CLIENT_HPP
#define BOOST_WINTLS_TEST_ECHO_CLIENT_HPP

#include "unittest.hpp"

template<typename Stream>
class ws_echo_client : public Stream {
public:
  using Stream::stream;

  ws_echo_client(net::io_context& context)
      : Stream(context)
      , ws_(stream) {
  }

  void handshake() {
    ws_.next_layer().handshake(Stream::handshake_type::client);
    ws_.handshake("localhost", "/");
  }

  void shutdown() {
    ws_.close(websocket::close_code::normal);
  }

  void read() {
    ws_.read(buffer_);
    ws_.text(ws_.got_text());
  }

  template<typename T>
  void write(const T& data) {
    ws_.write(net::buffer(data));
  }

  template<typename T>
  T data() const {
    return T(net::buffers_begin(buffer_.data()),
             net::buffers_begin(buffer_.data()) + static_cast<std::ptrdiff_t>(buffer_.size()));
  }

private:
  beast::flat_buffer buffer_;
  websocket::stream<decltype(stream)&> ws_;
};

#endif // BOOST_WINTLS_TEST_ECHO_CLIENT_HPP
