//
// Copyright (c) 2023 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_TEST_ECHO_SERVER_HPP
#define BOOST_WINTLS_TEST_ECHO_SERVER_HPP

#include "unittest.hpp"

#include <future>

template<typename Stream>
class ws_echo_server : public Stream {
public:
  using Stream::stream;

  ws_echo_server(net::io_context& context)
      : Stream(context)
      , ws_(stream) {
  }

  std::future<boost::system::error_code> handshake() {
    return std::async(std::launch::async, [this]() {
      boost::system::error_code ec{};
      ws_.next_layer().handshake(Stream::handshake_type::server, ec);
      ws_.accept(ec);
      return ec;
    });
  }

  std::future<boost::system::error_code> shutdown() {
    return std::async(std::launch::async, [this]() {
      boost::system::error_code ec{};
      ws_.close(websocket::close_code::normal, ec);
      return ec;
    });
  }

  void read() {
    ws_.read(buffer_);
    ws_.text(ws_.got_text());
  }

  void write() {
    ws_.write(buffer_.data());
  }

private:
  beast::flat_buffer buffer_;
  websocket::stream<decltype(stream)&> ws_;
};

#endif // BOOST_WINTLS_TEST_ECHO_SERVER_HPP
