//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_TEST_ASYNC_ECHO_SERVER_HPP
#define WINTLS_TEST_ASYNC_ECHO_SERVER_HPP

#include "unittest.hpp"

template<typename Stream>
class async_echo_server : public Stream {
public:
  using Stream::stream;

  async_echo_server(net::io_context& context)
    : Stream(context) {
  }

  void run() {
    do_handshake();
  }

  virtual ~async_echo_server() = default;

  virtual void do_handshake() {
    stream.async_handshake(Stream::handshake_type::server,
                           [this](const error_code& ec) {
                             REQUIRE_FALSE(ec);
                             do_read();
                           });
  }

  virtual void do_read() {
    net::async_read_until(stream, recv_buffer_, '\0',
                          [this](const error_code& ec, std::size_t) {
                            REQUIRE_FALSE(ec);
                            do_write();
                          });
  }

  virtual void do_write() {
    net::async_write(stream, recv_buffer_,
                     [this](const error_code& ec, std::size_t) {
                       REQUIRE_FALSE(ec);
                       do_shutdown();
                     });
  }

  virtual void do_shutdown() {
    stream.async_shutdown([](const error_code& ec) {
      REQUIRE_FALSE(ec);
    });
  }

  net::streambuf recv_buffer_;
};

#endif // WINTLS_TEST_ASYNC_ECHO_SERVER_HPP
