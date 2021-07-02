//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef ASIO_SSL_CLIENT_STREAM_HPP
#define ASIO_SSL_CLIENT_STREAM_HPP

#include "unittest.hpp"

struct asio_ssl_client_context : public asio_ssl::context {
  asio_ssl_client_context()
    : asio_ssl::context(asio_ssl::context_base::tls) {
    load_verify_file(TEST_CERTIFICATE_PATH);
  }
};

struct asio_ssl_client_stream {
  using handshake_type = asio_ssl::stream_base::handshake_type;

  template <class... Args>
  asio_ssl_client_stream(Args&&... args)
    : tst(std::forward<Args>(args)...)
    , stream(tst, ctx) {
  }

  asio_ssl_client_context ctx;
  test_stream tst;
  asio_ssl::stream<test_stream&> stream;
};

#endif // ASIO_SSL_CLIENT_STREAM_HPP
