//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef WINTLS_SERVER_STREAM_HPP
#define WINTLS_SERVER_STREAM_HPP

#include "unittest.hpp"

#include <boost/wintls.hpp>

struct wintls_server_context : public boost::wintls::context {
  wintls_server_context()
    : boost::wintls::context(boost::wintls::method::system_default) {
    use_certificate_file(TEST_CERTIFICATE_PATH, boost::wintls::file_format::pem);
    use_private_key_file(TEST_PRIVATE_KEY_PATH, boost::wintls::file_format::pem);
  }
};

struct wintls_server_stream {
  using handshake_type = boost::wintls::handshake_type;

  template <class... Args>
  wintls_server_stream(Args&&... args)
    : tst(std::forward<Args>(args)...)
    , stream(tst, ctx) {
  }

  wintls_server_context ctx;
  test_stream tst;
  boost::wintls::stream<test_stream&> stream;
};

#endif // WINTLS_SERVER_STREAM_HPP
