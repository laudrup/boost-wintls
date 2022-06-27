//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef WINTLS_CLIENT_STREAM_HPP
#define WINTLS_CLIENT_STREAM_HPP

#include "certificate.hpp"
#include "unittest.hpp"

#include <boost/wintls.hpp>

#include <fstream>
#include <iterator>

struct wintls_client_context : public boost::wintls::context {
  wintls_client_context()
    : boost::wintls::context(boost::wintls::method::system_default) {
    const auto cert_ptr = x509_to_cert_context(net::buffer(test_certificate), boost::wintls::file_format::pem);
    add_certificate_authority(cert_ptr.get());
  }
};

struct wintls_client_stream {
  using handshake_type = boost::wintls::handshake_type;

  template <class... Args>
  wintls_client_stream(Args&&... args)
    : tst(std::forward<Args>(args)...)
    , stream(tst, ctx) {
  }

  wintls_client_context ctx;
  test_stream tst;
  boost::wintls::stream<test_stream&> stream;
};

#endif // WINTLS_CLIENT_STREAM_HPP
