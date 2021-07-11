//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef BOOST_WINTLS_UNITTEST_HPP
#define BOOST_WINTLS_UNITTEST_HPP

#include <boost/wintls/detail/config.hpp>

#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio/ssl.hpp>

#include <catch2/catch.hpp>

#include <fstream>
#include <iterator>
#include <sstream>

namespace Catch {
template<>
struct StringMaker<boost::system::error_code> {
  static std::string convert(const boost::system::error_code& ec) {
    std::ostringstream oss;
    oss << ec.message() << " (0x" << std::hex << ec.value() << ")";
    return oss.str();
  }
};
}

inline std::vector<char> test_cert_bytes() {
  std::ifstream ifs{TEST_CERTIFICATE_PATH};
  return {std::istreambuf_iterator<char>{ifs}, {}};
}

inline std::vector<char> test_key_bytes() {
  std::ifstream ifs{TEST_PRIVATE_KEY_PATH};
  return {std::istreambuf_iterator<char>{ifs}, {}};
}

namespace net = boost::wintls::net;
namespace asio_ssl = boost::asio::ssl;
using test_stream = boost::beast::test::stream;

#endif // BOOST_WINTLS_UNITTEST_HPP
