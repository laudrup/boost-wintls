//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef WINTLS_TEST_UNITTEST_HPP
#define WINTLS_TEST_UNITTEST_HPP

#include <wintls/detail/config.hpp>

#ifndef WINTLS_USE_STANDALONE_ASIO
#include <boost/beast/core.hpp>
#endif // !WINTLS_USE_STANDALONE_ASIO

#include "test_stream/stream.hpp"

#ifdef WINTLS_USE_STANDALONE_ASIO
#include <asio/ssl.hpp>
#else // WINTLS_USE_STANDALONE_ASIO
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <wintls/beast.hpp>
#endif // !WINTLS_USE_STANDALONE_ASIO

#include <catch2/catch.hpp>

#include <fstream>
#include <iterator>
#include <sstream>
#include <string>

namespace Catch {
template<>
struct StringMaker<error_code> {
  static std::string convert(const error_code& ec) {
    std::ostringstream oss;
    oss << ec.message() << " (0x" << std::hex << ec.value() << ")";
    return oss.str();
  }
};
} // namespace Catch

inline std::vector<unsigned char> bytes_from_file(const std::string& path) {
  std::ifstream ifs{path};
  if (ifs.fail()) {
    throw std::runtime_error("Failed to open file " + path);
  }
  return {std::istreambuf_iterator<char>{ifs}, {}};
}

namespace net = wintls::net;
#ifdef WINTLS_USE_STANDALONE_ASIO
namespace asio_ssl = asio::ssl;
#else  // WINTLS_USE_STANDALONE_ASIO
namespace asio_ssl = boost::asio::ssl;
namespace beast = boost::beast;
namespace websocket = boost::beast::websocket;
#endif // !WINTLS_USE_STANDALONE_ASIO
using test_stream = wintls::test::stream;

#endif // WINTLS_TEST_UNITTEST_HPP
