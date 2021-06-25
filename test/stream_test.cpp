//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "unittest.hpp"

#include <boost/wintls.hpp>
#include <boost/wintls/detail/config.hpp>

#include <boost/asio/io_context.hpp>

#include <array>

TEST_CASE("handshake not done") {
  boost::wintls::context ctx{boost::wintls::method::system_default};
  boost::asio::io_context ioc;
  std::array<char, 4> buf{};

  boost::wintls::stream<boost::asio::ip::tcp::socket> stream(ioc, ctx);
  boost::system::error_code ec{};

  SECTION("write fails") {
    boost::wintls::net::write(stream, boost::wintls::net::buffer(buf), ec);
    CHECK(ec);
  }

  SECTION("async_write fails") {
    boost::wintls::net::async_write(stream, boost::wintls::net::buffer(buf),
                                    [&ec](const boost::system::error_code& error, std::size_t) {
                                      ec = error;
                                    });
    ioc.run_one();
    CHECK(ec);
  }

  SECTION("read fails") {
    boost::wintls::net::read(stream, boost::wintls::net::buffer(buf), ec);
    CHECK(ec);
  }

  SECTION("async_read fails") {
    boost::wintls::net::async_read(stream, boost::wintls::net::buffer(buf),
                                   [&ec](const boost::system::error_code& error, std::size_t) {
                                      ec = error;
                                    });
    ioc.run_one();
    CHECK(ec);
  }
}
