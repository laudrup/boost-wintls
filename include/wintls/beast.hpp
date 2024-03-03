//
// Copyright (c) 2024 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_BEAST_HPP
#define BOOST_WINTLS_BEAST_HPP

#include <boost/version.hpp>
#include <boost/beast/websocket.hpp>
#include <wintls/context.hpp>
#include <wintls/stream.hpp>

namespace boost {
namespace beast {

namespace detail {

template<class AsyncStream>
struct wintls_shutdown_op : boost::asio::coroutine {
  wintls_shutdown_op(wintls::stream<AsyncStream>& s, role_type role)
      : s_(s)
      , role_(role) {
  }

  template<class Self>
  void operator()(Self& self, error_code ec = {}, std::size_t = 0) {
    BOOST_ASIO_CORO_REENTER(*this) {
#if (BOOST_VERSION / 100 % 1000) >= 77
      self.reset_cancellation_state(net::enable_total_cancellation());
#endif

      BOOST_ASIO_CORO_YIELD
      s_.async_shutdown(std::move(self));
      ec_ = ec;

      using boost::beast::websocket::async_teardown;
      BOOST_ASIO_CORO_YIELD
      async_teardown(role_, s_.next_layer(), std::move(self));
      if (!ec_) {
        ec_ = ec;
      }

      self.complete(ec_);
    }
  }

private:
  wintls::stream<AsyncStream>& s_;
  role_type role_;
  error_code ec_;
};

} // namespace detail

template<class AsyncStream, class TeardownHandler>
void async_teardown(role_type role, wintls::stream<AsyncStream>& stream, TeardownHandler&& handler) {
  return boost::asio::async_compose<TeardownHandler, void(error_code)>(
      detail::wintls_shutdown_op<AsyncStream>(stream, role), handler, stream);
}

template<class AsyncStream>
void teardown(boost::beast::role_type role, wintls::stream<AsyncStream>& stream, boost::system::error_code& ec) {
  stream.shutdown(ec);
  using boost::beast::websocket::teardown;
  boost::system::error_code ec2;
  teardown(role, stream.next_layer(), ec ? ec2 : ec);
}

} // namespace beast
} // namespace boost

#endif
