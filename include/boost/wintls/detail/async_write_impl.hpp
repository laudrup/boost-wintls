//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASYNC_WRITE_IMPL_HPP
#define BOOST_WINTLS_DETAIL_ASYNC_WRITE_IMPL_HPP

#include <boost/asio/coroutine.hpp>

#include <boost/core/ignore_unused.hpp>

namespace boost {
namespace wintls {
namespace detail {

template <typename NextLayer, typename ConstBufferSequence>
struct async_write_impl : boost::asio::coroutine {
  async_write_impl(NextLayer& next_layer, const ConstBufferSequence& buffer, detail::sspi_impl& sspi_impl)
    : next_layer_(next_layer)
    , buffer_(buffer)
    , sspi_impl_(sspi_impl) {
  }

  template <typename Self>
  void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    boost::ignore_unused(length);
    BOOST_ASIO_CORO_REENTER(*this) {
      bytes_consumed_ = sspi_impl_.encrypt(buffer_, ec);
      if (ec) {
        self.complete(ec, 0);
        return;
      }

      BOOST_ASIO_CORO_YIELD {
        // TODO: Avoid this copy by consuming from the buffer in sspi_encrypt instead
        message_ = sspi_impl_.encrypt.data();
        auto buf = net::buffer(message_, sspi_impl_.encrypt.size());
        net::async_write(next_layer_, buf, std::move(self));
      }
      self.complete(ec, bytes_consumed_);
    }
  }

private:
  NextLayer& next_layer_;
  ConstBufferSequence buffer_;
  detail::sspi_impl& sspi_impl_;
  std::vector<char> message_;
  size_t bytes_consumed_{0};
};

} // detail
} // namespace wintls
} // namespace boost


#endif
