//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASYNC_READ_IMPL_HPP
#define BOOST_WINTLS_DETAIL_ASYNC_READ_IMPL_HPP

#include <boost/asio/coroutine.hpp>

namespace boost {
namespace wintls {
namespace detail {

template <typename NextLayer, typename MutableBufferSequence>
struct async_read_impl : boost::asio::coroutine {
  async_read_impl(NextLayer& next_layer, const MutableBufferSequence& buffers, detail::sspi_impl& sspi_impl)
    : next_layer_(next_layer)
    , buffers_(buffers)
    , sspi_impl_(sspi_impl)
    , entry_count_(0) {
  }

  template <typename Self>
  void operator()(Self& self, boost::system::error_code ec = {}, std::size_t size_read = 0) {
    if (ec) {
      self.complete(ec, size_read);
      return;
    }

    ++entry_count_;
    auto is_continuation = [this] {
      return entry_count_ > 1;
    };

    detail::sspi_decrypt::state state;
    BOOST_ASIO_CORO_REENTER(*this) {
      while((state = sspi_impl_.decrypt(buffers_)) == detail::sspi_decrypt::state::data_needed) {
        BOOST_ASIO_CORO_YIELD {
          next_layer_.async_read_some(sspi_impl_.decrypt.input_buffer, std::move(self));
        }
        sspi_impl_.decrypt.size_read(size_read);
        continue;
      }

      if (state == detail::sspi_decrypt::state::error) {
        if (!is_continuation()) {
          BOOST_ASIO_CORO_YIELD {
            auto e = self.get_executor();
            net::post(e, [self = std::move(self), ec, size_read]() mutable { self(ec, size_read); });
          }
        }
        ec = sspi_impl_.decrypt.last_error();
        self.complete(ec, 0);
        return;
      }

      self.complete(boost::system::error_code{}, sspi_impl_.decrypt.size_decrypted);
    }
  }

private:
  NextLayer& next_layer_;
  MutableBufferSequence buffers_;
  detail::sspi_impl& sspi_impl_;
  int entry_count_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif
