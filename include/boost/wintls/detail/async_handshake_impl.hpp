//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_IMPL_HPP
#define BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_IMPL_HPP

#include <boost/wintls/handshake_type.hpp>

#include <boost/asio/coroutine.hpp>

namespace boost {
namespace wintls {
namespace detail {

template <typename NextLayer>
struct async_handshake_impl : boost::asio::coroutine {
  async_handshake_impl(NextLayer& next_layer, detail::sspi_impl& sspi_impl, handshake_type type)
    : next_layer_(next_layer)
    , sspi_impl_(sspi_impl)
    , entry_count_(0)
    , state_(state::idle) {
    sspi_impl_.handshake(type);
  }

  template <typename Self>
  void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    if (ec) {
      self.complete(ec);
      return;
    }

    ++entry_count_;
    auto is_continuation = [this] {
      return entry_count_ > 1;
    };

    switch(state_) {
      case state::reading:
        sspi_impl_.handshake.size_read(length);
        state_ = state::idle;
        break;
      case state::writing:
        sspi_impl_.handshake.size_written(length);
        state_ = state::idle;
        break;
      case state::idle:
        break;
    }

    detail::sspi_handshake::state handshake_state;
    BOOST_ASIO_CORO_REENTER(*this) {
      while((handshake_state = sspi_impl_.handshake()) != detail::sspi_handshake::state::done) {
        if (handshake_state == detail::sspi_handshake::state::data_needed) {
          BOOST_ASIO_CORO_YIELD {
            state_ = state::reading;
            next_layer_.async_read_some(sspi_impl_.handshake.in_buffer(), std::move(self));
          }
          continue;
        }

        if (handshake_state == detail::sspi_handshake::state::data_available) {
          BOOST_ASIO_CORO_YIELD {
            state_ = state::writing;
            net::async_write(next_layer_, sspi_impl_.handshake.out_buffer(), std::move(self));
          }
          continue;
        }

        if (handshake_state == detail::sspi_handshake::state::error) {
          if (!is_continuation()) {
            BOOST_ASIO_CORO_YIELD {
              auto e = self.get_executor();
              net::post(e, [self = std::move(self), ec, length]() mutable { self(ec, length); });
            }
          }
          self.complete(sspi_impl_.handshake.last_error());
          return;
        }
      }

      if (!is_continuation()) {
        BOOST_ASIO_CORO_YIELD {
          auto e = self.get_executor();
          net::post(e, [self = std::move(self), ec, length]() mutable { self(ec, length); });
        }
      }
      BOOST_ASSERT(!sspi_impl_.handshake.last_error());
      self.complete(sspi_impl_.handshake.last_error());
    }
  }

private:
  NextLayer& next_layer_;
  detail::sspi_impl& sspi_impl_;
  int entry_count_;
  std::vector<char> input_;
  enum class state {
    idle,
    reading,
    writing
  } state_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif //BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_IMPL_HPP
