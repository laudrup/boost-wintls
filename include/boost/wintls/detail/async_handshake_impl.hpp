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
    , entry_count_(0) {
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

    detail::sspi_handshake::state state;
    BOOST_ASIO_CORO_REENTER(*this) {
      while((state = sspi_impl_.handshake()) != detail::sspi_handshake::state::done) {
        if (state == detail::sspi_handshake::state::data_needed) {
          // TODO: Use a fixed size buffer instead
          input_.resize(0x10000);
          BOOST_ASIO_CORO_YIELD {
            auto buf = net::buffer(input_);
            next_layer_.async_read_some(buf, std::move(self));
          }
          sspi_impl_.handshake.put({input_.data(), input_.data() + length});
          input_.clear();
          continue;
        }

        if (state == detail::sspi_handshake::state::data_available) {
          output_ = sspi_impl_.handshake.get();
          BOOST_ASIO_CORO_YIELD
          {
            auto buf = net::buffer(output_);
            net::async_write(next_layer_, buf, std::move(self));
          }
          continue;
        }

        if (state == detail::sspi_handshake::state::error) {
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
  std::vector<char> output_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif //BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_IMPL_HPP
