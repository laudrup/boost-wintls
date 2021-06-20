//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASYNC_SHUTDOWN_IMPL_HPP
#define BOOST_WINTLS_DETAIL_ASYNC_SHUTDOWN_IMPL_HPP

#include ASIO_INLCUDE(coroutine)
#include ASIO_INLCUDE(error)

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace detail {

template <typename NextLayer>
struct async_shutdown_impl : net::coroutine {
  async_shutdown_impl(NextLayer& next_layer, detail::sspi_impl& sspi_impl)
    : m_next_layer(next_layer)
    , m_sspi_impl(sspi_impl)
    , m_entry_count(0) {
  }

  template <typename Self>
  void operator()(Self& self, wintls::error::error_code ec = {}, std::size_t length = 0) {
    if (ec) {
      self.complete(ec);
      return;
    }

    ++m_entry_count;
    auto is_continuation = [this] {
      return m_entry_count > 1;
    };

    WINTLS_ASIO_CORO_REENTER(*this) {
      if (m_sspi_impl.shutdown() == detail::sspi_shutdown::state::data_available) {
        WINTLS_ASIO_CORO_YIELD {
          net::async_write(m_next_layer, m_sspi_impl.shutdown.output(), std::move(self));
        }
        m_sspi_impl.shutdown.consume(length);
        self.complete({});
        return;
      }

      if (m_sspi_impl.shutdown() == detail::sspi_shutdown::state::error) {
        if (!is_continuation()) {
          WINTLS_ASIO_CORO_YIELD {
            auto e = self.get_executor();
            net::post(e, [self = std::move(self), ec, length]() mutable { self(ec, length); });
          }
        }
        self.complete(m_sspi_impl.shutdown.last_error());
        return;
      }
    }
  }

private:
  NextLayer& m_next_layer;
  detail::sspi_impl& m_sspi_impl;
  int m_entry_count;
};

} // namespace detail
} // namespace wintls
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_DETAIL_ASYNC_SHUTDOWN_IMPL_HPP
