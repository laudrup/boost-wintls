//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_IMPL_HPP
#define BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_IMPL_HPP

#include WINTLS_INCLUDE(handshake_type)

#include ASIO_INLCUDE(coroutine)

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace detail {

template <typename NextLayer>
struct async_handshake_impl : net::coroutine {
  async_handshake_impl(NextLayer& next_layer, detail::sspi_impl& sspi_impl, handshake_type type)
    : m_next_layer(next_layer)
    , m_sspi_impl(sspi_impl)
    , m_entry_count(0) {
    m_sspi_impl.handshake(type);
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

    detail::sspi_handshake::state state;
    WINTLS_ASIO_CORO_REENTER(*this) {
      while((state = m_sspi_impl.handshake()) != detail::sspi_handshake::state::done) {
        if (state == detail::sspi_handshake::state::data_needed) {
          // TODO: Use a fixed size buffer instead
          m_input.resize(0x10000);
          WINTLS_ASIO_CORO_YIELD{
            auto buf = net::buffer(m_input);
            m_next_layer.async_read_some(buf, std::move(self));
          }
          m_sspi_impl.handshake.put({m_input.data(), m_input.data() + length});
          m_input.clear();
          continue;
        }

        if (state == detail::sspi_handshake::state::data_available) {
          m_output = m_sspi_impl.handshake.get();
          WINTLS_ASIO_CORO_YIELD
          {
            auto buf = net::buffer(m_output);
            net::async_write(m_next_layer, buf, std::move(self));
          }
          continue;
        }

        if (state == detail::sspi_handshake::state::error) {
          if (!is_continuation()) {
              WINTLS_ASIO_CORO_YIELD{
              auto e = self.get_executor();
              net::post(e, [self = std::move(self), ec, length]() mutable { self(ec, length); });
            }
          }
          self.complete(m_sspi_impl.handshake.last_error());
          return;
        }
      }

      if (!is_continuation()) {
          WINTLS_ASIO_CORO_YIELD{
          auto e = self.get_executor();
          net::post(e, [self = std::move(self), ec, length]() mutable { self(ec, length); });
        }
      }
      WINTLS_ASSERT_MSG(!m_sspi_impl.handshake.last_error(), "");
      self.complete(m_sspi_impl.handshake.last_error());
    }
  }

private:
  NextLayer& m_next_layer;
  detail::sspi_impl& m_sspi_impl;
  int m_entry_count;
  std::vector<char> m_input;
  std::vector<char> m_output;
};

} // namespace detail
} // namespace wintls
BOOST_NAMESPACE_END

#endif //BOOST_WINTLS_DETAIL_ASYNC_HANDSHAKE_IMPL_HPP
