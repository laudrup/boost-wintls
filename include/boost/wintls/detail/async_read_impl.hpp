//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASYNC_READ_IMPL_HPP
#define BOOST_WINTLS_DETAIL_ASYNC_READ_IMPL_HPP

#include ASIO_INLCUDE(coroutine)

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace detail {

template <typename NextLayer, typename MutableBufferSequence>
struct async_read_impl : net::coroutine {
  async_read_impl(NextLayer& next_layer, const MutableBufferSequence& buffers, detail::sspi_impl& sspi_impl)
    : m_next_layer(next_layer)
    , m_buffers(buffers)
    , m_sspi_impl(sspi_impl)
    , m_entry_count(0) {
  }

  template <typename Self>
  void operator()(Self& self, wintls::error::error_code ec = {}, std::size_t length = 0) {
    if (ec) {
      self.complete(ec, length);
      return;
    }

    ++m_entry_count;
    auto is_continuation = [this] {
      return m_entry_count > 1;
    };

    detail::sspi_decrypt::state state;
    WINTLS_ASIO_CORO_REENTER(*this) {
      while((state = m_sspi_impl.decrypt()) == detail::sspi_decrypt::state::data_needed) {
        WINTLS_ASIO_CORO_YIELD {
          // TODO: Use a fixed size buffer instead
          m_input.resize(0x10000);
          auto buf = net::buffer(m_input);
          m_next_layer.async_read_some(buf, std::move(self));
        }
        m_sspi_impl.decrypt.put({m_input.begin(), m_input.begin() + length});
        m_input.clear();
        continue;
      }

      if (state == detail::sspi_decrypt::state::error) {
        if (!is_continuation()) {
          WINTLS_ASIO_CORO_YIELD {
            auto e = self.get_executor();
            net::post(e, [self = std::move(self), ec, length]() mutable { self(ec, length); });
          }
        }
        ec = m_sspi_impl.decrypt.last_error();
        self.complete(ec, 0);
        return;
      }

      // TODO: Avoid this copy if possible
      const auto data = m_sspi_impl.decrypt.get(net::buffer_size(m_buffers));
      std::size_t bytes_copied = net::buffer_copy(m_buffers, net::buffer(data));
      BOOST_ASSERT(bytes_copied == data.size());
      self.complete(wintls::error::error_code{}, bytes_copied);
    }
  }

private:
  NextLayer& m_next_layer;
  MutableBufferSequence m_buffers;
  detail::sspi_impl& m_sspi_impl;
  int m_entry_count;
  std::vector<char> m_input;
};

} // namespace detail
} // namespace wintls
BOOST_NAMESPACE_END

#endif
