//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASYNC_WRITE_IMPL_HPP
#define BOOST_WINTLS_DETAIL_ASYNC_WRITE_IMPL_HPP

#include ASIO_INLCUDE(coroutine)

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace detail {

template <typename NextLayer, typename ConstBufferSequence>
struct async_write_impl : net::coroutine {
  async_write_impl(NextLayer& next_layer, const ConstBufferSequence& buffer, detail::sspi_impl& sspi_impl)
    : m_next_layer(next_layer)
    , m_buffer(buffer)
    , m_sspi_impl(sspi_impl) {
  }

  template <typename Self>
  void operator()(Self& self, wintls::error::error_code ec = {}, std::size_t length = 0) {
    WINTLS_IGNORE_UNUSED(ignore_unused(length));
    WINTLS_ASIO_CORO_REENTER(*this) {
      m_bytes_consumed = m_sspi_impl.encrypt(m_buffer, ec);
      if (ec) {
        self.complete(ec, 0);
        return;
      }

      WINTLS_ASIO_CORO_YIELD {
        // TODO: Avoid this copy by consuming from the buffer in sspi_encrypt instead
        m_message = m_sspi_impl.encrypt.data();
        auto buf = net::buffer(m_message, m_sspi_impl.encrypt.size());
        net::async_write(m_next_layer, buf, std::move(self));
      }
      self.complete(ec, m_bytes_consumed);
    }
  }

private:
  NextLayer& m_next_layer;
  ConstBufferSequence m_buffer;
  detail::sspi_impl& m_sspi_impl;
  std::vector<char> m_message;
  size_t m_bytes_consumed{0};
};

} // detail
} // namespace wintls
BOOST_NAMESPACE_END


#endif
