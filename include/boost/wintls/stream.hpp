//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_STREAM_HPP
#define BOOST_WINTLS_STREAM_HPP

#include <boost/wintls/error.hpp>
#include <boost/wintls/handshake_type.hpp>

#include <boost/wintls/detail/sspi_impl.hpp>
#include <boost/wintls/detail/async_handshake_impl.hpp>
#include <boost/wintls/detail/async_read_impl.hpp>
#include <boost/wintls/detail/async_shutdown_impl.hpp>
#include <boost/wintls/detail/async_write_impl.hpp>

#include <boost/asio/compose.hpp>
#include <boost/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <iterator>
#include <stdexcept>
#include <type_traits>

namespace boost {
namespace wintls {

template <typename NextLayer>
class stream {
public:
  using next_layer_type = typename std::remove_reference<NextLayer>::type;
  using executor_type = typename std::remove_reference<next_layer_type>::type::executor_type;

  template <typename Arg>
  stream(Arg&& arg, context& ctx)
    : m_next_layer(std::forward<Arg>(arg))
    , m_context(ctx)
    , m_sspi_impl(ctx) {
  }

  executor_type get_executor() {
    return next_layer().get_executor();
  }

  const next_layer_type& next_layer() const {
    return m_next_layer;
  }

  next_layer_type& next_layer() {
    return m_next_layer;
  }

  void handshake(handshake_type type, boost::system::error_code& ec) {
    m_sspi_impl.handshake(type);

    detail::sspi_handshake::state state;
    while((state = m_sspi_impl.handshake()) != detail::sspi_handshake::state::done) {
      switch (state) {
        case detail::sspi_handshake::state::data_needed:
          {
            std::array<char, 0x10000> input_buffer;
            std::size_t size_read = m_next_layer.read_some(net::buffer(input_buffer.data(), input_buffer.size()), ec);
            if (ec) {
              return;
            }
            m_sspi_impl.handshake.put({input_buffer.begin(), input_buffer.begin() + size_read});
            continue;
          }
        case detail::sspi_handshake::state::data_available:
          {
            auto data = m_sspi_impl.handshake.get();
            net::write(m_next_layer, net::buffer(data), ec);
            if (ec) {
              return;
            }
            continue;
          }
        case detail::sspi_handshake::state::error:
          ec = m_sspi_impl.handshake.last_error();
          return;
        case detail::sspi_handshake::state::done:
          BOOST_ASSERT(!m_sspi_impl.handshake.last_error());
          ec = m_sspi_impl.handshake.last_error();
          return;
      }
    }
  }

  void handshake(handshake_type type) {
    boost::system::error_code ec{};
    handshake(type, ec);
    if (ec) {
      detail::throw_error(ec);
    }
  }

  template <typename CompletionToken>
  auto async_handshake(handshake_type type, CompletionToken&& token) ->
      typename net::async_result<typename std::decay<CompletionToken>::type,
                                 void(boost::system::error_code)>::return_type {
    return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
        detail::async_handshake_impl<next_layer_type>{m_next_layer, m_sspi_impl, type}, token);
  }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code& ec) {
    detail::sspi_decrypt::state state;
    while((state = m_sspi_impl.decrypt()) == detail::sspi_decrypt::state::data_needed) {
      std::array<char, 0x10000> input_buffer;
      std::size_t size_read = m_next_layer.read_some(net::buffer(input_buffer.data(), input_buffer.size()), ec);
      if (ec) {
        return 0;
      }
      m_sspi_impl.decrypt.put({input_buffer.begin(), input_buffer.begin() + size_read});
      continue;
    }

    if (state == detail::sspi_decrypt::state::error) {
      ec = m_sspi_impl.decrypt.last_error();
      return 0;
    }

    const auto data = m_sspi_impl.decrypt.get(net::buffer_size(buffers));
    std::size_t bytes_copied = net::buffer_copy(buffers, net::buffer(data));
    BOOST_ASSERT(bytes_copied == data.size());
    return bytes_copied;
  }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    boost::system::error_code ec{};
    read_some(buffers, ec);
    if (ec) {
      detail::throw_error(ec);
    }
  }

  template <typename MutableBufferSequence, typename CompletionToken>
  auto async_read_some(const MutableBufferSequence& buffer, CompletionToken&& token) ->
    typename net::async_result<typename std::decay<CompletionToken>::type,
                                 void(boost::system::error_code, std::size_t)>::return_type {
    return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
        detail::async_read_impl<next_layer_type, MutableBufferSequence>{m_next_layer, buffer, m_sspi_impl}, token);
  }

  template <typename ConstBufferSequence>
  std::size_t write_some(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    std::size_t bytes_consumed = m_sspi_impl.encrypt(buffers, ec);
    if (ec) {
      return 0;
    }

    net::write(m_next_layer, net::buffer(m_sspi_impl.encrypt.data()), net::transfer_exactly(m_sspi_impl.encrypt.data().size()), ec);
    if (ec) {
      return 0;
    }

    return bytes_consumed;
  }

  template <typename ConstBufferSequence>
  std::size_t write_some(const ConstBufferSequence& buffers) {
    boost::system::error_code ec{};
    write_some(buffers, ec);
    if (ec) {
      detail::throw_error(ec);
    }
  }

  template <typename ConstBufferSequence, typename CompletionToken>
  auto async_write_some(const ConstBufferSequence& buffer, CompletionToken&& token) ->
      typename net::async_result<typename std::decay<CompletionToken>::type,
                                 void(boost::system::error_code, std::size_t)>::return_type {
    return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
        detail::async_write_impl<next_layer_type, ConstBufferSequence>{m_next_layer, buffer, m_sspi_impl}, token);
  }

  void shutdown(boost::system::error_code& ec) {
    switch(m_sspi_impl.shutdown()) {
      case detail::sspi_shutdown::state::data_available: {
        auto size = net::write(m_next_layer, m_sspi_impl.shutdown.output(), ec);
        m_sspi_impl.shutdown.consume(size);
        return;
      }
      case detail::sspi_shutdown::state::error:
        ec = m_sspi_impl.shutdown.last_error();
    }
  }

  void shutdown() {
    boost::system::error_code ec{};
    shutdown(ec);
    if (ec) {
      detail::throw_error(ec);
    }
  }

  template <typename CompletionToken>
  auto async_shutdown(CompletionToken&& token) ->
    typename net::async_result<typename std::decay<CompletionToken>::type,
                               void(boost::system::error_code)>::return_type {
    return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
        detail::async_shutdown_impl<next_layer_type>{m_next_layer, m_sspi_impl}, token);
  }

private:
  next_layer_type m_next_layer;
  context& m_context;
  detail::sspi_impl m_sspi_impl;
};

} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_STREAM_HPP
