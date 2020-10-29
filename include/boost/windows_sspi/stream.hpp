//
// windows_sspi/stream.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_SSPI_STREAM_HPP
#define BOOST_WINDOWS_SSPI_STREAM_HPP

#include <boost/windows_sspi/detail/sspi_impl.hpp>
#include <boost/windows_sspi/error.hpp>
#include <boost/windows_sspi/stream_base.hpp>

#include <boost/asio/compose.hpp>
#include <boost/asio/coroutine.hpp>
#include <boost/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <boost/core/ignore_unused.hpp>

#include <array>
#include <iterator>
#include <stdexcept>
#include <type_traits>

namespace boost {
namespace windows_sspi {

// TODO: Move away from this file
template <typename NextLayer>
struct async_handshake_impl : boost::asio::coroutine {
  async_handshake_impl(NextLayer& next_layer, detail::sspi_impl& sspi_impl)
    : m_next_layer(next_layer)
    , m_sspi_impl(sspi_impl)
    , m_entry_count(0) {
  }

  template <typename Self>
  void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    if (ec) {
      self.complete(ec);
      return;
    }

    ++m_entry_count;
    auto is_continuation = [this] {
      return m_entry_count > 1;
    };

    detail::sspi_handshake::state state;
    BOOST_ASIO_CORO_REENTER(*this) {
      while((state = m_sspi_impl.handshake()) != detail::sspi_handshake::state::done) {
        if (state == detail::sspi_handshake::state::data_needed) {
          // TODO: Use a fixed size buffer instead
          m_input.resize(0x10000);
          BOOST_ASIO_CORO_YIELD {
            auto buf = net::buffer(m_input);
            m_next_layer.async_read_some(buf, std::move(self));
          }
          m_sspi_impl.handshake.put({m_input.data(), m_input.data() + length});
          m_input.clear();
          continue;
        }

        if (state == detail::sspi_handshake::state::data_available) {
          m_output = m_sspi_impl.handshake.get();
          BOOST_ASIO_CORO_YIELD
          {
            auto buf = net::buffer(m_output);
            net::async_write(m_next_layer, buf, std::move(self));
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
          self.complete(m_sspi_impl.handshake.last_error());
          return;
        }
      }

      if (!is_continuation()) {
        BOOST_ASIO_CORO_YIELD {
          auto e = self.get_executor();
          net::post(e, [self = std::move(self), ec, length]() mutable { self(ec, length); });
        }
      }
      BOOST_ASSERT(!m_sspi_impl.handshake.last_error());
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

// TODO: Move away from this file
template <typename NextLayer, typename ConstBufferSequence>
struct async_write_impl : boost::asio::coroutine {
  async_write_impl(NextLayer& next_layer, const ConstBufferSequence& buffer, detail::sspi_impl& sspi_impl)
    : m_next_layer(next_layer)
    , m_buffer(buffer)
    , m_sspi_impl(sspi_impl) {
  }

  template <typename Self>
  void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    boost::ignore_unused(length);
    BOOST_ASIO_CORO_REENTER(*this) {
      m_bytes_consumed = m_sspi_impl.encrypt(m_buffer, ec);
      if (ec) {
        self.complete(ec, 0);
        return;
      }

      BOOST_ASIO_CORO_YIELD {
        // TODO: Avoid this copy by consuming from the buffer in sspi_encrypt instead
        m_message = m_sspi_impl.encrypt.data();
        auto buf = net::buffer(m_message);
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

// TODO: Move away from this file
template <typename NextLayer, typename MutableBufferSequence>
struct async_read_impl : boost::asio::coroutine {
  async_read_impl(NextLayer& next_layer, const MutableBufferSequence& buffers, detail::sspi_impl& sspi_impl)
    : m_next_layer(next_layer)
    , m_buffers(buffers)
    , m_sspi_impl(sspi_impl)
    , m_entry_count(0) {
  }

  template <typename Self>
  void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    if (ec) {
      self.complete(ec, length);
      return;
    }

    ++m_entry_count;
    auto is_continuation = [this] {
      return m_entry_count > 1;
    };

    detail::sspi_decrypt::state state;
    BOOST_ASIO_CORO_REENTER(*this) {
      while((state = m_sspi_impl.decrypt()) == detail::sspi_decrypt::state::data_needed) {
        BOOST_ASIO_CORO_YIELD {
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
          BOOST_ASIO_CORO_YIELD {
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
      self.complete(boost::system::error_code{}, bytes_copied);
    }
  }

private:
  NextLayer& m_next_layer;
  MutableBufferSequence m_buffers;
  detail::sspi_impl& m_sspi_impl;
  int m_entry_count;
  std::vector<char> m_input;
};

// TODO: Move away from this file
template <typename NextLayer>
struct async_shutdown_impl : boost::asio::coroutine {
  async_shutdown_impl(NextLayer& next_layer, detail::sspi_impl& sspi_impl)
    : m_next_layer(next_layer)
    , m_sspi_impl(sspi_impl)
    , m_entry_count(0) {
  }

  template <typename Self>
  void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    if (ec) {
      self.complete(ec);
      return;
    }

    ++m_entry_count;
    auto is_continuation = [this] {
      return m_entry_count > 1;
    };

    BOOST_ASIO_CORO_REENTER(*this) {
      if (m_sspi_impl.shutdown() == detail::sspi_shutdown::state::data_available) {
        BOOST_ASIO_CORO_YIELD {
          net::async_write(m_next_layer, m_sspi_impl.shutdown.output(), std::move(self));
        }
        m_sspi_impl.shutdown.consume(length);
        self.complete({});
        return;
      }

      if (m_sspi_impl.shutdown() == detail::sspi_shutdown::state::error) {
        if (!is_continuation()) {
          BOOST_ASIO_CORO_YIELD {
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

template <typename NextLayer>
class stream : public stream_base {
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

  void handshake(handshake_type, boost::system::error_code& ec) {
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

  template <typename CompletionToken>
  auto async_handshake(handshake_type, CompletionToken&& token) ->
    typename net::async_result<typename std::decay<CompletionToken>::type,
                                 void(boost::system::error_code)>::return_type {
    return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
        async_handshake_impl<next_layer_type>{m_next_layer, m_sspi_impl}, token);
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

  template <typename MutableBufferSequence, typename CompletionToken>
  auto async_read_some(const MutableBufferSequence& buffer, CompletionToken&& token) ->
    typename net::async_result<typename std::decay<CompletionToken>::type,
                                 void(boost::system::error_code, std::size_t)>::return_type {
    return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
        async_read_impl<next_layer_type, MutableBufferSequence>{m_next_layer, buffer, m_sspi_impl}, token);
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

  template <typename ConstBufferSequence, typename CompletionToken>
  auto async_write_some(const ConstBufferSequence& buffer, CompletionToken&& token) ->
      typename net::async_result<typename std::decay<CompletionToken>::type,
                                 void(boost::system::error_code, std::size_t)>::return_type {
    return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
        async_write_impl<next_layer_type, ConstBufferSequence>{m_next_layer, buffer, m_sspi_impl}, token);
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

  template <typename CompletionToken>
  auto async_shutdown(CompletionToken&& token) ->
    typename net::async_result<typename std::decay<CompletionToken>::type,
                               void(boost::system::error_code)>::return_type {
    return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
        async_shutdown_impl<next_layer_type>{m_next_layer, m_sspi_impl}, token);
  }

private:
  next_layer_type m_next_layer;
  context& m_context;
  detail::sspi_impl m_sspi_impl;
};

} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_STREAM_HPP
