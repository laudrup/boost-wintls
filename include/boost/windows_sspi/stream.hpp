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

#include <boost/windows_sspi/detail/sspi_functions.hpp>
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
template <typename NextLayer, typename ConstBufferSequence> struct async_write_impl : boost::asio::coroutine {
  async_write_impl(NextLayer& next_layer, const ConstBufferSequence& buffer, detail::sspi_impl& sspi_impl)
    : m_next_layer(next_layer)
    , m_buffer(buffer)
    , m_sspi_impl(sspi_impl) {
  }

  template <typename Self> void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    boost::ignore_unused(length);
    BOOST_ASIO_CORO_REENTER(*this) {
      m_bytes_consumed = m_sspi_impl.encrypt(m_buffer, ec);
      if (ec) {
        self.complete(ec, 0);
        return;
      }
      // TODO: Figure out why we need a copy of the data here. It
      // should be enough to keep the encrypt member in sspi_impl
      // alive, but using that causes a segfault.
      m_message = m_sspi_impl.encrypt.data();
      BOOST_ASIO_CORO_YIELD net::async_write(m_next_layer,
                                             net::buffer(m_message),
                                             net::transfer_exactly(m_message.size()),
                                             std::move(self));
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
template <typename NextLayer, typename MutableBufferSequence> struct async_read_impl : boost::asio::coroutine {
  async_read_impl(NextLayer& next_layer, const MutableBufferSequence& buffers, detail::sspi_impl& sspi_impl)
    : m_next_layer(next_layer)
    , m_buffers(buffers)
    , m_sspi_impl(sspi_impl) {
  }

  template <typename Self> void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    BOOST_ASIO_CORO_REENTER(*this) {
      while(m_sspi_impl.decrypt() == detail::sspi_decrypt::state::data_needed) {
        // TODO: Use a fixed size buffer instead
        m_input.resize(0x10000);
        BOOST_ASIO_CORO_YIELD net::async_read(m_next_layer,
                                              net::buffer(m_input),
                                              std::move(self));
        m_sspi_impl.decrypt.put({m_input.begin(), m_input.begin() + length});
        m_input.clear();
        continue;
      }

      if (m_sspi_impl.decrypt() == detail::sspi_decrypt::state::error) {
        ec = boost::error::make_error_code(m_sspi_impl.decrypt.last_error);
        self.complete(ec, 0);
        return;
      }

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
  std::vector<char> m_input;
};

template <typename NextLayer> class stream : public stream_base {
public:
  using next_layer_type = typename std::remove_reference<NextLayer>::type;
  using executor_type = typename std::remove_reference<next_layer_type>::type::executor_type;

  template <typename Arg>
  stream(Arg&& arg, context& ctx)
    : stream_base(ctx)
    , m_next_layer(std::forward<Arg>(arg))
    , m_sspi_impl(&m_security_context) {
  }

  ~stream() {
    detail::sspi_functions::DeleteSecurityContext(&m_security_context);
  }

  const next_layer_type& next_layer() const {
    return m_next_layer;
  }

  next_layer_type& next_layer() {
    return m_next_layer;
  }

  void handshake(handshake_type type) {
    DWORD flags_out = 0;
    DWORD flags_in = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                     ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    boost::system::error_code ec;
    SECURITY_STATUS sc = SEC_E_OK;

    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
    SecBufferDesc InBuffer;
    SecBuffer InBuffers[2];

    if (type == client) {
      OutBuffers[0].pvBuffer = NULL;
      OutBuffers[0].BufferType = SECBUFFER_TOKEN;
      OutBuffers[0].cbBuffer = 0;

      OutBuffer.cBuffers = 1;
      OutBuffer.pBuffers = OutBuffers;
      OutBuffer.ulVersion = SECBUFFER_VERSION;

      sc = detail::sspi_functions::InitializeSecurityContext(&m_context_impl->handle,
                                                             NULL,
                                                             NULL,
                                                             flags_in,
                                                             0,
                                                             SECURITY_NATIVE_DREP,
                                                             NULL,
                                                             0,
                                                             &m_security_context,
                                                             &OutBuffer,
                                                             &flags_out,
                                                             NULL);
      if (sc != SEC_I_CONTINUE_NEEDED) {
        throw boost::system::system_error(error::make_error_code(sc), "InitializeSecurityContext");
      }

      size_t size_written = m_next_layer.write_some(net::const_buffer(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer), ec);
      boost::ignore_unused(size_written);
      BOOST_ASSERT(size_written == OutBuffers[0].cbBuffer);
      detail::sspi_functions::FreeContextBuffer(OutBuffers[0].pvBuffer);
      if (ec) {
        throw boost::system::system_error(ec);
      }
    }

    size_t input_size = 0;
    std::array<char, 0x10000> buffer;

    while (true) {
      input_size += m_next_layer.read_some(net::buffer(buffer.data() + input_size, buffer.size() - input_size), ec);
      if (ec) {
        throw boost::system::system_error(ec);
      }

      InBuffers[0].pvBuffer = reinterpret_cast<void*>(buffer.data());
      InBuffers[0].cbBuffer = static_cast<ULONG>(input_size);
      InBuffers[0].BufferType = SECBUFFER_TOKEN;

      InBuffers[1].pvBuffer = NULL;
      InBuffers[1].cbBuffer = 0;
      InBuffers[1].BufferType = SECBUFFER_EMPTY;

      InBuffer.cBuffers = 2;
      InBuffer.pBuffers = InBuffers;
      InBuffer.ulVersion = SECBUFFER_VERSION;

      OutBuffers[0].pvBuffer = NULL;
      OutBuffers[0].BufferType = SECBUFFER_TOKEN;
      OutBuffers[0].cbBuffer = 0;

      OutBuffer.cBuffers = 1;
      OutBuffer.pBuffers = OutBuffers;
      OutBuffer.ulVersion = SECBUFFER_VERSION;

      sc = detail::sspi_functions::InitializeSecurityContext(&m_context_impl->handle,
                                                             &m_security_context,
                                                             NULL,
                                                             flags_in,
                                                             0,
                                                             SECURITY_NATIVE_DREP,
                                                             &InBuffer,
                                                             0,
                                                             NULL,
                                                             &OutBuffer,
                                                             &flags_out,
                                                             NULL);

      if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL) {
        m_next_layer.write_some(net::const_buffer(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer), ec);
        detail::sspi_functions::FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
        if (ec) {
          throw boost::system::system_error(ec);
        }
      }

      switch (sc) {
      case SEC_E_INCOMPLETE_MESSAGE:
        continue;

      case SEC_E_OK:
        BOOST_ASSERT_MSG(InBuffers[1].BufferType != SECBUFFER_EXTRA, "Handle extra data from handshake");
        return;

      case SEC_I_INCOMPLETE_CREDENTIALS:
        BOOST_ASSERT_MSG(false, "client authentication not implemented");

      default:
        if (FAILED(sc)) {
          throw boost::system::system_error(error::make_error_code(sc), "InitializeSecurityContext");
        }
      }

      if (InBuffers[1].BufferType == SECBUFFER_EXTRA) {
        std::copy_n(buffer.data() + (input_size - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer, buffer.data());
        input_size = InBuffers[1].cbBuffer;
      } else {
        input_size = 0;
      }
    }
  }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code& ec) {
    while(m_sspi_impl.decrypt() == detail::sspi_decrypt::state::data_needed) {
      std::array<char, 0x10000> input_buffer;
      std::size_t size_read = m_next_layer.read_some(net::buffer(input_buffer.data(), input_buffer.size()), ec);
      m_sspi_impl.decrypt.put({input_buffer.begin(), input_buffer.begin() + size_read});
      continue;
    }

    if (m_sspi_impl.decrypt() == detail::sspi_decrypt::state::error) {
      ec = boost::error::make_error_code(m_sspi_impl.decrypt.last_error);
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

private:
  next_layer_type m_next_layer;
  CtxtHandle m_security_context;
  detail::sspi_impl m_sspi_impl;
};

} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_STREAM_HPP
