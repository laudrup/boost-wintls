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

namespace net = boost::asio;

// TODO: Move away from this file and into detail namespace
class sspi_impl {
public:
  sspi_impl(CtxtHandle* context)
    : m_context(context) {
  }

  // TODO: Calculate this once when handshake is complete
  SecPkgContext_StreamSizes stream_sizes() const {
    SecPkgContext_StreamSizes stream_sizes;
    SECURITY_STATUS sc = detail::sspi_functions::QueryContextAttributes(m_context, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);

    // TODO: Signal error to user (throw exception or use error code?)
    boost::ignore_unused(sc);
    BOOST_ASSERT(sc == SEC_E_OK);
    return stream_sizes;
  }

  template <typename ConstBufferSequence>
  std::vector<char> encrypt(const ConstBufferSequence& buffers, boost::system::error_code& ec, size_t& size_encrypted) {
    SecBufferDesc Message;
    SecBuffer Buffers[4];

    // TODO: Consider encrypting all buffer contents before returning
    size_encrypted = std::min(net::buffer_size(buffers), static_cast<size_t>(stream_sizes().cbMaximumMessage));
    std::vector<char> message(stream_sizes().cbHeader + size_encrypted + stream_sizes().cbTrailer);

    Buffers[0].pvBuffer = message.data();
    Buffers[0].cbBuffer = stream_sizes().cbHeader;
    Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    net::buffer_copy(net::buffer(message.data() + stream_sizes().cbHeader, size_encrypted), buffers);
    Buffers[1].pvBuffer = message.data() + stream_sizes().cbHeader;
    Buffers[1].cbBuffer = static_cast<ULONG>(size_encrypted);
    Buffers[1].BufferType = SECBUFFER_DATA;

    Buffers[2].pvBuffer = message.data() + stream_sizes().cbHeader + size_encrypted;
    Buffers[2].cbBuffer = stream_sizes().cbTrailer;
    Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    Buffers[3].pvBuffer = SECBUFFER_EMPTY;
    Buffers[3].cbBuffer = SECBUFFER_EMPTY;
    Buffers[3].BufferType = SECBUFFER_EMPTY;

    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;
    SECURITY_STATUS sc = detail::sspi_functions::EncryptMessage(m_context, 0, &Message, 0);

    if (sc != SEC_E_OK) {
      ec = error::make_error_code(sc);
      return {};
    }
    return message;
  }

  SECURITY_STATUS decrypt(const std::vector<char>& data) {
    encrypted_data.insert(encrypted_data.end(), data.begin(), data.end());

    SecBufferDesc Message;
    SecBuffer Buffers[4];

    Buffers[0].pvBuffer = encrypted_data.data();
    Buffers[0].cbBuffer = static_cast<ULONG>(encrypted_data.size());
    Buffers[0].BufferType = SECBUFFER_DATA;
    Buffers[1].BufferType = SECBUFFER_EMPTY;
    Buffers[2].BufferType = SECBUFFER_EMPTY;
    Buffers[3].BufferType = SECBUFFER_EMPTY;

    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;

    SECURITY_STATUS sc = detail::sspi_functions::DecryptMessage(m_context, &Message, 0, NULL);
    if (sc != SEC_E_OK) {
      return sc;
    }

    encrypted_data.clear();
    for (int i = 1; i < 4; i++) {
      if (Buffers[i].BufferType == SECBUFFER_DATA) {
        SecBuffer* pDataBuffer = &Buffers[i];
        decrypted_data = std::vector<char>(reinterpret_cast<const char*>(pDataBuffer->pvBuffer), reinterpret_cast<const char*>(pDataBuffer->pvBuffer) + pDataBuffer->cbBuffer);
      }
      if (Buffers[i].BufferType == SECBUFFER_EXTRA) {
        SecBuffer* pExtraBuffer = &Buffers[i];
        encrypted_data = std::vector<char>(reinterpret_cast<const char*>(pExtraBuffer->pvBuffer), reinterpret_cast<const char*>(pExtraBuffer->pvBuffer) + pExtraBuffer->cbBuffer);
      }
    }
    return sc;
  }

  std::vector<char> encrypted_data;
  std::vector<char> decrypted_data;

private:
  CtxtHandle* m_context;
};

// TODO: Move away from this file
template <typename NextLayer, typename ConstBufferSequence> struct async_write_impl : boost::asio::coroutine {
  async_write_impl(NextLayer& next_layer, const ConstBufferSequence& buffer, std::shared_ptr<sspi_impl> sspi_impl)
    : m_next_layer(next_layer)
    , m_buffer(buffer)
    , m_sspi_impl(std::move(sspi_impl)) {
  }

  template <typename Self> void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    boost::ignore_unused(length);
    BOOST_ASIO_CORO_REENTER(*this) {
      m_message = m_sspi_impl->encrypt(m_buffer, ec, m_size_encrypted);
      if (ec) {
        self.complete(ec, 0);
        return;
      }
      BOOST_ASIO_CORO_YIELD net::async_write(m_next_layer,
                                             net::buffer(m_message),
                                             net::transfer_exactly(m_message.size()),
                                             std::move(self));
      self.complete(ec, m_size_encrypted);
    }
  }

private:
  NextLayer& m_next_layer;
  ConstBufferSequence m_buffer;
  std::shared_ptr<sspi_impl> m_sspi_impl;
  std::vector<char> m_message;
  size_t m_size_encrypted{0};
};

// TODO: Move away from this file
template <typename NextLayer, typename MutableBufferSequence> struct async_read_impl : boost::asio::coroutine {
  async_read_impl(NextLayer& next_layer, const MutableBufferSequence& buffer, std::shared_ptr<sspi_impl> sspi_impl)
    : m_next_layer(next_layer)
    , m_buffer(buffer)
    , m_sspi_impl(std::move(sspi_impl)) {
  }

  template <typename Self> void operator()(Self& self, boost::system::error_code ec = {}, std::size_t length = 0) {
    BOOST_ASIO_CORO_REENTER(*this) {
      while(m_sspi_impl->decrypted_data.empty()) {
        // TODO: Find some way to make the sspi_impl, the decrypt
        // function or something else be responsible for keeping track
        // of state and buffer(s)
        // TODO: Fix so overflow cannot happen (we don't need to read
        // more data unless DecryptMessage asks us to).
        BOOST_ASSERT(m_sspi_impl->encrypted_data.size() < 0x10000);
        m_message.resize(0x10000 - m_sspi_impl->encrypted_data.size());
        BOOST_ASIO_CORO_YIELD net::async_read(m_next_layer,
                                              net::buffer(m_message),
                                              std::move(self));
        if (ec && length == 0 && m_sspi_impl->decrypted_data.empty()) {
          self.complete(ec, 0);
          return;
        }
        m_message.resize(length);
        auto sc = m_sspi_impl->decrypt(m_message);
        m_message.clear();
        if (sc == SEC_E_INCOMPLETE_MESSAGE) {
          continue;
        }
        if (sc == SEC_I_CONTEXT_EXPIRED) {
          // TODO: Shutdown the TLS context gracefully (implement
          // async_shutdown), then return EOF.
          self.complete(net::error::eof, 0);
          return;
        }
        if (sc != SEC_E_OK) {
          self.complete(error::make_error_code(sc), 0);
          return;
        }
      }

      std::size_t to_return = std::min(net::buffer_size(m_buffer), m_sspi_impl->decrypted_data.size());
      std::size_t bytes_copied = net::buffer_copy(m_buffer, net::buffer(m_sspi_impl->decrypted_data, to_return));
      boost::ignore_unused(bytes_copied);
      BOOST_ASSERT(bytes_copied == to_return);
      m_sspi_impl->decrypted_data.erase(m_sspi_impl->decrypted_data.begin(), m_sspi_impl->decrypted_data.begin() + to_return);
      self.complete(boost::system::error_code{}, to_return);
    }
  }

private:
  NextLayer& m_next_layer;
  MutableBufferSequence m_buffer;
  std::shared_ptr<sspi_impl> m_sspi_impl;
  std::vector<char> m_message;
};

template <typename NextLayer> class stream : public stream_base {
public:
  using next_layer_type = typename std::remove_reference<NextLayer>::type;
  using executor_type = typename std::remove_reference<next_layer_type>::type::executor_type;

  template <typename Arg>
  stream(Arg&& arg, context& ctx)
    : stream_base(ctx)
    , m_next_layer(std::forward<Arg>(arg))
    , m_sspi_impl(std::make_shared<sspi_impl>(&m_security_context)) {
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
    SECURITY_STATUS sc = SEC_E_OK;
    while(m_sspi_impl->decrypted_data.empty()) {
      // TODO: This is duplicated in the async version. Move logic to
      // sspi_impl some way. Possibly a decryption class for keep
      // track of state and buffers.
      std::vector<char> input_buffer;
      if (m_sspi_impl->encrypted_data.empty() || sc == SEC_E_INCOMPLETE_MESSAGE) {
        input_buffer.resize(0x10000);
        std::size_t size_read = m_next_layer.read_some(net::buffer(input_buffer.data(), input_buffer.size()), ec);
        if (ec && size_read == 0 && m_sspi_impl->decrypted_data.empty()) {
          return 0;
        }
        input_buffer.resize(size_read);
      }
      sc = m_sspi_impl->decrypt(input_buffer);
      input_buffer.clear();
      if (sc == SEC_E_INCOMPLETE_MESSAGE) {
        continue;
      }
      if (sc == SEC_I_CONTEXT_EXPIRED) {
        // TODO: Shutdown the TLS context gracefully (implement
        // shutdown), then return EOF.
        ec = net::error::eof;
        return 0;
      }
      if (sc != SEC_E_OK) {
        ec = error::make_error_code(sc);
        return 0;
      }
      break;
    }

    std::size_t to_return = std::min(net::buffer_size(buffers), m_sspi_impl->decrypted_data.size());
    std::size_t bytes_copied = net::buffer_copy(buffers, net::buffer(m_sspi_impl->decrypted_data, to_return));
    boost::ignore_unused(bytes_copied);
    BOOST_ASSERT(bytes_copied == to_return);
    m_sspi_impl->decrypted_data.erase(m_sspi_impl->decrypted_data.begin(), m_sspi_impl->decrypted_data.begin() + to_return);
    return to_return;
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
    size_t size_encrypted{0};
    auto message = m_sspi_impl->encrypt(buffers, ec, size_encrypted);
    if (ec) {
      return 0;
    }

    auto sent = net::write(m_next_layer, net::buffer(message), net::transfer_exactly(message.size()), ec);

    boost::ignore_unused(sent);
    BOOST_ASSERT(sent == message.size());
    if (ec) {
      return 0;
    }

    return size_encrypted;
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
  std::shared_ptr<sspi_impl> m_sspi_impl;
};

} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_STREAM_HPP
