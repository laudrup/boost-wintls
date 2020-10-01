//
// windows_sspi/detail/sspi_impl.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_SSPI_DETAIL_SSPI_IMPL_HPP
#define BOOST_WINDOWS_SSPI_DETAIL_SSPI_IMPL_HPP

#include <boost/windows_sspi/detail/sspi_functions.hpp>
#include <boost/windows_sspi/detail/config.hpp>

#include <boost/core/ignore_unused.hpp>

#include <array>

namespace boost {
namespace windows_sspi {
namespace detail {

class sspi_encrypt {
public:
  sspi_encrypt(CtxtHandle* context)
    : m_context(context)
    , m_message(context) {
  }

  template <typename ConstBufferSequence>
  std::size_t operator()(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    SECURITY_STATUS sc;

    std::size_t size_encrypted = m_message(buffers, sc);
    if (sc != SEC_E_OK) {
      ec = error::make_error_code(sc);
      return 0;
    }

    sc = detail::sspi_functions::EncryptMessage(m_context, 0, m_message, 0);
    if (sc != SEC_E_OK) {
      ec = error::make_error_code(sc);
      return 0;
    }

    return size_encrypted;
  }

  std::vector<char> data() const {
    return m_message.data();
  }

private:
  class message {
  public:
    message(CtxtHandle* context)
      : m_context(context) {
    }

    operator PSecBufferDesc() {
      return &m_message;
    }

    template <typename ConstBufferSequence>
    std::size_t operator()(const ConstBufferSequence& buffers, SECURITY_STATUS& sc) {
      const auto sizes = stream_sizes(sc);
      if (sc != SEC_E_OK) {
        return 0;
      }

      const auto size_encrypted = std::min(net::buffer_size(buffers), static_cast<size_t>(sizes.cbMaximumMessage));
      // TODO: No need to resize this. Since we know the max size, we
      // can allocate a static buffer. Just reserving the max size
      // would probably be good enough in practice, or at least better.
      m_data.resize(sizes.cbHeader + size_encrypted + sizes.cbTrailer);

      m_buffers[0].pvBuffer = m_data.data();
      m_buffers[0].cbBuffer = sizes.cbHeader;
      m_buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

      net::buffer_copy(net::buffer(m_data.data() + sizes.cbHeader, size_encrypted), buffers);
      m_buffers[1].pvBuffer = m_data.data() + sizes.cbHeader;
      m_buffers[1].cbBuffer = static_cast<ULONG>(size_encrypted);
      m_buffers[1].BufferType = SECBUFFER_DATA;

      m_buffers[2].pvBuffer = m_data.data() + sizes.cbHeader + size_encrypted;
      m_buffers[2].cbBuffer = sizes.cbTrailer;
      m_buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

      m_buffers[3].pvBuffer = SECBUFFER_EMPTY;
      m_buffers[3].cbBuffer = SECBUFFER_EMPTY;
      m_buffers[3].BufferType = SECBUFFER_EMPTY;

      m_message.ulVersion = SECBUFFER_VERSION;
      m_message.cBuffers = 4;
      m_message.pBuffers = m_buffers.data();

      return size_encrypted;
    }

    std::vector<char> data() const {
      return m_data;
    }

  private:
    // TODO: We only need to call this once, but after the handshake
    // has completed, so it cannot be in the constructor unless we
    // defer the message construction till its needed.
    SecPkgContext_StreamSizes stream_sizes(SECURITY_STATUS& sc) const {
      SecPkgContext_StreamSizes stream_sizes;
      sc = detail::sspi_functions::QueryContextAttributes(m_context, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);
      return stream_sizes;
    }

    CtxtHandle* m_context;
    std::vector<char> m_data;
    SecBufferDesc m_message;
    std::array<SecBuffer, 4> m_buffers;
  };

  CtxtHandle* m_context;
  message m_message;
};

class sspi_decrypt {
public:
  sspi_decrypt(CtxtHandle* context)
    : last_error(SEC_E_OK)
    , m_context(context) {
  }

  enum class state {
    data_needed,
    data_available,
    error
  };

  state operator()() {
    if (!decrypted_data.empty()) {
      return state::data_available;
    }
    if (encrypted_data.empty()) {
      return state::data_needed;
    }

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

    last_error = detail::sspi_functions::DecryptMessage(m_context, &Message, 0, NULL);
    if (last_error == SEC_E_INCOMPLETE_MESSAGE) {
      return state::data_needed;
    }
    if (last_error != SEC_E_OK) {
      return state::error;
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
    BOOST_ASSERT(!decrypted_data.empty());

    return state::data_available;
  }

  // TODO: Consider making this more flexible by not requering a
  // vector of chars, but any view of a range of bytes
  void put(const std::vector<char>& data) {
    encrypted_data.insert(encrypted_data.end(), data.begin(), data.end());
  }

  std::vector<char> get(std::size_t max) {
    // TODO: Figure out a way to avoid removing from the front of the
    // vector. Since the caller will ask for decrypted data as long as
    // it's there, this buffer should just give out chunks from the
    // beginning until it's empty.
    std::size_t size = std::min(max, decrypted_data.size());
    std::vector<char> ret{decrypted_data.begin(), decrypted_data.begin() + size};
    decrypted_data.erase(decrypted_data.begin(), decrypted_data.begin() + size);
    return ret;
  }

  // TODO: Make private
  std::vector<char> encrypted_data;
  std::vector<char> decrypted_data;
  SECURITY_STATUS last_error;

private:
  CtxtHandle* m_context;
};

class sspi_impl {
public:
  sspi_impl(CtxtHandle* context)
    : encrypt(context)
    , decrypt(context) {
  }

  // TODO: Find some better names
  sspi_encrypt encrypt;
  sspi_decrypt decrypt;
};

} // namespace detail
} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_DETAIL_SSPI_IMPL_HPP
