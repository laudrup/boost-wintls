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

namespace boost {
namespace windows_sspi {
namespace detail {

class sspi_encrypt {
public:
  sspi_encrypt(CtxtHandle* context)
    : m_context(context) {
  }

  // TODO: Since this is now a functor class, consider getting rid of these output arguments
  template <typename ConstBufferSequence>
  std::vector<char> operator()(const ConstBufferSequence& buffers, boost::system::error_code& ec, size_t& size_encrypted) {
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

private:
  // TODO: Calculate this once when handshake is complete
  SecPkgContext_StreamSizes stream_sizes() const {
    SecPkgContext_StreamSizes stream_sizes;
    SECURITY_STATUS sc = detail::sspi_functions::QueryContextAttributes(m_context, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);

    // TODO: Signal error to user (throw exception or use error code?)
    boost::ignore_unused(sc);
    BOOST_ASSERT(sc == SEC_E_OK);
    return stream_sizes;
  }

  CtxtHandle* m_context;
};

class sspi_decrypt {
public:
  sspi_decrypt(CtxtHandle* context)
    : error_code(SEC_E_OK)
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

    error_code = detail::sspi_functions::DecryptMessage(m_context, &Message, 0, NULL);
    if (error_code == SEC_E_INCOMPLETE_MESSAGE) {
      return state::data_needed;
    }
    if (error_code != SEC_E_OK) {
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
    std::size_t size = std::min(max, decrypted_data.size());
    std::vector<char> ret{decrypted_data.begin(), decrypted_data.begin() + size};
    decrypted_data.erase(decrypted_data.begin(), decrypted_data.begin() + size);
    return ret;
  }

  // TODO: Make private
  std::vector<char> encrypted_data;
  std::vector<char> decrypted_data;
  SECURITY_STATUS error_code;

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
