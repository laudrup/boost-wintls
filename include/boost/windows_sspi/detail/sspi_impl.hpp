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
#include <vector>

namespace boost {
namespace windows_sspi {
namespace detail {

class sspi_handshake {
public:
  enum class state {
    data_needed,
    data_available,
    done,
    error
  };

  sspi_handshake(CtxtHandle* context, CredHandle* credentials)
    : m_context(context)
    , m_credentials(credentials)
    , m_last_error(SEC_E_OK)
    , m_flags_out(0)
    , m_flags_in(ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                 ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM) {

    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];

    OutBuffers[0].pvBuffer = nullptr;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    m_last_error = detail::sspi_functions::InitializeSecurityContext(m_credentials,
                                                                     nullptr,
                                                                     nullptr,
                                                                     m_flags_in,
                                                                     0,
                                                                     SECURITY_NATIVE_DREP,
                                                                     nullptr,
                                                                     0,
                                                                     m_context,
                                                                     &OutBuffer,
                                                                     &m_flags_out,
                                                                     nullptr);
    if (m_last_error == SEC_I_CONTINUE_NEEDED) {
      // TODO: Avoid this copy
      m_output_data = std::vector<char>{reinterpret_cast<const char*>(OutBuffers[0].pvBuffer)
        , reinterpret_cast<const char*>(OutBuffers[0].pvBuffer) + OutBuffers[0].cbBuffer};
      detail::sspi_functions::FreeContextBuffer(OutBuffers[0].pvBuffer);
    }
  }

  state operator()() {
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
    SecBufferDesc InBuffer;
    SecBuffer InBuffers[2];

    if (m_last_error != SEC_I_CONTINUE_NEEDED) {
      return state::error;
    }
    if (!m_output_data.empty()) {
      return state::data_available;
    }
    if (m_input_data.empty()) {
      return state::data_needed;
    }

    InBuffers[0].pvBuffer = reinterpret_cast<void*>(m_input_data.data());
    InBuffers[0].cbBuffer = static_cast<ULONG>(m_input_data.size());
    InBuffers[0].BufferType = SECBUFFER_TOKEN;

    InBuffers[1].pvBuffer = nullptr;
    InBuffers[1].cbBuffer = 0;
    InBuffers[1].BufferType = SECBUFFER_EMPTY;

    InBuffer.cBuffers = 2;
    InBuffer.pBuffers = InBuffers;
    InBuffer.ulVersion = SECBUFFER_VERSION;

    OutBuffers[0].pvBuffer = nullptr;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    m_last_error = detail::sspi_functions::InitializeSecurityContext(m_credentials,
                                                                     m_context,
                                                                     nullptr,
                                                                     m_flags_in,
                                                                     0,
                                                                     SECURITY_NATIVE_DREP,
                                                                     &InBuffer,
                                                                     0,
                                                                     nullptr,
                                                                     &OutBuffer,
                                                                     &m_flags_out,
                                                                     nullptr);

    if (InBuffers[1].BufferType == SECBUFFER_EXTRA) {
      // Some data needs to be reused for the next call, move that to the front for reuse
      // TODO: Test that this works.
      std::move(m_input_data.end() - InBuffers[1].cbBuffer, m_input_data.end(), m_input_data.begin());
      m_input_data.resize(InBuffers[1].cbBuffer);
    } else {
      m_input_data.clear();
    }

    if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != nullptr) {
      // TODO: Avoid this copy
      m_output_data = std::vector<char>{reinterpret_cast<const char*>(OutBuffers[0].pvBuffer)
        , reinterpret_cast<const char*>(OutBuffers[0].pvBuffer) + OutBuffers[0].cbBuffer};
      detail::sspi_functions::FreeContextBuffer(OutBuffers[0].pvBuffer);
      return state::data_available;
    }

    switch (m_last_error) {
      case SEC_E_INCOMPLETE_MESSAGE:
        return state::data_needed;

      case SEC_E_OK:
        BOOST_ASSERT_MSG(InBuffers[1].BufferType != SECBUFFER_EXTRA, "Handle extra data from handshake");
        return state::done;

      case SEC_I_INCOMPLETE_CREDENTIALS:
        BOOST_ASSERT_MSG(false, "client authentication not implemented");

      default:
        return state::error;
    }
  }

  // TODO: Consider making this more flexible by not requering a
  // vector of chars, but any view of a range of bytes
  void put(const std::vector<char>& data) {
    m_input_data.insert(m_input_data.end(), data.begin(), data.end());
  }

  std::vector<char> get() {
    // TODO: Avoid this copy if possible
    auto ret = m_output_data;
    m_output_data.clear();
    return ret;
  }

  boost::system::error_code last_error() const {
    return error::make_error_code(m_last_error);
  }

private:
  CtxtHandle* m_context;
  CredHandle* m_credentials;
  SECURITY_STATUS m_last_error;
  DWORD m_flags_out;
  DWORD m_flags_in;
  std::vector<char> m_input_data;
  std::vector<char> m_output_data;
};

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
  enum class state {
    data_needed,
    data_available,
    error
  };

  sspi_decrypt(CtxtHandle* context)
    : m_context(context)
    , m_last_error(SEC_E_OK){
  }

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

    m_last_error = detail::sspi_functions::DecryptMessage(m_context, &Message, 0, nullptr);
    if (m_last_error == SEC_E_INCOMPLETE_MESSAGE) {
      return state::data_needed;
    }
    if (m_last_error != SEC_E_OK) {
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

  boost::system::error_code last_error() const {
    return error::make_error_code(m_last_error);
  }

private:
  CtxtHandle* m_context;
  SECURITY_STATUS m_last_error;
};

class sspi_impl {
public:
  sspi_impl(CredHandle* cred_handle)
    : m_cred_handle(cred_handle)
    , handshake(&m_context, cred_handle)
    , encrypt(&m_context)
    , decrypt(&m_context) {
  }

  sspi_impl(const sspi_impl&) = delete;
  sspi_impl& operator=(const sspi_impl&) = delete;

  ~sspi_impl() {
    detail::sspi_functions::DeleteSecurityContext(&m_context);
  }

private:
  CredHandle* m_cred_handle;
  CtxtHandle m_context;

public:
  // TODO: Find some better names
  sspi_handshake handshake;
  sspi_encrypt encrypt;
  sspi_decrypt decrypt;
};

} // namespace detail
} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_DETAIL_SSPI_IMPL_HPP
