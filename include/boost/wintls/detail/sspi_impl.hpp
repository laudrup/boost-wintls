//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_SSPI_IMPL_HPP
#define BOOST_WINTLS_DETAIL_SSPI_IMPL_HPP

#include WINTLS_INCLUDE(handshake_type)
#include WINTLS_INCLUDE(error)

#include WINTLS_INCLUDE(detail/sspi_functions)
#include WINTLS_INCLUDE(detail/config)

#include WINAPI_INCLUDE(basic_types)
#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

#include <array>
#include <numeric>
#include <vector>

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace detail {

const DWORD client_context_flags =
  ISC_REQ_SEQUENCE_DETECT | // Detect messages received out of sequence
  ISC_REQ_REPLAY_DETECT | // Detect replayed messages
  ISC_REQ_CONFIDENTIALITY | // Encrypt messages
  ISC_RET_EXTENDED_ERROR | // When errors occur, the remote party will be notified
  ISC_REQ_ALLOCATE_MEMORY | // Allocate buffers. Free them with FreeContextBuffer
  ISC_REQ_STREAM; // Support a stream-oriented connection

const DWORD server_context_flags =
  ASC_REQ_SEQUENCE_DETECT | // Detect messages received out of sequence
  ASC_REQ_REPLAY_DETECT | // Detect replayed messages
  ASC_REQ_CONFIDENTIALITY | // Encrypt messages
  ASC_RET_EXTENDED_ERROR | // When errors occur, the remote party will be notified
  ASC_REQ_ALLOCATE_MEMORY | // Allocate buffers. Free them with FreeContextBuffer
  ASC_REQ_STREAM; // Support a stream-oriented connection

class sspi_handshake {
public:
  enum class state {
    data_needed,
    data_available,
    done,
    error
  };

  sspi_handshake(context& context, CtxtHandle* ctx_handle, CredHandle* cred_handle)
    : m_context(context)
    , m_ctx_handle(ctx_handle)
    , m_cred_handle(cred_handle)
    , m_last_error(SEC_E_OK) {
  }

  void operator()(handshake_type type) {
    m_handshake_type = type;

    SCHANNEL_CRED creds{};
    creds.dwVersion = SCHANNEL_CRED_VERSION;
    creds.grbitEnabledProtocols = static_cast<int>(m_context.m_method);
    creds.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION;

    auto usage = [this]() {
      switch (m_handshake_type) {
        case handshake_type::client:
          return SECPKG_CRED_OUTBOUND;
        case handshake_type::server:
          return SECPKG_CRED_INBOUND;
      }
      UNREACHABLE_RETURN(0);
    }();

    auto server_cert = m_context.server_cert();
    if (m_handshake_type == handshake_type::server && server_cert != nullptr) {
      creds.cCreds = 1;
      creds.paCred = &server_cert;
    }

    TimeStamp expiry;
    m_last_error = detail::sspi_functions::AcquireCredentialsHandle(nullptr,
                                                                    const_cast<BOOST_NAMESPACE_USE winapi::LPWSTR_>(UNISP_NAME),
                                                                    usage,
                                                                    nullptr,
                                                                    &creds,
                                                                    nullptr,
                                                                    nullptr,
                                                                    m_cred_handle,
                                                                    &expiry);
    if (m_last_error != SEC_E_OK) {
      return;
    }

    if (m_handshake_type == handshake_type::client) {
      SecBufferDesc OutBuffer;
      SecBuffer OutBuffers[1];

      OutBuffers[0].pvBuffer = nullptr;
      OutBuffers[0].BufferType = SECBUFFER_TOKEN;
      OutBuffers[0].cbBuffer = 0;

      OutBuffer.cBuffers = 1;
      OutBuffer.pBuffers = OutBuffers;
      OutBuffer.ulVersion = SECBUFFER_VERSION;

      DWORD out_flags = 0;

      m_last_error = detail::sspi_functions::InitializeSecurityContext(m_cred_handle,
                                                                       nullptr,
                                                                       m_server_hostname.get(),
                                                                       client_context_flags,
                                                                       0,
                                                                       SECURITY_NATIVE_DREP,
                                                                       nullptr,
                                                                       0,
                                                                       m_ctx_handle,
                                                                       &OutBuffer,
                                                                       &out_flags,
                                                                       nullptr);
      if (m_last_error == SEC_I_CONTINUE_NEEDED) {
        // TODO: Avoid this copy
        m_output_data = std::vector<char>{reinterpret_cast<const char*>(OutBuffers[0].pvBuffer)
          , reinterpret_cast<const char*>(OutBuffers[0].pvBuffer) + OutBuffers[0].cbBuffer};
        detail::sspi_functions::FreeContextBuffer(OutBuffers[0].pvBuffer);
      }
    } else {
      m_last_error = SEC_I_CONTINUE_NEEDED;
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

    DWORD out_flags = 0;

    switch(m_handshake_type) {
      case handshake_type::client:
        m_last_error = detail::sspi_functions::InitializeSecurityContext(m_cred_handle,
                                                                         m_ctx_handle,
                                                                         nullptr,
                                                                         client_context_flags,
                                                                         0,
                                                                         SECURITY_NATIVE_DREP,
                                                                         &InBuffer,
                                                                         0,
                                                                         nullptr,
                                                                         &OutBuffer,
                                                                         &out_flags,
                                                                         nullptr);
        break;
      case handshake_type::server: {
        const bool first_call = m_ctx_handle->dwLower == 0 && m_ctx_handle->dwUpper == 0;
        TimeStamp expiry;
        m_last_error = detail::sspi_functions::AcceptSecurityContext(m_cred_handle,
                                                                     first_call ? nullptr : m_ctx_handle,
                                                                     &InBuffer,
                                                                     server_context_flags,
                                                                     SECURITY_NATIVE_DREP,
                                                                     first_call ? m_ctx_handle : nullptr,
                                                                     &OutBuffer,
                                                                     &out_flags,
                                                                     &expiry);
      }
    }
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
      case SEC_I_CONTINUE_NEEDED:
        return state::data_needed;

      case SEC_E_OK: {
        if (m_context.m_verify_server_certificate) {
          const CERT_CONTEXT* ctx_ptr = nullptr;
          m_last_error = detail::sspi_functions::QueryContextAttributes(m_ctx_handle, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &ctx_ptr);
          if (m_last_error != SEC_E_OK) {
            return state::error;
          }

          cert_context_ptr remote_cert{ctx_ptr, &CertFreeCertificateContext};

          m_last_error = m_context.verify_certificate(remote_cert.get());
          if (m_last_error != SEC_E_OK) {
            return state::error;
          }
        }

        WINTLS_ASSERT_MSG(InBuffers[1].BufferType != SECBUFFER_EXTRA, "Handle extra data from handshake");
        return state::done;
      }

      case SEC_I_INCOMPLETE_CREDENTIALS:
        WINTLS_ASSERT_MSG(false, "client authentication not implemented");

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

  wintls::error::error_code last_error() const {
    return error::make_error_code(m_last_error);
  }

  void set_server_hostname(const winapi::WindowsString& hostname) {
    using CharType = BOOST_NAMESPACE_USE winapi::WCHAR_;
    const auto size = hostname.size() + 1;
    m_server_hostname = std::make_unique<CharType[]>(size);
    std::transform(hostname.begin(), hostname.end(), m_server_hostname.get(), [](auto c) {return static_cast<CharType>(c); });
    m_server_hostname[size-1] = 0;
  }

private:
  context& m_context;
  CtxtHandle* m_ctx_handle;
  CredHandle* m_cred_handle;
  SECURITY_STATUS m_last_error;
  handshake_type m_handshake_type;
  std::vector<char> m_input_data;
  std::vector<char> m_output_data;
  std::unique_ptr<BOOST_NAMESPACE_USE winapi::WCHAR_[]> m_server_hostname;
};

class sspi_encrypt {
public:
  sspi_encrypt(CtxtHandle* context)
    : m_context(context)
    , m_message(context) {
  }

  template <typename ConstBufferSequence>
  std::size_t operator()(const ConstBufferSequence& buffers, wintls::error::error_code& ec) {
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

  std::size_t size() const {
    return m_message.size();
  }

  std::vector<char> data() const {
    return m_message.data();
  }

private:
  // TODO: Generalize this class and move it outsize of the encrypt
  // class possibly meeting asio::buffer_sequence requirements
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

    std::size_t size() const {
      return std::accumulate(m_buffers.begin(), m_buffers.end(), 0, [](auto size, const auto& buffer) {
        return size += buffer.cbBuffer;
      });
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
    , m_last_error(SEC_E_OK) {
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
    WINTLS_ASSERT_MSG(!decrypted_data.empty(), "");

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

  wintls::error::error_code last_error() const {
    return error::make_error_code(m_last_error);
  }

private:
  CtxtHandle* m_context;
  SECURITY_STATUS m_last_error;
};

class sspi_shutdown {
public:
  enum class state {
    data_available,
    error
  };

  sspi_shutdown(CtxtHandle* context, CredHandle* credentials)
    : m_context(context)
    , m_credentials(credentials)
    , m_last_error(SEC_E_OK) {
  }

  state operator()() {
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];

    DWORD shutdown_type = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer = &shutdown_type;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer = sizeof(shutdown_type);

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    m_last_error = detail::sspi_functions::ApplyControlToken(m_context, &OutBuffer);
    if (m_last_error != SEC_E_OK) {
      return state::error;
    }

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    DWORD out_flags = 0;

    m_last_error = detail::sspi_functions::InitializeSecurityContext(m_credentials,
                                                                     m_context,
                                                                     NULL,
                                                                     client_context_flags,
                                                                     0,
                                                                     SECURITY_NATIVE_DREP,
                                                                     NULL,
                                                                     0,
                                                                     m_context,
                                                                     &OutBuffer,
                                                                     &out_flags,
                                                                     nullptr);
    if (m_last_error != SEC_E_OK) {
      return state::error;
    }

    m_buf = net::buffer(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
    return state::data_available;
  }

  net::const_buffer output() const {
    return m_buf;
  }

  void consume(std::size_t size) {
    // TODO: Handle this instead of asserting
      WINTLS_VERIFY_MSG(size == m_buf.size(), "");
    // TODO: RAII this buffer to ensure it's freed even if the consume function is never called
    detail::sspi_functions::FreeContextBuffer(const_cast<void*>(m_buf.data()));
    m_buf = net::const_buffer{};
  }

  wintls::error::error_code last_error() const {
    return error::make_error_code(m_last_error);
  }

private:
  CtxtHandle* m_context;
  CredHandle* m_credentials;
  SECURITY_STATUS m_last_error;
  net::const_buffer m_buf;
};

class sspi_impl {
public:
  sspi_impl(context& ctx)
    : handshake(ctx, &m_context, &m_credentials)
    , encrypt(&m_context)
    , decrypt(&m_context)
    , shutdown(&m_context, &m_credentials) {
  }

  sspi_impl(const sspi_impl&) = delete;
  sspi_impl& operator=(const sspi_impl&) = delete;

  ~sspi_impl() {
    WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Memory corrupt before shutdown, please check your usage code");
    detail::sspi_functions::DeleteSecurityContext(&m_context);
    detail::sspi_functions::FreeCredentialsHandle(&m_credentials);
    WINTLS_ASSERT_MSG(winapi::CrtCheckMemory(), "Internal error: memory corrupted during shutdown");
  }

  void set_server_hostname(const winapi::WindowsString& hostname) {
    handshake.set_server_hostname(hostname);
  }

private:
  CredHandle m_credentials{0, 0};
  CtxtHandle m_context{0, 0};

public:
  // TODO: Find some better names
  sspi_handshake handshake;
  sspi_encrypt encrypt;
  sspi_decrypt decrypt;
  sspi_shutdown shutdown;
};

} // namespace detail
} // namespace wintls
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_DETAIL_SSPI_IMPL_HPP
