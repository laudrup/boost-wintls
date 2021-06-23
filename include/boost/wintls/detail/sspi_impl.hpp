//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_SSPI_IMPL_HPP
#define BOOST_WINTLS_DETAIL_SSPI_IMPL_HPP

#include <boost/wintls/handshake_type.hpp>

#include <boost/wintls/detail/encrypt_buffers.hpp>
#include <boost/wintls/detail/sspi_functions.hpp>
#include <boost/wintls/detail/config.hpp>

#include <boost/winapi/basic_types.hpp>

#include <array>
#include <vector>

namespace boost {
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
    : context_(context)
    , ctx_handle_(ctx_handle)
    , cred_handle_(cred_handle)
    , last_error_(SEC_E_OK) {
  }

  void operator()(handshake_type type) {
    handshake_type_ = type;

    SCHANNEL_CRED creds{};
    creds.dwVersion = SCHANNEL_CRED_VERSION;
    creds.grbitEnabledProtocols = static_cast<int>(context_.method_);
    creds.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION;

    auto usage = [this]() {
      switch (handshake_type_) {
        case handshake_type::client:
          return SECPKG_CRED_OUTBOUND;
        case handshake_type::server:
          return SECPKG_CRED_INBOUND;
      }
      BOOST_UNREACHABLE_RETURN(0);
    }();

    auto server_cert = context_.server_cert();
    if (handshake_type_ == handshake_type::server && server_cert != nullptr) {
      creds.cCreds = 1;
      creds.paCred = &server_cert;
    }

    TimeStamp expiry;
    last_error_ = detail::sspi_functions::AcquireCredentialsHandle(nullptr,
                                                                    const_cast<boost::winapi::LPWSTR_>(UNISP_NAME),
                                                                    usage,
                                                                    nullptr,
                                                                    &creds,
                                                                    nullptr,
                                                                    nullptr,
                                                                    cred_handle_,
                                                                    &expiry);
    if (last_error_ != SEC_E_OK) {
      return;
    }

    if (handshake_type_ == handshake_type::client) {
      SecBufferDesc OutBuffer;
      SecBuffer OutBuffers[1];

      OutBuffers[0].pvBuffer = nullptr;
      OutBuffers[0].BufferType = SECBUFFER_TOKEN;
      OutBuffers[0].cbBuffer = 0;

      OutBuffer.cBuffers = 1;
      OutBuffer.pBuffers = OutBuffers;
      OutBuffer.ulVersion = SECBUFFER_VERSION;

      DWORD out_flags = 0;

      last_error_ = detail::sspi_functions::InitializeSecurityContext(cred_handle_,
                                                                       nullptr,
                                                                       server_hostname_.get(),
                                                                       client_context_flags,
                                                                       0,
                                                                       SECURITY_NATIVE_DREP,
                                                                       nullptr,
                                                                       0,
                                                                       ctx_handle_,
                                                                       &OutBuffer,
                                                                       &out_flags,
                                                                       nullptr);
      if (last_error_ == SEC_I_CONTINUE_NEEDED) {
        // TODO: Avoid this copy
        output_data_ = std::vector<char>{reinterpret_cast<const char*>(OutBuffers[0].pvBuffer)
          , reinterpret_cast<const char*>(OutBuffers[0].pvBuffer) + OutBuffers[0].cbBuffer};
        detail::sspi_functions::FreeContextBuffer(OutBuffers[0].pvBuffer);
      }
    } else {
      last_error_ = SEC_I_CONTINUE_NEEDED;
    }
  }

  state operator()() {
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
    SecBufferDesc InBuffer;
    SecBuffer InBuffers[2];

    if (last_error_ != SEC_I_CONTINUE_NEEDED) {
      return state::error;
    }
    if (!output_data_.empty()) {
      return state::data_available;
    }
    if (input_data_.empty()) {
      return state::data_needed;
    }

    InBuffers[0].pvBuffer = reinterpret_cast<void*>(input_data_.data());
    InBuffers[0].cbBuffer = static_cast<ULONG>(input_data_.size());
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

    switch(handshake_type_) {
      case handshake_type::client:
        last_error_ = detail::sspi_functions::InitializeSecurityContext(cred_handle_,
                                                                        ctx_handle_,
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
        const bool first_call = ctx_handle_->dwLower == 0 && ctx_handle_->dwUpper == 0;
        TimeStamp expiry;
        last_error_ = detail::sspi_functions::AcceptSecurityContext(cred_handle_,
                                                                    first_call ? nullptr : ctx_handle_,
                                                                    &InBuffer,
                                                                    server_context_flags,
                                                                    SECURITY_NATIVE_DREP,
                                                                    first_call ? ctx_handle_ : nullptr,
                                                                    &OutBuffer,
                                                                    &out_flags,
                                                                    &expiry);
      }
    }
    if (InBuffers[1].BufferType == SECBUFFER_EXTRA) {
      // Some data needs to be reused for the next call, move that to the front for reuse
      // TODO: Test that this works.
      std::move(input_data_.end() - InBuffers[1].cbBuffer, input_data_.end(), input_data_.begin());
      input_data_.resize(InBuffers[1].cbBuffer);
    } else {
      input_data_.clear();
    }

    if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != nullptr) {
      // TODO: Avoid this copy
      output_data_ = std::vector<char>{reinterpret_cast<const char*>(OutBuffers[0].pvBuffer)
        , reinterpret_cast<const char*>(OutBuffers[0].pvBuffer) + OutBuffers[0].cbBuffer};
      detail::sspi_functions::FreeContextBuffer(OutBuffers[0].pvBuffer);
      return state::data_available;
    }

    switch (last_error_) {
      case SEC_E_INCOMPLETE_MESSAGE:
      case SEC_I_CONTINUE_NEEDED:
        return state::data_needed;

      case SEC_E_OK: {
        if (context_.verify_server_certificate_) {
          const CERT_CONTEXT* ctx_ptr = nullptr;
          last_error_ = detail::sspi_functions::QueryContextAttributes(ctx_handle_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &ctx_ptr);
          if (last_error_ != SEC_E_OK) {
            return state::error;
          }

          cert_context_ptr remote_cert{ctx_ptr, &CertFreeCertificateContext};

          last_error_ = context_.verify_certificate(remote_cert.get());
          if (last_error_ != SEC_E_OK) {
            return state::error;
          }
        }

        BOOST_ASSERT_MSG(InBuffers[1].BufferType != SECBUFFER_EXTRA, "Handle extra data from handshake");
        return state::done;
      }

      case SEC_I_INCOMPLETE_CREDENTIALS:
        BOOST_ASSERT_MSG(false, "client authentication not implemented");

      default:
        return state::error;
    }
  }

  // TODO: Consider making this more flexible by not requering a
  // vector of chars, but any view of a range of bytes
  void put(const std::vector<char>& data) {
    input_data_.insert(input_data_.end(), data.begin(), data.end());
  }

  std::vector<char> get() {
    // TODO: Avoid this copy if possible
    auto ret = output_data_;
    output_data_.clear();
    return ret;
  }

  boost::system::error_code last_error() const {
    return error::make_error_code(last_error_);
  }

  void set_server_hostname(const std::string& hostname) {
    const auto size = hostname.size() + 1;
    server_hostname_ = std::make_unique<boost::winapi::WCHAR_[]>(size);
    const auto size_converted = mbstowcs(server_hostname_.get(), hostname.c_str(), size);
    BOOST_VERIFY_MSG(size_converted == hostname.size(), "mbstowcs");
  }

private:
  context& context_;
  CtxtHandle* ctx_handle_;
  CredHandle* cred_handle_;
  SECURITY_STATUS last_error_;
  handshake_type handshake_type_;
  std::vector<char> input_data_;
  std::vector<char> output_data_;
  std::unique_ptr<boost::winapi::WCHAR_[]> server_hostname_;
};

class sspi_encrypt {
public:
  sspi_encrypt(CtxtHandle* context)
    : context_(context)
    , buffers_(context) {
  }

  template <typename ConstBufferSequence>
  std::size_t operator()(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    SECURITY_STATUS sc;

    std::size_t size_encrypted = buffers_(buffers, sc);
    if (sc != SEC_E_OK) {
      ec = error::make_error_code(sc);
      return 0;
    }

    sc = detail::sspi_functions::EncryptMessage(context_, 0, buffers_, 0);
    if (sc != SEC_E_OK) {
      ec = error::make_error_code(sc);
      return 0;
    }

    return size_encrypted;
  }

  std::size_t size() const {
    return buffers_.size();
  }

  std::vector<char> data() const {
    return buffers_.data();
  }

private:
  CtxtHandle* context_;
  encrypt_buffers buffers_;
};

class sspi_decrypt {
public:
  enum class state {
    data_needed,
    data_available,
    error
  };

  sspi_decrypt(CtxtHandle* context)
    : context_(context)
    , last_error_(SEC_E_OK) {
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

    last_error_ = detail::sspi_functions::DecryptMessage(context_, &Message, 0, nullptr);
    if (last_error_ == SEC_E_INCOMPLETE_MESSAGE) {
      return state::data_needed;
    }
    if (last_error_ != SEC_E_OK) {
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
    return error::make_error_code(last_error_);
  }

private:
  CtxtHandle* context_;
  SECURITY_STATUS last_error_;
};

class sspi_shutdown {
public:
  enum class state {
    data_available,
    error
  };

  sspi_shutdown(CtxtHandle* context, CredHandle* credentials)
    : context_(context)
    , credentials_(credentials)
    , last_error_(SEC_E_OK) {
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

    last_error_ = detail::sspi_functions::ApplyControlToken(context_, &OutBuffer);
    if (last_error_ != SEC_E_OK) {
      return state::error;
    }

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    DWORD out_flags = 0;

    last_error_ = detail::sspi_functions::InitializeSecurityContext(credentials_,
                                                                     context_,
                                                                     NULL,
                                                                     client_context_flags,
                                                                     0,
                                                                     SECURITY_NATIVE_DREP,
                                                                     NULL,
                                                                     0,
                                                                     context_,
                                                                     &OutBuffer,
                                                                     &out_flags,
                                                                     nullptr);
    if (last_error_ != SEC_E_OK) {
      return state::error;
    }

    buf_ = net::buffer(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
    return state::data_available;
  }

  net::const_buffer output() const {
    return buf_;
  }

  void consume(std::size_t size) {
    // TODO: Handle this instead of asserting
    BOOST_VERIFY(size == buf_.size());
    // TODO: RAII this buffer to ensure it's freed even if the consume function is never called
    detail::sspi_functions::FreeContextBuffer(const_cast<void*>(buf_.data()));
    buf_ = net::const_buffer{};
  }

  boost::system::error_code last_error() const {
    return error::make_error_code(last_error_);
  }

private:
  CtxtHandle* context_;
  CredHandle* credentials_;
  SECURITY_STATUS last_error_;
  net::const_buffer buf_;
};

class sspi_impl {
public:
  sspi_impl(context& ctx)
    : handshake(ctx, &context_, &credentials_)
    , encrypt(&context_)
    , decrypt(&context_)
    , shutdown(&context_, &credentials_) {
  }

  sspi_impl(const sspi_impl&) = delete;
  sspi_impl& operator=(const sspi_impl&) = delete;

  ~sspi_impl() {
    detail::sspi_functions::DeleteSecurityContext(&context_);
    detail::sspi_functions::FreeCredentialsHandle(&credentials_);
  }

  void set_server_hostname(const std::string& hostname) {
    handshake.set_server_hostname(hostname);
  }

private:
  CredHandle credentials_{0, 0};
  CtxtHandle context_{0, 0};

public:
  // TODO: Find some better names
  sspi_handshake handshake;
  sspi_encrypt encrypt;
  sspi_decrypt decrypt;
  sspi_shutdown shutdown;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_IMPL_HPP
