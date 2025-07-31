//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_SSPI_HANDSHAKE_HPP
#define WINTLS_DETAIL_SSPI_HANDSHAKE_HPP

#include <wintls/detail/assert.hpp>
#include <wintls/detail/config.hpp>
#include <wintls/detail/sspi_functions.hpp>
#include <wintls/detail/context_flags.hpp>
#include <wintls/detail/handshake_input_buffers.hpp>
#include <wintls/detail/handshake_output_buffers.hpp>
#include <wintls/detail/sspi_context_buffer.hpp>
#include <wintls/detail/sspi_sec_handle.hpp>

#include <wintls/handshake_type.hpp>

#include <array>
#include <memory>
#include <string>

namespace wintls {
namespace detail {

class sspi_handshake {
public:
  enum class state {
    data_needed,           // data needs to be read from peer
    data_available,        // data needs to be write to peer
    done,                  // handshake success
    error                  // handshake error
  };

  sspi_handshake(context& context, ctxt_handle& ctxt_handle, cred_handle& cred_handle)
    : context_(context)
    , ctxt_handle_(ctxt_handle)
    , cred_handle_(cred_handle)
    , last_error_(SEC_E_OK)
    , in_buffer_(net::buffer(input_data_)) {
    input_buffers_[0].pvBuffer = reinterpret_cast<void*>(input_data_.data());
  }

  void operator()(handshake_type type) {
    handshake_type_ = type;

    TLS_PARAMETERS tls_parameters{};
    SCH_CREDENTIALS credentials{};
    SCHANNEL_CRED creds{};
    void* cred = nullptr;

    auto usage = [this]() {
      switch (handshake_type_) {
        case handshake_type::client:
          return SECPKG_CRED_OUTBOUND;
        case handshake_type::server:
          return SECPKG_CRED_INBOUND;
      }
      WINTLS_UNREACHABLE_RETURN(0);
    }();

    auto server_cert = context_.server_cert();
    bool is_tlsv13 = [this]() {
      switch (context_.method_) {
        case method::tlsv13:
        case method::tlsv13_client:
        case method::tlsv13_server:
          return true;
        default:
          return false;
      }
      WINTLS_UNREACHABLE_RETURN(0);
    }();

    DWORD version = is_tlsv13 ? SCH_CREDENTIALS_VERSION : SCHANNEL_CRED_VERSION;
    DWORD flags = is_tlsv13 ? SCH_USE_STRONG_CRYPTO : (SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS);
    DWORD protocols = static_cast<DWORD>(context_.method_);

    // If revocation checking is enables, specify SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
    // to cause the TLS certificate status request extension (commonly known as OCSP stapling)
    // to be sent. This flag matches the CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
    // flag that we pass to the CertGetCertificateChain calls during our manual authentication.
    if (check_revocation_) {
      flags |= SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    }

    DWORD num_creds = 0;
    decltype(&server_cert) creds_list = nullptr;

    if (handshake_type_ == handshake_type::server && server_cert != nullptr) {
      num_creds = 1;
      creds_list = &server_cert;
    }

    // TODO: rename server_cert field since it is also used for client cert.
    // Note: if client cert is set, sspi will auto validate server cert with it.
    // Even though verify_server_certificate_ in context is set to false.
    if (handshake_type_ == handshake_type::client && server_cert != nullptr) {
      num_creds = 1;
      creds_list = &server_cert;
    }

    if (!is_tlsv13) {
      cred = &creds;
      creds.dwVersion = version;
      creds.grbitEnabledProtocols = protocols;
      creds.dwFlags = flags;
      creds.cCreds = num_creds;
      creds.paCred = creds_list;
    } else {
      cred = &credentials;
      credentials.dwVersion = version;
      credentials.dwFlags = flags;
      credentials.cTlsParameters = 1;
      credentials.pTlsParameters = &tls_parameters;
      credentials.pTlsParameters->grbitDisabledProtocols = ~protocols;
      credentials.cCreds = num_creds;
      credentials.paCred = creds_list;
    }

    TimeStamp expiry;
    last_error_ = detail::sspi_functions::AcquireCredentialsHandleA(nullptr,
                                                                   const_cast<SEC_CHAR*>(UNISP_NAME),
                                                                   static_cast<unsigned>(usage),
                                                                   nullptr,
                                                                   cred,
                                                                   nullptr,
                                                                   nullptr,
                                                                   cred_handle_.get(),
                                                                   &expiry);
    if (last_error_ != SEC_E_OK) {
      return;
    }

    switch(handshake_type_) {
      case handshake_type::client: {
        DWORD out_flags = 0;

        handshake_output_buffers buffers;
        last_error_ = detail::sspi_functions::InitializeSecurityContextA(cred_handle_.get(),
                                                                        nullptr,
                                                                        const_cast<SEC_CHAR*>(server_hostname_.c_str()),
                                                                        client_context_flags,
                                                                        0,
                                                                        SECURITY_NATIVE_DREP,
                                                                        nullptr,
                                                                        0,
                                                                        ctxt_handle_.get(),
                                                                        buffers.desc(),
                                                                        &out_flags,
                                                                        nullptr);
        if (buffers[0].cbBuffer != 0 && buffers[0].pvBuffer != nullptr) {
          out_buffer_ = sspi_context_buffer{buffers[0].pvBuffer, buffers[0].cbBuffer};
        }
        break;
      }
      case handshake_type::server:
        last_error_ = SEC_I_CONTINUE_NEEDED;
    }
  }

  state operator()() {
    if (last_error_ == SEC_E_OK) {
      return state::done;
    }
    if (last_error_ != SEC_I_CONTINUE_NEEDED && last_error_ != SEC_E_INCOMPLETE_MESSAGE) {
      return state::error;
    }
    if (!out_buffer_.empty()) {
      return state::data_available;
    }
    if (input_buffers_[0].cbBuffer == 0) {
      return state::data_needed;
    }

    handshake_output_buffers out_buffers;
    DWORD out_flags = 0;

    input_buffers_[1].BufferType = SECBUFFER_EMPTY;
    input_buffers_[1].pvBuffer = nullptr;
    input_buffers_[1].cbBuffer = 0;

    switch(handshake_type_) {
      case handshake_type::client:
        last_error_ = detail::sspi_functions::InitializeSecurityContextA(cred_handle_.get(),
                                                                        ctxt_handle_.get(),
                                                                        const_cast<SEC_CHAR*>(server_hostname_.c_str()),
                                                                        client_context_flags,
                                                                        0,
                                                                        SECURITY_NATIVE_DREP,
                                                                        input_buffers_.desc(),
                                                                        0,
                                                                        nullptr,
                                                                        out_buffers.desc(),
                                                                        &out_flags,
                                                                        nullptr);
        break;
      case handshake_type::server: {
        TimeStamp expiry;
        DWORD f_context_req = server_context_flags;
        if (context_.verify_server_certificate_) {
          f_context_req |= ASC_REQ_MUTUAL_AUTH;
        }
        last_error_ = detail::sspi_functions::AcceptSecurityContext(cred_handle_.get(),
                                                                    ctxt_handle_ ? ctxt_handle_.get() : nullptr,
                                                                    input_buffers_.desc(),
                                                                    f_context_req,
                                                                    SECURITY_NATIVE_DREP,
                                                                    ctxt_handle_.get(),
                                                                    out_buffers.desc(),
                                                                    &out_flags,
                                                                    &expiry);
      }
    }
    if (input_buffers_[1].BufferType == SECBUFFER_EXTRA) {
      // Some data needs to be reused for the next call, move that to the front for reuse
      const auto previous_size = input_buffers_[0].cbBuffer;
      const auto extra_size = input_buffers_[1].cbBuffer;
      const auto extra_data_begin = input_data_.begin() + previous_size - extra_size;
      const auto extra_data_end = input_data_.begin() + previous_size;

      std::move(extra_data_begin, extra_data_end, input_data_.begin());
      input_buffers_[0].cbBuffer = extra_size;
      in_buffer_ = net::buffer(input_data_) + extra_size;

      WINTLS_ASSERT_MSG(in_buffer_.size() > 0, "buffer not large enough for tls handshake message");
      return state::data_needed;
    } else if (last_error_ == SEC_E_INCOMPLETE_MESSAGE) {
      WINTLS_ASSERT_MSG(in_buffer_.size() > 0, "buffer not large enough for tls handshake message");
      return state::data_needed;
    } else {
      input_buffers_[0].cbBuffer = 0;
      in_buffer_ = net::buffer(input_data_);
    }

    bool has_buffer_output = out_buffers[0].cbBuffer != 0 && out_buffers[0].pvBuffer != nullptr;
    if(has_buffer_output){
      out_buffer_ = sspi_context_buffer{out_buffers[0].pvBuffer, out_buffers[0].cbBuffer};
    }

    switch (last_error_) {
      case SEC_I_CONTINUE_NEEDED: {
        return has_buffer_output ? state::data_available : state::data_needed;
      }
      case SEC_E_OK: {
        // sspi handshake ok. Manual authentication will be done after the handshake loop.

        if (handshake_type_ == handshake_type::server) {
          // Note: we are not checking (out_flags & ASC_RET_MUTUAL_AUTH) is true,
          // but instead rely on our manual cert validation to establish trust.
          // "The AcceptSecurityContext function will return ASC_RET_MUTUAL_AUTH if a
          // client certificate was received from the client and schannel was
          // successfully able to map the certificate to a user account in AD"
          // As observed in tests, this check would wrongly reject openssl client with valid certificate.

          // AcceptSecurityContext documentation:
          // "If function generated an output token, the token must be sent to the client process."
          // This happens when client cert is requested.
          if (has_buffer_output) {
            return state::data_available;
          }
        } else if (handshake_type_ == handshake_type::client) {
          if (has_buffer_output) {
            return state::data_available;
          }
        }
        return state::done;
      }

      case SEC_I_INCOMPLETE_CREDENTIALS:
        WINTLS_ASSERT_MSG(false, "client authentication not implemented");

      case SEC_I_RENEGOTIATE:
        WINTLS_ASSERT_MSG(false, "renegotiation not implemented");

      default:
        return state::error;
    }
  }

  void size_written(std::size_t size) {
    (void)(size);
    assert(size == out_buffer_.size());
    out_buffer_ = sspi_context_buffer{};
  }

  void size_read(std::size_t size) {
    input_buffers_[0].cbBuffer += static_cast<ULONG>(size);
    in_buffer_ = net::buffer(input_data_) + input_buffers_[0].cbBuffer;
  }

  net::const_buffer out_buffer() {
    return out_buffer_.asio_buffer();
  }

  net::mutable_buffer in_buffer() {
    return in_buffer_;
  }

  wintls::error_code last_error() const {
    return error::make_error_code(last_error_);
  }

  void set_server_hostname(const std::string& hostname) {
    server_hostname_ = hostname;
  }

  void set_certificate_revocation_check(bool check) {
    check_revocation_ = check;
  }

  SECURITY_STATUS manual_auth(){
    if (!context_.verify_server_certificate_) {
      return SEC_E_OK;
    }
    const CERT_CONTEXT* ctx_ptr = nullptr;
    last_error_ = detail::sspi_functions::QueryContextAttributesA(ctxt_handle_.get(), SECPKG_ATTR_REMOTE_CERT_CONTEXT, &ctx_ptr);
    if (last_error_ != SEC_E_OK) {
      return last_error_;
    }
    cert_context_ptr remote_cert{ctx_ptr};
    last_error_ = static_cast<SECURITY_STATUS>(context_.verify_certificate(remote_cert.get(), server_hostname_, check_revocation_));
    return last_error_;
  }

private:
  context& context_;
  ctxt_handle& ctxt_handle_;
  cred_handle& cred_handle_;

  SECURITY_STATUS last_error_;
  handshake_type handshake_type_ = handshake_type::client;
  std::array<char, 0x10000> input_data_;
  sspi_context_buffer out_buffer_;
  net::mutable_buffer in_buffer_;
  handshake_input_buffers input_buffers_;
  std::string server_hostname_;
  bool check_revocation_ = false;
};

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_SSPI_HANDSHAKE_HPP