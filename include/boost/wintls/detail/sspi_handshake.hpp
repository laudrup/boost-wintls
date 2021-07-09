//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_SSPI_HANDSHAKE_HPP
#define BOOST_WINTLS_DETAIL_SSPI_HANDSHAKE_HPP

#include <boost/wintls/handshake_type.hpp>
#include <boost/wintls/detail/sspi_functions.hpp>
#include <boost/wintls/detail/context_flags.hpp>
#include <boost/wintls/detail/handshake_input_buffers.hpp>
#include <boost/wintls/detail/handshake_output_buffers.hpp>
#include <boost/wintls/detail/sspi_context_buffer.hpp>

#include <boost/winapi/basic_types.hpp>

#include <array>
#include <memory>

namespace boost {
namespace wintls {
namespace detail {

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
    , last_error_(SEC_E_OK)
    , in_buffer_(net::buffer(input_data_)) {
    input_buffers_[0].pvBuffer = reinterpret_cast<void*>(input_data_.data());
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

    switch(handshake_type_) {
      case handshake_type::client: {
        DWORD out_flags = 0;

        handshake_output_buffers buffers;
        last_error_ = detail::sspi_functions::InitializeSecurityContext(cred_handle_,
                                                                        nullptr,
                                                                        server_hostname_.get(),
                                                                        client_context_flags,
                                                                        0,
                                                                        SECURITY_NATIVE_DREP,
                                                                        nullptr,
                                                                        0,
                                                                        ctx_handle_,
                                                                        buffers,
                                                                        &out_flags,
                                                                        nullptr);
        if (buffers[0].cbBuffer != 0 && buffers[0].pvBuffer != nullptr) {
          out_buffer_ = sspi_context_buffer{buffers[0].pvBuffer, buffers[0].cbBuffer};
        }
      }
      case handshake_type::server:
        last_error_ = SEC_I_CONTINUE_NEEDED;
    }
  }

  state operator()() {
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
        last_error_ = detail::sspi_functions::InitializeSecurityContext(cred_handle_,
                                                                        ctx_handle_,
                                                                        server_hostname_.get(),
                                                                        client_context_flags,
                                                                        0,
                                                                        SECURITY_NATIVE_DREP,
                                                                        input_buffers_,
                                                                        0,
                                                                        nullptr,
                                                                        out_buffers,
                                                                        &out_flags,
                                                                        nullptr);
        break;
      case handshake_type::server: {
        const bool first_call = ctx_handle_->dwLower == 0 && ctx_handle_->dwUpper == 0;
        TimeStamp expiry;
        last_error_ = detail::sspi_functions::AcceptSecurityContext(cred_handle_,
                                                                    first_call ? nullptr : ctx_handle_,
                                                                    input_buffers_,
                                                                    server_context_flags,
                                                                    SECURITY_NATIVE_DREP,
                                                                    first_call ? ctx_handle_ : nullptr,
                                                                    out_buffers,
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

      BOOST_ASSERT_MSG(in_buffer_.size() > 0, "buffer not large enough for tls handshake message");
      return state::data_needed;
    } else if (last_error_ == SEC_E_INCOMPLETE_MESSAGE) {
      BOOST_ASSERT_MSG(in_buffer_.size() > 0, "buffer not large enough for tls handshake message");
      return state::data_needed;
    } else {
      input_buffers_[0].cbBuffer = 0;
      in_buffer_ = net::buffer(input_data_);
    }

    if (out_buffers[0].cbBuffer != 0 && out_buffers[0].pvBuffer != nullptr) {
      out_buffer_ = sspi_context_buffer{out_buffers[0].pvBuffer, out_buffers[0].cbBuffer};
      return state::data_available;
    }

    switch (last_error_) {
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

        return state::done;
      }

      case SEC_I_INCOMPLETE_CREDENTIALS:
        BOOST_ASSERT_MSG(false, "client authentication not implemented");

      case SEC_I_RENEGOTIATE:
        BOOST_ASSERT_MSG(false, "renegotiation not implemented");

      default:
        return state::error;
    }
  }

  void size_written(std::size_t size) {
    BOOST_VERIFY(size == out_buffer_.size());
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
  std::array<char, 0x10000> input_data_;
  sspi_context_buffer out_buffer_;
  net::mutable_buffer in_buffer_;
  handshake_input_buffers input_buffers_;
  std::unique_ptr<boost::winapi::WCHAR_[]> server_hostname_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_HANDSHAKE_HPP
