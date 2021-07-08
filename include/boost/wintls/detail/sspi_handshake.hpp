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

#include <boost/winapi/basic_types.hpp>

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
      if (last_error_ == SEC_I_CONTINUE_NEEDED) {
        // TODO: Not SEC_I_CONTINUE_NEEDED is an error. Maybe make that clearer?
        // TODO: Avoid this copy
        output_data_ = std::vector<char>{reinterpret_cast<const char*>(buffers[0].pvBuffer)
          , reinterpret_cast<const char*>(buffers[0].pvBuffer) + buffers[0].cbBuffer};
        detail::sspi_functions::FreeContextBuffer(buffers[0].pvBuffer);
      }
    } else {
      last_error_ = SEC_I_CONTINUE_NEEDED;
    }
  }

  state operator()() {
    if (last_error_ != SEC_I_CONTINUE_NEEDED && last_error_ != SEC_E_INCOMPLETE_MESSAGE) {
      return state::error;
    }
    if (!output_data_.empty()) {
      return state::data_available;
    }
    if (input_data_.empty()) {
      return state::data_needed;
    }

    handshake_input_buffers in_buffers;
    handshake_output_buffers out_buffers;
    DWORD out_flags = 0;

    in_buffers[0].pvBuffer = reinterpret_cast<void*>(input_data_.data());
    in_buffers[0].cbBuffer = static_cast<ULONG>(input_data_.size());

    switch(handshake_type_) {
      case handshake_type::client:
        last_error_ = detail::sspi_functions::InitializeSecurityContext(cred_handle_,
                                                                        ctx_handle_,
                                                                        server_hostname_.get(),
                                                                        client_context_flags,
                                                                        0,
                                                                        SECURITY_NATIVE_DREP,
                                                                        in_buffers,
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
                                                                    in_buffers,
                                                                    server_context_flags,
                                                                    SECURITY_NATIVE_DREP,
                                                                    first_call ? ctx_handle_ : nullptr,
                                                                    out_buffers,
                                                                    &out_flags,
                                                                    &expiry);
      }
    }
    if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
      // Some data needs to be reused for the next call, move that to the front for reuse
      std::move(input_data_.end() - in_buffers[1].cbBuffer, input_data_.end(), input_data_.begin());
      input_data_.resize(in_buffers[1].cbBuffer);
      return state::data_needed;
    } else if (last_error_ == SEC_E_INCOMPLETE_MESSAGE) {
      return state::data_needed;
    } else {
      input_data_.clear();
    }

    if (out_buffers[0].cbBuffer != 0 && out_buffers[0].pvBuffer != nullptr) {
      // TODO: Avoid this copy
      output_data_ = std::vector<char>{reinterpret_cast<const char*>(out_buffers[0].pvBuffer)
        , reinterpret_cast<const char*>(out_buffers[0].pvBuffer) + out_buffers[0].cbBuffer};
      detail::sspi_functions::FreeContextBuffer(out_buffers[0].pvBuffer);
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

        BOOST_ASSERT_MSG(in_buffers[1].BufferType != SECBUFFER_EXTRA, "Handle extra data from handshake");
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

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_HANDSHAKE_HPP
