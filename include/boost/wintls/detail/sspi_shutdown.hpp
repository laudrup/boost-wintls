//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_SSPI_SHUTDOWN_HPP
#define BOOST_WINTLS_DETAIL_SSPI_SHUTDOWN_HPP

#include <boost/wintls/detail/sspi_functions.hpp>
#include <boost/wintls/detail/config.hpp>
#include <boost/wintls/detail/context_flags.hpp>

namespace boost {
namespace wintls {
namespace detail {

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

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_SHUTDOWN_HPP
