//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_SSPI_SHUTDOWN_HPP
#define WINTLS_DETAIL_SSPI_SHUTDOWN_HPP

#include <wintls/detail/sspi_functions.hpp>
#include <wintls/detail/config.hpp>
#include <wintls/detail/context_flags.hpp>
#include <wintls/detail/shutdown_buffers.hpp>
#include <wintls/detail/sspi_context_buffer.hpp>
#include <wintls/detail/sspi_sec_handle.hpp>

#include <cassert>

namespace wintls {
namespace detail {

class sspi_shutdown {
public:
  sspi_shutdown(ctxt_handle& ctxt_handle, cred_handle& cred_handle)
    : ctxt_handle_(ctxt_handle)
    , cred_handle_(cred_handle) {
  }

  wintls::error_code operator()() {
    shutdown_buffers buffers;

    SECURITY_STATUS sc = detail::sspi_functions::ApplyControlToken(ctxt_handle_.get(), buffers.desc());
    if (sc != SEC_E_OK) {
      return error::make_error_code(sc);
    }

    DWORD out_flags = 0;
    sc = detail::sspi_functions::InitializeSecurityContextA(cred_handle_.get(),
                                                           ctxt_handle_.get(),
                                                           nullptr,
                                                           client_context_flags,
                                                           0,
                                                           SECURITY_NATIVE_DREP,
                                                           nullptr,
                                                           0,
                                                           ctxt_handle_.get(),
                                                           buffers.desc(),
                                                           &out_flags,
                                                           nullptr);
    if (sc != SEC_E_OK) {
      return error::make_error_code(sc);
    }

    buffer_ = sspi_context_buffer{buffers[0].pvBuffer, buffers[0].cbBuffer};
    return {};
  }

  net::const_buffer buffer() {
    return buffer_.asio_buffer();
  }

  void size_written(std::size_t size) {
    (void)(size);
    assert(size == buffer_.size());
    buffer_ = sspi_context_buffer{};
  }

private:
  ctxt_handle& ctxt_handle_;
  cred_handle& cred_handle_;
  sspi_context_buffer buffer_;
};

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_SSPI_SHUTDOWN_HPP
