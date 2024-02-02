//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_SSPI_ENCRYPT_HPP
#define WINTLS_DETAIL_SSPI_ENCRYPT_HPP

#include <wintls/detail/config.hpp>
#include <wintls/detail/encrypt_buffers.hpp>
#include <wintls/detail/sspi_sec_handle.hpp>

namespace wintls {
namespace detail {

class sspi_encrypt {
public:
  sspi_encrypt(ctxt_handle& ctxt_handle)
    : buffers(ctxt_handle)
    , ctxt_handle_(ctxt_handle) {
  }

  template <typename ConstBufferSequence>
  std::size_t operator()(const ConstBufferSequence& buf, wintls::error_code& ec) {
    SECURITY_STATUS sc = SEC_E_OK;

    std::size_t size_encrypted = buffers(buf, sc);
    if (sc != SEC_E_OK) {
      ec = error::make_error_code(sc);
      return 0;
    }

    sc = detail::sspi_functions::EncryptMessage(ctxt_handle_.get(), 0, buffers.desc(), 0);
    if (sc != SEC_E_OK) {
      ec = error::make_error_code(sc);
      return 0;
    }

    return size_encrypted;
  }

  encrypt_buffers buffers;

private:
  ctxt_handle& ctxt_handle_;
};

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_SSPI_ENCRYPT_HPP
