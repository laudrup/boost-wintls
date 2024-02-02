//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_SSPI_STREAM_HPP
#define WINTLS_DETAIL_SSPI_STREAM_HPP

#include <wintls/detail/sspi_handshake.hpp>
#include <wintls/detail/sspi_encrypt.hpp>
#include <wintls/detail/sspi_decrypt.hpp>
#include <wintls/detail/sspi_shutdown.hpp>
#include <wintls/detail/sspi_sec_handle.hpp>

namespace wintls {
namespace detail {

class sspi_stream {
public:
  sspi_stream(context& ctx)
    : handshake(ctx, ctxt_handle_, cred_handle_)
    , encrypt(ctxt_handle_)
    , decrypt(ctxt_handle_)
    , shutdown(ctxt_handle_, cred_handle_) {
  }

  sspi_stream(sspi_stream&&) = delete;
  sspi_stream& operator=(sspi_stream&&) = delete;

private:
  ctxt_handle ctxt_handle_;
  cred_handle cred_handle_;

public:
  sspi_handshake handshake;
  sspi_encrypt encrypt;
  sspi_decrypt decrypt;
  sspi_shutdown shutdown;
};

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_SSPI_STREAM_HPP
