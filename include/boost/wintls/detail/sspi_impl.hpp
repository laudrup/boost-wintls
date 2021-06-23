//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_SSPI_IMPL_HPP
#define BOOST_WINTLS_DETAIL_SSPI_IMPL_HPP

#include <boost/wintls/detail/sspi_handshake.hpp>
#include <boost/wintls/detail/sspi_encrypt.hpp>
#include <boost/wintls/detail/sspi_decrypt.hpp>
#include <boost/wintls/detail/sspi_shutdown.hpp>
#include <boost/wintls/detail/sspi_functions.hpp>
#include <boost/wintls/detail/config.hpp>

namespace boost {
namespace wintls {
namespace detail {

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

  sspi_handshake handshake;
  sspi_encrypt encrypt;
  sspi_decrypt decrypt;
  sspi_shutdown shutdown;

private:
  CredHandle credentials_{0, 0};
  CtxtHandle context_{0, 0};
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_IMPL_HPP
