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
#include <boost/wintls/detail/shutdown_buffers.hpp>
#include <boost/wintls/detail/sspi_context_buffer.hpp>

#include <boost/assert.hpp>

namespace boost {
namespace wintls {
namespace detail {

class sspi_shutdown {
public:
  sspi_shutdown(CtxtHandle* context, CredHandle* credentials)
    : context_(context)
    , credentials_(credentials) {
  }

  boost::system::error_code operator()() {
    shutdown_buffers buffers;

    SECURITY_STATUS sc = detail::sspi_functions::ApplyControlToken(context_, buffers);
    if (sc != SEC_E_OK) {
      return error::make_error_code(sc);
    }

    DWORD out_flags = 0;
    sc = detail::sspi_functions::InitializeSecurityContext(credentials_,
                                                           context_,
                                                           nullptr,
                                                           client_context_flags,
                                                           0,
                                                           SECURITY_NATIVE_DREP,
                                                           nullptr,
                                                           0,
                                                           context_,
                                                           buffers,
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
    BOOST_VERIFY(size == buffer_.size());
    buffer_ = sspi_context_buffer{};
  }

private:
  CtxtHandle* context_;
  CredHandle* credentials_;
  sspi_context_buffer buffer_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_SHUTDOWN_HPP
