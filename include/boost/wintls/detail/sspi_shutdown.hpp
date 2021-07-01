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
    shutdown_buffers buffers;

    last_error_ = detail::sspi_functions::ApplyControlToken(context_, buffers);
    if (last_error_ != SEC_E_OK) {
      return state::error;
    }

    DWORD out_flags = 0;
    last_error_ = detail::sspi_functions::InitializeSecurityContext(credentials_,
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
    if (last_error_ != SEC_E_OK) {
      return state::error;
    }

    buffer_ = std::move(sspi_context_buffer{buffers[0].pvBuffer, buffers[0].cbBuffer});
    return state::data_available;
  }

  net::const_buffer output() const {
    return buffer_;
  }

  boost::system::error_code last_error() const {
    return error::make_error_code(last_error_);
  }

private:
  CtxtHandle* context_;
  CredHandle* credentials_;
  SECURITY_STATUS last_error_;
  sspi_context_buffer buffer_;
};

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_SSPI_SHUTDOWN_HPP
