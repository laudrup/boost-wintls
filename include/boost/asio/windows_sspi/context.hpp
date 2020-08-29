//
// windows_sspi/context.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_ASIO_WINDOWS_SSPI_CONTEXT_HPP
#define BOOST_ASIO_WINDOWS_SSPI_CONTEXT_HPP

#include <boost/asio/windows_sspi/error.hpp>
#include <boost/asio/windows_sspi/context_base.hpp>
#include <boost/asio/windows_sspi/detail/sspi_functions.hpp>

// TODO: Avoid cluttering global namespace (and avoid Windows headers if possible)
#define SECURITY_WIN32
#include <schannel.h>
#include <sspi.h>

#include <memory>
#include <stdexcept>

namespace boost {
namespace asio {
namespace windows_sspi {

class context : public context_base {
public:
  using native_handle_type = CredHandle;
  using error_code = boost::system::error_code;

  explicit context(method m)
    : m_impl(std::make_shared<impl>(m)) {
  }

private:
  struct impl {
    explicit impl(method) {
      SCHANNEL_CRED creds{};
      creds.dwVersion = SCHANNEL_CRED_VERSION;
      // TODO: Set protocols to enable from method param
      creds.grbitEnabledProtocols = 0;
      // TODO: Set proper flags based on options. This basically disables certificate validation.
      creds.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK;

      TimeStamp expiry;
      SECURITY_STATUS sc = detail::sspi_functions::AcquireCredentialsHandle(NULL,
                                                                            const_cast<SEC_CHAR*>(UNISP_NAME), // Yikes...
                                                                            SECPKG_CRED_OUTBOUND,              // TODO: Should probably be set based on client/server
                                                                            NULL,
                                                                            &creds,
                                                                            NULL,
                                                                            NULL,
                                                                            &handle,
                                                                            &expiry);
      if (sc != SEC_E_OK) {
        throw boost::system::system_error(error::make_error_code(sc),
                                          "AcquireCredentialsHandleA");
      }
    }

    ~impl() {
      detail::sspi_functions::FreeCredentialsHandle(&handle);
    }

    CredHandle handle;
  };

  friend class stream_base;
  std::shared_ptr<impl> m_impl;
};

} // namespace windows_sspi
} // namespace asio
} // namespace boost

#endif // BOOST_ASIO_WINDOWS_SSPI_CONTEXT_HPP
