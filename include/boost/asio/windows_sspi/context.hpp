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

#include "error.hpp"

// TODO: Avoid cluttering global namespace (and avoid Windows headers if possible)
#define SECURITY_WIN32
#include <schannel.h>
#include <sspi.h>

#include <memory>
#include <stdexcept>

namespace boost {
namespace asio {
namespace windows_sspi {

class context
{
public:
    using native_handle_type = CredHandle;
    using error_code = boost::system::error_code;

    context()
        : m_impl(std::make_shared<impl>())
    {}

private:
    struct impl
    {
        impl()
            : sspi_functions(InitSecurityInterface())
        {
            SCHANNEL_CRED creds{};
            creds.dwVersion = SCHANNEL_CRED_VERSION;
            // TODO: Set protocols to enable
            creds.grbitEnabledProtocols = 0;
            // TODO: Set proper flags based on options. This basically disables certificate validation.
            creds.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK;

            TimeStamp expiry;
            SECURITY_STATUS sc = sspi_functions->AcquireCredentialsHandle(
                NULL,
                const_cast<SEC_CHAR*>(UNISP_NAME), // Yikes...
                SECPKG_CRED_OUTBOUND,              // TODO: Should probably be set based on client/server
                NULL,
                &creds,
                NULL,
                NULL,
                &handle,
                &expiry);
            if (sc != SEC_E_OK)
            {
                throw boost::system::system_error(error::make_error_code(sc),
                                                  "AcquireCredentialsHandleA");
            }
        }

        ~impl() { FreeCredentialsHandle(&handle); }

        SecurityFunctionTable* sspi_functions;
        CredHandle handle;
    };

    friend class stream_base;
    std::shared_ptr<impl> m_impl;
};

} // namespace windows_sspi
} // namespace asio
} // namespace boost

#endif // BOOST_ASIO_WINDOWS_SSPI_CONTEXT_HPP
