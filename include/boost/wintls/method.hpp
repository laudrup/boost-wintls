//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_METHOD_HPP
#define BOOST_WINTLS_METHOD_HPP

#include WINTLS_INCLUDE(detail/sspi_types)

BOOST_NAMESPACE_DECLARE
namespace wintls {

/// Different methods supported by a context.
enum class method {
  /// Operating system defaults.
  system_default = 0,

  /// Generic SSL version 3.
  sslv3 = SP_PROT_SSL3_SERVER | SP_PROT_SSL3_CLIENT,

  /// SSL version 3 client.
  sslv3_client = SP_PROT_SSL3_CLIENT,

  /// SSL version 3 server.
  sslv3_server = SP_PROT_SSL3_SERVER,

  /// Generic TLS version 1.
  tlsv1 = SP_PROT_TLS1_SERVER | SP_PROT_TLS1_CLIENT,

  /// TLS version 1 client.
  tlsv1_client = SP_PROT_TLS1_CLIENT,

  /// TLS version 1 server.
  tlsv1_server = SP_PROT_TLS1_SERVER,

  /// Generic TLS version 1.1.
  tlsv11 = SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_1_CLIENT,

  /// TLS version 1.1 client.
  tlsv11_client = SP_PROT_TLS1_1_CLIENT,

  /// TLS version 1.1 server.
  tlsv11_server = SP_PROT_TLS1_1_SERVER,

  /// Generic TLS version 1.2.
  tlsv12 = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_2_CLIENT,

  /// TLS version 1.2 client.
  tlsv12_client = SP_PROT_TLS1_2_CLIENT,

  /// TLS version 1.2 server.
  tlsv12_server = SP_PROT_TLS1_2_SERVER
};

} // namespace wintls
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_METHOD_HPP
