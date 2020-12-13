//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_TLS_HANDSHAKE_TYPE_HPP
#define BOOST_WINDOWS_TLS_HANDSHAKE_TYPE_HPP

namespace boost {
namespace windows_tls {

/// Different handshake types.
enum class handshake_type {
  /// Perform handshaking as a client.
  client,

  /// Perform handshaking as a server.
  server
};

} // namespace windows_tls
} // namespace boost

#endif
