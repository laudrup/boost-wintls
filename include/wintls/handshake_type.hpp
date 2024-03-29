//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_HANDSHAKE_TYPE_HPP
#define WINTLS_HANDSHAKE_TYPE_HPP

namespace wintls {

/// Different handshake types.
enum class handshake_type {
  /// Perform handshaking as a client.
  client,

  /// Perform handshaking as a server.
  server
};

} // namespace wintls

#endif // WINTLS_HANDSHAKE_TYPE_HPP
