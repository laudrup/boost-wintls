//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_FILE_FORMAT_HPP
#define WINTLS_FILE_FORMAT_HPP

namespace wintls {

/// File format types.
enum class file_format {
  /// ASN.1 file.
  asn1,

  /// PEM file.
  pem
};

} // namespace wintls

#endif // WINTLS_FILE_FORMAT_HPP
