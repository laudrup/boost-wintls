//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_ERROR_HPP
#define WINTLS_DETAIL_ERROR_HPP

#include <wintls/detail/config.hpp>

namespace wintls {
namespace detail {

inline wintls::error_code get_last_error() noexcept {
  return wintls::error_code(static_cast<int>(GetLastError()), wintls::system_category());
}

inline void throw_last_error(const char* msg) {
  throw wintls::system_error(get_last_error(), msg);
}

inline void throw_last_error() {
  throw wintls::system_error(get_last_error());
}

inline void throw_error(const wintls::error_code& ec) {
  throw wintls::system_error(ec);
}

inline void throw_error(const wintls::error_code& ec, const char* msg) {
  throw wintls::system_error(ec, msg);
}

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_ERROR_HPP
