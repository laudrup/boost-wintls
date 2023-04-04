//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_ERROR_HPP
#define BOOST_WINTLS_ERROR_HPP

#include <boost/wintls/detail/error.hpp>
#include <boost/wintls/detail/sspi_types.hpp>

namespace boost {
namespace wintls {
namespace error {

enum stream_errors {
  /// The underlying stream closed before the ssl stream gracefully shut down.
  stream_truncated = 1
};

class stream_category : public boost::system::error_category {
public:
  const char* name() const BOOST_ASIO_ERROR_CATEGORY_NOEXCEPT {
    return "wintls.stream";
  }

  std::string message(int value) const {
    switch (value) {
      case stream_truncated:
        return "stream truncated";
      default:
        return "wintls.stream error";
    }
  }
};

inline const boost::system::error_category& get_stream_category() {
  static stream_category instance;
  return instance;
}

inline boost::system::error_code make_error_code(stream_errors e) {
  return boost::system::error_code(static_cast<int>(e), get_stream_category());
}

inline boost::system::error_code make_error_code(SECURITY_STATUS sc) {
  return boost::system::error_code(static_cast<int>(sc), boost::system::system_category());
}

} // namespace error
} // namespace wintls
} // namespace boost

namespace boost {
namespace system {

template<>
struct is_error_code_enum<boost::wintls::error::stream_errors> {
  static const bool value = true;
};

} // namespace system
} // namespace boost

#endif // BOOST_WINTLS_ERROR_HPP
