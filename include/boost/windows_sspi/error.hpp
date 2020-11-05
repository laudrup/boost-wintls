//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_SSPI_ERROR_HPP
#define BOOST_WINDOWS_SSPI_ERROR_HPP

#include <boost/system/system_error.hpp>
#include <boost/system/error_code.hpp>

typedef long SECURITY_STATUS;

namespace boost {
namespace windows_sspi {
namespace error {

inline boost::system::error_code make_error_code(SECURITY_STATUS sc) {
  return boost::system::error_code(static_cast<int>(sc), boost::system::system_category());
}

} // namespace error
} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_ERROR_HPP
