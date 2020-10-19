//
// windows_sspi/stream_base.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_SSPI_STREAM_BASE_HPP
#define BOOST_WINDOWS_SSPI_STREAM_BASE_HPP

#include <boost/windows_sspi/context.hpp>

namespace boost {
namespace windows_sspi {

class stream_base {
public:
  enum handshake_type { client, server };

protected:
  ~stream_base() = default;
};

} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_STREAM_BASE_HPP
