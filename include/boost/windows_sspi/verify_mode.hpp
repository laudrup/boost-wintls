//
// windows_sspi/verify_mode.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_SSPI_VERIFY_MODE_HPP
#define BOOST_WINDOWS_SSPI_VERIFY_MODE_HPP

namespace boost {
namespace windows_sspi {

using verify_mode = int;

// Copied from asio::ssl implementation using constants from
// openssl. Currently only verify_none is used which disables
// verification, all other values enables certificate validation.
const int verify_none = 0x00;
const int verify_peer = 0x01;
const int verify_fail_if_no_peer_cert = 0x02;
const int verify_client_once = 0x04;

} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_VERIFY_MODE_HPP
