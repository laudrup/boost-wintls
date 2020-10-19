//
// windows_sspi/context.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_SSPI_CONTEXT_HPP
#define BOOST_WINDOWS_SSPI_CONTEXT_HPP

#include <boost/windows_sspi/context_base.hpp>
#include <boost/windows_sspi/detail/context_impl.hpp>

#include <boost/winapi/handles.hpp>

#include <memory>

namespace boost {
namespace windows_sspi {

namespace detail {
class sspi_handshake;
}

class context : public context_base {
public:
  using native_handle_type = CredHandle*;
  using error_code = boost::system::error_code;

  explicit context(method)
    : m_impl(std::make_unique<detail::context_impl>()) {
  }

  native_handle_type native_handle() const {
    return m_impl->handle();
  }

  void add_certificate_authority(const net::const_buffer& ca, boost::system::error_code& ec) {
    return m_impl->add_certificate_authority(ca, ec);
  }

  void load_verify_file(const std::string& filename, boost::system::error_code& ec) {
    return m_impl->load_verify_file(filename, ec);
  }

private:
  boost::winapi::DWORD_ verify_certificate(const CERT_CONTEXT* cert) {
    return m_impl->verify_certificate(cert);
  }

  friend class stream_base;
  friend class detail::sspi_handshake;
  std::unique_ptr<detail::context_impl> m_impl;
};

} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_CONTEXT_HPP
