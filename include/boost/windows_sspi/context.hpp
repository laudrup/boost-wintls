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
#include <boost/windows_sspi/verify_mode.hpp>

#include <boost/windows_sspi/detail/context_impl.hpp>
#include <boost/windows_sspi/detail/config.hpp>

#include <boost/winapi/handles.hpp>

#include <memory>
#include <string>

namespace boost {
namespace windows_sspi {

namespace detail {
class sspi_handshake;
}

class context : public context_base {
public:
  explicit context(method)
    : m_impl(std::make_unique<detail::context_impl>())
    , m_verify_mode(verify_none) {
  }

  void add_certificate_authority(const net::const_buffer& ca, boost::system::error_code& ec) {
    try {
      m_impl->add_certificate_authority(ca);
    } catch (const boost::system::system_error& e) {
      ec = e.code();
    }
  }

  void add_certificate_authority(const net::const_buffer& ca) {
    m_impl->add_certificate_authority(ca);
  }

  void load_verify_file(const std::string& filename, boost::system::error_code& ec) {
    ec = {};
    try {
      m_impl->load_verify_file(filename);
    } catch (const boost::system::system_error& e) {
      ec = e.code();
    }
  }

  void load_verify_file(const std::string& filename) {
    m_impl->load_verify_file(filename);
  }

  void set_verify_mode(verify_mode v, boost::system::error_code& ec) {
    ec = {};
    m_verify_mode = v;
  }

  void set_verify_mode(verify_mode v) {
    m_verify_mode = v;
  }

  void set_default_verify_paths() {
    m_impl->use_default_cert_store = true;
  }

  void set_default_verify_paths(boost::system::error_code& ec) {
    m_impl->use_default_cert_store = true;
    ec = {};
  }

  void use_certificate(const net::const_buffer& certificate, file_format format, boost::system::error_code& ec) {
    try {
      m_impl->use_certificate(certificate, format);
    } catch (const boost::system::system_error& e) {
      ec = e.code();
    }
  }

  void use_certificate(const net::const_buffer& certificate, file_format format) {
    m_impl->use_certificate(certificate, format);
  }

  void use_certificate_file(const std::string& filename, file_format format, boost::system::error_code& ec) {
    try {
      m_impl->use_certificate_file(filename, format);
    } catch (const boost::system::system_error& e) {
      ec = e.code();
    }
  }

  void use_certificate_file(const std::string& filename, file_format format) {
    m_impl->use_certificate_file(filename, format);
  }

  void use_private_key(const net::const_buffer& private_key, file_format format, boost::system::error_code& ec) {
    try {
      m_impl->use_private_key(private_key, format);
    } catch (const boost::system::system_error& e) {
      ec = e.code();
    }
  }

  void use_private_key(const net::const_buffer& private_key, file_format format) {
    m_impl->use_private_key(private_key, format);
  }

  void use_private_key_file(const std::string& filename, file_format format, boost::system::error_code& ec) {
    try {
      m_impl->use_private_key_file(filename, format);
    } catch (const boost::system::system_error& e) {
      ec = e.code();
    }
  }

  void use_private_key_file(const std::string& filename, file_format format) {
    m_impl->use_private_key_file(filename, format);
  }

private:
  boost::winapi::DWORD_ verify_certificate(const CERT_CONTEXT* cert) {
    if (m_verify_mode == verify_none) {
      return boost::winapi::ERROR_SUCCESS_;
    }
    return m_impl->verify_certificate(cert);
  }

  const CERT_CONTEXT* server_cert() {
    return m_impl->server_cert.ptr;
  }

  friend class stream_base;
  friend class detail::sspi_handshake;
  std::unique_ptr<detail::context_impl> m_impl;
  verify_mode m_verify_mode;
};

} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_CONTEXT_HPP
