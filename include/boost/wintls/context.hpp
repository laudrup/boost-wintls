//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_CONTEXT_HPP
#define BOOST_WINTLS_CONTEXT_HPP

#include <boost/wintls/method.hpp>

#include <boost/wintls/detail/context_impl.hpp>
#include <boost/wintls/detail/config.hpp>

#include <boost/winapi/handles.hpp>

#include <memory>
#include <string>

namespace boost {
namespace wintls {

/// @cond
namespace detail {
class sspi_handshake;
}
/// @endcond

class context {
public:
  /** Construct a context.
   *
   * @param method The @ref method to use for connections.
   */
  explicit context(method connection_method)
    : m_impl(std::make_unique<detail::context_impl>())
    , m_method(connection_method)
    , m_verify_server_certificate(false) {
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

  /** Enables/disables remote server certificate verification
   *
   * This function may be used to enable clients to verify the
   * certificate presented by the server with the known trusted
   * certificates.
   *
   * @param verify True if the remote server certificate should be
   * verified
   */
  void verify_server_certificate(bool verify) {
    m_verify_server_certificate = verify;
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
    if (!m_verify_server_certificate) {
      return boost::winapi::ERROR_SUCCESS_;
    }
    return m_impl->verify_certificate(cert);
  }

  const CERT_CONTEXT* server_cert() const {
    return m_impl->server_cert.get();
  }

  friend class detail::sspi_handshake;
  std::unique_ptr<detail::context_impl> m_impl;
  method m_method;
  bool m_verify_server_certificate;
};

} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_CONTEXT_HPP
