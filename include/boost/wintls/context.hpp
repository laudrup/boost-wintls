//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_CONTEXT_HPP
#define BOOST_WINTLS_CONTEXT_HPP

#include WINTLS_INCLUDE(method)

#include WINTLS_INCLUDE(detail/context_impl)
#include WINTLS_INCLUDE(detail/config)

#include WINAPI_INCLUDE(handles)

#include <memory>
#include <string>

BOOST_NAMESPACE_DECLARE
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
   * @param connection_method The @ref method to use for connections.
   */
  explicit context(method connection_method)
    : m_impl(std::make_unique<detail::context_impl>())
    , m_method(connection_method)
    , m_verify_server_certificate(false) {
  }

  /** Add certification authority for performing verification.
   *
   * This function is used to add one trusted certification authority
   * to the contexts certificate store used for certificate validation
   *
   * @param cert The certficate to add to the certificate store
   *
   * @throws BOOST_NAMESPACE_USE system::system_error Thrown on failure.
   */
  void add_certificate_authority(const CERT_CONTEXT* cert) {
    m_impl->add_certificate_authority(cert);
  }

  /** Add certification authority for performing verification.
   *
   * This function is used to add one trusted certification authority
   * to the contexts certificate store used for certificate validation
   *
   * @param cert The certficate to add to the certificate store
   *
   * @param ec Set to indicate what error occurred, if any.
   */
  void add_certificate_authority(const CERT_CONTEXT* cert, wintls::error::error_code& ec) {
    try {
      m_impl->add_certificate_authority(cert);
    } catch (const BOOST_NAMESPACE_USE wintls::error::named_error& e) {
      ec = e.code();
    }
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

  void set_default_verify_paths(BOOST_NAMESPACE_USE wintls::error::error_code& ec) {
    m_impl->use_default_cert_store = true;
    ec = {};
  }

  void use_certificate(const net::const_buffer& certificate, file_format format, wintls::system_error& ec) {
    try {
      m_impl->use_certificate(certificate, format);
    } catch (const BOOST_NAMESPACE_USE wintls::error::named_error& e) {
      ec = e.code();
    }
  }

  void use_certificate(const net::const_buffer& certificate, file_format format) {
    m_impl->use_certificate(certificate, format);
  }

  void use_certificate_file(const winapi::WindowsString& filename, file_format format, wintls::error::error_code& ec) {
    try {
      m_impl->use_certificate_file(filename, format);
    } catch (const wintls::error::named_error& e) {
      ec = e.code();
    }
  }

  void use_certificate_file(const winapi::WindowsString& filename, file_format format) {
    m_impl->use_certificate_file(filename, format);
  }

  void use_private_key(const net::const_buffer& private_key, file_format format, wintls::error::error_code& ec) {
    try {
      m_impl->use_private_key(private_key, format);
    } catch (const wintls::error::named_error& e) {
      ec = e.code();
    }
  }

  void use_private_key(const net::const_buffer& private_key, file_format format) {
    m_impl->use_private_key(private_key, format);
  }

  void use_private_key_file(const winapi::WindowsString& filename, file_format format, wintls::error::error_code& ec) {
    try {
      m_impl->use_private_key_file(filename, format);
    } catch (const BOOST_NAMESPACE_USE wintls::error::named_error& e) {
      ec = e.code();
    }
  }

  void use_private_key_file(const winapi::WindowsString& filename, file_format format) {
    m_impl->use_private_key_file(filename, format);
  }

private:
  BOOST_NAMESPACE_USE winapi::DWORD_ verify_certificate(const CERT_CONTEXT* cert) {
    if (!m_verify_server_certificate) {
      return BOOST_NAMESPACE_USE winapi::ERROR_SUCCESS_;
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
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_CONTEXT_HPP
