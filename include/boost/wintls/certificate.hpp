//
// Copyright (c) 2021 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_CERTIFICATE_HPP
#define BOOST_WINTLS_CERTIFICATE_HPP

#include WINTLS_INCLUDE(error)
#include WINTLS_INCLUDE(file_format)

#include WINTLS_INCLUDE(detail/win32_crypto)
#include WINTLS_INCLUDE(net)

#include <memory>

BOOST_NAMESPACE_DECLARE
namespace wintls {

/**
 * @verbatim embed:rst:leading-asterisk
 * Custom std::unique_ptr for managing a `CERT_CONTEXT`_
 * @endverbatim
 */
using cert_context_ptr = std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)>;

/**
 * @verbatim embed:rst:leading-asterisk
 * Convert certificate from standard X509 format to Windows `CERT_CONTEXT`_
 * @endverbatim
 *
 * @param x509 Buffer holding the X509 certificate contents
 *
 * @param format The @ref file_format of the X509 contents
 *
 * @return A managed cert_context
 *
 * @throws BOOST_NAMESPACE_USE system::system_error Thrown on failure.
 *
 */
inline cert_context_ptr x509_to_cert_context(const net::const_buffer& x509, file_format format) {
  // TODO: Support DER format
  WINTLS_VERIFY_MSG(format == file_format::pem, "Only PEM format currently implemented");

  auto data = detail::crypt_string_to_binary(x509);
  auto cert = CertCreateCertificateContext(X509_ASN_ENCODING, data.data(), static_cast<BOOST_NAMESPACE_USE winapi::DWORD_>(data.size()));
  if (!cert) {
    detail::throw_last_error("CertCreateCertificateContext");
  }

  return cert_context_ptr{cert, &CertFreeCertificateContext};
}

/**
 * @verbatim embed:rst:leading-asterisk
 * Convert certificate from standard X509 format to Windows `CERT_CONTEXT`_
 * @endverbatim
 *
 * @param x509 Buffer holding the X509 certificate contents
 *
 * @param format The @ref file_format of the X509 contents
 *
 * @param ec Set to indicate what error occurred, if any.
 *
 * @return A managed cert_context
 *
 */
inline cert_context_ptr x509_to_cert_context(const net::const_buffer& x509, file_format format, error::error_code& ec) {
  try {
    return x509_to_cert_context(x509, format);
  } catch (const error::named_error& e) {
    ec = e.code();
    return cert_context_ptr{nullptr, &CertFreeCertificateContext};
  }
}

} // namespace wintls
BOOST_NAMESPACE_END

#endif
