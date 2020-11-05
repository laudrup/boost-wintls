//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINDOWS_SSPI_DETAIL_WIN32_CRYPTO_HPP
#define BOOST_WINDOWS_SSPI_DETAIL_WIN32_CRYPTO_HPP

#include <boost/windows_sspi/detail/config.hpp>
#include <boost/windows_sspi/detail/sspi_types.h>
#include <boost/windows_sspi/error.hpp>

#include <boost/winapi/handles.hpp>

#include <memory>

namespace boost {
namespace windows_sspi {
namespace detail {

using cert_context = std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)>;

inline std::vector<boost::winapi::BYTE_> crypt_string_to_binary(const net::const_buffer& crypt_string) {
  boost::winapi::DWORD_ size;
  if (!CryptStringToBinaryA(reinterpret_cast<boost::winapi::LPCSTR_>(crypt_string.data()),
                            static_cast<boost::winapi::DWORD_>(crypt_string.size()),
                            0,
                            nullptr,
                            &size,
                            nullptr,
                            nullptr)) {
    throw_last_error("CryptStringToBinaryA");
  }

  std::vector<boost::winapi::BYTE_> data(size);
  if (!CryptStringToBinaryA(reinterpret_cast<boost::winapi::LPCSTR_>(crypt_string.data()),
                            static_cast<boost::winapi::DWORD_>(crypt_string.size()),
                            0,
                            data.data(),
                            &size,
                            nullptr,
                            nullptr)) {
    throw_last_error("CryptStringToBinaryA");
  }
  return data;
}

inline std::vector<boost::winapi::BYTE_> crypt_decode_object_ex(const net::const_buffer& crypt_object, winapi::LPCSTR_ type) {
  boost::winapi::DWORD_ size;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                           type,
                           reinterpret_cast<const boost::winapi::BYTE_*>(crypt_object.data()),
                           static_cast<boost::winapi::DWORD_>(crypt_object.size()),
                           0,
                           nullptr,
                           nullptr,
                           &size)) {
    throw_last_error("CryptDecodeObjectEx");
  }
  std::vector<boost::winapi::BYTE_> data(size);
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                           type,
                           reinterpret_cast<const boost::winapi::BYTE_*>(crypt_object.data()),
                           static_cast<boost::winapi::DWORD_>(crypt_object.size()),
                           0,
                           nullptr,
                           data.data(),
                           &size)) {
    throw_last_error("CryptDecodeObjectEx");
  }
  return data;
}

inline const CERT_CONTEXT* pem_to_cert_context(const net::const_buffer& ca) {
  auto data = crypt_string_to_binary(ca);
  auto cert = CertCreateCertificateContext(X509_ASN_ENCODING, data.data(), static_cast<boost::winapi::DWORD_>(data.size()));
  if (!cert) {
    throw_last_error("CertCreateCertificateContext");
  }
  return cert;
}

} // namespace detail
} // namespace windows_sspi
} // namespace boost

#endif // BOOST_WINDOWS_SSPI_DETAIL_WIN32_CRYPTO_HPP
