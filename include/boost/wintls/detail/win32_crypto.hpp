//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_WIN32_CRYPTO_HPP
#define BOOST_WINTLS_DETAIL_WIN32_CRYPTO_HPP

#include WINTLS_INCLUDE(detail/config)
#include WINTLS_INCLUDE(detail/sspi_types)
#include WINTLS_INCLUDE(error)

#include WINAPI_INCLUDE(handles)

#include <memory>

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace detail {

inline std::vector<BOOST_NAMESPACE_USE winapi::BYTE_> crypt_string_to_binary(const net::const_buffer& crypt_string) {
  BOOST_NAMESPACE_USE winapi::DWORD_ size;
  if (!CryptStringToBinaryA(reinterpret_cast<BOOST_NAMESPACE_USE winapi::LPCSTR_>(crypt_string.data()),
                            static_cast<BOOST_NAMESPACE_USE winapi::DWORD_>(crypt_string.size()),
                            0,
                            nullptr,
                            &size,
                            nullptr,
                            nullptr)) {
    throw_last_error("CryptStringToBinaryA");
  }

  std::vector<BOOST_NAMESPACE_USE winapi::BYTE_> data(size);
  if (!CryptStringToBinaryA(reinterpret_cast<BOOST_NAMESPACE_USE winapi::LPCSTR_>(crypt_string.data()),
                            static_cast<BOOST_NAMESPACE_USE winapi::DWORD_>(crypt_string.size()),
                            0,
                            data.data(),
                            &size,
                            nullptr,
                            nullptr)) {
    throw_last_error("CryptStringToBinaryA");
  }
  return data;
}

inline std::vector<BOOST_NAMESPACE_USE winapi::BYTE_> crypt_decode_object_ex(const net::const_buffer& crypt_object, winapi::LPCSTR_ type) {
  BOOST_NAMESPACE_USE winapi::DWORD_ size;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                           type,
                           reinterpret_cast<const BOOST_NAMESPACE_USE winapi::BYTE_*>(crypt_object.data()),
                           static_cast<BOOST_NAMESPACE_USE winapi::DWORD_>(crypt_object.size()),
                           0,
                           nullptr,
                           nullptr,
                           &size)) {
    throw_last_error("CryptDecodeObjectEx");
  }
  std::vector<BOOST_NAMESPACE_USE winapi::BYTE_> data(size);
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                           type,
                           reinterpret_cast<const BOOST_NAMESPACE_USE winapi::BYTE_*>(crypt_object.data()),
                           static_cast<BOOST_NAMESPACE_USE winapi::DWORD_>(crypt_object.size()),
                           0,
                           nullptr,
                           data.data(),
                           &size)) {
    throw_last_error("CryptDecodeObjectEx");
  }
  return data;
}

} // namespace detail
} // namespace wintls
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_DETAIL_WIN32_CRYPTO_HPP
