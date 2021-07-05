//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_WIN32_CRYPTO_HPP
#define BOOST_WINTLS_DETAIL_WIN32_CRYPTO_HPP

#include <boost/wintls/detail/config.hpp>
#include <boost/wintls/error.hpp>

extern "C" {
  typedef struct _CRYPT_DECODE_PARA CRYPT_DECODE_PARA;
  typedef CRYPT_DECODE_PARA* PCRYPT_DECODE_PARA;
  const DWORD X509_ASN_ENCODING = 1;

  BOOST_SYMBOL_IMPORT BOOL CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
  BOOST_SYMBOL_IMPORT BOOL CryptDecodeObjectEx(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, PCRYPT_DECODE_PARA, void*, DWORD*);
}

namespace boost {
namespace wintls {
namespace detail {

inline std::vector<BYTE> crypt_string_to_binary(const net::const_buffer& crypt_string) {
  DWORD size = 0;
  if (!CryptStringToBinaryA(reinterpret_cast<LPCSTR>(crypt_string.data()),
                            static_cast<DWORD>(crypt_string.size()),
                            0,
                            nullptr,
                            &size,
                            nullptr,
                            nullptr)) {
    throw_last_error("CryptStringToBinaryA");
  }

  std::vector<BYTE> data(size);
  if (!CryptStringToBinaryA(reinterpret_cast<LPCSTR>(crypt_string.data()),
                            static_cast<DWORD>(crypt_string.size()),
                            0,
                            data.data(),
                            &size,
                            nullptr,
                            nullptr)) {
    throw_last_error("CryptStringToBinaryA");
  }
  return data;
}

inline std::vector<BYTE> crypt_decode_object_ex(const net::const_buffer& crypt_object, LPCSTR type) {
  DWORD size = 0;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                           type,
                           reinterpret_cast<const BYTE*>(crypt_object.data()),
                           static_cast<DWORD>(crypt_object.size()),
                           0,
                           nullptr,
                           nullptr,
                           &size)) {
    throw_last_error("CryptDecodeObjectEx");
  }
  std::vector<BYTE> data(size);
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                           type,
                           reinterpret_cast<const BYTE*>(crypt_object.data()),
                           static_cast<DWORD>(crypt_object.size()),
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
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_WIN32_CRYPTO_HPP
