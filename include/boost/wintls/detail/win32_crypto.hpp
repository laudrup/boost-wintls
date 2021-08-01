//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_WIN32_CRYPTO_HPP
#define BOOST_WINTLS_DETAIL_WIN32_CRYPTO_HPP

#include <boost/wintls/detail/config.hpp>
#include <boost/wintls/detail/win32_crypto.hpp>
#include <boost/wintls/error.hpp>

#include <boost/winapi/basic_types.hpp>

#include <wincrypt.h>

namespace boost {
namespace wintls {
namespace detail {

inline std::vector<boost::winapi::BYTE_> crypt_string_to_binary(const net::const_buffer& crypt_string) {
  boost::winapi::DWORD_ size = 0;
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
  boost::winapi::DWORD_ size = 0;
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

} // namespace detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_WIN32_CRYPTO_HPP
