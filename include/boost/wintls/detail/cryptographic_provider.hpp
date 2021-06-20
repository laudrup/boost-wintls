//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_CRYPTOGRAPHIC_PROVIDER_HPP
#define BOOST_WINTLS_DETAIL_CRYPTOGRAPHIC_PROVIDER_HPP

#include WINTLS_INCLUDE(detail/sspi_types)
#include WINTLS_INCLUDE(detail/uuid)

BOOST_NAMESPACE_DECLARE
namespace wintls {
namespace detail {

class cryptographic_provider {
  // In order to use a private key it needs to be imported into a
  // cryptographic storage provider which can then return a handle.
  //
  // This means the private key will not be readable, not even in the
  // address room of the currently running process (which makes
  // sense), but there doesn't seem to be a way to avoid persisting
  // it, so this class adds the key to a randomly generated container
  // name and removes it again on destrution.
  //
  // TODO: Figure out if there's a better way to handle this.
public:
  cryptographic_provider() {
    if (!CryptAcquireContextW(&ptr, container_name.c_str(), MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
      auto last_error = BOOST_NAMESPACE_USE winapi::GetLastError();
      if (last_error == static_cast<BOOST_NAMESPACE_USE winapi::DWORD_>(NTE_EXISTS)) {
          if(!CryptAcquireContextW(&ptr, container_name.c_str(), MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_SILENT)) {
            BOOST_NAMESPACE_USE wintls::throw_system_error();
          }
      } else {
          BOOST_NAMESPACE_USE wintls::throw_system_error(last_error);
      }
    }
  }

  ~cryptographic_provider() {
    // Releasing the handle and then using it to delete the stored key set taken from here:
    // https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-using-cryptacquirecontext
    CryptReleaseContext(ptr, 0);
    CryptAcquireContextW(&ptr, container_name.c_str(), MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
  }

  cryptographic_provider(const cryptographic_provider&) = delete;
  cryptographic_provider& operator=(const cryptographic_provider&) = delete;

  std::wstring container_name = create_uuid();
  HCRYPTPROV ptr = 0;
};

} // namespace detail
} // namespace wintls
BOOST_NAMESPACE_END

#endif // BOOST_WINTLS_DETAIL_CRYPTOGRAPHIC_PROVIDER_HPP
